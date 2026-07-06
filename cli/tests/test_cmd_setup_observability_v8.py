# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

import json
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

import click
import pytest
from click.testing import CliRunner
from defenseclaw.commands.cmd_setup_observability import (
    _build_v8_preset_destination,
    _print_v8_destination_list,
    _remove_v8_destination,
    _set_v8_destination_enabled,
    _test_v8_destination,
    _v8_destination_update_mutations,
    _v8_source_destination_index,
)
from defenseclaw.observability import PRESETS
from defenseclaw.observability.v8_config import load_validate_v8
from defenseclaw.observability.v8_status import V8DestinationStatus, V8OperatorStatus
from defenseclaw.observability.v8_writer import V8PolicyWriteResult
from defenseclaw.observability.v8_yaml import DELETE


def _source() -> str:
    return """config_version: 8
observability:
  destinations:
    - name: terminal
      kind: console
    - name: archive
      kind: jsonl
      path: /tmp/archive.jsonl
"""


def _status() -> V8OperatorStatus:
    return V8OperatorStatus(
        source="/tmp/config.yaml",
        data_dir="/tmp",
        plan_digest="a" * 64,
        bucket_catalog_version=1,
        retention_days=90,
        local_path="/tmp/audit.db",
        judge_bodies_path="",
        destinations=(
            V8DestinationStatus(
                name="local-sqlite",
                kind="sqlite",
                enabled=True,
                generated=True,
                capabilities=("logs",),
                selected_signals=("logs",),
                policy_form="implicit_local",
                endpoint="/tmp/audit.db",
                route_count=1,
                buckets=("compliance.activity",),
                redaction_profiles=("none",),
            ),
            V8DestinationStatus(
                name="collector",
                kind="otlp",
                enabled=True,
                generated=False,
                capabilities=("logs", "traces", "metrics"),
                selected_signals=("logs", "traces", "metrics"),
                policy_form="capability_default",
                endpoint="https://collector.example.test",
                route_count=1,
                buckets=("compliance.activity",),
                redaction_profiles=("none",),
            ),
        ),
        buckets=(),
        warnings=(),
    )


def test_v8_source_destination_index_uses_authored_not_generated_order(tmp_path: Path) -> None:
    (tmp_path / "config.yaml").write_text(_source())
    assert _v8_source_destination_index(str(tmp_path), "terminal") == 0
    assert _v8_source_destination_index(str(tmp_path), "archive") == 1
    with pytest.raises(click.ClickException, match="mandatory"):
        _v8_source_destination_index(str(tmp_path), "local-sqlite")
    with pytest.raises(click.ClickException, match="terminal, archive|archive, terminal"):
        _v8_source_destination_index(str(tmp_path), "missing")


def test_v8_enable_mutates_exact_source_index() -> None:
    result = V8PolicyWriteResult(True, "a" * 64, "b" * 64)
    with (
        patch(
            "defenseclaw.commands.cmd_setup_observability._v8_source_destination_index",
            return_value=3,
        ),
        patch(
            "defenseclaw.observability.v8_writer.mutate_v8_config",
            return_value=result,
        ) as mutate,
    ):
        _set_v8_destination_enabled("/tmp/dc", "collector", True, "")
    args, kwargs = mutate.call_args
    assert str(args[0]).endswith("/tmp/dc/config.yaml")
    assert args[1][0].path == ("observability", "destinations", 3, "enabled")
    assert args[1][0].value is True
    assert kwargs == {"data_dir": "/tmp/dc"}


def test_v8_remove_mutates_exact_source_index_and_rejects_connector_scope() -> None:
    result = V8PolicyWriteResult(True, "a" * 64, "b" * 64)
    with (
        patch(
            "defenseclaw.commands.cmd_setup_observability._v8_source_destination_index",
            return_value=1,
        ),
        patch(
            "defenseclaw.observability.v8_writer.mutate_v8_config",
            return_value=result,
        ) as mutate,
    ):
        _remove_v8_destination("/tmp/dc", "archive", "")
    mutation = mutate.call_args.args[1][0]
    assert mutation.path == ("observability", "destinations", 1)
    with pytest.raises(click.ClickException, match="process-wide"):
        _remove_v8_destination("/tmp/dc", "archive", "codex")


@pytest.mark.parametrize("emit_json", [False, True])
def test_v8_destination_list_exposes_signals_policy_and_unredacted_default(emit_json: bool) -> None:
    @click.command()
    def command() -> None:
        _print_v8_destination_list(_status(), emit_json=emit_json)

    result = CliRunner().invoke(command)
    assert result.exit_code == 0, result.output
    if emit_json:
        rows = json.loads(result.output)
        assert rows[1]["signals"] == ["logs", "traces", "metrics"]
        assert rows[1]["redaction"] == "unredacted (none)"
        assert rows[1]["bucket_count"] == 1
    else:
        assert "capability_default" in result.output
        assert "logs,traces,metrics" in result.output
        assert "unredacted (none)" in result.output
        assert "Retention: 90 days" in result.output


@pytest.mark.parametrize(
    ("preset_id", "inputs"),
    [
        ("splunk-o11y", {"realm": "us1"}),
        (
            "splunk-hec",
            {
                "host": "localhost",
                "port": "8088",
                "index": "defenseclaw",
                "source": "defenseclaw",
                "sourcetype": "_json",
            },
        ),
        (
            "splunk-enterprise",
            {
                "endpoint": "https://splunk.example.test:8088/services/collector/event",
                "index": "defenseclaw",
                "source": "defenseclaw",
                "sourcetype": "_json",
            },
        ),
        ("datadog", {"site": "us5"}),
        ("honeycomb", {"dataset": "defenseclaw"}),
        ("newrelic", {"region": "us"}),
        ("grafana-cloud", {"region": "prod-us-east-0"}),
        (
            "galileo",
            {
                "endpoint": "https://api.galileo.ai/otel/traces",
                "project": "defenseclaw",
                "logstream": "default",
            },
        ),
        ("local-otlp", {"endpoint": "127.0.0.1:4317"}),
        ("otlp", {"endpoint": "collector.example.test:4317", "protocol": "grpc"}),
        ("webhook", {"url": "https://example.test/events", "method": "POST"}),
    ],
)
def test_every_setup_preset_builds_a_schema_valid_v8_destination(
    preset_id: str,
    inputs: dict[str, str],
) -> None:
    destination = _build_v8_preset_destination(
        PRESETS[preset_id],
        inputs,
        name="target",
        enabled=True,
        signals=None,
        target=None,
    )
    validated = load_validate_v8(
        {
            "config_version": 8,
            "observability": {"destinations": [destination]},
        }
    ).source
    assert validated["observability"]["destinations"][0]["name"] == "target"


def test_v8_otlp_default_is_all_capabilities_unredacted_and_explicit_signals_narrow() -> None:
    preset = PRESETS["otlp"]
    default = _build_v8_preset_destination(
        preset,
        {"endpoint": "collector.example.test:4317", "protocol": "grpc"},
        name="all-signals",
        enabled=True,
        signals=None,
        target=None,
    )
    assert "send" not in default

    narrowed = _build_v8_preset_destination(
        preset,
        {"endpoint": "collector.example.test:4317", "protocol": "grpc"},
        name="logs-only",
        enabled=True,
        signals=("logs",),
        target=None,
    )
    assert narrowed["send"] == {
        "signals": ["logs"],
        "buckets": ["*"],
        "redaction_profile": "none",
    }


def test_v8_explicit_signal_update_removes_stale_signal_overrides() -> None:
    existing = {
        "name": "datadog",
        "kind": "otlp",
        "signal_overrides": {
            "logs": {"path": "/v1/logs"},
            "traces": {"path": "/v1/traces"},
            "metrics": {"path": "/v1/metrics"},
        },
    }
    narrowed = _build_v8_preset_destination(
        PRESETS["datadog"],
        {"site": "us5"},
        name="datadog",
        enabled=True,
        signals=("logs",),
        target=None,
    )
    mutations = _v8_destination_update_mutations(0, existing, narrowed)
    deleted = {mutation.path for mutation in mutations if mutation.value is DELETE}
    assert deleted == {
        ("observability", "destinations", 0, "signal_overrides", "traces"),
        ("observability", "destinations", 0, "signal_overrides", "metrics"),
    }


def test_v8_galileo_is_trace_only_and_uses_secret_reference() -> None:
    preset = PRESETS["galileo"]
    destination = _build_v8_preset_destination(
        preset,
        {
            "endpoint": "https://api.galileo.ai/otel/traces",
            "project": "project",
            "logstream": "stream",
        },
        name="galileo",
        enabled=True,
        signals=None,
        target=None,
    )
    assert destination["preset"] == "galileo"
    assert destination["batch"] == {"scheduled_delay_ms": 1000}
    assert destination["headers"]["Galileo-API-Key"] == {"env": "GALILEO_API_KEY"}
    with pytest.raises(ValueError, match="traces only"):
        _build_v8_preset_destination(
            preset,
            {
                "endpoint": "https://api.galileo.ai/otel/traces",
                "project": "project",
                "logstream": "stream",
            },
            name="galileo",
            enabled=True,
            signals=("logs",),
            target=None,
        )


def test_setup_v8_destination_test_uses_canonical_local_evidence_path() -> None:
    inspected = SimpleNamespace(
        effective={"destinations": []},
        source="/tmp/dc/config.yaml",
        data_dir="/tmp/dc",
    )
    result = SimpleNamespace(
        destination="collector",
        mode="write_probe",
        protocol="grpc",
        endpoint_count=1,
        probe_id="probe-123",
    )
    with (
        patch(
            "defenseclaw.config_inspect.inspect_v8_config",
            return_value=inspected,
        ),
        patch(
            "defenseclaw.observability.destination_test.canonical_local_compliance_recorder",
            return_value="recorder",
        ) as recorder,
        patch(
            "defenseclaw.observability.destination_test.run_destination_test",
            return_value=result,
        ) as run,
    ):
        _test_v8_destination("/tmp/dc", "collector", 3.0, write_probe=True)
    recorder.assert_called_once_with(
        config_path="/tmp/dc/config.yaml",
        data_dir="/tmp/dc",
    )
    assert run.call_args.kwargs["write_probe"] is True
    assert run.call_args.kwargs["compliance"] == "recorder"
