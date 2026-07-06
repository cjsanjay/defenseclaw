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

import copy
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

import pytest
from defenseclaw.observability.v8_config import V8ConfigError
from defenseclaw.observability.v8_status import (
    V8BucketStatus,
    V8DestinationStatus,
    V8OperatorStatus,
    operator_status_from_effective,
    source_is_v8,
)


def _effective() -> dict[str, object]:
    bucket_names = ("compliance.activity", "model.io", "platform.health")
    return {
        "bucket_catalog_version": 1,
        "local": {
            "path": "/var/lib/defenseclaw/audit.db",
            "judge_bodies_path": "/var/lib/defenseclaw/judge.db",
            "retention_days": 90,
        },
        "buckets": [
            {
                "bucket": name,
                "collect": {
                    "logs": True,
                    "traces": name != "model.io",
                    "metrics": True,
                },
                "redaction_profile": "none" if name != "model.io" else "sensitive",
            }
            for name in bucket_names
        ],
        "destinations": [
            {
                "name": "local-sqlite",
                "kind": "sqlite",
                "enabled": True,
                "generated": True,
                "capabilities": {"signals": ["logs"]},
                "selected_signals": ["logs"],
                "policy_form": "implicit_local",
                "routes": [
                    {
                        "action": "send",
                        "selector": {"bucket_wildcard": True},
                        "redaction_profile_by_bucket": {
                            "compliance.activity": "none",
                            "model.io": "sensitive",
                            "platform.health": "none",
                        },
                    }
                ],
                "transport": {"path": "/var/lib/defenseclaw/audit.db"},
            },
            {
                "name": "collector",
                "kind": "otlp",
                "enabled": True,
                "generated": False,
                "capabilities": {"signals": ["logs", "traces", "metrics"]},
                "selected_signals": ["logs", "traces", "metrics"],
                "policy_form": "capability_default",
                "routes": [
                    {
                        "action": "send",
                        "selector": {"bucket_wildcard": True},
                        "redaction_profile_by_bucket": {
                            "compliance.activity": "none",
                            "model.io": "none",
                            "platform.health": "none",
                        },
                    }
                ],
                "transport": {"endpoint": "https://collector.example.test", "headers": {"authorization": "<masked>"}},
            },
            {
                "name": "strict-jsonl",
                "kind": "jsonl",
                "enabled": False,
                "generated": False,
                "capabilities": {"signals": ["logs"]},
                "selected_signals": ["logs"],
                "policy_form": "advanced_routes",
                "routes": [
                    {
                        "action": "drop",
                        "selector": {"buckets": ["model.io"]},
                    },
                    {
                        "action": "send",
                        "selector": {"buckets": ["compliance.activity"]},
                        "redaction_profile_by_bucket": {"compliance.activity": "strict"},
                    },
                ],
                "transport": {"path": "/tmp/events.jsonl"},
            },
        ],
        "warnings": [
            {
                "code": "unbounded_retention",
                "path": "observability.local.retention_days",
                "summary": "retention is unbounded",
            }
        ],
    }


def test_operator_status_preserves_effective_capabilities_routes_and_redaction() -> None:
    status = operator_status_from_effective(
        _effective(),
        source="/tmp/config.yaml",
        data_dir="/tmp",
        plan_digest="a" * 64,
    )

    assert status.bucket_catalog_version == 1
    assert status.retention_days == 90
    assert not status.unbounded_retention
    assert status.local_path.endswith("audit.db")
    assert [bucket.name for bucket in status.buckets] == [
        "compliance.activity",
        "model.io",
        "platform.health",
    ]
    assert status.buckets[1].collected_signals == ("logs", "metrics")
    assert status.buckets[1].redaction_profile == "sensitive"

    local, collector, jsonl = status.destinations
    assert local.generated and local.kind == "sqlite"
    assert local.redaction_label == "mixed: none, sensitive"
    assert collector.selected_signals == ("logs", "traces", "metrics")
    assert collector.buckets == (
        "compliance.activity",
        "model.io",
        "platform.health",
    )
    assert collector.redaction_label == "unredacted (none)"
    assert collector.endpoint == "https://collector.example.test"
    assert jsonl.route_count == 2
    assert jsonl.buckets == ("compliance.activity",)
    assert jsonl.redaction_label == "redacted: strict"
    assert "authorization" not in repr(status)


def test_operator_status_reports_unbounded_retention() -> None:
    effective = _effective()
    assert isinstance(effective["local"], dict)
    effective["local"]["retention_days"] = 0
    status = operator_status_from_effective(effective, source="x", data_dir="y", plan_digest="z")
    assert status.unbounded_retention


def test_operator_status_accepts_canonical_null_warning_slice() -> None:
    effective = _effective()
    effective["warnings"] = None
    status = operator_status_from_effective(effective, source="x", data_dir="y", plan_digest="z")
    assert status.warnings == ()


@pytest.mark.parametrize(
    ("mutation", "message"),
    [
        (lambda value: value.pop("local"), "local"),
        (lambda value: value["buckets"][0]["collect"].update(logs="yes"), "collect.logs"),
        (lambda value: value["destinations"][0].update(enabled="yes"), "enabled"),
        (lambda value: value["destinations"][0].update(selected_signals="logs"), "selected_signals"),
        (lambda value: value["destinations"][0]["routes"][0].update(action=""), "action"),
    ],
)
def test_operator_status_fails_closed_on_malformed_canonical_wire(mutation, message: str) -> None:
    effective = copy.deepcopy(_effective())
    mutation(effective)
    with pytest.raises(ValueError, match=message):
        operator_status_from_effective(effective, source="x", data_dir="y", plan_digest="z")


def test_source_is_v8_distinguishes_exact_v7_and_valid_v8(tmp_path: Path) -> None:
    path = tmp_path / "config.yaml"
    path.write_text("config_version: 7\n")
    assert not source_is_v8(path)
    path.write_text("config_version: 8\nobservability: {}\n")
    assert source_is_v8(path)


def test_source_is_v8_does_not_downgrade_invalid_v8_to_v7(tmp_path: Path) -> None:
    path = tmp_path / "config.yaml"
    path.write_text("config_version: 8\nobservability:\n  destinations: wrong\n")
    with pytest.raises(V8ConfigError):
        source_is_v8(path)


def test_missing_source_is_not_v8(tmp_path: Path) -> None:
    assert not source_is_v8(tmp_path / "missing.yaml")


def test_doctor_v8_dispatch_renders_retention_destinations_and_warnings(tmp_path: Path) -> None:
    from defenseclaw.commands.cmd_doctor import _check_observability, _DoctorResult

    config_path = tmp_path / "config.yaml"
    config_path.write_text("config_version: 8\nobservability: {}\n")
    status = V8OperatorStatus(
        source=str(config_path),
        data_dir=str(tmp_path),
        plan_digest="a" * 64,
        bucket_catalog_version=1,
        retention_days=0,
        local_path=str(tmp_path / "audit.db"),
        judge_bodies_path=str(tmp_path / "judge.db"),
        destinations=(
            V8DestinationStatus(
                name="local-sqlite",
                kind="sqlite",
                enabled=True,
                generated=True,
                capabilities=("logs",),
                selected_signals=("logs",),
                policy_form="implicit_local",
                endpoint=str(tmp_path / "audit.db"),
                route_count=1,
                buckets=("compliance.activity",),
                redaction_profiles=("none",),
            ),
            V8DestinationStatus(
                name="collector",
                kind="otlp",
                enabled=False,
                generated=False,
                capabilities=("logs", "traces", "metrics"),
                selected_signals=("logs", "traces", "metrics"),
                policy_form="capability_default",
                endpoint="https://collector.example.test",
                route_count=1,
                buckets=("compliance.activity",),
                redaction_profiles=("strict",),
            ),
        ),
        buckets=(V8BucketStatus("compliance.activity", ("logs",), "none"),),
        warnings=(
            (
                "unbounded_retention",
                "observability.local.retention_days",
                "capacity may grow",
            ),
        ),
    )
    result = _DoctorResult()
    with patch(
        "defenseclaw.observability.v8_status.inspect_v8_operator_status",
        return_value=status,
    ):
        _check_observability(SimpleNamespace(data_dir=str(tmp_path)), result)

    checks = {item["label"]: item for item in result.checks}
    assert checks["Local SQLite"]["status"] == "warn"
    assert "retention=unbounded" in checks["Local SQLite"]["detail"]
    assert checks["Destination: local-sqlite"]["status"] == "pass"
    assert "redaction=unredacted (none)" in checks["Destination: local-sqlite"]["detail"]
    assert checks["Destination: collector"]["status"] == "skip"
    assert checks["Bucket catalog"]["detail"] == "version=1; collected=1/1"
    assert checks["Observability warning: unbounded_retention"]["status"] == "warn"


def test_doctor_invalid_v8_never_falls_back_to_legacy_destination_reader(tmp_path: Path) -> None:
    from defenseclaw.commands.cmd_doctor import _check_observability, _DoctorResult

    (tmp_path / "config.yaml").write_text("config_version: 8\nobservability:\n  destinations: wrong\n")
    result = _DoctorResult()
    with patch("defenseclaw.observability.list_destinations") as legacy:
        _check_observability(SimpleNamespace(data_dir=str(tmp_path)), result)
    legacy.assert_not_called()
    assert result.failed == 1
    assert result.checks[0]["label"] == "Observability v8 configuration"
