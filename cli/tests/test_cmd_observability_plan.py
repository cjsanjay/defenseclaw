# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import patch

import click
from click.testing import CliRunner
from defenseclaw.commands import cmd_observability
from defenseclaw.config_inspect import ConfigV8WireResult


def _effective() -> dict:
    return {
        "buckets": [
            {
                "bucket": "security.finding",
                "collect": {"logs": True, "traces": True, "metrics": True},
                "redaction_profile": "none",
            },
            {
                "bucket": "model.io",
                "collect": {"logs": False, "traces": False, "metrics": False},
                "redaction_profile": "none",
            },
        ],
        "destinations": [
            {
                "name": "local-sqlite",
                "enabled": True,
                "selected_signals": ["logs"],
                "routes": [
                    {
                        "name": "all-collected-logs-and-mandatory-floor",
                        "signals": ["logs"],
                        "selector": {"buckets": ["security.finding", "model.io"]},
                        "action": "send",
                        "includes_mandatory_floor": True,
                        "redaction_profile_by_bucket": {
                            "security.finding": "none",
                            "model.io": "none",
                        },
                    }
                ],
            },
            {
                "name": "soc",
                "kind": "http_jsonl",
                "enabled": True,
                "selected_signals": ["logs"],
                "transport": {
                    "batch": {
                        "max_queue_size": 2048,
                        "max_queue_bytes": 67108864,
                        "max_export_batch_size": 512,
                        "max_export_batch_bytes": 8388608,
                        "scheduled_delay_ms": 5000,
                    }
                },
                "routes": [
                    {
                        "name": "ai-findings",
                        "signals": ["logs"],
                        "selector": {"buckets": ["security.finding"], "sources": ["ai_defense"]},
                        "action": "send",
                        "redaction_profile_by_bucket": {"security.finding": "sensitive"},
                    },
                    {
                        "name": "remaining",
                        "signals": ["logs"],
                        "selector": {"buckets": ["security.finding", "model.io"]},
                        "action": "send",
                        "redaction_profile_by_bucket": {
                            "security.finding": "strict",
                            "model.io": "strict",
                        },
                    },
                ],
            },
        ],
        "warnings": [],
    }


def _wire() -> ConfigV8WireResult:
    return ConfigV8WireResult(
        wire_version=1,
        kind="effective",
        config_version=8,
        source="/tmp/config.yaml",
        data_dir="/tmp/dc",
        plan_digest="plan-digest",
        network_validation="offline_syntax_and_literal_policy_only",
        effective=_effective(),
    )


def test_plan_labels_unknown_metadata_match_as_conditional() -> None:
    rows = cmd_observability._plan_rows(
        _effective(),
        selected_buckets={"security.finding"},
        selected_signals={"logs"},
        filters=cmd_observability._PlanFilters(),
    )
    remote = next(row for row in rows if row["destination"] == "soc")
    assert remote["decision"] == "conditional"
    assert remote["route"] == "ai-findings"
    assert remote["potential_action"] == "send"
    assert "compatibility_profile" not in remote


def test_plan_filters_resolve_first_match_without_recompiling_routes() -> None:
    rows = cmd_observability._plan_rows(
        _effective(),
        selected_buckets={"security.finding"},
        selected_signals={"logs"},
        filters=cmd_observability._PlanFilters(source="gateway"),
    )
    remote = next(row for row in rows if row["destination"] == "soc")
    assert remote["decision"] == "send"
    assert remote["route"] == "remaining"
    assert remote["redaction_profile"] == "strict"


def test_plan_labels_event_level_floor_as_conditional_and_remote_as_not_collected() -> None:
    rows = cmd_observability._plan_rows(
        _effective(),
        selected_buckets={"model.io"},
        selected_signals={"logs"},
        filters=cmd_observability._PlanFilters(),
    )
    by_destination = {row["destination"]: row for row in rows}
    assert by_destination["local-sqlite"]["decision"] == "conditional"
    assert by_destination["local-sqlite"]["potential_action"] == "floor_only"
    assert by_destination["local-sqlite"]["condition"] == "mandatory_floor_event_qualification"
    assert by_destination["local-sqlite"]["route"] == "all-collected-logs-and-mandatory-floor"
    assert by_destination["soc"]["decision"] == "not_collected"


def test_top_level_plan_skips_legacy_runtime_config_load(tmp_path: Path) -> None:
    from defenseclaw.main import cli

    config_path = tmp_path / "config.yaml"
    config_path.write_text("config_version: 8\nobservability: {}\n", encoding="utf-8")
    with (
        patch.object(cmd_observability.config_module, "config_path", return_value=config_path),
        patch.object(cmd_observability, "inspect_v8_config", return_value=_wire()),
        patch("defenseclaw.config.load", side_effect=AssertionError("legacy config loader must not run")),
    ):
        result = CliRunner().invoke(
            cli,
            ["observability", "plan", "--bucket", "security.finding", "--signal", "logs", "--format", "json"],
        )

    assert result.exit_code == 0, result.output
    payload = json.loads(result.output)
    assert payload["basis"] == "canonical_go_compiled_routes"
    assert payload["plan_digest"] == "plan-digest"
    assert payload["delivery"] == [
        {
            "destination": "soc",
            "kind": "http_jsonl",
            "max_queue_size": 2048,
            "max_queue_bytes": 67108864,
            "max_export_batch_size": 512,
            "max_export_batch_bytes": 8388608,
            "scheduled_delay_ms": 5000,
        }
    ]
    assert len(payload["rows"]) == 2


def test_plan_table_renders_compiled_delivery_limits() -> None:
    runner = CliRunner()
    with runner.isolated_filesystem():
        result = runner.invoke(
            click.Command(
                "render",
                callback=lambda: cmd_observability._render_plan_table(
                    [], "digest", cmd_observability._delivery_settings(_effective())
                ),
            )
        )

    assert result.exit_code == 0, result.output
    assert "Delivery limits (compiled defaults and source overrides):" in result.output
    assert "67108864" in result.output
    assert "8388608" in result.output
