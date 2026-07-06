# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
# SPDX-License-Identifier: Apache-2.0

"""Offline contracts for the single historical release-upgrade harness."""

from __future__ import annotations

import re
import subprocess
from pathlib import Path

import pytest
import yaml
from defenseclaw.observability.v8_migration import convert_v7_observability_to_v8

ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / "scripts" / "test-upgrade-release.sh"
MAKEFILE = ROOT / "Makefile"


def _source_script(command: str, *arguments: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        ["bash", "-c", f'source "$1"; {command}', "upgrade-smoke-contract", str(SCRIPT), *arguments],
        cwd=ROOT,
        text=True,
        capture_output=True,
        check=False,
    )


@pytest.mark.parametrize(
    ("target", "expected"),
    [
        ("0.8.3", False),
        ("0.8.4", True),
        ("0.9.0", True),
        ("1.0.0", True),
    ],
)
def test_target_version_selects_the_forward_v8_contract(target: str, expected: bool) -> None:
    completed = _source_script(
        'TARGET_VERSION="$2"; target_uses_observability_v8',
        target,
    )
    assert (completed.returncode == 0) is expected, completed.stderr


def _seed_fixture(tmp_path: Path) -> Path:
    home = tmp_path / "home"
    completed = _source_script(
        'SMOKE_HOME="$2"; mkdir -p "$SMOKE_HOME"; seed_v8_observability_fixture',
        str(home),
    )
    assert completed.returncode == 0, completed.stderr
    return home / ".defenseclaw"


def test_v8_fixture_covers_the_historical_matrix_contract(tmp_path: Path) -> None:
    data_dir = _seed_fixture(tmp_path)
    document = yaml.safe_load((data_dir / "config.yaml").read_text(encoding="utf-8"))

    assert document["config_version"] == 7
    assert document["otel"]["endpoint"] == "127.0.0.1:4317"
    assert {item["name"] for item in document["otel"]["destinations"]} == {
        "existing-otlp",
        "galileo",
    }
    assert document["otel"]["logs"]["enabled"] is True
    assert document["otel"]["traces"]["enabled"] is True
    assert document["otel"]["metrics"]["enabled"] is True
    assert {item["kind"] for item in document["audit_sinks"]} == {
        "splunk_hec",
        "http_jsonl",
        "otlp_logs",
    }
    assert document["observability"]["connectors"]["codex"]["audit_sinks"] == []
    assert document["privacy"]["disable_redaction"] is False
    assert document["ai_discovery"]["emit_otel"] is False
    assert document["audit_db"].endswith("/state/audit-custom.db")
    assert document["judge_bodies_db"].endswith("/state/judge-custom.db")
    assert (data_dir / "observability-stack/operator/volume-continuity.txt").is_file()
    assert (data_dir / "observability-stack/grafana/dashboards/team-upgrade-smoke.json").is_file()
    assert (tmp_path / "home/fixture-evidence/config.v7.source").read_bytes() == (data_dir / "config.yaml").read_bytes()


def test_source_0_8_0_proves_the_0_8_4_fixture_conversion(tmp_path: Path) -> None:
    data_dir = _seed_fixture(tmp_path)
    source = (data_dir / "config.yaml").read_bytes()
    result = convert_v7_observability_to_v8(
        source,
        {},
        source_name=str(data_dir / "config.yaml"),
        effective_data_dir=str(data_dir),
    )
    candidate_text = result.candidate.decode("utf-8")
    document = yaml.safe_load(candidate_text)
    observability = document["observability"]
    destinations = {item["name"]: item for item in observability["destinations"]}

    assert document["config_version"] == 8
    assert not {"otel", "audit_sinks", "privacy"} & document.keys()
    assert document["ai_discovery"] == {"enabled": True}
    assert observability["defaults"]["redaction_profile"] == "legacy-v7"
    assert observability["local"] == {
        "path": str(data_dir / "state/audit-custom.db"),
        "judge_bodies_path": str(data_dir / "state/judge-custom.db"),
    }
    assert {
        "gateway-jsonl",
        "gateway-console",
        "local-observability",
        "existing-otlp",
        "galileo",
        "galileo-logs-metrics",
        "splunk-protected",
        "http-protected",
        "audit-otlp",
    }.issubset(destinations)
    assert destinations["galileo"]["preset"] == "galileo"
    assert destinations["galileo"]["batch"]["scheduled_delay_ms"] == 1000
    assert destinations["audit-otlp"]["logger_name"] == "defenseclaw.upgrade-smoke"
    assert destinations["splunk-protected"]["token_env"] == ("DEFENSECLAW_MIGRATED_SPLUNK_PROTECTED_TOKEN")
    assert destinations["http-protected"]["bearer_env"] == ("DEFENSECLAW_MIGRATED_HTTP_PROTECTED_BEARER")
    assert {edit.name for edit in result.environment_edits} == {
        "DEFENSECLAW_MIGRATED_AUDIT_OTLP_AUTHORIZATION",
        "DEFENSECLAW_MIGRATED_HTTP_PROTECTED_BEARER",
        "DEFENSECLAW_MIGRATED_LOCAL_OBSERVABILITY_X_FLAT_PROTECTED",
        "DEFENSECLAW_MIGRATED_SPLUNK_PROTECTED_TOKEN",
    }
    for protected in (
        "upgrade-smoke-flat-protected-value",
        "upgrade-smoke-splunk-protected-value",
        "upgrade-smoke-http-protected-value",
        "upgrade-smoke-otlp-protected-value",
    ):
        assert protected not in candidate_text
    assert "# ┌──── OBSERVABILITY UPGRADE SMOKE ────┐" in candidate_text
    assert "# unrelated section survives" in candidate_text


def test_matrix_includes_every_downloadable_v7_baseline() -> None:
    line = next(
        line for line in MAKEFILE.read_text(encoding="utf-8").splitlines() if line.startswith("UPGRADE_SMOKE_FROM")
    )
    assert line.split("?=", 1)[1].split() == [
        "0.8.3",
        "0.8.2",
        "0.8.1",
        "0.8.0",
        "0.7.2",
        "0.7.1",
        "0.6.6",
        "0.6.5",
        "0.6.4",
        "0.6.3",
        "0.6.2",
        "0.6.1",
        "0.6.0",
        "0.5.0",
        "0.4.0",
    ]


def test_harness_invokes_existing_permission_retry_rollback_and_bundle_tests() -> None:
    script = SCRIPT.read_text(encoding="utf-8")
    assert "run_v8_source_contract_tests" in script
    for test_file in (
        "cli/tests/test_observability_v8_activation.py",
        "cli/tests/test_observability_v8_upgrade_migration.py",
        "cli/tests/test_local_observability_bundle_upgrade.py",
        "cli/tests/test_local_observability_upgrade_wiring.py",
    ):
        assert test_file in script
    assert 'if [[ "${BASH_SOURCE[0]}" == "$0" ]]' in script


def test_harness_embedded_python_and_v8_verifier_contract_are_static_valid() -> None:
    script = SCRIPT.read_text(encoding="utf-8")
    lines = script.splitlines()
    programs: list[str] = []
    index = 0
    while index < len(lines):
        if re.search(r"<<'PY'\s*$", lines[index]):
            end = index + 1
            while end < len(lines) and lines[end] != "PY":
                end += 1
            assert end < len(lines), f"unterminated Python heredoc after line {index + 1}"
            programs.append("\n".join(lines[index + 1 : end]) + "\n")
            index = end
        index += 1

    assert programs
    for program in programs:
        compile(program, str(SCRIPT), "exec")
    for verifier_contract in (
        'config.get("config_version") != 8',
        'for legacy in ("otel", "audit_sinks", "privacy")',
        '"DEFENSECLAW_MIGRATED_SPLUNK_PROTECTED_TOKEN"',
        'glob("observability-v8-*/manifest.json")',
        'bundle_manifest.get("bundle_version") != target_version',
        "defenseclaw-gateway status",
        "DOCKER_HOST=",
        "tail_v8_upgrade_log_secret_safe",
    ):
        assert verifier_contract in script


def test_v8_failure_tail_redacts_every_fixture_value(tmp_path: Path) -> None:
    protected = (
        "upgrade-smoke-flat-protected-value",
        "upgrade-smoke-splunk-protected-value",
        "upgrade-smoke-http-protected-value",
        "Bearer upgrade-smoke-otlp-protected-value",
    )
    log = tmp_path / "upgrade.log"
    log.write_text("\n".join(protected) + "\nordinary diagnostic\n", encoding="utf-8")

    completed = _source_script('tail_v8_upgrade_log_secret_safe "$2"', str(log))

    assert completed.returncode == 0
    assert "ordinary diagnostic" in completed.stderr
    assert "[REDACTED]" in completed.stderr
    assert all(value not in completed.stderr for value in protected)
