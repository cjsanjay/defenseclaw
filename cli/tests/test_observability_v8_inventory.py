"""Regression tests for the observability-v8 current-state inventory gate."""

from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[2]
CHECKER = ROOT / "scripts" / "check_observability_v8_inventory.py"
INVENTORY = ROOT / "docs" / "design" / "observability-v8" / "current-state-inventory.yaml"


def _run(
    inventory: Path | None = INVENTORY,
    *,
    env: dict[str, str] | None = None,
) -> subprocess.CompletedProcess[str]:
    command = [sys.executable, str(CHECKER)]
    if inventory is not None:
        command.extend(("--inventory", str(inventory)))
    return subprocess.run(
        command,
        cwd=ROOT,
        check=False,
        capture_output=True,
        text=True,
        timeout=60,
        env=env,
    )


def test_observability_v8_current_state_inventory_matches_sources() -> None:
    result = _run()

    assert result.returncode == 0, result.stdout + result.stderr
    # These counts are intentional drift pins: adding or removing a covered source
    # surface must update the reviewed inventory and this baseline together.
    assert "legacy_config_anchors=37" in result.stdout
    assert "gateway_event_types=14" in result.stdout
    assert "audit_actions=188" in result.stdout
    assert "emitted_metrics=131" in result.stdout
    assert "schema_files=23" in result.stdout
    assert "grafana_dashboard_uids=14" in result.stdout
    assert "grafana_datasource_uids=3" in result.stdout
    assert "compatibility_baseline_commits=2" in result.stdout


def test_observability_v8_inventory_uses_default_path_without_arguments() -> None:
    result = _run(None)

    assert result.returncode == 0, result.stdout + result.stderr
    assert "check_observability_v8_inventory: ok" in result.stdout


def test_observability_v8_inventory_is_portable_without_git(tmp_path: Path) -> None:
    environment = dict(os.environ)
    environment["PATH"] = str(tmp_path)

    result = _run(env=environment)

    assert result.returncode == 0, result.stdout + result.stderr
    assert "compatibility_baseline_commits=2" in result.stdout


def test_observability_v8_inventory_detects_untracked_action(tmp_path: Path) -> None:
    document = yaml.safe_load(INVENTORY.read_text(encoding="utf-8"))
    document["classes"]["audit_actions"]["items"].pop("ActionInit")
    tampered = tmp_path / "current-state-inventory.yaml"
    tampered.write_text(yaml.safe_dump(document, sort_keys=False), encoding="utf-8")

    result = _run(tampered)

    assert result.returncode == 1
    assert "audit_actions: untracked source item 'ActionInit'" in result.stderr


def test_observability_v8_inventory_requires_disposition(tmp_path: Path) -> None:
    document = yaml.safe_load(INVENTORY.read_text(encoding="utf-8"))
    del document["classes"]["gateway_event_types"]["migration_disposition"]
    tampered = tmp_path / "current-state-inventory.yaml"
    tampered.write_text(yaml.safe_dump(document, sort_keys=False), encoding="utf-8")

    result = _run(tampered)

    assert result.returncode == 2
    assert "classes.gateway_event_types.migration_disposition" in result.stderr


def test_observability_v8_inventory_rejects_non_mapping_root(tmp_path: Path) -> None:
    malformed = tmp_path / "current-state-inventory.yaml"
    malformed.write_text("- not\n- a\n- mapping\n", encoding="utf-8")

    result = _run(malformed)

    assert result.returncode == 2
    assert "inventory root must be a mapping" in result.stderr


def test_observability_v8_inventory_rejects_malformed_legacy_anchor(tmp_path: Path) -> None:
    document = yaml.safe_load(INVENTORY.read_text(encoding="utf-8"))
    document["classes"]["legacy_config_anchors"]["items"][0] = "not-a-mapping"
    malformed = tmp_path / "current-state-inventory.yaml"
    malformed.write_text(yaml.safe_dump(document, sort_keys=False), encoding="utf-8")

    result = _run(malformed)

    assert result.returncode == 2
    assert "classes.legacy_config_anchors.items[0] must be a mapping" in result.stderr
