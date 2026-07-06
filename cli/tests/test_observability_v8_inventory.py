"""Regression tests for the observability-v8 current-state inventory gate."""

from __future__ import annotations

import importlib.util
import json
import os
import subprocess
import sys
from pathlib import Path

import pytest
import yaml

ROOT = Path(__file__).resolve().parents[2]
CHECKER = ROOT / "scripts" / "check_observability_v8_inventory.py"
INVENTORY = ROOT / "docs" / "design" / "observability-v8" / "current-state-inventory.yaml"
ANALYZER = ROOT / "scripts" / "extract_observability_v8_metric_labels.py"


def _load_script_module(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


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
    assert "gateway_event_types=15" in result.stdout
    assert "audit_actions=188" in result.stdout
    assert "emitted_metrics=131" in result.stdout
    assert "schema_files=23" in result.stdout
    assert "grafana_dashboard_uids=14" in result.stdout
    assert "grafana_datasource_uids=3" in result.stdout
    assert "compatibility_baseline_commits=2" in result.stdout


def test_metric_label_analyzer_is_projection_aware_and_pins_counts() -> None:
    result = subprocess.run(
        [sys.executable, str(ANALYZER), "--root", str(ROOT)],
        cwd=ROOT,
        check=False,
        capture_output=True,
        text=True,
        timeout=60,
    )

    assert result.returncode == 0, result.stdout + result.stderr
    report = json.loads(result.stdout)
    assert report["summary"]["instrument_count"] == 131
    assert report["summary"]["labeled_instrument_count"] == 114
    assert report["summary"]["label_free_instrument_count"] == 17
    assert report["summary"]["domain_family_mismatch_count_at_snapshot"] == 0
    assert report["summary"]["domain_missing_label_reference_count_at_snapshot"] == 0
    assert report["summary"]["domain_extra_label_reference_count_at_snapshot"] == 0


@pytest.mark.parametrize("field", ["labels", "callsites"])
def test_observability_v8_inventory_detects_metric_evidence_drift(
    tmp_path: Path,
    field: str,
) -> None:
    document = yaml.safe_load(INVENTORY.read_text(encoding="utf-8"))
    contract = document["classes"]["emitted_metrics"]["items"]["defenseclaw.activity.diff_entries"]
    contract[field] = ["tampered"]
    tampered = tmp_path / "current-state-inventory.yaml"
    tampered.write_text(yaml.safe_dump(document, sort_keys=False), encoding="utf-8")

    result = _run(tampered)

    assert result.returncode == 1
    assert "emitted_metrics: 'defenseclaw.activity.diff_entries' changed" in result.stderr


def test_metric_label_analyzer_fails_closed_on_dynamic_attribute_key(tmp_path: Path) -> None:
    for relative in (
        "internal/telemetry/metrics.go",
        "internal/telemetry/gateway_events.go",
        "internal/telemetry/provider.go",
    ):
        path = tmp_path / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text("package telemetry\nfunc placeholder() {}\n", encoding="utf-8")
    (tmp_path / "internal/telemetry/metrics.go").write_text(
        """package telemetry
func emit() {
    attrs := metric.WithAttributes(attribute.String(dynamicKey, "value"))
    p.metrics.example.Add(ctx, 1, attrs)
}
""",
        encoding="utf-8",
    )
    module = _load_script_module("metric_label_analyzer_dynamic_test", ANALYZER)

    with pytest.raises(module.AnalysisError, match="dynamic or unresolved attribute key"):
        module.producer_contract(tmp_path, {"example": "defenseclaw.example"})


def test_metric_label_analyzer_fails_closed_on_helper_sourced_attributes(
    tmp_path: Path,
) -> None:
    for relative in (
        "internal/telemetry/metrics.go",
        "internal/telemetry/gateway_events.go",
        "internal/telemetry/provider.go",
    ):
        path = tmp_path / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text("package telemetry\nfunc placeholder() {}\n", encoding="utf-8")
    (tmp_path / "internal/telemetry/metrics.go").write_text(
        """package telemetry
func emit() {
    attrs := helperMetricOptions()
    p.metrics.example.Add(ctx, 1, attrs)
}
""",
        encoding="utf-8",
    )
    module = _load_script_module("metric_label_analyzer_helper_test", ANALYZER)

    with pytest.raises(module.AnalysisError, match="unmodeled metric option source 'attrs'"):
        module.producer_contract(tmp_path, {"example": "defenseclaw.example"})


def test_metric_label_analyzer_resolves_generated_global_gate_authority(tmp_path: Path) -> None:
    gate = tmp_path / "internal/telemetry/metrics_v8.go"
    gate.parent.mkdir(parents=True)
    gate.write_text(
        """
var v8MetricAllowedAttributeKeys = generatedV8MetricAttributeKeys()
func generatedV8MetricAttributeKeys() map[attribute.Key]struct{} {
    descriptors, err := V8MetricDescriptorCatalog()
    for _, descriptor := range descriptors {
        for _, label := range descriptor.AllowedLabels {}
        for _, mapping := range descriptor.LocalLabelMapping { _ = mapping.Local }
    }
}
// V8MetricAllowedAttributeKeys returns the generated vocabulary.
""",
        encoding="utf-8",
    )
    module = _load_script_module("metric_label_analyzer_generated_gate_test", ANALYZER)

    assert module.global_gate(tmp_path, {"metric.one": {"alpha"}, "metric.two": {"beta"}}) == {
        "alpha",
        "beta",
    }


def test_metric_label_analyzer_rejects_unknown_global_gate_authority(tmp_path: Path) -> None:
    gate = tmp_path / "internal/telemetry/metrics_v8.go"
    gate.parent.mkdir(parents=True)
    gate.write_text(
        "var v8MetricAllowedAttributeKeys = unknown()\n"
        "// V8MetricAllowedAttributeKeys returns an unknown vocabulary.\n",
        encoding="utf-8",
    )
    module = _load_script_module("metric_label_analyzer_unknown_gate_test", ANALYZER)

    with pytest.raises(module.AnalysisError, match="unrecognized v8 metric global-gate authority"):
        module.global_gate(tmp_path, {"metric.one": {"alpha"}})


def test_metric_label_analyzer_rejects_duplicate_yaml_keys(tmp_path: Path) -> None:
    path = tmp_path / "domain.yaml"
    path.write_text("schema_version: 1\nschema_version: 2\n", encoding="utf-8")
    module = _load_script_module("metric_label_analyzer_yaml_test", ANALYZER)

    with pytest.raises(module.AnalysisError, match="duplicate YAML key"):
        module.load_yaml_strict(path)


def test_inventory_checker_reports_metric_analyzer_timeout(monkeypatch: pytest.MonkeyPatch) -> None:
    module = _load_script_module("observability_inventory_timeout_test", CHECKER)

    def timeout(*args, **kwargs):
        raise subprocess.TimeoutExpired(cmd=args[0] if args else "analyzer", timeout=60)

    monkeypatch.setattr(module.subprocess, "run", timeout)
    with pytest.raises(module.InventoryError, match="timed out after 60 seconds"):
        module.discover_metric_label_contract(ROOT)


def test_observability_v8_inventory_uses_default_path_without_arguments() -> None:
    result = _run(None)

    assert result.returncode == 0, result.stdout + result.stderr
    assert "check_observability_v8_inventory: ok" in result.stdout


def test_observability_v8_inventory_excludes_canonical_v8_target_schemas(tmp_path: Path) -> None:
    document = yaml.safe_load(INVENTORY.read_text(encoding="utf-8"))
    del document["classes"]["schema_files"]["excluded_target_directories"]
    tampered = tmp_path / "current-state-inventory.yaml"
    tampered.write_text(yaml.safe_dump(document, sort_keys=False), encoding="utf-8")

    result = _run(tampered)

    assert result.returncode == 1
    assert "schema_files: untracked source item" in result.stderr
    assert "schemas/telemetry/v8/" in result.stderr


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


def test_observability_v8_inventory_validates_v7_selection_without_generic_items(
    tmp_path: Path,
) -> None:
    document = yaml.safe_load(INVENTORY.read_text(encoding="utf-8"))
    selection = document["classes"]["v7_exporter_selection"]
    assert "items" not in selection
    del selection["projection_profile"]
    malformed = tmp_path / "current-state-inventory.yaml"
    malformed.write_text(yaml.safe_dump(document, sort_keys=False), encoding="utf-8")

    result = _run(malformed)

    assert result.returncode == 2
    assert "classes.v7_exporter_selection is missing required fields: projection_profile" in result.stderr


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
