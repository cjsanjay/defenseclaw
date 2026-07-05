"""Mechanical contract tests for the checked local-observability-v1 baseline."""

from __future__ import annotations

import copy
import json
import shutil
from pathlib import Path

import yaml

from scripts import check_grafana_dashboards as audit
from scripts import local_observability_v1 as compat

ROOT = Path(__file__).resolve().parents[2]
DASHBOARDS = ROOT / "bundles/local_observability_stack/grafana/dashboards"


def _dashboards() -> list[tuple[Path, dict]]:
    return [(path, json.loads(path.read_text(encoding="utf-8"))) for path in sorted(DASHBOARDS.glob("*.json"))]


def test_local_observability_v1_inventory_matches_pr412_baseline() -> None:
    inventory, errors = compat.compatibility_errors(_dashboards(), require_packaged=True)

    assert errors == []
    assert inventory["query_count"] == 441
    assert inventory["query_counts_by_datasource"] == {
        "prometheus": 364,
        "loki": 58,
        "tempo": 5,
    }
    assert inventory["query_sha256"] == compat.EXPECTED_QUERY_SHA256
    assert inventory["dependency_sha256"] == compat.EXPECTED_DEPENDENCY_SHA256
    assert inventory["histogram_sha256"] == compat.EXPECTED_HISTOGRAM_SHA256


def test_every_query_dependency_correlates_to_a_current_input() -> None:
    inventory = compat.build_inventory(_dashboards())
    dependencies = inventory["dependencies"]

    assert set(dependencies["prometheus_metrics"]) <= inventory["known_metrics"]
    assert set(dependencies["prometheus_labels"]) <= compat.prometheus_label_inputs()
    assert set(dependencies["loki_fields"]) <= compat.loki_inputs()
    assert set(dependencies["tempo_attributes"]) <= compat.tempo_inputs()
    assert {
        "defenseclaw_agent_last_seen_seconds",
        "defenseclaw_agent_phase_transitions_total",
        "defenseclaw_agent_span_calls_total",
        "defenseclaw_agent_span_duration_milliseconds_bucket",
    } <= set(dependencies["prometheus_metrics"])
    assert {
        "defenseclaw_agent_root_id",
        "defenseclaw_agent_parent_id",
        "defenseclaw_agent_lifecycle_id",
        "defenseclaw_agent_execution_id",
    } <= set(dependencies["prometheus_labels"])
    assert {
        "agent_sequence",
        "hook_decision_raw_action",
        "hook_decision_would_block",
        "tool_invocation_phase",
    } <= set(dependencies["loki_fields"])
    assert {
        "defenseclaw.agent.root.id",
        "defenseclaw.agent.lifecycle.event",
        "gen_ai.agent.id",
        "gen_ai.operation.name",
    } <= set(dependencies["tempo_attributes"])


def test_unknown_prometheus_input_is_not_hidden_by_a_parsing_dashboard() -> None:
    dashboards = copy.deepcopy(_dashboards())
    dashboard = dashboards[0][1]
    first_panel = next(panel for panel in dashboard["panels"] if panel.get("targets"))
    first_panel["targets"][0] = {
        "datasource": {"type": "prometheus", "uid": "defenseclaw-prometheus"},
        "expr": 'rate(defenseclaw_removed_metric_total{connector="codex"}[5m])',
        "refId": "A",
    }

    _inventory, errors = compat.compatibility_errors(dashboards, require_packaged=False)

    assert any("unknown current inputs" in error and "defenseclaw_removed_metric_total" in error for error in errors)


def test_query_and_histogram_baselines_are_semantic_drift_gates() -> None:
    dashboards = copy.deepcopy(_dashboards())
    dashboard = dashboards[0][1]
    first_panel = next(panel for panel in dashboard["panels"] if panel.get("targets"))
    first_panel["targets"][0]["expr"] += " or on() vector(0)"
    changed = compat.build_inventory(dashboards)

    assert changed["query_sha256"] != compat.EXPECTED_QUERY_SHA256
    assert changed["histogram_sha256"] == compat.EXPECTED_HISTOGRAM_SHA256

    histograms = compat.histogram_inventory()
    assert histograms["defenseclaw.connector.hook.latency"] == ("1,2,5,10,25,50,100,250,500,1000,2500,5000,10000")
    assert histograms["defenseclaw.slo.block.latency"] == ("50,100,250,500,1000,2000,5000,10000")


def test_collector_preserves_three_signal_pipeline_and_agent360_dimensions() -> None:
    assert compat._collector_errors() == []
    collector = yaml.safe_load(compat.COLLECTOR.read_text(encoding="utf-8"))
    pipelines = collector["service"]["pipelines"]

    assert pipelines["metrics"]["processors"] == ["resource", "deltatocumulative", "batch"]
    assert pipelines["metrics"]["exporters"].count("prometheusremotewrite/prometheus") == 1
    assert "deltatocumulative" not in pipelines["logs"]["processors"]
    assert "deltatocumulative" not in pipelines["traces"]["processors"]
    assert pipelines["traces"]["exporters"] == ["otlp/tempo", "forward/agent360", "debug"]
    assert pipelines["traces/agent360-spanmetrics"] == {
        "receivers": ["forward/agent360"],
        "processors": ["filter/agent360-canary"],
        "exporters": ["spanmetrics/agent360"],
    }
    dimensions = {item["name"] for item in collector["connectors"]["spanmetrics/agent360"]["dimensions"]}
    assert dimensions == compat.EXPECTED_SPANMETRICS_DIMENSIONS
    assert not dimensions & {
        "trace_id",
        "span_id",
        "gen_ai.prompt",
        "gen_ai.completion",
        "defenseclaw.tool.arguments",
        "defenseclaw.tool.result",
        "error.message",
    }


def _trace_terminals(collector: dict, span_attributes: dict[str, object]) -> set[str]:
    """Walk the configured trace-connector graph for one representative span."""

    pipelines = collector["service"]["pipelines"]
    connectors = collector["connectors"]
    receiving_pipelines: dict[str, list[str]] = {}
    for pipeline_name, pipeline in pipelines.items():
        if not pipeline_name.startswith("traces"):
            continue
        for receiver in pipeline.get("receivers", []):
            if receiver in connectors:
                receiving_pipelines.setdefault(receiver, []).append(pipeline_name)

    terminals: set[str] = set()

    def walk(pipeline_name: str) -> None:
        pipeline = pipelines[pipeline_name]
        for processor_name in pipeline.get("processors", []):
            if processor_name != "filter/agent360-canary":
                continue
            processor = collector["processors"][processor_name]
            assert processor == {
                "error_mode": "ignore",
                "trace_conditions": [compat.EXPECTED_CANARY_FILTER_CONDITION],
            }
            if span_attributes.get(compat.EXPECTED_CANARY_ATTRIBUTE) is True:
                return
        for exporter in pipeline.get("exporters", []):
            downstream = receiving_pipelines.get(exporter, [])
            if downstream:
                for downstream_pipeline in downstream:
                    walk(downstream_pipeline)
            elif exporter != "forward/agent360":
                terminals.add(exporter)

    walk("traces")
    return terminals


def test_source_and_packaged_collector_keep_canary_in_tempo_but_out_of_spanmetrics() -> None:
    paths = [
        compat.COLLECTOR,
        compat.PACKAGED / "otel-collector/config.yaml",
    ]
    for path in paths:
        collector = yaml.safe_load(path.read_text(encoding="utf-8"))
        condition = collector["processors"]["filter/agent360-canary"]["trace_conditions"]
        assert condition == [compat.EXPECTED_CANARY_FILTER_CONDITION]
        assert "span.name" not in condition[0]
        assert "defenseclaw.destination" not in condition[0]
        assert "operation" not in condition[0]

        assert _trace_terminals(
            collector,
            {compat.EXPECTED_CANARY_ATTRIBUTE: True},
        ) == {"otlp/tempo", "debug"}
        assert _trace_terminals(collector, {}) == {
            "otlp/tempo",
            "spanmetrics/agent360",
            "debug",
        }
        assert _trace_terminals(
            collector,
            {compat.EXPECTED_CANARY_ATTRIBUTE: False},
        ) == {"otlp/tempo", "spanmetrics/agent360", "debug"}
        assert _trace_terminals(
            collector,
            {compat.EXPECTED_CANARY_ATTRIBUTE: "true"},
        ) == {"otlp/tempo", "spanmetrics/agent360", "debug"}


def test_collector_validator_rejects_canary_filter_or_branch_drift(
    monkeypatch,
    tmp_path: Path,
) -> None:
    collector = yaml.safe_load(compat.COLLECTOR.read_text(encoding="utf-8"))
    collector["processors"]["filter/agent360-canary"]["trace_conditions"] = [
        'span.name == "invoke_agent defenseclaw"',
    ]
    collector["service"]["pipelines"]["traces"]["exporters"].remove("otlp/tempo")
    path = tmp_path / "collector.yaml"
    path.write_text(yaml.safe_dump(collector), encoding="utf-8")
    monkeypatch.setattr(compat, "COLLECTOR", path)

    errors = compat._collector_errors()

    assert "Collector signal pipelines drifted from local-observability-v1" in errors
    assert (
        "Agent360 canary filter must drop only the exact canonical boolean span attribute"
        in errors
    )


def test_collector_validator_rejects_delta_conversion_or_dimension_drift(
    monkeypatch,
    tmp_path: Path,
) -> None:
    collector = yaml.safe_load(compat.COLLECTOR.read_text(encoding="utf-8"))
    collector["service"]["pipelines"]["metrics"]["processors"].remove("deltatocumulative")
    collector["connectors"]["spanmetrics/agent360"]["dimensions"].append(
        {"name": "trace_id"},
    )
    path = tmp_path / "collector.yaml"
    path.write_text(yaml.safe_dump(collector), encoding="utf-8")
    monkeypatch.setattr(compat, "COLLECTOR", path)

    errors = compat._collector_errors()

    assert any("signal pipelines drifted" in error for error in errors)
    assert any("spanmetrics/agent360 dimensions drifted" in error and "trace_id" in error for error in errors)


def test_complete_bundle_and_packaged_tree_are_byte_identical() -> None:
    assert compat._bundle_parity_errors() == []


def test_bundle_parity_covers_collector_rules_and_stateful_config(
    monkeypatch,
    tmp_path: Path,
) -> None:
    source = tmp_path / "source"
    packaged = tmp_path / "packaged"
    shutil.copytree(compat.BUNDLE, source)
    shutil.copytree(compat.BUNDLE, packaged)
    target = packaged / "otel-collector/config.yaml"
    target.write_text(target.read_text(encoding="utf-8") + "\n# drift\n", encoding="utf-8")
    monkeypatch.setattr(compat, "BUNDLE", source)
    monkeypatch.setattr(compat, "PACKAGED", packaged)

    errors = compat._bundle_parity_errors()

    assert errors == ["local-observability packaged file differs: otel-collector/config.yaml"]


def test_live_audit_fails_fast_when_one_of_five_services_is_unready(monkeypatch) -> None:
    monkeypatch.setattr(audit, "request_json", lambda *_args, **_kwargs: {"database": "ok"})
    monkeypatch.setattr(audit, "tempo_readiness_error", lambda: None)
    monkeypatch.setattr(
        audit,
        "_readiness_endpoint_error",
        lambda name, _url: "Loki readiness returned HTTP 503" if name == "Loki" else None,
    )

    assert audit.backend_readiness_errors() == ["Loki readiness returned HTTP 503"]


def test_live_inventory_has_one_global_deadline_not_per_query_timeouts() -> None:
    inventory, errors = audit.live_inventory([], deadline=0)

    assert inventory == []
    assert errors == []

    dashboards = [(Path("fixture.json"), {"uid": "fixture", "title": "fixture", "panels": []})]
    inventory, errors = audit.live_inventory(dashboards, deadline=0)
    assert inventory == []
    assert errors == ["live dashboard audit exceeded its global deadline"]
