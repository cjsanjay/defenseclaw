#!/usr/bin/env python3
"""Static local-observability-v1 compatibility inventory and validator.

This module deliberately does not generate the eventual telemetry-registry
consumer profile.  It is the checked, non-generated bridge for P3: derive every
current dashboard/rule dependency from the shipped assets, correlate it to the
current metric schemas and emitters, and freeze the PR #412 query surface until
P5 makes the registry the sole generator.
"""

from __future__ import annotations

import hashlib
import json
import re
from collections.abc import Iterable
from pathlib import Path
from typing import Any

import yaml

ROOT = Path(__file__).resolve().parents[1]
BUNDLE = ROOT / "bundles/local_observability_stack"
PACKAGED = ROOT / "cli/defenseclaw/_data/local_observability_stack"
METRIC_SCHEMA = ROOT / "schemas/otel/metrics.schema.json"
METRIC_EMITTER = ROOT / "internal/telemetry/metrics.go"
GATEWAY_SCHEMA = ROOT / "schemas/gateway-event-envelope.json"
COLLECTOR = BUNDLE / "otel-collector/config.yaml"
COMPOSE = BUNDLE / "docker-compose.yml"
RULES = BUNDLE / "prometheus/rules"

EXPECTED_DASHBOARD_UIDS = {
    "defenseclaw-activity",
    "defenseclaw-agent-360",
    "defenseclaw-agent-identity",
    "defenseclaw-ai-discovery",
    "defenseclaw-connector-detail",
    "defenseclaw-connectors",
    "defenseclaw-findings",
    "defenseclaw-hitl",
    "defenseclaw-overview",
    "defenseclaw-policy-decisions",
    "defenseclaw-runtime",
    "defenseclaw-scanners",
    "defenseclaw-security",
    "defenseclaw-traffic",
}
EXPECTED_PANEL_COUNT = 313
EXPECTED_DATASOURCE_UIDS = {
    "prometheus": "defenseclaw-prometheus",
    "loki": "defenseclaw-loki",
    "tempo": "defenseclaw-tempo",
}
EXPECTED_SPANMETRICS_DIMENSIONS = {
    "gen_ai.operation.name",
    "gen_ai.agent.id",
    "gen_ai.agent.name",
    "gen_ai.agent.type",
    "defenseclaw.agent.root.id",
    "defenseclaw.agent.parent.id",
    "defenseclaw.agent.lifecycle.id",
    "defenseclaw.agent.execution.id",
    "defenseclaw.agent.lifecycle.event",
    "defenseclaw.agent.lifecycle.state",
    "defenseclaw.agent.phase",
    "defenseclaw.agent.phase.previous",
    "defenseclaw.agent.phase.code",
    "connector",
    "gen_ai.tool.name",
    "defenseclaw.destination.app",
    "gen_ai.provider.name",
    "gen_ai.request.model",
}
EXPECTED_SPANMETRICS_BUCKETS = [
    "5ms",
    "10ms",
    "25ms",
    "50ms",
    "100ms",
    "250ms",
    "500ms",
    "1s",
    "2s",
    "5s",
    "10s",
    "30s",
    "1m",
    "5m",
]
EXPECTED_VOLUMES = {"prometheus-data", "loki-data", "tempo-data", "grafana-data"}

# Checked PR #412/P3 baselines.  These are intentionally hashes, not generated
# artifacts.  A changed hash requires reviewing the emitted semantic inventory
# returned by build_inventory(); P5 will replace these with registry output.
EXPECTED_QUERY_SHA256 = "920b14660df51309b93ccda126281d580b229434c5341c85d0b4d604ce846244"
EXPECTED_DEPENDENCY_SHA256 = "a10cba47de174031d815db28337508d65ab1127b3ef7c2286bd4b2ada3acb3a7"
EXPECTED_HISTOGRAM_SHA256 = "5fcf36c247ed6a483bd5b9d53a0c9c1105c6210d8eb0d9ec18bdf94b80850f9c"

PROMETHEUS_RESOURCE_LABELS = {
    "deployment_environment",
    "host_arch",
    "host_name",
    "instance",
    "job",
    "os_type",
    "otel_scope_name",
    "otel_scope_version",
    "service_name",
    "service_namespace",
    "service_version",
}
PROMETHEUS_DERIVED_LABELS = {
    "alertstate",
    "hook_event",
    "le",
    "quantile",
    "span_name",
    "status_code",
}
EXTERNAL_PROMETHEUS_METRICS = {
    "loki_discarded_samples_total",
    "loki_distributor_lines_received_total",
    "up",
}
LOKI_BUILTIN_FIELDS = {
    "__error__",
    "level",
    "severity_text",
    "service_name",
    "span_id",
    "trace_id",
}


def _digest(value: Any) -> str:
    encoded = json.dumps(value, sort_keys=True, separators=(",", ":")).encode()
    return hashlib.sha256(encoded).hexdigest()


def _load_yaml(path: Path) -> dict[str, Any]:
    value = yaml.safe_load(path.read_text(encoding="utf-8"))
    return value if isinstance(value, dict) else {}


def _panels(dashboard: dict[str, Any]) -> Iterable[dict[str, Any]]:
    for panel in dashboard.get("panels", []):
        yield panel
        yield from _panels(panel)


def _query_text(value: Any) -> str:
    if isinstance(value, str):
        return value
    if isinstance(value, dict):
        query = value.get("query")
        return query if isinstance(query, str) else ""
    return ""


def dashboard_queries(
    dashboards: list[tuple[Path, dict[str, Any]]],
) -> list[dict[str, str]]:
    result: list[dict[str, str]] = []
    for path, dashboard in dashboards:
        uid = str(dashboard.get("uid", path.stem))
        for panel in _panels(dashboard):
            for target in panel.get("targets", []):
                datasource = target.get("datasource") or panel.get("datasource") or {}
                datasource_type = datasource.get("type", "") if isinstance(datasource, dict) else ""
                expression = target.get("expr") or target.get("query") or ""
                if not expression and datasource_type == "tempo" and target.get("filters"):
                    conditions = []
                    for item in target["filters"]:
                        scope = item.get("scope")
                        tag = item.get("tag")
                        if scope and tag:
                            conditions.append(f"{scope}.{tag}")
                    structured = json.dumps(
                        {
                            "queryType": target.get("queryType"),
                            "filters": target.get("filters"),
                        },
                        sort_keys=True,
                        separators=(",", ":"),
                    )
                    expression = "{ " + " && ".join(conditions) + " } # " + structured
                if expression:
                    result.append(
                        {
                            "source": f"dashboard:{uid}",
                            "consumer": str(panel.get("title", "untitled")),
                            "ref": str(target.get("refId", "?")),
                            "datasource": str(datasource_type),
                            "query": str(expression),
                        },
                    )
        for section in ("templating", "annotations"):
            for index, item in enumerate(dashboard.get(section, {}).get("list", [])):
                datasource = item.get("datasource") or {}
                datasource_type = datasource.get("type", "") if isinstance(datasource, dict) else ""
                expression = _query_text(item.get("query")) or _query_text(item.get("definition"))
                if expression:
                    result.append(
                        {
                            "source": f"dashboard:{uid}",
                            "consumer": f"{section}:{item.get('name', index)}",
                            "ref": str(index),
                            "datasource": str(datasource_type),
                            "query": expression,
                        },
                    )
    return result


def rule_queries() -> tuple[list[dict[str, str]], set[str]]:
    result: list[dict[str, str]] = []
    recording_names: set[str] = set()
    for path in sorted(RULES.glob("*.yml")):
        for group in _load_yaml(path).get("groups", []):
            for index, rule in enumerate(group.get("rules", [])):
                name = rule.get("record") or rule.get("alert") or str(index)
                if rule.get("record"):
                    recording_names.add(str(rule["record"]))
                if rule.get("expr"):
                    result.append(
                        {
                            "source": f"rule:{path.name}",
                            "consumer": f"{group.get('name', '?')}:{name}",
                            "ref": str(index),
                            "datasource": "prometheus",
                            "query": str(rule["expr"]),
                        },
                    )
    return result, recording_names


def _prometheus_projection(metric: dict[str, Any]) -> set[str]:
    name = str(metric["name"]).replace(".", "_").replace("-", "_")
    kind = str(metric["type"])
    unit = str(metric.get("unit", ""))
    unit_suffix = {"ms": "milliseconds", "s": "seconds", "ns": "nanoseconds"}.get(unit)
    if unit_suffix:
        name += f"_{unit_suffix}"
    elif unit == "USD":
        name += "_USD"
    elif unit == "1" and kind == "gauge":
        name += "_ratio"
    if kind == "counter" and not name.endswith("_total"):
        name += "_total"
    if kind == "histogram":
        return {f"{name}_bucket", f"{name}_sum", f"{name}_count"}
    return {name}


def prometheus_inputs(recording_names: set[str]) -> set[str]:
    schema = json.loads(METRIC_SCHEMA.read_text(encoding="utf-8"))
    result = set(EXTERNAL_PROMETHEUS_METRICS) | set(recording_names)
    for metric in schema.get("x-emitted-metrics", []):
        result.update(_prometheus_projection(metric))
    result.update(
        {
            "defenseclaw_agent_span_calls_total",
            "defenseclaw_agent_span_duration_milliseconds_bucket",
            "defenseclaw_agent_span_duration_milliseconds_sum",
            "defenseclaw_agent_span_duration_milliseconds_count",
        },
    )
    return result


def _prometheus_metric_dependencies(query: str, known: set[str]) -> set[str]:
    unquoted = re.sub(r'"(?:\\.|[^"\\])*"', "", query)
    result = {
        match
        for match in re.findall(
            r"\b((?:defenseclaw|gen_ai|loki|otelcol|prometheus)_[A-Za-z0-9_:]+)\s*(?=\{|\[)",
            unquoted,
        )
    }
    for name in known:
        if re.search(rf"(?<![A-Za-z0-9_:]){re.escape(name)}(?![A-Za-z0-9_:])", unquoted):
            result.add(name)
    return result


def _prometheus_label_dependencies(query: str) -> set[str]:
    result: set[str] = set()
    for selector in re.findall(r"\{([^{}]*)\}", query):
        result.update(
            re.findall(r"([A-Za-z_][A-Za-z0-9_]*)\s*(?:=~|!~|=|!=)", selector),
        )
    for group in re.findall(r"\b(?:by|without|on)\s*\(([^)]*)\)", query):
        result.update(item.strip() for item in group.split(",") if item.strip())
    for function in ("label_replace", "label_join"):
        for call in re.findall(rf"{function}\((.*?)\)", query):
            result.update(re.findall(r'"([A-Za-z_][A-Za-z0-9_]*)"', call))
    result.discard("scope_label")
    return result


def prometheus_label_inputs() -> set[str]:
    result = set(PROMETHEUS_RESOURCE_LABELS) | set(PROMETHEUS_DERIVED_LABELS)
    source = "\n".join(path.read_text(encoding="utf-8", errors="ignore") for path in (ROOT / "internal").rglob("*.go"))
    for key in re.findall(
        r'(?:attribute|otellog|log)\.(?:String|Int|Int64|Bool|Float64|StringSlice)\(\s*"([^"]+)"',
        source,
    ):
        result.add(key.replace(".", "_").replace("-", "_"))
    result.update(item.replace(".", "_") for item in EXPECTED_SPANMETRICS_DIMENSIONS)
    return result


def _loki_dependencies(query: str) -> set[str]:
    result = set(re.findall(r"\.([A-Za-z_][A-Za-z0-9_]*)", query))
    unquoted = re.sub(r'"(?:\\.|[^"\\])*"', "", query)
    for field in re.findall(r"(?<![.$])\b([A-Za-z_][A-Za-z0-9_]*)\s*(?:=~|!~|=|!=)", unquoted):
        if field not in {"job", "level", "service_name", "stream"}:
            result.add(field)
    result.discard("_")
    return result


def loki_inputs() -> set[str]:
    result = set(LOKI_BUILTIN_FIELDS)
    schema = json.loads(GATEWAY_SCHEMA.read_text(encoding="utf-8"))
    top = schema.get("properties", {})
    for name in top:
        result.update({name, f"defenseclaw_{name}"})
    for parent, definition_name in {
        "verdict": "VerdictPayload",
        "hook_decision": "HookDecisionPayload",
        "judge": "JudgePayload",
        "lifecycle": "LifecyclePayload",
        "error": "ErrorPayload",
        "diagnostic": "DiagnosticPayload",
        "egress": "EgressPayload",
        "llm_prompt": "LLMPromptPayload",
        "llm_response": "LLMResponsePayload",
        "tool_invocation": "ToolPayload",
        "ai_discovery": "AIDiscoveryPayload",
    }.items():
        definition = schema.get("$defs", {}).get(definition_name, {})
        for child in definition.get("properties", {}):
            result.update({child, f"{parent}_{child}"})
    # External scan payload schemas use the same deterministic parent_child
    # JSON flattening consumed by Loki.
    for parent, filename in {
        "scan": "scan-event.json",
        "scan_finding": "scan-finding-event.json",
    }.items():
        payload = json.loads((ROOT / "schemas" / filename).read_text(encoding="utf-8"))
        for definition in payload.get("$defs", {}).values():
            for child in definition.get("properties", {}):
                result.update({child, f"{parent}_{child}"})
    source = (ROOT / "internal/telemetry/gateway_events.go").read_text(encoding="utf-8")
    for key in re.findall(r'log\.(?:String|Int|Int64|Bool|Float64)\("([^"]+)"', source):
        result.add(key.replace(".", "_").replace("-", "_"))
    # Grafana-created labels and legacy JSON aliases retained for the one-release
    # query compatibility window.
    result.update(
        {"destination", "destination_host", "effective", "enforced", "host", "local", "raw", "trace", "would_block"}
    )
    return result


def _tempo_dependencies(query: str) -> set[str]:
    return set(re.findall(r"\b(?:span|resource)\.([A-Za-z_][A-Za-z0-9_.]*)", query))


def tempo_inputs() -> set[str]:
    result: set[str] = {"name", "service.name"}
    for path in (ROOT / "schemas/otel").glob("*.json"):
        value = json.loads(path.read_text(encoding="utf-8"))
        stack: list[Any] = [value]
        while stack:
            item = stack.pop()
            if isinstance(item, dict):
                properties = item.get("properties")
                if isinstance(properties, dict):
                    result.update(name for name in properties if "." in name)
                stack.extend(item.values())
            elif isinstance(item, list):
                stack.extend(item)
    for path in (ROOT / "internal").rglob("*.go"):
        source = path.read_text(encoding="utf-8", errors="ignore")
        result.update(
            re.findall(
                r'attribute\.(?:String|Int|Int64|Bool|Float64|StringSlice)\(\s*"([^"]+)"',
                source,
            ),
        )
    return result


def histogram_inventory() -> dict[str, str]:
    source = METRIC_EMITTER.read_text(encoding="utf-8")
    go_mod = (ROOT / "go.mod").read_text(encoding="utf-8")
    sdk_version_match = re.search(
        r"^\s*go\.opentelemetry\.io/otel/sdk\s+(v[^\s]+)",
        go_mod,
        re.MULTILINE,
    )
    sdk_version = sdk_version_match.group(1) if sdk_version_match else "unresolved"
    variables: dict[str, str] = {}
    for name, body in re.findall(r"(\w+)\s*:=\s*\[\]float64\s*\{([^}]*)\}", source, re.DOTALL):
        values = [
            part.strip()
            for part in body.replace("\n", " ").split(",")
            if part.strip() and not part.strip().startswith("//")
        ]
        variables[name] = ",".join(values)
    result: dict[str, str] = {}
    pattern = re.compile(
        r'ms\.\w+,\s*err\s*=\s*m\.(?:Float64|Int64)Histogram\("([^"]+)"(.*?)(?=\n\tif err != nil)',
        re.DOTALL,
    )
    for match in pattern.finditer(source):
        name, body = match.groups()
        boundaries = re.search(r"WithExplicitBucketBoundaries\((.*?)\)", body, re.DOTALL)
        if boundaries is None:
            result[name] = f"otel-sdk-default-{sdk_version}"
            continue
        value = " ".join(boundaries.group(1).split())
        if value.endswith("...") and value[:-3] in variables:
            value = variables[value[:-3]]
        result[name] = re.sub(r"\s*,\s*", ",", value)
    return result


def _bundle_parity_errors() -> list[str]:
    errors: list[str] = []
    source_files = {path.relative_to(BUNDLE) for path in BUNDLE.rglob("*") if path.is_file()}
    packaged_files = {path.relative_to(PACKAGED) for path in PACKAGED.rglob("*") if path.is_file()}
    if source_files != packaged_files:
        errors.append(
            "local-observability source/packaged file inventories differ: "
            f"source_only={sorted(map(str, source_files - packaged_files))}, "
            f"packaged_only={sorted(map(str, packaged_files - source_files))}",
        )
    for relative in sorted(source_files & packaged_files):
        if (BUNDLE / relative).read_bytes() != (PACKAGED / relative).read_bytes():
            errors.append(f"local-observability packaged file differs: {relative}")
    return errors


def _collector_errors() -> list[str]:
    errors: list[str] = []
    collector = _load_yaml(COLLECTOR)
    pipelines = collector.get("service", {}).get("pipelines", {})
    expected_pipelines = {
        "traces": {
            "receivers": ["otlp"],
            "processors": ["resource", "batch"],
            "exporters": ["otlp/tempo", "spanmetrics/agent360", "debug"],
        },
        "metrics": {
            "receivers": ["otlp", "spanmetrics/agent360"],
            "processors": ["resource", "deltatocumulative", "batch"],
            "exporters": ["prometheusremotewrite/prometheus", "debug"],
        },
        "logs": {
            "receivers": ["otlp"],
            "processors": ["resource", "attributes/strip-bodies", "transform/loki-payload-cap", "batch"],
            "exporters": ["otlphttp/loki", "debug"],
        },
    }
    if pipelines != expected_pipelines:
        errors.append("Collector signal pipelines drifted from local-observability-v1")
    spanmetrics = collector.get("connectors", {}).get("spanmetrics/agent360", {})
    dimensions = {item.get("name") for item in spanmetrics.get("dimensions", [])}
    if dimensions != EXPECTED_SPANMETRICS_DIMENSIONS:
        errors.append(
            "spanmetrics/agent360 dimensions drifted: "
            f"missing={sorted(EXPECTED_SPANMETRICS_DIMENSIONS - dimensions)}, "
            f"extra={sorted(dimensions - EXPECTED_SPANMETRICS_DIMENSIONS)}",
        )
    buckets = spanmetrics.get("histogram", {}).get("explicit", {}).get("buckets")
    if buckets != EXPECTED_SPANMETRICS_BUCKETS:
        errors.append(f"spanmetrics/agent360 buckets drifted: {buckets!r}")
    if spanmetrics.get("metrics_flush_interval") != "15s":
        errors.append("spanmetrics/agent360 metrics_flush_interval must remain 15s")
    compose = _load_yaml(COMPOSE)
    collector_image = compose.get("services", {}).get("otel-collector", {}).get("image")
    if collector_image != "otel/opentelemetry-collector-contrib:0.153.0":
        errors.append(f"Collector image drifted from 0.153.0: {collector_image!r}")
    if set(compose.get("volumes", {})) != EXPECTED_VOLUMES:
        errors.append("persistent local-observability volume inventory drifted")
    expected_mounts = {
        "prometheus": "prometheus-data:/prometheus",
        "loki": "loki-data:/loki",
        "tempo": "tempo-data:/var/tempo",
        "grafana": "grafana-data:/var/lib/grafana",
    }
    for service_name, expected_mount in expected_mounts.items():
        mounts = compose.get("services", {}).get(service_name, {}).get("volumes", []) or []
        if expected_mount not in mounts:
            errors.append(
                f"{service_name} no longer mounts persistent volume {expected_mount}",
            )
    for service in compose.get("services", {}).values():
        for port in service.get("ports", []) or []:
            if isinstance(port, str) and not port.startswith("${HOST_BIND:-127.0.0.1}:"):
                errors.append(f"local-observability host port is not loopback-defaulted: {port}")
    return errors


def build_inventory(
    dashboards: list[tuple[Path, dict[str, Any]]],
) -> dict[str, Any]:
    dashboard_items = dashboard_queries(dashboards)
    rules, recording_names = rule_queries()
    all_queries = dashboard_items + rules
    known_metrics = prometheus_inputs(recording_names)
    metric_dependencies: set[str] = set()
    label_dependencies: set[str] = set()
    loki_dependencies: set[str] = set()
    tempo_dependencies: set[str] = set()
    counts = {"prometheus": 0, "loki": 0, "tempo": 0}
    for item in all_queries:
        datasource = item["datasource"]
        if datasource in counts:
            counts[datasource] += 1
        if datasource == "prometheus":
            metric_dependencies.update(_prometheus_metric_dependencies(item["query"], known_metrics))
            label_dependencies.update(_prometheus_label_dependencies(item["query"]))
        elif datasource == "loki":
            loki_dependencies.update(_loki_dependencies(item["query"]))
        elif datasource == "tempo":
            tempo_dependencies.update(_tempo_dependencies(item["query"]))
    dependency_inventory = {
        "prometheus_metrics": sorted(metric_dependencies),
        "prometheus_labels": sorted(label_dependencies),
        "loki_fields": sorted(loki_dependencies),
        "tempo_attributes": sorted(tempo_dependencies),
    }
    return {
        "query_count": len(all_queries),
        "query_counts_by_datasource": counts,
        "query_sha256": _digest(all_queries),
        "dependency_sha256": _digest(dependency_inventory),
        "histogram_sha256": _digest(histogram_inventory()),
        "dependencies": dependency_inventory,
        "known_metrics": known_metrics,
    }


def compatibility_errors(
    dashboards: list[tuple[Path, dict[str, Any]]],
    *,
    require_packaged: bool,
) -> tuple[dict[str, Any], list[str]]:
    errors: list[str] = []
    inventory = build_inventory(dashboards)
    uids = {str(dashboard.get("uid", "")) for _, dashboard in dashboards}
    if uids != EXPECTED_DASHBOARD_UIDS:
        missing_uids = sorted(EXPECTED_DASHBOARD_UIDS - uids)
        extra_uids = sorted(uids - EXPECTED_DASHBOARD_UIDS)
        errors.append(
            f"local-observability-v1 dashboard UIDs drifted: missing={missing_uids}, extra={extra_uids}",
        )
    panel_count = sum(1 for _, dashboard in dashboards for panel in _panels(dashboard) if panel.get("type") != "row")
    if panel_count != EXPECTED_PANEL_COUNT:
        errors.append(f"local-observability-v1 panel count={panel_count}, want {EXPECTED_PANEL_COUNT}")

    datasource_config = _load_yaml(BUNDLE / "grafana/provisioning/datasources/datasources.yml")
    datasource_uids = {
        item.get("type"): item.get("uid")
        for item in datasource_config.get("datasources", [])
        if item.get("type") in EXPECTED_DATASOURCE_UIDS
    }
    if datasource_uids != EXPECTED_DATASOURCE_UIDS:
        errors.append(f"local-observability-v1 datasource UIDs drifted: {datasource_uids!r}")

    dependencies = inventory["dependencies"]
    unknown_metrics = set(dependencies["prometheus_metrics"]) - inventory["known_metrics"]
    if unknown_metrics:
        errors.append(f"Prometheus queries reference unknown current inputs: {sorted(unknown_metrics)}")
    unknown_labels = set(dependencies["prometheus_labels"]) - prometheus_label_inputs()
    if unknown_labels:
        errors.append(f"Prometheus queries reference unknown current labels: {sorted(unknown_labels)}")
    unknown_loki = set(dependencies["loki_fields"]) - loki_inputs()
    if unknown_loki:
        errors.append(f"Loki queries reference unknown current fields: {sorted(unknown_loki)}")
    unknown_tempo = set(dependencies["tempo_attributes"]) - tempo_inputs()
    if unknown_tempo:
        errors.append(f"Tempo queries reference unknown current attributes: {sorted(unknown_tempo)}")

    for field, expected in (
        ("query_sha256", EXPECTED_QUERY_SHA256),
        ("dependency_sha256", EXPECTED_DEPENDENCY_SHA256),
        ("histogram_sha256", EXPECTED_HISTOGRAM_SHA256),
    ):
        if expected != "PENDING" and inventory[field] != expected:
            errors.append(f"local-observability-v1 {field} drifted: got {inventory[field]}, want {expected}")

    errors.extend(_collector_errors())
    if require_packaged:
        errors.extend(_bundle_parity_errors())
    return inventory, errors
