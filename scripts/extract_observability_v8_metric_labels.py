#!/usr/bin/env python3
# Copyright 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: Apache-2.0
"""Extract the current DefenseClaw Go metric-to-label contract.

This is a read-only, one-release bootstrap analyzer. It intentionally understands
only the small set of Go construction patterns used by internal/telemetry today:

* metricsSet field assignment to an OTel constructor;
* Add/Record calls through p.metrics/m.metrics/metrics;
* literal attribute constructors;
* local metric.WithAttributes options;
* local []attribute.KeyValue slices; and
* position-sensitive append chains, including shadowed variable names.

The output is deterministic for a given checkout. It is evidence for moving the
contract into the v8 registry, not a proposed permanent second source of truth.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import yaml

PRODUCTION_SOURCES = (
    Path("internal/telemetry/metrics.go"),
    Path("internal/telemetry/gateway_events.go"),
    Path("internal/telemetry/provider.go"),
)
V8_GATE_SOURCE = Path("internal/telemetry/metrics_v8.go")
DOMAIN_SOURCES = tuple(
    Path("schemas/telemetry/v8") / name for name in ("genai.yaml", "security.yaml", "operations.yaml")
)
PR412_EVIDENCE = (
    Path("internal/telemetry/agent360_metrics_test.go"),
    Path("bundles/local_observability_stack/otel-collector/config.yaml"),
    Path("bundles/local_observability_stack/grafana/dashboards/defenseclaw-agent-360.json"),
    Path("bundles/local_observability_stack/grafana/dashboards/defenseclaw-agent-identity.json"),
)

ATTRIBUTE_CONSTRUCTORS = (
    "String",
    "Int",
    "Int64",
    "Bool",
    "Float64",
    "StringSlice",
    "BoolSlice",
    "Int64Slice",
    "Float64Slice",
)
ATTRIBUTE_KEY_RE = re.compile(r"attribute\.(?:" + "|".join(ATTRIBUTE_CONSTRUCTORS) + r")\(\s*\"([^\"]+)\"")
ATTRIBUTE_CALL_RE = re.compile(r"attribute\.(?:" + "|".join(ATTRIBUTE_CONSTRUCTORS) + r")\(")
METRIC_CALL_RE = re.compile(r"(?:p\.|m\.)?metrics\.(\w+)\.(Add|Record)\s*\(")
IDENTIFIER_RE = re.compile(r"[A-Za-z_]\w*\Z")


class AnalysisError(RuntimeError):
    pass


class _StrictLoader(yaml.SafeLoader):
    pass


def _construct_mapping(
    loader: _StrictLoader,
    node: yaml.MappingNode,
    deep: bool = False,
) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key_node, value_node in node.value:
        key = loader.construct_object(key_node, deep=deep)
        if not isinstance(key, str):
            raise AnalysisError("YAML mapping keys must be strings")
        if key == "<<":
            raise AnalysisError("YAML merge keys are not allowed")
        if key in result:
            raise AnalysisError(f"duplicate YAML key {key!r}")
        result[key] = loader.construct_object(value_node, deep=deep)
    return result


_StrictLoader.add_constructor(
    yaml.resolver.BaseResolver.DEFAULT_MAPPING_TAG,
    _construct_mapping,
)


def load_yaml_strict(path: Path) -> dict[str, Any]:
    try:
        text = path.read_text(encoding="utf-8")
        for token in yaml.scan(text):
            if isinstance(token, (yaml.tokens.AnchorToken, yaml.tokens.AliasToken)):
                raise AnalysisError(f"{path}: YAML anchors and aliases are not allowed")
            if isinstance(token, yaml.tokens.TagToken):
                raise AnalysisError(f"{path}: explicit YAML tags are not allowed")
        value = yaml.load(text, Loader=_StrictLoader)
    except UnicodeDecodeError as exc:
        raise AnalysisError(f"{path}: invalid UTF-8") from exc
    except yaml.YAMLError as exc:
        raise AnalysisError(f"{path}: invalid YAML") from exc
    if not isinstance(value, dict):
        raise AnalysisError(f"{path}: document root must be a mapping")
    return value


@dataclass(frozen=True)
class Function:
    signature: str
    body: str
    body_source_offset: int


@dataclass(frozen=True)
class Assignment:
    variable: str
    position: int
    operator: str
    expression: str


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def matching_delimiter(
    source: str,
    opening_position: int,
    opening: str = "(",
    closing: str = ")",
) -> int:
    """Return the matching delimiter while ignoring Go strings/comments."""

    depth = 0
    index = opening_position
    mode = "code"
    quote = ""
    while index < len(source):
        char = source[index]
        following = source[index + 1] if index + 1 < len(source) else ""
        if mode == "line_comment":
            if char == "\n":
                mode = "code"
        elif mode == "block_comment":
            if char == "*" and following == "/":
                mode = "code"
                index += 1
        elif mode == "quoted":
            if char == "\\":
                index += 1
            elif char == quote:
                mode = "code"
        elif mode == "raw":
            if char == "`":
                mode = "code"
        else:
            if char == "/" and following == "/":
                mode = "line_comment"
                index += 1
            elif char == "/" and following == "*":
                mode = "block_comment"
                index += 1
            elif char in ('"', "'"):
                mode = "quoted"
                quote = char
            elif char == "`":
                mode = "raw"
            elif char == opening:
                depth += 1
            elif char == closing:
                depth -= 1
                if depth == 0:
                    return index
        index += 1
    raise AnalysisError(f"unclosed {opening!r} at byte {opening_position}")


def functions(source: str) -> list[Function]:
    result: list[Function] = []
    for match in re.finditer(r"(?m)^func\b", source):
        opening = source.find("{", match.start())
        if opening < 0:
            raise AnalysisError("function has no body")
        closing = matching_delimiter(source, opening, "{", "}")
        result.append(
            Function(
                signature=source[match.start() : opening].strip(),
                body=source[opening + 1 : closing],
                body_source_offset=opening + 1,
            )
        )
    return result


def attribute_keys(expression: str) -> set[str]:
    return set(ATTRIBUTE_KEY_RE.findall(expression))


def assignments(body: str) -> list[Assignment]:
    result: list[Assignment] = []
    pattern = re.compile(
        r"(?m)(?:^|[;\n])\s*(\w+)\s*(:=|=)\s*"
        r"(metric\.WithAttributes\s*\(|"
        r"\[\]attribute\.KeyValue\s*\{|append\s*\()"
    )
    for match in pattern.finditer(body):
        start = match.start(3)
        opening_delimiter = "{" if "{" in match.group(3) else "("
        opening = body.find(opening_delimiter, start)
        closing_delimiter = "}" if opening_delimiter == "{" else ")"
        closing = matching_delimiter(body, opening, opening_delimiter, closing_delimiter)
        result.append(
            Assignment(
                variable=match.group(1),
                position=match.start(1),
                operator=match.group(2),
                expression=body[start : closing + 1],
            )
        )
    return result


def split_top_level_arguments(call: str) -> list[str]:
    opening = call.find("(")
    if opening < 0:
        raise AnalysisError("metric call has no argument list")
    closing = matching_delimiter(call, opening)
    body = call[opening + 1 : closing]
    result: list[str] = []
    start = 0
    depths = {"(": 0, "[": 0, "{": 0}
    pairs = {")": "(", "]": "[", "}": "{"}
    mode = "code"
    quote = ""
    index = 0
    while index < len(body):
        char = body[index]
        following = body[index + 1] if index + 1 < len(body) else ""
        if mode == "line_comment":
            if char == "\n":
                mode = "code"
        elif mode == "block_comment":
            if char == "*" and following == "/":
                mode = "code"
                index += 1
        elif mode == "quoted":
            if char == "\\":
                index += 1
            elif char == quote:
                mode = "code"
        elif mode == "raw":
            if char == "`":
                mode = "code"
        elif char == "/" and following == "/":
            mode = "line_comment"
            index += 1
        elif char == "/" and following == "*":
            mode = "block_comment"
            index += 1
        elif char in ('"', "'"):
            mode = "quoted"
            quote = char
        elif char == "`":
            mode = "raw"
        elif char in depths:
            depths[char] += 1
        elif char in pairs:
            depths[pairs[char]] -= 1
        elif char == "," and not any(depths.values()):
            result.append(body[start:index].strip())
            start = index + 1
        index += 1
    tail = body[start:].strip()
    if tail:
        result.append(tail)
    return result


def latest_assignment(
    variable: str,
    before_position: int,
    available: list[Assignment],
) -> Assignment | None:
    candidates = [
        item
        for item in available
        if item.variable == variable and item.position < before_position
    ]
    return max(candidates, key=lambda item: item.position) if candidates else None


def validate_attribute_expression(
    expression: str,
    before_position: int,
    available: list[Assignment],
) -> None:
    for component in split_top_level_arguments(f"attributes({expression})"):
        candidate = component.strip()
        if re.match(r"attribute\.(?:" + "|".join(ATTRIBUTE_CONSTRUCTORS) + r")\s*\(", candidate):
            continue
        variable = candidate.removesuffix("...").strip()
        if IDENTIFIER_RE.fullmatch(variable):
            if latest_assignment(variable, before_position, available) is None:
                raise AnalysisError(f"unmodeled metric attribute source {variable!r}")
            continue
        raise AnalysisError(f"unmodeled metric attribute expression {candidate!r}")


def validate_metric_options(
    call: str,
    before_position: int,
    available: list[Assignment],
) -> None:
    arguments = split_top_level_arguments(call)
    if len(arguments) < 2:
        raise AnalysisError("metric Add/Record call has fewer than two arguments")
    for option in arguments[2:]:
        expression = option.strip()
        if expression.startswith("metric.WithAttributes"):
            opening = expression.find("(")
            closing = matching_delimiter(expression, opening)
            validate_attribute_expression(
                expression[opening + 1 : closing],
                before_position,
                available,
            )
            continue
        identifier = expression.removesuffix("...").strip()
        if IDENTIFIER_RE.fullmatch(identifier):
            assignment = latest_assignment(identifier, before_position, available)
            if assignment is None or not assignment.expression.lstrip().startswith(
                "metric.WithAttributes"
            ):
                raise AnalysisError(f"unmodeled metric option source {identifier!r}")
            opening = assignment.expression.find("(")
            closing = matching_delimiter(assignment.expression, opening)
            validate_attribute_expression(
                assignment.expression[opening + 1 : closing],
                assignment.position,
                available,
            )
            continue
        raise AnalysisError(f"unmodeled metric option expression {expression!r}")


def resolve_variable(
    variable: str,
    before_position: int,
    available: list[Assignment],
    seen: set[tuple[str, int]] | None = None,
) -> set[str]:
    """Resolve the latest assignment visible textually before one call.

    This preserves the current RecordAgentLifecycle shadowing behavior: the first
    transitionAttrs is used by lifecycle.transitions, while the later shadowed
    transitionAttrs is used by phase.transitions.
    """

    if seen is None:
        seen = set()
    identity = (variable, before_position)
    if identity in seen:
        return set()
    seen.add(identity)
    candidates = [item for item in available if item.variable == variable and item.position < before_position]
    if not candidates:
        return set()
    selected = max(candidates, key=lambda item: item.position)
    result = attribute_keys(selected.expression)
    dependencies: list[str] = []
    if selected.expression.lstrip().startswith("append"):
        inner = selected.expression[selected.expression.find("(") + 1 : -1]
        first_argument = inner.split(",", 1)[0].strip()
        if IDENTIFIER_RE.fullmatch(first_argument):
            dependencies.append(first_argument)
    dependencies.extend(re.findall(r"\b([A-Za-z_]\w*)\s*\.\.\.", selected.expression))
    for dependency in dependencies:
        result.update(
            resolve_variable(
                dependency,
                selected.position,
                available,
                seen,
            )
        )
    return result


def instrument_fields(metrics_source: str) -> dict[str, str]:
    pairs = re.findall(
        r"ms\.(\w+)\s*,\s*err\s*=\s*"
        r"m\.[A-Za-z0-9_]+\(\s*\"([^\"]+)\"",
        metrics_source,
    )
    result = dict(pairs)
    if len(result) != len(pairs):
        raise AnalysisError("duplicate metricsSet field assignment")
    return result


def producer_contract(
    root: Path,
    field_to_name: dict[str, str],
) -> tuple[dict[str, set[str]], dict[str, set[str]], list[dict[str, str]]]:
    labels = {name: set() for name in field_to_name.values()}
    callsites = {name: set() for name in field_to_name.values()}
    unresolved_dynamic_keys: list[dict[str, str]] = []
    for relative_path in PRODUCTION_SOURCES:
        path = root / relative_path
        source = path.read_text(encoding="utf-8")
        for function in functions(source):
            available = assignments(function.body)
            for assignment in available:
                if len(ATTRIBUTE_CALL_RE.findall(assignment.expression)) > len(
                    ATTRIBUTE_KEY_RE.findall(assignment.expression)
                ):
                    unresolved_dynamic_keys.append(
                        {
                            "path": relative_path.as_posix(),
                            "function": function.signature,
                            "call": assignment.expression,
                        }
                    )
            for match in METRIC_CALL_RE.finditer(function.body):
                field = match.group(1)
                if field not in field_to_name:
                    raise AnalysisError(f"{relative_path}: unknown metricsSet field {field}")
                opening = function.body.find("(", match.start())
                closing = matching_delimiter(function.body, opening)
                call = function.body[match.start() : closing + 1]
                validate_metric_options(call, match.start(), available)
                keys = attribute_keys(call)
                for variable in re.findall(r"\b([A-Za-z_]\w*)\b", call):
                    keys.update(
                        resolve_variable(
                            variable,
                            match.start(),
                            available,
                        )
                    )
                # A constructor found without a literal first argument would make
                # the extraction incomplete and must fail the one-release check.
                if len(ATTRIBUTE_CALL_RE.findall(call)) > len(ATTRIBUTE_KEY_RE.findall(call)):
                    unresolved_dynamic_keys.append(
                        {
                            "path": relative_path.as_posix(),
                            "function": function.signature,
                            "call": call,
                        }
                    )
                name = field_to_name[field]
                labels[name].update(keys)
                line = (
                    source.count(
                        "\n",
                        0,
                        function.body_source_offset + match.start(),
                    )
                    + 1
                )
                callsites[name].add(f"{relative_path.as_posix()}:{line}")
    if unresolved_dynamic_keys:
        raise AnalysisError(
            "dynamic or unresolved attribute key construction found: "
            + json.dumps(unresolved_dynamic_keys, sort_keys=True)
        )
    missing_calls = sorted(name for name, sites in callsites.items() if not sites)
    if missing_calls:
        raise AnalysisError(f"instruments have no production callsite: {missing_calls}")
    return labels, callsites, unresolved_dynamic_keys


def registry_contract(root: Path) -> dict[str, set[str]]:
    documents = [load_yaml_strict(root / relative) for relative in DOMAIN_SOURCES]
    groups = {group["id"]: group for document in documents for group in document["groups"]}

    def resolved(group_id: str, seen: set[str] | None = None) -> set[str]:
        if seen is None:
            seen = set()
        if group_id in seen:
            raise AnalysisError(f"group inheritance cycle at {group_id}")
        seen.add(group_id)
        group = groups[group_id]
        result = {field["ref"] for field in group.get("attributes", []) + group.get("body_fields", [])}
        for parent in group.get("extends", []):
            result.update(resolved(parent, set(seen)))
        return result

    result: dict[str, set[str]] = {}
    for group in groups.values():
        if group["type"] != "metric":
            continue
        labels = resolved(group["id"])
        projections = group["metric"].get("label_projections", [])
        local = [
            projection
            for projection in projections
            if projection["profile"] == "local-observability-v1"
        ]
        if len(local) > 1:
            raise AnalysisError(
                f"duplicate local-observability-v1 projection for {group['id']}"
            )
        mappings = (
            {item["ref"]: item["label"] for item in local[0]["mappings"]}
            if local
            else {}
        )
        if not mappings.keys() <= labels:
            raise AnalysisError(f"projection references unknown labels for {group['id']}")
        projected = {mappings.get(label, label) for label in labels}
        if len(projected) != len(labels):
            raise AnalysisError(f"projection collision for {group['id']}")
        result[group["metric"]["instrument_name"]] = projected
    return result


def global_gate(root: Path) -> set[str]:
    source = (root / V8_GATE_SOURCE).read_text(encoding="utf-8")
    start = source.index("var v8MetricAllowedAttributeKeys")
    end = source.index("// V8MetricAllowedAttributeKeys returns", start)
    return set(re.findall(r'"([^\"]+)"\s*:\s*\{\}', source[start:end]))


def build_report(root: Path) -> dict[str, Any]:
    field_to_name = instrument_fields((root / PRODUCTION_SOURCES[0]).read_text(encoding="utf-8"))
    labels, callsites, _ = producer_contract(root, field_to_name)
    registry = registry_contract(root)
    gate = global_gate(root)
    if set(labels) != set(registry):
        raise AnalysisError(
            "producer/registry metric inventory mismatch: "
            f"producer_only={sorted(set(labels) - set(registry))} "
            f"registry_only={sorted(set(registry) - set(labels))}"
        )
    label_free_reason = (
        "All current production Add/Record callsites pass no instrument-specific "
        "attributes; OTel resource attributes may still be attached by the provider."
    )
    instruments: dict[str, Any] = {}
    for name in sorted(labels):
        emitted = labels[name]
        declared = registry[name]
        instruments[name] = {
            "labels": sorted(emitted),
            "callsites": sorted(callsites[name]),
            "label_free_reason": label_free_reason if not emitted else None,
            "domain_declared_labels_at_snapshot": sorted(declared),
            "domain_missing_labels_at_snapshot": sorted(emitted - declared),
            "domain_extra_labels_at_snapshot": sorted(declared - emitted),
            "dropped_by_current_global_v8_gate": sorted(emitted - gate),
        }
    label_free = [name for name, contract in instruments.items() if not contract["labels"]]
    dropped = sorted(
        {key for contract in instruments.values() for key in contract["dropped_by_current_global_v8_gate"]}
    )
    hashed_sources = (*PRODUCTION_SOURCES, V8_GATE_SOURCE, *DOMAIN_SOURCES)
    return {
        "format_version": 1,
        "purpose": (
            "Read-only bootstrap inventory of current Go metric producer label "
            "contracts for the P5 telemetry-registry cutover."
        ),
        "source_sha256": {path.as_posix(): sha256(root / path) for path in hashed_sources},
        "summary": {
            "instrument_count": len(instruments),
            "labeled_instrument_count": len(instruments) - len(label_free),
            "label_free_instrument_count": len(label_free),
            "domain_labeled_instrument_count_at_snapshot": sum(bool(item) for item in registry.values()),
            "domain_family_mismatch_count_at_snapshot": sum(labels[name] != registry[name] for name in labels),
            "domain_missing_label_reference_count_at_snapshot": sum(
                len(labels[name] - registry[name]) for name in labels
            ),
            "domain_extra_label_reference_count_at_snapshot": sum(
                len(registry[name] - labels[name]) for name in labels
            ),
            "label_free_instruments": label_free,
            "current_global_v8_gate_dropped_metric_keys": dropped,
            "current_caps": {
                "max_attributes_per_sample": 32,
                "max_string_bytes": 256,
                "max_slice_elements": 16,
                "sdk_cardinality_limit": 2048,
                "overflow_string": "other",
                "invalid_utf8_string": "invalid",
            },
        },
        "analysis_notes": [
            "Labels are the union of literal attribute keys reachable at every "
            "production Add/Record callsite; optional labels remain in the family "
            "vocabulary.",
            "No dynamic label-key construction is accepted by this analyzer.",
            "Local WithAttributes, KeyValue slices, and append chains are resolved "
            "at each call position; shadowed Agent360 transitionAttrs remain distinct.",
            "Resource attributes are excluded from instrument-specific label sets.",
            "This is bootstrap evidence only; after cutover the registry and generated builders must be authoritative.",
        ],
        "pr412_evidence": [path.as_posix() for path in PR412_EVIDENCE],
        "instruments": instruments,
    }


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--root",
        type=Path,
        required=True,
        help="DefenseClaw repository root",
    )
    parser.add_argument(
        "--output",
        type=Path,
        help="Output JSON path; stdout when omitted",
    )
    parser.add_argument(
        "--check",
        type=Path,
        help="Compare deterministic output with an existing JSON file",
    )
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    report = build_report(args.root.resolve())
    rendered = json.dumps(report, indent=2, sort_keys=True) + "\n"
    if args.check is not None:
        expected = args.check.read_text(encoding="utf-8")
        if rendered != expected:
            print(f"metric label inventory drift: {args.check}", file=sys.stderr)
            return 1
    if args.output is not None:
        args.output.write_text(rendered, encoding="utf-8")
    elif args.check is None:
        sys.stdout.write(rendered)
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (AnalysisError, KeyError, TypeError, ValueError, yaml.YAMLError) as error:
        print(f"metric label analysis failed: {error}", file=sys.stderr)
        raise SystemExit(2) from error
