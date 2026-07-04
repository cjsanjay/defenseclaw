# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

import dataclasses
import hashlib
import importlib.util
import json
import sys
from pathlib import Path
from types import ModuleType, SimpleNamespace
from typing import Any

import pytest

ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location("telemetry_go_api_plan_test", ROOT / "scripts/telemetry_go_api_plan.py")
assert SPEC is not None and SPEC.loader is not None
plan = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = plan
SPEC.loader.exec_module(plan)


KIND_ORDER = (
    "attribute",
    "family",
    "log_event",
    "span_event",
    "link_relation",
    "metric_instrument",
    "condition",
    "condition_fact",
    "phase",
    "phase_code",
    "semantic_profile",
    "structured_type",
    "structured_member",
    "structured_arm",
    "structured_member_input",
    "structured_member_constructor",
    "family_input",
    "family_builder",
    "span_event_input",
    "span_event_constructor",
    "span_link_input",
    "span_link_constructor",
)
FORM_BY_KIND = {
    **{
        kind: "exported_const"
        for kind in (
            "attribute",
            "family",
            "log_event",
            "span_event",
            "link_relation",
            "metric_instrument",
            "condition",
            "condition_fact",
            "phase",
            "phase_code",
            "semantic_profile",
            "structured_member",
        )
    },
    **{
        kind: "exported_type"
        for kind in (
            "structured_type",
            "structured_arm",
            "structured_member_input",
            "family_input",
            "span_event_input",
            "span_link_input",
        )
    },
    **{
        kind: "exported_function"
        for kind in (
            "structured_member_constructor",
            "span_event_constructor",
            "span_link_constructor",
        )
    },
    "family_builder": "family_builder_method",
}


def symbol(kind: str, source_id: str, go_symbol: str) -> dict[str, str]:
    return {
        "kind": kind,
        "source_id": source_id,
        "symbol": go_symbol,
        "declaration_form": FORM_BY_KIND[kind],
    }


def symbol_table(rows: list[dict[str, str]]) -> SimpleNamespace:
    rank = {kind: index for index, kind in enumerate(KIND_ORDER)}
    rows = sorted(rows, key=lambda row: (rank[row["kind"]], row["source_id"].encode("ascii")))
    payload = json.dumps(
        [[row["kind"], row["source_id"], row["symbol"], row["declaration_form"]] for row in rows],
        separators=(",", ":"),
    ).encode()
    kind_counts = {kind: 0 for kind in KIND_ORDER}
    declaration_counts = {
        "exported_const": 0,
        "exported_type": 0,
        "exported_function": 0,
        "family_builder_method": 0,
    }
    for row in rows:
        kind_counts[row["kind"]] += 1
        declaration_counts[row["declaration_form"]] += 1
    return SimpleNamespace(
        version=1,
        package="observability",
        rows=tuple(SimpleNamespace(**row) for row in rows),
        kind_counts=kind_counts,
        declaration_form_counts=declaration_counts,
        table_sha256=hashlib.sha256(b"DefenseClaw GoSymbolTableIR v1\x00" + payload).hexdigest(),
    )


def policy() -> SimpleNamespace:
    return SimpleNamespace(
        version=1,
        package="observability",
        separators=(".", "-", "/", "_"),
        brand_spellings={"defenseclaw": "DefenseClaw", "opentelemetry": "OpenTelemetry", "otel": "OTel"},
        initialisms=(
            "AI",
            "API",
            "DB",
            "HEC",
            "HTTP",
            "ID",
            "JSON",
            "LLM",
            "OTEL",
            "OTLP",
            "PII",
            "RPC",
            "SDK",
            "SQL",
            "TLS",
            "URL",
            "UTF8",
        ),
        reserved_word_policy="reject",
        collision_policy="reject",
        auto_suffix_policy="reject",
    )


def enriched_field(
    identifier: str,
    owner_id: str,
    component: str,
    semantic_source_id: str,
    primitive_type: str,
    order: int,
    *,
    requirement: str = "required",
    condition_fact: str | None = None,
    value_source: str = "input",
    input_owner_kind: str = "family",
    structured_type: str | None = None,
) -> dict[str, Any]:
    context = {"log": "log", "span": "span", "metric": "metric"}.get(owner_id.split(".", 1)[0], component)
    placement = {
        "family": "family_input",
        "resource": "resource_input",
        "scope": "family_input",
        "event": "event_input",
        "link": "link_input",
        "structured": "structured_input",
    }[component]
    target_slot = {
        "log": "body",
        "span": "trace.attributes",
        "metric": "metric.attributes",
        "resource": "trace.resource.attributes",
        "scope": "trace.scope.attributes",
        "event": "trace.event.attributes",
        "link": "trace.link.attributes",
        "structured": "structured.value",
    }[context]
    return {
        "id": identifier,
        "owner_id": owner_id,
        "context": context,
        "attribute_id": semantic_source_id,
        "field_types": (primitive_type,) if primitive_type != "structured" else ("canonical_json",),
        "structured_type": structured_type,
        "requirement_level": requirement,
        "condition_id": "condition." + condition_fact if condition_fact is not None else None,
        "condition_fact": condition_fact,
        "condition_false_requirement": "optional" if condition_fact is not None else None,
        "field_class": "metadata",
        "effective_constraints": {},
        "value_source": value_source,
        "target_slot": target_slot,
        "input_placement": "private_derived" if value_source != "input" else placement,
        "order": order,
    }


def mandatory_program(*facts: str) -> dict[str, Any]:
    return {
        "rule_ids": tuple("rule." + fact for fact in facts),
        "constant_terms": (),
        "fact_terms": facts,
    }


def family(
    identifier: str,
    signal: str,
    domain: str,
    *,
    field_ids: tuple[str, ...] = (),
    resource_field_ids: tuple[str, ...] = (),
    scope_field_ids: tuple[str, ...] = (),
    events: tuple[dict[str, Any], ...] = (),
    links: tuple[dict[str, Any], ...] = (),
    outcome_requirement: str | None = None,
    metric_value_type: str = "int64",
    mandatory: dict[str, Any] | None = None,
) -> dict[str, Any]:
    outcome = outcome_requirement or {"log": "required", "span": "required", "metric": "forbidden"}[signal]
    return {
        "id": identifier,
        "removed_in": None,
        "signal": {"log": "logs", "span": "traces", "metric": "metrics"}[signal],
        "domain": domain,
        "outcome_requirement": outcome,
        "field_descriptor_ids": field_ids,
        "mandatory_program_id": identifier if signal == "log" else None,
        "allowed_outcomes": () if signal == "metric" else ("completed", "failed"),
        "bucket": {"log": "diagnostic", "span": "agent.lifecycle", "metric": "platform.health"}[signal],
        "event_name": identifier,
        "family_schema_version": 1,
    }


def constant_value(kind: str, source_id: str, go_symbol: str, value: str) -> dict[str, Any]:
    return {
        "kind": kind,
        "source_id": source_id,
        "symbol": go_symbol,
        "go_type": "string",
        "literal_kind": "string",
        "value": value,
    }


def synthetic_candidate_fields() -> dict[str, Any]:
    def bounded_field(name: str, max_items: int) -> dict[str, Any]:
        return {
            "name": name,
            "normalization": {
                "effective_constraints": {
                    "max_utf8_bytes": 4096,
                    "max_item_utf8_bytes": 1024,
                    "max_items": max_items,
                    "max_depth": 8,
                    "max_properties": 256,
                }
            },
        }

    return {
        "semantic_profiles": ({"id": "profile-v1", "trace_schema_version": "trace-v1"},),
        "structural_contract": {
            "trace_body": {
                "fields": (
                    bounded_field("attributes", 256),
                    bounded_field("events", 128),
                    bounded_field("links", 64),
                )
            },
            "trace_resource": {"fields": (bounded_field("attributes", 256),)},
            "trace_scope": {
                "fields": (
                    {"name": "name", "const": "defenseclaw.telemetry"},
                    {"name": "schema_url", "const": "https://defenseclaw.io/schemas/telemetry/v8"},
                    bounded_field("attributes", 16),
                )
            },
            "trace_event": {"fields": (bounded_field("attributes", 64),)},
            "trace_link": {"fields": (bounded_field("attributes", 64),)},
            "metric_instrument_data": {"fields": (bounded_field("attributes", 256),)},
        },
    }


def rich_index() -> SimpleNamespace:
    rows = [
        symbol("attribute", "gen_ai.request.model", "TelemetryAttributeGenAIRequestModel"),
        symbol("structured_type", "gen_ai.box", "TelemetryStructuredGenAIBox"),
        symbol("structured_member", "gen_ai.box#entry", "TelemetryStructuredMemberGenAIBoxEntry"),
        symbol("structured_member_input", "gen_ai.box#entry", "GenAIBoxEntryMemberInput"),
        symbol("structured_member_constructor", "gen_ai.box#entry", "NewGenAIBoxEntryMember"),
        symbol("family_input", "log.test", "LogTestInput"),
        symbol("family_input", "metric.test", "MetricTestInput"),
        symbol("family_input", "span.test", "SpanTestInput"),
        symbol("family_builder", "log.test", "BuildLogTest"),
        symbol("family_builder", "metric.test", "BuildMetricTest"),
        symbol("family_builder", "span.test", "BuildSpanTest"),
        symbol("span_event_input", "span.test#content.redacted", "SpanTestContentRedactedEventInput"),
        symbol("span_event_constructor", "span.test#content.redacted", "NewSpanTestContentRedactedEvent"),
        symbol("span_link_input", "span.test#caused_by", "SpanTestCausedByLinkInput"),
        symbol("span_link_constructor", "span.test#caused_by", "NewSpanTestCausedByLink"),
    ]
    fields = [
        enriched_field("log-model", "log.test", "family", "gen_ai.request.model", "string", 0),
        enriched_field(
            "log-tags",
            "log.test",
            "family",
            "http.request.headers",
            "string[]",
            1,
            requirement="optional",
        ),
        enriched_field(
            "log-box",
            "log.test",
            "family",
            "gen_ai.input.box",
            "structured",
            2,
            requirement="conditional",
            condition_fact="payload_available",
            structured_type="gen_ai.box",
        ),
        enriched_field("resource-service", "resource.core", "resource", "service.name", "string", 0),
        enriched_field("span-operation", "span.test", "family", "gen_ai.operation.name", "string", 0),
        enriched_field(
            "event-reason",
            "content.redacted",
            "event",
            "defenseclaw.reason",
            "string",
            0,
            requirement="conditional",
            condition_fact="event_reason_available",
            input_owner_kind="event",
        ),
        enriched_field(
            "link-kind",
            "link.core",
            "link",
            "defenseclaw.link.kind",
            "string",
            0,
            input_owner_kind="link",
        ),
        enriched_field("metric-kind", "metric.test", "family", "defenseclaw.metric.kind", "string", 0),
        enriched_field(
            "structured-content",
            "gen_ai.box",
            "structured",
            "field:content",
            "string",
            0,
            input_owner_kind="structured",
        ),
        enriched_field(
            "structured-entry-name",
            "gen_ai.box",
            "structured",
            "dynamic_name:entry",
            "string",
            1,
            requirement="optional",
            input_owner_kind="structured",
        ),
    ]
    families = [
        family(
            "log.test",
            "log",
            "security",
            field_ids=("log-model", "log-tags", "log-box"),
            mandatory=mandatory_program("operator_mutation"),
        ),
        family("metric.test", "metric", "operations", field_ids=("metric-kind",), metric_value_type="double"),
        family(
            "span.test",
            "span",
            "genai",
            field_ids=("span-operation",),
            resource_field_ids=("resource-service",),
            events=(
                {
                    "source_id": "span.test#content.redacted",
                    "event_name": "content.redacted",
                    "field_ids": ("event-reason",),
                },
            ),
            links=({"source_id": "span.test#caused_by", "relation": "caused_by", "field_ids": ("link-kind",)},),
        ),
    ]
    return SimpleNamespace(
        materialized_view_sha256="1" * 64,
        go_symbol_policy=policy(),
        go_symbol_table=symbol_table(rows),
        enriched_fields=tuple(fields),
        enriched_families=tuple(families),
        structured_types=(
            {
                "id": "gen_ai.box",
                "kind": "object",
                "fields": (
                    {
                        "name": "content",
                        "required": True,
                        "scalar": {"field_type": "string"},
                        "reference": None,
                    },
                ),
                "items_scalar": None,
                "items_reference": None,
                "variants": None,
                "dynamic_variant": None,
                "canonical_json": None,
                "discriminator": None,
                "dynamic_members": {"member_id": "entry", "value": {"structured_ref": "gen_ai.box"}},
            },
        ),
        enriched_containers={
            "structured:gen_ai.box": SimpleNamespace(
                child_fields=("structured-content", "structured-entry-name"),
                child_containers=("structured-edge:gen_ai.box:dynamic:entry",),
                bounds={},
            ),
            "structured-edge:gen_ai.box:dynamic:entry": SimpleNamespace(reference_target="gen_ai.box"),
        },
        enriched_traces={
            "span.test": SimpleNamespace(
                resource_field_descriptor_ids=("resource-service",),
                scope_field_descriptor_ids=(),
                event_field_descriptor_ids={"content.redacted": ("event-reason",)},
                event_refs=("content.redacted",),
                link_field_descriptor_ids=("link-kind",),
                link_relations=("caused_by",),
                span_name_parts=({"kind": "literal", "literal": "test", "field": None},),
                span_kinds=("INTERNAL",),
            )
        },
        enriched_metrics={
            "metric.test": SimpleNamespace(
                value_type="double",
                instrument_name="test.total",
                instrument_type="counter",
                unit="{event}",
                temporality="delta",
                description="Synthetic metric.",
                boundaries=(),
            )
        },
        mandatory_programs={
            "log.test": SimpleNamespace(
                rule_ids=("rule.operator_mutation",),
                constant_rule_ids=(),
                fact_terms=(("rule.operator_mutation", "operator_mutation"),),
            )
        },
        fields=synthetic_candidate_fields(),
        examples=(
            {
                "id": "valid-log-test",
                "signal": "logs",
                "family": "log.test",
                "valid": True,
                "record": {"signal": "logs", "body": {}},
                "builder_context": {},
                "expected_error": None,
                "base_example": None,
            },
        ),
        expanded_producer_mappings=({"id": "producer.test"},),
        go_declaration_values=(
            constant_value(
                "attribute",
                "gen_ai.request.model",
                "TelemetryAttributeGenAIRequestModel",
                "gen_ai.request.model",
            ),
            constant_value(
                "structured_member",
                "gen_ai.box#entry",
                "TelemetryStructuredMemberGenAIBoxEntry",
                "entry",
            ),
        ),
    )


def input_by_source(compiled: plan.GoAPIPlanIR, source_id: str) -> plan.GoInputPlanIR:
    return next(item for item in compiled.inputs if item.declaration_source_id == source_id)


def load_module(name: str, path: Path) -> ModuleType:
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


def test_real_candidate_index_compiles_complete_semantic_plan() -> None:
    generator = load_module("telemetry_go_plan_real_generator", ROOT / "scripts/generate_telemetry_registry.py")
    renderer = load_module("telemetry_go_plan_real_renderer", ROOT / "scripts/render_telemetry_registry_candidates.py")
    view = generator.compile_registry(ROOT).materialized_view
    index = renderer.build_candidate_render_index(view)
    first = plan.compile_go_api_plan(index)
    second = plan.compile_go_api_plan(index)

    assert first == second
    assert first.api_plan_sha256 == "dc07a40c4b23412dba411b6acf7c0de4215e08f40508c572a09a0560c92b5a5c"
    assert len(first.declarations) == 1773
    assert len(first.inputs) == len(first.callables) == 421
    assert len(first.descriptors) == 243
    assert len(first.structured) == 21
    assert len(first.fixtures) == 12
    assert sum(len(item.scalar_descriptor_ids) for item in first.structured) == 47
    assert sum(item.trace_contract is not None for item in first.descriptors) == 25
    assert sum(item.metric_attribute_limits is not None for item in first.descriptors) == 131
    assert all(
        {field.descriptor_id for field in item.field_contracts}
        == set(item.enriched_field_descriptor_ids)
        | set(item.resource_field_descriptor_ids)
        | set(item.scope_field_descriptor_ids)
        | {field_id for _, _, field_ids in item.event_contracts for field_id in field_ids}
        | {field_id for _, field_ids in item.link_contracts for field_id in field_ids}
        for item in first.descriptors
    )
    assert all(
        field.constraints.arm == "object" for descriptor in first.descriptors for field in descriptor.field_contracts
    )
    phase_codes = [item for item in first.declarations if item.kind == "phase_code"]
    assert len(phase_codes) == 12
    assert all(item.go_type == plan.GoTypeRefIR("builtin", name="int") for item in phase_codes)
    assert all(item.literal_kind == "integer" and isinstance(item.literal_value, int) for item in phase_codes)
    owned = [descriptor_id for file in first.files for descriptor_id in file.private_descriptor_ids]
    catalog = next(file for file in first.files if file.path.endswith("zz_generated_telemetry_catalog.go"))
    assert owned == list(catalog.private_descriptor_ids)
    assert len(owned) == len(set(owned)) == 264
    counts = {item.path: len(item.declarations) for item in first.files}
    assert counts["internal/observability/zz_generated_telemetry_ids.go"] == 893
    assert counts["internal/observability/zz_generated_telemetry_builders_genai.go"] == 282
    assert counts["internal/observability/zz_generated_telemetry_builders_security.go"] == 212
    assert counts["internal/observability/zz_generated_telemetry_builders_operations.go"] == 386


def test_compiler_owns_names_types_layouts_signatures_and_constant_values() -> None:
    compiled = plan.compile_go_api_plan(rich_index())
    log_input = input_by_source(compiled, "log.test")
    assert tuple(field.selector for field in log_input.fields) == (
        "Envelope",
        "Severity",
        "LogLevel",
        "Outcome",
        "GenAIRequestModel",
        "HTTPRequestHeaders",
        "GenAIInputBox",
        "ConditionPayloadAvailable",
        "MandatoryOperatorMutation",
    )
    assert log_input.fields[4].type_ref == plan.GoTypeRefIR("builtin", name="string")
    assert log_input.fields[5].type_ref == plan.GoTypeRefIR(
        "optional", element=plan.GoTypeRefIR("slice", element=plan.GoTypeRefIR("builtin", name="string"))
    )
    assert log_input.fields[6].type_ref == plan.GoTypeRefIR(
        "optional", element=plan.GoTypeRefIR("named", name="TelemetryStructuredGenAIBox")
    )
    assert log_input.fields[5].conversion_op == "copied_string_slice"
    assert log_input.fields[6].conversion_op == "structured_encoder"

    span_input = input_by_source(compiled, "span.test")
    assert tuple(field.selector for field in span_input.fields[:14]) == (
        "Envelope",
        "Outcome",
        "Kind",
        "StartTimeUnixNano",
        "EndTimeUnixNano",
        "ParentSpanID",
        "Status",
        "Resource",
        "Scope",
        "DroppedAttributesCount",
        "Events",
        "DroppedEventsCount",
        "Links",
        "DroppedLinksCount",
    )
    assert tuple(field.selector for field in span_input.fields[14:]) == ("ResourceServiceName", "GenAIOperationName")
    metric_input = input_by_source(compiled, "metric.test")
    assert metric_input.fields[1].selector == "Value"
    assert metric_input.fields[1].type_ref == plan.GoTypeRefIR("builtin", name="float64")
    assert metric_input.fields[1].conversion_op == "metric_number"

    event_input = input_by_source(compiled, "span.test#content.redacted")
    assert tuple(field.selector for field in event_input.fields) == (
        "TimeUnixNano",
        "DroppedAttributesCount",
        "DefenseClawReason",
        "ConditionEventReasonAvailable",
    )
    link_input = input_by_source(compiled, "span.test#caused_by")
    assert tuple(field.selector for field in link_input.fields[:4]) == (
        "TraceID",
        "SpanID",
        "TraceState",
        "DroppedAttributesCount",
    )

    builder = next(item for item in compiled.callables if item.declaration_source_id == "log.test")
    assert builder.receiver_name == "builder"
    assert builder.receiver_pointer is True
    assert builder.receiver_type == plan.GoTypeRefIR("named", name="FamilyBuilder")
    assert builder.parameters == (("input", plan.GoTypeRefIR("named", name="LogTestInput")),)
    assert builder.results == (
        plan.GoTypeRefIR("named", name="Record"),
        plan.GoTypeRefIR("builtin", name="error"),
    )
    assert builder.private_target == "buildGeneratedResolvedLog"

    attribute = next(item for item in compiled.declarations if item.kind == "attribute")
    assert attribute.go_type == plan.GoTypeRefIR("builtin", name="string")
    assert attribute.literal_kind == "string"
    assert attribute.literal_value == "gen_ai.request.model"
    assert attribute.output_file.endswith("zz_generated_telemetry_ids.go")
    assert len(compiled.files) == 7
    assert tuple(item.path for item in compiled.files) == plan.GO_OUTPUT_FILES
    assert all(
        file.declarations == tuple(d for d in compiled.declarations if d.output_file == file.path)
        for file in compiled.files
    )


@pytest.mark.parametrize(
    ("mutation", "message"),
    (
        ("missing family", "complete family descriptor inventory"),
        ("missing structured", "complete structured descriptor inventory"),
        ("selector collision", "field selector/order collision"),
        ("common collision", "field selector/order collision"),
        ("unsupported type", "unsupported Go field type"),
        ("missing constant", "exact exported-constant coverage"),
    ),
)
def test_compiler_fails_closed_for_missing_facts_types_and_collisions(mutation: str, message: str) -> None:
    index = rich_index()
    if mutation == "missing family":
        index.enriched_families = index.enriched_families[:-1]
    elif mutation == "missing structured":
        index.structured_types = ()
    elif mutation == "selector collision":
        fields = list(index.enriched_fields)
        fields[1] = {**fields[1], "attribute_id": "gen_ai_request_model"}
        index.enriched_fields = tuple(fields)
    elif mutation == "common collision":
        fields = list(index.enriched_fields)
        fields[0] = {**fields[0], "attribute_id": "envelope"}
        index.enriched_fields = tuple(fields)
    elif mutation == "unsupported type":
        fields = list(index.enriched_fields)
        fields[0] = {**fields[0], "field_types": ("bytes",)}
        index.enriched_fields = tuple(fields)
    elif mutation == "missing constant":
        index.go_declaration_values = index.go_declaration_values[:-1]
    with pytest.raises(plan.GoAPIPlanError, match=message):
        plan.compile_go_api_plan(index)


def test_plan_digest_is_deterministic_and_binds_typed_constant_values() -> None:
    first_index = rich_index()
    second_index = rich_index()
    second_index.enriched_fields = tuple(reversed(second_index.enriched_fields))
    second_index.enriched_families = tuple(reversed(second_index.enriched_families))
    first = plan.compile_go_api_plan(first_index)
    second = plan.compile_go_api_plan(second_index)
    assert first == second
    assert first.api_plan_sha256 == second.api_plan_sha256

    changed_index = rich_index()
    changed = list(changed_index.go_declaration_values)
    changed[0] = {**changed[0], "value": "changed.attribute.value"}
    changed_index.go_declaration_values = tuple(changed)
    changed_plan = plan.compile_go_api_plan(changed_index)
    assert changed_plan.api_plan_sha256 != first.api_plan_sha256


def test_integer_declaration_values_use_portable_signed_32_bit_range() -> None:
    index = rich_index()
    values = list(index.go_declaration_values)
    values[0] = {**values[0], "go_type": "int", "literal_kind": "integer", "value": 2**31 - 1}
    index.go_declaration_values = tuple(values)
    compiled = plan.compile_go_api_plan(index)
    declaration = next(item for item in compiled.declarations if item.kind == "attribute")
    assert declaration.go_type == plan.GoTypeRefIR("builtin", name="int")
    assert declaration.literal_value == 2**31 - 1

    values[0] = {**values[0], "value": 2**31}
    index.go_declaration_values = tuple(values)
    with pytest.raises(plan.GoAPIPlanError, match="integer literal"):
        plan.compile_go_api_plan(index)


def partition_index(*, wrong_domain: bool = False) -> SimpleNamespace:
    rows: list[dict[str, str]] = []
    constants: list[dict[str, Any]] = []
    for index in range(893):
        source_id = f"attribute.{index:04d}"
        rows.append(symbol("attribute", source_id, f"TelemetryAttributeA{index:04d}"))
        constants.append(constant_value("attribute", source_id, f"TelemetryAttributeA{index:04d}", source_id))
    structured = []
    for index in range(282):
        source_id = f"synthetic.type.{index:04d}"
        rows.append(symbol("structured_type", source_id, f"TelemetryStructuredSyntheticType{index:04d}"))
        structured.append(
            {
                "id": source_id,
                "kind": "object",
                "fields": None,
                "items_scalar": None,
                "items_reference": None,
                "variants": None,
                "dynamic_variant": None,
                "canonical_json": None,
                "discriminator": None,
                "dynamic_members": None,
            }
        )
    families: list[dict[str, Any]] = []
    family_domains: list[tuple[str, str]] = [(f"log.security{index:04d}", "security") for index in range(106)]
    family_domains.extend((f"log.operations{index:04d}", "operations") for index in range(193))
    if wrong_domain:
        family_domains[0] = (family_domains[0][0], "operations")
    for source_id, domain in family_domains:
        suffix = source_id.removeprefix("log.").replace(".", "")
        rows.append(symbol("family_input", source_id, "Log" + suffix.title() + "Input"))
        rows.append(symbol("family_builder", source_id, "BuildLog" + suffix.title()))
        families.append(family(source_id, "log", domain, outcome_requirement="forbidden"))
    derived_field = enriched_field(
        "derived-only",
        family_domains[0][0],
        "family",
        "defenseclaw.bucket",
        "string",
        0,
        value_source="envelope.bucket",
        input_owner_kind="none",
    )
    families[0]["field_descriptor_ids"] = ("derived-only",)
    structured_containers = {
        f"structured:synthetic.type.{index:04d}": SimpleNamespace(child_fields=(), child_containers=(), bounds={})
        for index in range(282)
    }
    return SimpleNamespace(
        materialized_view_sha256="2" * 64,
        go_symbol_policy=policy(),
        go_symbol_table=symbol_table(rows),
        enriched_fields=(derived_field,),
        enriched_families=tuple(families),
        structured_types=tuple(structured),
        enriched_containers=structured_containers,
        enriched_traces={},
        enriched_metrics={},
        mandatory_programs={
            source_id: SimpleNamespace(rule_ids=(), constant_rule_ids=(), fact_terms=())
            for source_id, _ in family_domains
        },
        fields=synthetic_candidate_fields(),
        examples=(),
        expanded_producer_mappings=(),
        go_declaration_values=tuple(constants),
    )


def test_exact_1773_row_partition_and_every_declaration_file_assignment() -> None:
    compiled = plan.compile_go_api_plan(partition_index())
    counts = {item.path: len(item.declarations) for item in compiled.files}
    assert counts["internal/observability/zz_generated_telemetry_ids.go"] == 893
    assert counts["internal/observability/zz_generated_telemetry_builders_genai.go"] == 282
    assert counts["internal/observability/zz_generated_telemetry_builders_security.go"] == 212
    assert counts["internal/observability/zz_generated_telemetry_builders_operations.go"] == 386
    assert sum(counts.values()) == 1773
    keys = [key for file in compiled.files for key in file.declaration_keys]
    assert len(keys) == len(set(keys)) == 1773

    with pytest.raises(plan.GoAPIPlanError, match="893/282/212/386"):
        plan.compile_go_api_plan(partition_index(wrong_domain=True))


def test_ir_is_frozen_and_contains_no_renderer_text_type_escape_hatch() -> None:
    compiled = plan.compile_go_api_plan(rich_index())
    with pytest.raises(dataclasses.FrozenInstanceError):
        compiled.version = 2  # type: ignore[misc]
    for input_plan in compiled.inputs:
        for field in input_plan.fields:
            assert field.type_ref.arm in {"builtin", "named", "optional", "slice"}
            assert field.conversion_op in {
                "required_scalar",
                "optional_scalar",
                "copied_string_slice",
                "structured_encoder",
                "metric_number",
                "condition_fact",
                "mandatory_fact",
                "trace_event",
                "trace_link",
            }
