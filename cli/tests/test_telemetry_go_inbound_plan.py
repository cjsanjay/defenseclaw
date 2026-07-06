# Copyright 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

import dataclasses
import importlib.util
import json
import sys
from pathlib import Path
from types import ModuleType
from typing import Any

import pytest

ROOT = Path(__file__).resolve().parents[2]
SCRIPTS = ROOT / "scripts"


def _load(name: str, path: Path) -> ModuleType:
    existing = sys.modules.get(name)
    if existing is not None:
        return existing
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


plan = _load("telemetry_go_inbound_plan", SCRIPTS / "telemetry_go_inbound_plan.py")


@pytest.fixture(scope="module")
def candidate() -> Any:
    _load("telemetry_canonical_record", SCRIPTS / "telemetry_canonical_record.py")
    _load("telemetry_go_api_plan", SCRIPTS / "telemetry_go_api_plan.py")
    generator = _load("telemetry_inbound_plan_generator", SCRIPTS / "generate_telemetry_registry.py")
    renderer = _load(
        "telemetry_inbound_plan_candidate_renderer",
        SCRIPTS / "render_telemetry_registry_candidates.py",
    )
    return renderer.build_candidate_render_index(generator.compile_registry(ROOT).materialized_view)


def test_go_inbound_plan_is_digest_bound_complete_and_private(candidate: Any) -> None:
    compiled = plan.compile_go_inbound_plan(candidate)

    assert compiled.materialized_view_sha256 == candidate.materialized_view_sha256
    assert compiled.candidate_render_index_sha256 == candidate.candidate_render_index_sha256
    assert len(compiled.aliases) == 9
    assert len(compiled.matches) == 237
    assert len(compiled.targets) == 245
    assert len(compiled.native_markers) == 24
    assert len(compiled.echo_recognizers) == 249
    assert len(compiled.import_contexts) == 93
    assert len(compiled.projection_ids) == 857
    assert len(set(compiled.projection_ids)) == len(compiled.projection_ids)
    assert compiled.native_malformed_external_fallback == "forbidden"
    assert compiled.unknown_fields == "drop_and_count"
    assert compiled.native_marker_rule == "any_declared_native_marker_selects_native_candidate"
    assert compiled.structural_marker_rule == "exact_declared_structure_only"
    assert compiled.native_malformed_disposition == "invalid_record"
    assert compiled.semantic_resource_instance_key != compiled.forward_instance_key
    assert all(
        not hasattr(context, "mandatory") and not hasattr(context, "floor") for context in compiled.import_contexts
    )
    assert all(item.startswith("inbound:") for item in compiled.projection_ids)


def test_go_inbound_plan_preserves_match_target_separation(candidate: Any) -> None:
    compiled = plan.compile_go_inbound_plan(candidate)
    targets = {target.id: target for target in compiled.targets}

    for match in compiled.matches:
        selected = [targets[target_id] for target_id in match.target_ids]
        assert sum(target.target_kind == "primary" for target in selected) == 1
        assert all(target.match_id == match.id for target in selected)
    codex = next(match for match in compiled.matches if match.class_id == "otlp.codex.response_completed.v1")
    assert len(codex.target_ids) == 3
    workflow = next(match for match in compiled.matches if match.id.endswith("span.workflow.run"))
    assert workflow.target_override == plan.GoInboundTargetOverrideIR(
        "gen_ai.workflow.name",
        "defenseclaw.workflow.name",
        "identifier-v1",
    )
    assert all(len(target.field_refs) == len(target.field_descriptor_ids) for target in compiled.targets)
    assert all(
        candidate.enriched_fields[descriptor_id].attribute_id == reference
        for target in compiled.targets
        for reference, descriptor_id in zip(target.field_refs, target.field_descriptor_ids, strict=True)
    )
    descriptors = {descriptor.family_id: descriptor for descriptor in candidate.go_api_plan.descriptors}
    assert all(
        target.descriptor_symbol == descriptors[target.family].catalog_contract.descriptor_type_symbol
        for target in compiled.targets
    )
    assert all(
        context.descriptor_symbol == descriptors[context.family_descriptor_id].catalog_contract.descriptor_type_symbol
        for context in compiled.import_contexts
    )
    assert all(descriptors[context.family_descriptor_id].signal == "log" for context in compiled.import_contexts)
    candidate_matches = {item["id"]: item for item in candidate.inbound_otlp.match_descriptors}
    for match in compiled.matches:
        source = candidate_matches[match.id]
        assert match.mapping_strategy == source["mapping"]["strategy"]
        assert match.alias_ids == tuple(item["id"] for item in source["mapping"]["alias_sets"])
        assert match.target_ids == tuple(source["target_ids"])
        assert [
            (item.location, item.key, item.operator, json.loads(item.values_json), item.value_type)
            for item in match.predicates
        ] == [
            (
                item["location"],
                item["key"],
                item["operator"],
                list(item["values"]),
                item["value_type"],
            )
            for item in source["discriminator"]["predicates"]
        ]

    duration_rule = plan.GoInboundUnitRuleIR(
        "scale-table-v1",
        "s",
        tuple(
            plan.GoInboundUnitScaleIR(unit, scale)
            for unit, scale in (
                ("", 1.0),
                ("s", 1.0),
                ("second", 1.0),
                ("seconds", 1.0),
                ("ms", 0.001),
                ("millisecond", 0.001),
                ("milliseconds", 0.001),
                ("us", 0.000001),
                ("microsecond", 0.000001),
                ("microseconds", 0.000001),
                ("ns", 0.000000001),
                ("nanosecond", 0.000000001),
                ("nanoseconds", 0.000000001),
            )
        ),
    )
    duration_matches = [match for match in compiled.matches if match.class_id == "otlp.genai.duration.metric.v1"]
    assert len(duration_matches) == 5
    assert all(match.source_unit_rule == duration_rule for match in duration_matches)
    assert all(
        targets[match.target_ids[0]].instrument_unit == "s"
        and targets[match.target_ids[0]].source_unit_rule == duration_rule
        for match in duration_matches
    )

    token_rule = plan.GoInboundUnitRuleIR(
        "scale-table-v1",
        "{token}",
        tuple(plan.GoInboundUnitScaleIR(unit, 1.0) for unit in ("", "{token}", "token", "tokens")),
    )
    token_match = next(match for match in compiled.matches if match.class_id == "otlp.claudecode.token_usage.v1")
    assert token_match.source_unit_rule == token_rule
    assert targets[token_match.target_ids[0]].instrument_unit == "{token}"
    assert targets[token_match.target_ids[0]].source_unit_rule == token_rule

    for native in (match for match in compiled.matches if match.class_id == "otlp.native.metric.v8"):
        target = targets[native.target_ids[0]]
        equality_rule = plan.GoInboundUnitRuleIR(
            "target-unit-equality-v1",
            target.instrument_unit,
            (plan.GoInboundUnitScaleIR(target.instrument_unit, 1.0),),
        )
        assert native.source_unit_rule == equality_rule
        assert target.source_unit_rule == equality_rule


def test_go_inbound_plan_rejects_untyped_or_mutable_input(candidate: Any) -> None:
    with pytest.raises(plan.GoInboundPlanError, match="compiler-owned candidate"):
        plan.compile_go_inbound_plan({"inbound_otlp": candidate.inbound_otlp})

    forged = dataclasses.replace(candidate, materialized_view_sha256="bad")
    with pytest.raises(plan.GoInboundPlanError, match="materialized digest is invalid"):
        plan.compile_go_inbound_plan(forged)
