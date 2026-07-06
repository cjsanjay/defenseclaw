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
import importlib.util
import sys
from collections import Counter
from collections.abc import Sequence
from pathlib import Path
from types import ModuleType, SimpleNamespace
from typing import Any

import pytest

ROOT = Path(__file__).resolve().parents[2]


def load_module(name: str, path: Path) -> ModuleType:
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


plan = load_module("telemetry_go_producer_plan_test", ROOT / "scripts/telemetry_go_producer_plan.py")


@dataclasses.dataclass(frozen=True, slots=True)
class IsolatedAPIPlan:
    """Keeps this focused compiler test independent of concurrent API-plan work."""

    api_plan_sha256: str = "a" * 64


@pytest.fixture(scope="module")
def candidate_index() -> Any:
    generator = load_module("telemetry_producer_real_generator", ROOT / "scripts/generate_telemetry_registry.py")
    renderer = load_module(
        "telemetry_producer_real_candidate_renderer",
        ROOT / "scripts/render_telemetry_registry_candidates.py",
    )
    renderer.compile_go_api_plan = lambda _provisional: IsolatedAPIPlan()
    view = generator.compile_registry(ROOT).materialized_view
    return renderer.build_candidate_render_index(view)


@pytest.fixture(scope="module")
def compiled(candidate_index: Any) -> plan.GoProducerPlanIR:
    return plan.compile_go_producer_plan(candidate_index)


def mutable_index(candidate_index: Any, rows: Sequence[Any]) -> SimpleNamespace:
    return SimpleNamespace(
        materialized_view_sha256=candidate_index.materialized_view_sha256,
        candidate_render_index_sha256=candidate_index.candidate_render_index_sha256,
        expanded_producer_mappings=rows,
    )


def test_real_candidate_compiles_lossless_typed_producer_authority(
    candidate_index: Any,
    compiled: plan.GoProducerPlanIR,
) -> None:
    repeated = plan.compile_go_producer_plan(candidate_index)

    assert compiled == repeated
    assert compiled.version == 1
    assert compiled.producer_plan_sha256 == "4799dd0fe3998860225726c11705807b294b58f45b5bbcd874e931f91a9c1388"
    assert compiled.materialized_view_sha256 == candidate_index.materialized_view_sha256
    assert compiled.candidate_render_index_sha256 == candidate_index.candidate_render_index_sha256
    assert len(compiled.rows) == len(candidate_index.expanded_producer_mappings) == 8077
    assert len(compiled.groups) == 203
    assert Counter(group.producer_kind.value for group in compiled.groups) == {
        "audit_action": 188,
        "gateway_event": 15,
    }
    assert sum(row.family_refs.family_descriptor_id is not None for row in compiled.rows) == 1820
    assert sum(row.compatibility_only for row in compiled.rows) == 6257
    assert tuple(row.row_id for row in compiled.rows) == tuple(
        row.id for row in candidate_index.expanded_producer_mappings
    )
    assert all(row.producer_kind.go_type == "ProducerKind" for row in compiled.rows)
    assert all(row.producer_key.go_type == "ProducerKey" for row in compiled.rows)
    assert all(row.source.go_type == "generatedProducerSource" for row in compiled.rows)
    assert all(row.event_name_policy.go_type == "EventNamePolicy" for row in compiled.rows)
    assert all(row.severity_policy.go_type == "SeverityPolicy" for row in compiled.rows)
    assert all(row.event_name.go_type == "EventName" and row.bucket.go_type == "Bucket" for row in compiled.rows)
    assert tuple(field.name for field in dataclasses.fields(plan.GoProducerFamilyRefsIR)) == (
        "family_descriptor_id",
        "selected_family_floor_id",
    )

    for source, rendered in zip(candidate_index.expanded_producer_mappings, compiled.rows):
        assert rendered.producer_kind.value == source.producer
        assert rendered.producer_key.value == source.key
        assert rendered.source.value == source.source
        assert rendered.event_name_policy.value == source.event_name_policy
        assert rendered.severity_policy.value == source.severity_policy
        assert rendered.event_name.value == source.event_name
        assert rendered.bucket.value == source.bucket
        assert rendered.family_refs.family_descriptor_id == source.family_id
        assert rendered.family_refs.selected_family_floor_id == source.selected_mandatory_program_id
        assert tuple(item.value for item in rendered.legacy_mapping_mandatory_rules) == (
            source.legacy_mapping_mandatory_rules
        )
        assert tuple(item.value for item in rendered.companion_rules) == source.companion_rules


def test_grouping_preserves_fixed_and_context_identity_precedence_without_wildcards(
    compiled: plan.GoProducerPlanIR,
) -> None:
    expected_steps = {
        "fixed": ("reject_nonempty_context_disagreement", "select_default"),
        "context_optional": (
            "select_exact_context_when_present",
            "select_default_when_context_absent",
            "reject_unmatched_context",
        ),
        "context_required": (
            "require_context_identity",
            "select_exact_context",
            "reject_unmatched_context",
        ),
    }
    rows = {row.row_id: row for row in compiled.rows}
    assert Counter(group.event_name_policy.value for group in compiled.groups) == {
        "context_optional": 182,
        "context_required": 15,
        "fixed": 6,
    }
    for group in compiled.groups:
        policy = group.event_name_policy.value
        assert tuple(step.opcode for step in group.selection_steps) == expected_steps[policy]
        assert group.ordered_row_ids == (() if group.default_row_id is None else (group.default_row_id,)) + (
            group.context_row_ids
        )
        assert group.default_identity_index == (0 if group.default_row_id is not None else -1)
        assert group.context_identity_start == (1 if group.default_row_id is not None else 0)
        assert group.context_identity_count == len(group.context_row_ids)
        assert all(rows[row_id].identity_origin.value == "allowed_context" for row_id in group.context_row_ids)
        assert all(rows[row_id].event_name.value != "*" for row_id in group.context_row_ids)
        assert all(rows[row_id].bucket.value != "*" for row_id in group.context_row_ids)
        if policy == "fixed":
            assert group.default_row_id is not None and not group.context_row_ids
            assert all(step.row_ids == (group.default_row_id,) for step in group.selection_steps)
        elif policy == "context_optional":
            assert group.default_row_id is not None and group.context_row_ids
            assert group.selection_steps[0].row_ids == group.context_row_ids
            assert group.selection_steps[1].row_ids == (group.default_row_id,)
        else:
            assert group.default_row_id is None and group.context_row_ids
            assert group.selection_steps[0].row_ids == ()
            assert group.selection_steps[1].row_ids == group.context_row_ids

    assert len(compiled.lookup_index.entries) == len(compiled.groups)
    assert tuple(entry.group_index for entry in compiled.lookup_index.entries) == tuple(range(203))
    assert sum(entry.row_count for entry in compiled.lookup_index.entries) == 8077
    assert tuple(entry.row_start for entry in compiled.lookup_index.entries) == tuple(
        sum(len(group.ordered_row_ids) for group in compiled.groups[:position]) for position in range(203)
    )


def test_selected_family_is_the_only_floor_authority_and_legacy_rules_remain_metadata(
    compiled: plan.GoProducerPlanIR,
) -> None:
    family_rows = [row for row in compiled.rows if row.family_refs.family_descriptor_id is not None]
    compatibility_rows = [row for row in compiled.rows if row.compatibility_only]
    assert all(row.family_refs.selected_family_floor_id == row.family_refs.family_descriptor_id for row in family_rows)
    assert all(
        row.family_refs.selected_family_floor_id is None and row.family_refs.family_descriptor_id is None
        for row in compatibility_rows
    )
    assert any(row.legacy_mapping_mandatory_rules for row in family_rows)
    assert any(
        row.legacy_mapping_mandatory_rules and row.family_refs.selected_family_floor_id is not None
        for row in family_rows
    )
    assert all(item.go_type == "MandatoryRule" for row in compiled.rows for item in row.legacy_mapping_mandatory_rules)
    assert all(item.go_type == "CompanionRule" for row in compiled.rows for item in row.companion_rules)


def test_private_go_plan_is_syntax_complete_and_copy_safe(compiled: plan.GoProducerPlanIR) -> None:
    file = compiled.file
    assert file.path == "internal/observability/zz_generated_telemetry_producers.go"
    assert file.package == "observability"
    assert file.imports == ("fmt",)
    assert tuple(item.symbol for item in file.type_declarations) == (
        "generatedProducerSource",
        "generatedIdentityOrigin",
        "generatedCompatibilityDisposition",
        "generatedProducerCompatibility",
        "generatedProducerFamilyRefs",
        "generatedProducerIdentity",
        "generatedProducerGroup",
        "generatedProducerLookupKey",
    )
    assert tuple(item.symbol for item in file.variables) == (
        "generatedProducerRows",
        "generatedProducerGroups",
        "generatedProducerGroupIndex",
    )
    assert file.variables[0].go_type == plan.GoTypeRefIR(
        "array", element=plan.GoTypeRefIR("named", name="generatedProducerIdentity"), length=8077
    )
    assert file.variables[1].go_type == plan.GoTypeRefIR(
        "array", element=plan.GoTypeRefIR("named", name="generatedProducerGroup"), length=203
    )
    assert tuple(item.symbol for item in file.functions) == (
        "lookupGeneratedProducerGroup",
        "resolveGeneratedProducerIdentity",
        "cloneGeneratedProducerGroup",
    )
    assert tuple(item.opcode for item in file.functions[0].body_operations) == (
        "construct_lookup_key",
        "lookup_group_index",
        "return_zero_false_when_missing",
        "deep_clone_group",
        "return_group_true",
    )
    assert tuple(item.opcode for item in file.functions[2].body_operations) == (
        "copy_group_value",
        "allocate_identity_rows",
        "copy_identity_rows",
        "clone_legacy_mandatory_rule_slices",
        "clone_companion_rule_slices",
        "return_group_copy",
    )
    assert tuple(item.code for item in file.functions[1].error_cases) == (
        "unknown_producer_mapping",
        "partial_context_identity",
        "fixed_context_disagreement",
        "missing_context_identity",
        "unmatched_context_identity",
    )
    assert all("%" not in item.format_string or item.operands for item in file.functions[1].error_cases)
    assert compiled.copy_operations == (
        plan.GoCopyOperationIR(
            "generatedProducerGroup",
            "Identities",
            "deep_clone_slice",
            ("LegacyMandatoryRules", "CompanionRules"),
        ),
        plan.GoCopyOperationIR("generatedProducerIdentity", "LegacyMandatoryRules", "clone_slice"),
        plan.GoCopyOperationIR("generatedProducerIdentity", "CompanionRules", "clone_slice"),
    )


@pytest.mark.parametrize(
    ("mutation", "message"),
    (
        ("missing row", "exact 8,077-row inventory"),
        ("wrong selected floor", "selected-family floor reference"),
        ("policy drift", "unsupported policy"),
        ("source drift", "producer source disagrees"),
        ("row id drift", "identity coordinates disagree"),
        ("mapping common drift", "mapping-common facts disagree"),
        ("duplicate context", "contextual identity is duplicated"),
        ("noncontiguous group", "mapping-index order|non-contiguous"),
    ),
)
def test_adversarial_expanded_rows_fail_closed(candidate_index: Any, mutation: str, message: str) -> None:
    rows = list(candidate_index.expanded_producer_mappings)
    if mutation == "missing row":
        rows.pop()
    elif mutation == "wrong selected floor":
        position = next(index for index, row in enumerate(rows) if row.family_id is not None)
        rows[position] = dataclasses.replace(rows[position], selected_mandatory_program_id="log.other")
    elif mutation == "policy drift":
        rows[0] = dataclasses.replace(rows[0], severity_policy="source_guess")
    elif mutation == "source drift":
        rows[0] = dataclasses.replace(rows[0], source="internal/other/events.go")
    elif mutation == "row id drift":
        rows[0] = dataclasses.replace(rows[0], id="operations:999:default:0")
    elif mutation == "mapping common drift":
        position = next(index for index, row in enumerate(rows[1:], 1) if row.key == rows[index - 1].key)
        rows[position] = dataclasses.replace(rows[position], companion_rules=("finding_per_observation",))
    elif mutation == "duplicate context":
        position = next(
            index
            for index, row in enumerate(rows[1:], 1)
            if row.identity_origin == rows[index - 1].identity_origin == "allowed_context"
            and row.key == rows[index - 1].key
        )
        rows[position] = dataclasses.replace(
            rows[position],
            event_name=rows[position - 1].event_name,
            bucket=rows[position - 1].bucket,
            family_id=rows[position - 1].family_id,
            compatibility_only=rows[position - 1].compatibility_only,
            selected_mandatory_program_id=rows[position - 1].selected_mandatory_program_id,
        )
    elif mutation == "noncontiguous group":
        boundary = next(index for index, row in enumerate(rows[1:], 1) if row.key != rows[index - 1].key)
        rows[0], rows[boundary] = rows[boundary], rows[0]
    with pytest.raises(plan.GoProducerPlanError, match=message):
        plan.compile_go_producer_plan(mutable_index(candidate_index, tuple(rows)))


class OversizedSequence(Sequence[object]):
    def __len__(self) -> int:
        return 8078

    def __getitem__(self, index: int) -> object:
        raise AssertionError("bounded preflight iterated an oversized producer sequence")


def test_input_bound_is_checked_before_iteration(candidate_index: Any) -> None:
    with pytest.raises(plan.GoProducerPlanError, match="sequence exceeds the compiler bound"):
        plan.compile_go_producer_plan(mutable_index(candidate_index, OversizedSequence()))


def test_plan_digest_binds_row_order_and_candidate_identity(
    candidate_index: Any, compiled: plan.GoProducerPlanIR
) -> None:
    changed_digest = mutable_index(candidate_index, candidate_index.expanded_producer_mappings)
    changed_digest.candidate_render_index_sha256 = "f" * 64
    assert plan.compile_go_producer_plan(changed_digest).producer_plan_sha256 != compiled.producer_plan_sha256

    rows = list(candidate_index.expanded_producer_mappings)
    first = next(
        index
        for index, row in enumerate(rows[:-1])
        if row.identity_origin == rows[index + 1].identity_origin == "allowed_context"
        and row.key == rows[index + 1].key
    )
    left, right = rows[first], rows[first + 1]
    rows[first] = dataclasses.replace(
        right,
        id=f"{right.domain}:{right.mapping_index}:allowed_context:{left.identity_index}",
        identity_index=left.identity_index,
    )
    rows[first + 1] = dataclasses.replace(
        left,
        id=f"{left.domain}:{left.mapping_index}:allowed_context:{right.identity_index}",
        identity_index=right.identity_index,
    )
    reordered = plan.compile_go_producer_plan(mutable_index(candidate_index, tuple(rows)))
    assert reordered.producer_plan_sha256 != compiled.producer_plan_sha256


def test_ir_is_recursively_immutable_and_has_no_source_text_escape_hatch(
    compiled: plan.GoProducerPlanIR,
) -> None:
    with pytest.raises(dataclasses.FrozenInstanceError):
        compiled.version = 2  # type: ignore[misc]
    with pytest.raises(dataclasses.FrozenInstanceError):
        compiled.rows[0].compatibility_only = False  # type: ignore[misc]
    with pytest.raises(dataclasses.FrozenInstanceError):
        compiled.file.functions[0].body_operations = ()  # type: ignore[misc]
    assert not any(
        "source" in field.name.casefold() or "text" in field.name.casefold()
        for ir_type in (
            plan.GoBodyOperationIR,
            plan.GoPrivateFunctionIR,
            plan.GoPrivateVariableIR,
            plan.GoProducerFilePlanIR,
        )
        for field in dataclasses.fields(ir_type)
    )


def test_compiler_source_has_no_yaml_golden_current_go_or_filesystem_reads() -> None:
    source = (ROOT / "scripts/telemetry_go_producer_plan.py").read_text(encoding="utf-8")
    assert "pathlib" not in source
    assert "import yaml" not in source.casefold()
    assert "yaml." not in source.casefold()
    assert "open(" not in source
    assert "read_text" not in source
    assert "baselines/" not in source
    assert "classification.go" not in source
    assert "read_bytes" not in source
