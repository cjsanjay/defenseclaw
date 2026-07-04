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
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest

ROOT = Path(__file__).resolve().parents[2]


def _load(name: str, path: Path) -> Any:
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


coordinator = _load("telemetry_go_output_coordinator", ROOT / "scripts/telemetry_go_output_coordinator.py")
renderer = _load("render_telemetry_go_test", ROOT / "scripts/render_telemetry_go.py")


def type_ref(name: str) -> SimpleNamespace:
    return SimpleNamespace(arm="builtin", name=name, element=None)


def declaration(
    kind: str = "attribute",
    source_id: str = "gen_ai.request.model",
    symbol: str = "TelemetryAttributeGenAIRequestModel",
    *,
    go_type: str = "string",
    literal_kind: str = "string",
    literal_value: str | int = "gen_ai.request.model",
) -> SimpleNamespace:
    return SimpleNamespace(
        kind=kind,
        source_id=source_id,
        symbol=symbol,
        declaration_form="exported_const",
        owner="package",
        output_file=coordinator.EXACT_GO_OUTPUT_PATHS[0],
        go_type=type_ref(go_type),
        literal_kind=literal_kind,
        literal_value=literal_value,
    )


def fixture(*, declarations: tuple[Any, ...] | None = None) -> tuple[SimpleNamespace, SimpleNamespace]:
    declarations = declarations or (
        declaration(),
        declaration(
            "phase_code",
            "runtime.turn:7",
            "TelemetryPhaseCodeRuntimeTurn",
            go_type="int",
            literal_kind="integer",
            literal_value=7,
        ),
    )
    files = []
    for path in coordinator.EXACT_GO_OUTPUT_PATHS:
        selected = declarations if path == coordinator.EXACT_GO_OUTPUT_PATHS[0] else ()
        files.append(
            SimpleNamespace(
                path=path,
                declaration_keys=tuple((item.kind, item.source_id) for item in selected),
                declarations=selected,
                private_descriptor_ids=(),
                private_projection_ids=(),
                expected_digest_headers=(
                    "materialized_view_sha256",
                    "candidate_render_index_sha256",
                    "go_symbol_table_sha256",
                ),
            )
        )
    plan = SimpleNamespace(
        version=1,
        materialized_view_sha256="1" * 64,
        go_symbol_table_sha256="3" * 64,
        inputs=(),
        callables=(),
        structured=(),
        descriptors=(),
        declarations=declarations,
        files=tuple(files),
        api_plan_sha256="4" * 64,
    )
    index = SimpleNamespace(
        materialized_view_sha256="1" * 64,
        candidate_render_index_sha256="2" * 64,
        expanded_producer_mappings=(),
        examples=(),
    )
    return index, plan


def test_renders_exact_seven_deterministic_outputs_and_coordinator_types() -> None:
    index, plan = fixture()
    first = renderer.render_go_candidate(index, plan)
    second = renderer.render_go_candidate(index, plan)
    assert first == second
    assert tuple(item.path for item in first.outputs) == coordinator.EXACT_GO_OUTPUT_PATHS
    assert tuple(item.path for item in first.declaration_inventory) == coordinator.EXACT_GO_OUTPUT_PATHS
    assert all(isinstance(item, coordinator.RenderedGoOutput) for item in first.outputs)
    assert all(isinstance(item, coordinator.GoFileDeclarationInventory) for item in first.declaration_inventory)
    assert first.expected_declaration_keys == (
        coordinator.GoDeclarationKey("attribute", "gen_ai.request.model"),
        coordinator.GoDeclarationKey("phase_code", "runtime.turn:7"),
    )
    header = coordinator.canonical_go_header("1" * 64, "2" * 64, "3" * 64)
    ids = first.outputs[0].payload
    assert ids.startswith(header + b"package observability\n\nconst (\n")
    assert b'\tTelemetryAttributeGenAIRequestModel string = "gen_ai.request.model"\n' in ids
    assert b"\tTelemetryPhaseCodeRuntimeTurn int = 7\n" in ids
    assert ids.endswith(b")\n\n")
    assert all(output.payload == header + b"package observability\n" for output in first.outputs[1:])


@pytest.mark.parametrize(
    ("target", "missing_fact"),
    (
        ("descriptors", "GoDescriptorPlanIR.kernel_contract_ast"),
        ("structured", "GoStructuredPlanIR.arm_shape_and_conversion_ast"),
        ("callables", "GoCallablePlanIR.body_ast"),
        ("inputs", "GoCallablePlanIR.body_ast"),
        ("expanded_producer_mappings", "GoProducerProjectionPlanIR"),
        ("examples", "GoFixturePlanIR"),
    ),
)
def test_missing_syntax_complete_ir_fails_before_any_partial_candidate(
    monkeypatch: pytest.MonkeyPatch, target: str, missing_fact: str
) -> None:
    index, plan = fixture()
    if hasattr(plan, target):
        setattr(plan, target, (SimpleNamespace(id="blocked"),))
    else:
        setattr(index, target, (SimpleNamespace(id="blocked"),))
    monkeypatch.setattr(renderer, "_render_ids_body", lambda _: pytest.fail("partial IDs payload escaped"))
    with pytest.raises(renderer.GoRenderError, match=missing_fact):
        renderer.render_go_candidate(index, plan)


def test_nonconstant_declaration_fails_closed_as_missing_callable_body_plan() -> None:
    index, plan = fixture()
    nonconstant = SimpleNamespace(**vars(plan.declarations[0]))
    nonconstant.declaration_form = "exported_type"
    plan.declarations = (nonconstant, *plan.declarations[1:])
    plan.files[0].declarations = plan.declarations
    plan.files[0].declaration_keys = tuple((item.kind, item.source_id) for item in plan.declarations)
    with pytest.raises(renderer.GoRenderError, match="GoCallablePlanIR.body_ast"):
        renderer.render_go_candidate(index, plan)


@pytest.mark.parametrize(
    ("mutation", "message"),
    (
        ("mixed digest", "digests disagree"),
        ("bad header", "expected digest headers"),
        ("extra path", "extra or duplicate output path"),
        ("duplicate declaration", "duplicate declaration key"),
        ("wrong integer type", "integer constant type/value disagree"),
        ("wrong string value", "string constant type/value disagree"),
        ("surrogate", "unpaired surrogate"),
    ),
)
def test_adversarial_plan_and_literal_facts_fail_closed(mutation: str, message: str) -> None:
    index, plan = fixture()
    if mutation == "mixed digest":
        index.materialized_view_sha256 = "9" * 64
    elif mutation == "bad header":
        plan.files[2].expected_digest_headers = ("materialized_view_sha256",)
    elif mutation == "extra path":
        plan.files[1].path = "internal/observability/extra.go"
    elif mutation == "duplicate declaration":
        duplicate = SimpleNamespace(**vars(plan.declarations[0]))
        plan.declarations = (*plan.declarations, duplicate)
        plan.files[0].declarations = plan.declarations
        plan.files[0].declaration_keys = tuple((item.kind, item.source_id) for item in plan.declarations)
    elif mutation == "wrong integer type":
        plan.declarations[1].go_type = type_ref("string")
    elif mutation == "wrong string value":
        plan.declarations[0].literal_value = 1
    elif mutation == "surrogate":
        plan.declarations[0].literal_value = "bad\ud800"
    with pytest.raises(renderer.GoRenderError, match=message):
        renderer.render_go_candidate(index, plan)


def test_declaration_sequence_is_bounded_before_iteration() -> None:
    index, plan = fixture(
        declarations=tuple(declaration(source_id=f"field.{i}", symbol=f"Field{i}") for i in range(10_001))
    )
    with pytest.raises(renderer.GoRenderError, match="sequence exceeds the renderer bound"):
        renderer.render_go_candidate(index, plan)


def test_renderer_source_has_no_filesystem_or_registry_source_dependency() -> None:
    source = (ROOT / "scripts/render_telemetry_go.py").read_text(encoding="utf-8")
    assert "pathlib" not in source
    assert "open(" not in source
    assert "import yaml" not in source.casefold()
    assert "yaml." not in source.casefold()
    assert "zz_generated_telemetry" not in source
    assert "internal/observability" not in source


def test_render_candidate_is_recursively_immutable() -> None:
    candidate = renderer.render_go_candidate(*fixture())
    with pytest.raises(dataclasses.FrozenInstanceError):
        candidate.outputs = ()
