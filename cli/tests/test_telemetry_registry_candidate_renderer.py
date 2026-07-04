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

import base64
import dataclasses
import hashlib
import importlib.util
import json
import sys
from collections.abc import Mapping
from pathlib import Path, PurePosixPath
from types import ModuleType
from typing import Any

import jsonschema
import pytest

ROOT = Path(__file__).resolve().parents[2]
GENERATOR = ROOT / "scripts/generate_telemetry_registry.py"
RENDERER = ROOT / "scripts/render_telemetry_registry_candidates.py"
PREFIX = "schemas/telemetry/generated"


def _load(name: str, path: Path) -> ModuleType:
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


@pytest.fixture(scope="module")
def generator() -> ModuleType:
    return _load("telemetry_candidate_test_generator", GENERATOR)


@pytest.fixture(scope="module")
def renderer() -> ModuleType:
    return _load("telemetry_candidate_test_renderer", RENDERER)


@pytest.fixture(scope="module")
def view(generator: ModuleType) -> Any:
    return generator.compile_registry(ROOT).materialized_view


@pytest.fixture(scope="module")
def artifacts(renderer: ModuleType, view: Any) -> Mapping[str, Any]:
    return renderer.render_candidate_artifacts(view)


def _json(artifacts: Mapping[str, Any], relative: str) -> dict[str, Any]:
    return json.loads(artifacts[f"{PREFIX}/{relative}"].payload)


def _subschema_validator(schema: Mapping[str, Any], subschema: Mapping[str, Any]) -> jsonschema.Draft202012Validator:
    definitions = dict(schema["$defs"])
    definitions["test:subject"] = subschema
    return jsonschema.Draft202012Validator(
        {
            "$schema": schema["$schema"],
            "$ref": "#/$defs/test:subject",
            "$defs": definitions,
        }
    )


def _span_record_for_family(
    artifacts: Mapping[str, Any],
    schema: Mapping[str, Any],
    family_id: str,
) -> dict[str, Any]:
    record = json.loads(
        json.dumps(
            _json(
                artifacts,
                "examples/valid/valid-model-chat-with-honest-missing-content-and-usage.json",
            )["record"]
        )
    )
    definition = schema["$defs"][f"family:{family_id}"]
    metadata = definition["x-defenseclaw-family"]
    body_overlay = definition["allOf"][1]["properties"]["body"]["allOf"][1]
    attributes_schema = body_overlay["properties"]["attributes"]
    allowed_attributes = attributes_schema["properties"]
    record["body"]["attributes"] = {
        key: value for key, value in record["body"]["attributes"].items() if key in allowed_attributes
    }
    for key, attribute_schema in allowed_attributes.items():
        if "const" in attribute_schema:
            record["body"]["attributes"][key] = attribute_schema["const"]
    record["body"]["kind"] = body_overlay["properties"]["kind"]["enum"][0]
    record["body"].pop("events", None)
    record["bucket"] = metadata["bucket"]
    record["event_name"] = metadata["event_name"]
    record["span_name"] = metadata["span_name_pattern"]
    record["outcome"] = "completed"
    return record


def _retagged_view(renderer: ModuleType, view: Any, facts: Mapping[str, Any]) -> Any:
    typed = renderer._typed_materialized_node(facts)
    digest = hashlib.sha256(
        renderer.MATERIALIZED_VIEW_DIGEST_DOMAIN + renderer._canonical_json_bytes(typed)
    ).hexdigest()
    return dataclasses.replace(view, facts=facts, typed_canonical_json_sha256=digest)


def _copy_materialized(value: Any) -> Any:
    if isinstance(value, Mapping):
        return {key: _copy_materialized(item) for key, item in value.items()}
    if isinstance(value, tuple):
        return tuple(_copy_materialized(item) for item in value)
    return value


def _set_unreferenced_invalid_example_id(facts: dict[str, Any], example_id: str) -> None:
    examples = facts["fields"]["examples"]
    referenced = {item["fields"]["base_example"] for item in examples if item["fields"]["base_example"] is not None}
    target = next(
        item for item in examples if item["fields"]["valid"] is False and item["fields"]["id"] not in referenced
    )
    target["fields"]["id"] = example_id


def test_public_candidate_render_index_is_identity_bound_deterministic_and_recursively_immutable(
    renderer: ModuleType,
    view: Any,
) -> None:
    first = renderer.build_candidate_render_index(view)
    second = renderer.build_candidate_render_index(view)

    assert isinstance(first, renderer.CandidateRenderIndex)
    assert first == second
    assert first.digest == view.typed_canonical_json_sha256
    assert first.schema_version == 1
    assert first.registry_version == 1
    assert first.bucket_catalog_version == 1
    assert len(first.families) == 243
    assert len(first.attributes) == 325
    assert len(first.domains) == 3
    assert sum(len(domain.producer_mappings) for domain in first.domains) == 202
    assert first.family_domains["span.model.chat"] == "genai"
    assert first.family_domains["log.finding.observed"] == "security"
    assert first.family_domains["log.telemetry.batch.rejected"] == "operations"
    assert tuple(first.example_output_paths) == tuple(item["id"] for item in first.examples)
    first_example = first.examples[0]
    first_paths = first.example_output_paths[first_example["id"]]
    category = "valid" if first_example["valid"] else "invalid"
    assert first_paths == renderer.CandidateExampleOutputPaths(
        first_example["id"],
        f"{PREFIX}/examples/{category}/{first_example['id']}.json",
        f"{PREFIX}/otlp-fixtures/cases/{first_example['id']}.json",
    )
    assert "$type" not in json.dumps(first.domains[0].producer_mappings)
    assert set(first.families[0]["resolved_uses"][0]) == {
        "ref",
        "role",
        "requirement_level",
        "conditional",
        "constraints",
        "origins",
    }
    assert tuple(first.groups) == tuple(sorted(first.groups))
    assert tuple(item["id"] for item in first.families) == tuple(sorted(item["id"] for item in first.families))
    with pytest.raises(TypeError):
        first.groups["new"] = first.families[0]  # type: ignore[index]
    with pytest.raises(TypeError):
        first.families[0]["brief"] = "changed"  # type: ignore[index]
    with pytest.raises(TypeError):
        first.attributes["gen_ai.input.messages"].metadata["field_class"] = "metadata"  # type: ignore[index]
    with pytest.raises(TypeError):
        first.example_output_paths["new"] = first_paths  # type: ignore[index]
    with pytest.raises(dataclasses.FrozenInstanceError):
        first_paths.normalized_example_path = "changed"  # type: ignore[misc]
    producer_domain = next(domain for domain in first.domains if domain.producer_mappings)
    with pytest.raises(TypeError):
        producer_domain.producer_mappings[0]["source"] = "changed"  # type: ignore[index]


def test_candidate_renderer_is_deterministic_complete_and_in_memory(
    renderer: ModuleType,
    view: Any,
    artifacts: Mapping[str, Any],
) -> None:
    repeated = renderer.render_candidate_artifacts(view)

    assert tuple(artifacts) == tuple(sorted(artifacts))
    assert {path: artifact.payload for path, artifact in repeated.items()} == {
        path: artifact.payload for path, artifact in artifacts.items()
    }
    assert len(artifacts) == 29
    assert {
        f"{PREFIX}/telemetry.schema.json",
        f"{PREFIX}/catalog.json",
        f"{PREFIX}/catalog.md",
        f"{PREFIX}/examples/manifest.json",
        f"{PREFIX}/otlp-fixtures/manifest.json",
    }.issubset(artifacts)
    assert sum("/examples/valid/" in path for path in artifacts) == 7
    assert sum("/examples/invalid/" in path for path in artifacts) == 5
    assert sum("/otlp-fixtures/cases/" in path for path in artifacts) == 12
    with pytest.raises(TypeError):
        artifacts["new"] = artifacts[next(iter(artifacts))]  # type: ignore[index]
    for path, artifact in artifacts.items():
        assert artifact.path == path
        assert artifact.mode == 0o644
        assert artifact.payload
        assert path.startswith(f"{PREFIX}/")
        assert renderer._normalized_candidate_path(path) == path
        assert not PurePosixPath(path).is_absolute()


@pytest.mark.parametrize(
    "example_id",
    [
        pytest.param("a/b", id="separator"),
        pytest.param("a/../b", id="parent-segment"),
        pytest.param("a..b", id="dot-dot"),
        pytest.param("a:b", id="colon"),
        pytest.param("Uppercase", id="uppercase"),
        pytest.param("case.Alias", id="nonportable-case-alias"),
        pytest.param("a" * 129, id="overlength"),
    ],
)
def test_example_ids_are_portable_path_segments_and_fail_before_payload_rendering(
    renderer: ModuleType,
    view: Any,
    monkeypatch: pytest.MonkeyPatch,
    example_id: str,
) -> None:
    facts = _copy_materialized(view.facts)
    _set_unreferenced_invalid_example_id(facts, example_id)
    retagged = _retagged_view(renderer, view, facts)
    payload_calls: list[object] = []
    renderer_calls: list[object] = []

    def unexpected_payload(document: object) -> bytes:
        payload_calls.append(document)
        return b"unexpected"

    def unexpected_renderer(model: object, marker: object) -> object:
        renderer_calls.append((model, marker))
        return {}

    with pytest.raises(renderer.CandidateRenderError, match="portable output path segment"):
        renderer.build_candidate_render_index(retagged)
    monkeypatch.setattr(renderer, "_json_payload", unexpected_payload)
    monkeypatch.setattr(renderer, "_render_schema", unexpected_renderer)
    with pytest.raises(renderer.CandidateRenderError, match="portable output path segment"):
        renderer.render_candidate_artifacts(retagged)
    assert payload_calls == []
    assert renderer_calls == []


@pytest.mark.parametrize(
    "example_id",
    [
        pytest.param("con", id="console"),
        pytest.param("nul", id="null-device"),
        pytest.param("com1", id="serial"),
        pytest.param("lpt9", id="parallel"),
    ],
)
def test_candidate_index_rejects_platform_reserved_example_ids(
    renderer: ModuleType,
    view: Any,
    example_id: str,
) -> None:
    facts = _copy_materialized(view.facts)
    _set_unreferenced_invalid_example_id(facts, example_id)

    with pytest.raises(renderer.CandidateRenderError, match="platform-reserved syntax"):
        renderer.build_candidate_render_index(_retagged_view(renderer, view, facts))


@pytest.mark.parametrize(
    "path",
    [
        pytest.param(f"{PREFIX}/cases/con.json", id="device-with-extension"),
        pytest.param(f"{PREFIX}/cases/NUL.txt", id="case-insensitive-device"),
        pytest.param(f"{PREFIX}/cases/CLOCK$.json", id="legacy-clock-device"),
        pytest.param(f"{PREFIX}/cases/CONIN$.txt", id="legacy-console-input-device"),
        pytest.param(f"{PREFIX}/cases/CONOUT$.txt", id="legacy-console-output-device"),
        pytest.param(f"{PREFIX}/cases/COM¹.json", id="superscript-serial-one"),
        pytest.param(f"{PREFIX}/cases/com².txt", id="superscript-serial-two"),
        pytest.param(f"{PREFIX}/cases/Com³.bin", id="superscript-serial-three"),
        pytest.param(f"{PREFIX}/cases/LPT¹.json", id="superscript-parallel-one"),
        pytest.param(f"{PREFIX}/cases/lpt².txt", id="superscript-parallel-two"),
        pytest.param(f"{PREFIX}/cases/Lpt³.bin", id="superscript-parallel-three"),
        pytest.param(f"{PREFIX}/cases/a:b.json", id="alternate-data-stream"),
        pytest.param(f"{PREFIX}/cases/trailing.", id="trailing-dot"),
        pytest.param(f"{PREFIX}/cases/trailing ", id="trailing-space"),
    ],
)
def test_candidate_path_and_complete_preflight_reject_platform_reserved_syntax(
    renderer: ModuleType,
    path: str,
) -> None:
    with pytest.raises(renderer.CandidateRenderError, match="platform-reserved syntax"):
        renderer._normalized_candidate_path(path)
    with pytest.raises(renderer.CandidateRenderError, match="platform-reserved syntax"):
        renderer._preflight_candidate_output_paths((*renderer._STATIC_CANDIDATE_OUTPUT_PATHS, path))


@pytest.mark.parametrize(
    "invalid_character",
    [pytest.param(character, id=f"punctuation-{ord(character):02x}") for character in '<>"|?*']
    + [pytest.param(chr(codepoint), id=f"control-{codepoint:02x}") for codepoint in range(1, 32)],
)
def test_candidate_path_preflight_rejects_every_windows_invalid_component_character(
    renderer: ModuleType,
    invalid_character: str,
) -> None:
    path = f"{PREFIX}/cases/before{invalid_character}after.json"

    with pytest.raises(renderer.CandidateRenderError, match="platform-reserved syntax"):
        renderer._normalized_candidate_path(path)
    with pytest.raises(renderer.CandidateRenderError, match="platform-reserved syntax"):
        renderer._preflight_candidate_output_paths((*renderer._STATIC_CANDIDATE_OUTPUT_PATHS, path))


@pytest.mark.parametrize(
    ("collision", "expected"),
    [
        pytest.param("exact", "duplicated", id="exact"),
        pytest.param("casefold", "portable collision", id="casefold"),
        pytest.param("nfc", "portable collision", id="nfc"),
    ],
)
def test_candidate_index_preflights_complete_output_path_set_before_materialization(
    renderer: ModuleType,
    view: Any,
    monkeypatch: pytest.MonkeyPatch,
    collision: str,
    expected: str,
) -> None:
    baseline = renderer.build_candidate_render_index(view)
    example_id = baseline.examples[0]["id"]
    target = baseline.example_output_paths[example_id].normalized_example_path
    if collision == "exact":
        additions = (target,)
    elif collision == "casefold":
        additions = (target.replace(example_id, example_id.upper()),)
    else:
        additions = (
            f"{PREFIX}/examples/valid/\u00e9.json",
            f"{PREFIX}/examples/valid/e\u0301.json",
        )
    monkeypatch.setattr(
        renderer,
        "_STATIC_CANDIDATE_OUTPUT_PATHS",
        (*renderer._STATIC_CANDIDATE_OUTPUT_PATHS, *additions),
    )

    with pytest.raises(renderer.CandidateRenderError, match=expected):
        renderer.build_candidate_render_index(view)


def test_renderer_consumes_materialized_example_output_path_facts(
    renderer: ModuleType,
    view: Any,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    index = renderer.build_candidate_render_index(view)
    example = index.examples[0]
    original_paths = index.example_output_paths[example["id"]]
    replacement_path = f"{PREFIX}/examples/valid/index-owned-render-path.json"
    replacement_paths = dataclasses.replace(
        original_paths,
        normalized_example_path=replacement_path,
    )
    output_paths = dict(index.example_output_paths)
    output_paths[example["id"]] = replacement_paths
    replacement_index = dataclasses.replace(index, example_output_paths=output_paths)
    monkeypatch.setattr(renderer, "build_candidate_render_index", lambda candidate_view: replacement_index)

    artifacts = renderer.render_candidate_artifacts(view)

    assert replacement_path in artifacts
    assert original_paths.normalized_example_path not in artifacts
    manifest = _json(artifacts, "examples/manifest.json")
    entry = next(item for item in manifest["cases"] if item["id"] == example["id"])
    assert entry["path"] == "examples/valid/index-owned-render-path.json"


def test_candidate_artifact_insertion_rejects_exact_and_unicode_casefold_collisions_atomically(
    renderer: ModuleType,
) -> None:
    def artifact(path: str, payload: bytes) -> Any:
        return renderer.CandidateArtifact(path, payload, "application/json", renderer.JSON_OWNERSHIP_MARKER)

    exact_path = f"{PREFIX}/cases/exact.json"
    artifacts: dict[str, Any] = {}
    renderer._add_candidate_artifact(artifacts, artifact(exact_path, b"first"))
    before = dict(artifacts)
    with pytest.raises(renderer.CandidateRenderError, match="duplicated"):
        renderer._add_candidate_artifact(artifacts, artifact(exact_path, b"second"))
    assert artifacts == before

    folded: dict[str, Any] = {}
    renderer._add_candidate_artifact(folded, artifact(f"{PREFIX}/cases/Straße.json", b"first"))
    folded_before = dict(folded)
    with pytest.raises(renderer.CandidateRenderError, match="portable collision"):
        renderer._add_candidate_artifact(folded, artifact(f"{PREFIX}/cases/STRASSE.json", b"second"))
    assert folded == folded_before


def test_full_candidate_preflight_rejects_case_alias_collision(
    renderer: ModuleType,
) -> None:
    lower = f"{PREFIX}/cases/alias.json"
    upper = f"{PREFIX}/cases/ALIAS.json"
    candidates = {
        lower: renderer.CandidateArtifact(lower, b"lower", "application/json", renderer.JSON_OWNERSHIP_MARKER),
        upper: renderer.CandidateArtifact(upper, b"upper", "application/json", renderer.JSON_OWNERSHIP_MARKER),
    }
    with pytest.raises(renderer.CandidateRenderError, match="portable collision"):
        renderer._preflight_candidate_artifacts(candidates)


def test_real_registry_compile_and_candidate_render_smoke(
    artifacts: Mapping[str, Any],
) -> None:
    assert f"{PREFIX}/telemetry.schema.json" in artifacts
    assert f"{PREFIX}/catalog.json" in artifacts


def test_every_artifact_carries_candidate_authority_and_view_digest(
    renderer: ModuleType,
    view: Any,
    artifacts: Mapping[str, Any],
) -> None:
    for path, artifact in artifacts.items():
        if path.endswith(".json"):
            assert 0 <= artifact.payload.find(renderer.JSON_OWNERSHIP_MARKER) < 4096
            document = json.loads(artifact.payload)
            marker = document["x-defenseclaw-generated"]
            assert marker == {
                "artifact": path.removeprefix(f"{PREFIX}/"),
                "authority": renderer.CANDIDATE_AUTHORITY,
                "generator": renderer.GENERATOR_ID,
                "materialized_view_sha256": view.typed_canonical_json_sha256,
                "registry_version": 1,
            }
            assert artifact.ownership_marker == renderer.JSON_OWNERSHIP_MARKER
        else:
            rendered = artifact.payload.decode("utf-8")
            assert rendered.startswith(renderer.MARKDOWN_MARKER_PREFIX)
            assert renderer.CANDIDATE_AUTHORITY in rendered.splitlines()[0]
            assert view.typed_canonical_json_sha256 in rendered.splitlines()[0]


def test_bundle_is_complete_draft_2020_12_and_examples_have_exact_dispositions(
    artifacts: Mapping[str, Any],
) -> None:
    schema = _json(artifacts, "telemetry.schema.json")
    jsonschema.Draft202012Validator.check_schema(schema)
    validator = jsonschema.Draft202012Validator(schema)

    assert schema["$schema"] == "https://json-schema.org/draft/2020-12/schema"
    assert schema["$id"] == "https://defenseclaw.dev/schemas/telemetry/v8/telemetry.schema.json"
    assert len(schema["oneOf"]) == 243
    assert len(schema["$defs"]) == 615
    assert set(schema["x-defenseclaw-conditions"][0]) == {"description", "enforcement", "false_requirement", "id"}
    assert "$type" not in json.dumps(schema["x-defenseclaw-conditions"])
    assert len(schema["x-defenseclaw-conditions"]) == 7
    mandatory_catalog = schema["x-defenseclaw-mandatory-rule-catalog"]
    assert mandatory_catalog["version"] == 1
    assert [rule["id"] for rule in mandatory_catalog["rules"]] == [
        "always",
        "control_plane_mutation",
        "approval_resolution",
        "alert_mutation",
        "protected_boundary_auth_failure",
        "enforced_outcome",
        "enforcement_state_change",
        "schema_validation_failure",
        "sqlite_failure",
        "exporter_initialization_failure",
        "durable_health_transition",
    ]
    assert mandatory_catalog["rules"][0]["enforcement"] == {
        "fact": None,
        "kind": "constant",
        "value": True,
    }
    assert "$type" not in json.dumps(mandatory_catalog)
    assert schema["x-defenseclaw-value-catalogs"][0]["id"] == "agent-phase-v1"
    otlp = schema["x-defenseclaw-canonical-to-otlp"]
    assert otlp["id"] == "defenseclaw-otlp-v1"
    assert otlp["null_value_policy"] == "reject"
    assert otlp["field_context_overrides"] == {
        "trace_resource.schema_url": "ResourceSpans",
        "trace_scope.schema_url": "ResourceSpans.scopeSpans[]",
    }
    assert len(schema["x-defenseclaw-trace-derivations"]) == 6
    conformance = schema["x-defenseclaw-conformance"]
    assert conformance["scope"] == "canonical-schema-comparison-only"
    assert conformance["builder_parity"] == "pending-source-inputs"
    assert conformance["required_materialized_inputs"] == [
        "builder_facts",
        "deterministic_occurrence_inputs",
    ]
    assert {
        "builder_fact_conditions",
        "complete_payload_leaf_field_class_coverage",
        "ordinary_shape_aware_utf8_byte_bounds",
        "ordinary_container_depth_bounds",
        "ordinary_string_leaf_utf8_byte_bounds",
        "portable_re2_full_match_patterns",
        "recursive_aggregate_max_items",
        "recursive_property_count_bounds",
        "typed_json_enum_membership",
        "span_name_pattern_rendering",
        "trace_cross_field_derivation_equality",
        "trace_time_order_relation",
        "typed_numeric_arm_int64_vs_finite_double",
    }.issubset(conformance["non_json_schema_gates"])

    observed = {True: 0, False: 0}
    for path, artifact in artifacts.items():
        if "/examples/valid/" not in path and "/examples/invalid/" not in path:
            continue
        example = json.loads(artifact.payload)
        errors = list(validator.iter_errors(example["record"]))
        observed[example["valid"]] += 1
        if example["valid"]:
            assert errors == [], example["id"]
            assert example["expected_error"] is None
            assert example["mutation"] is None
            assert example["builder_context"]["inheritance"] == {
                "base_example": None,
                "mode": "explicit",
            }
            assert example["builder_context"]["occurrence"] == {
                "record_id": example["record"]["record_id"],
                "timestamp": example["record"]["timestamp"],
            }
        else:
            assert errors, example["id"]
            assert example["expected_error"]
            assert example["base_example"]
            assert example["mutation"]["kind"] == example["expected_error"]
            assert example["mutation"]["changes"]
            assert example["builder_context"] == {
                "condition_facts": [],
                "inheritance": {
                    "base_example": example["base_example"],
                    "mode": "exact_base",
                },
                "mandatory_facts": [],
                "occurrence": None,
            }
    assert observed == {True: 7, False: 5}


def test_canonical_json_is_a_closed_recursive_non_null_union(
    renderer: ModuleType,
    artifacts: Mapping[str, Any],
) -> None:
    schema = _json(artifacts, "telemetry.schema.json")
    canonical = schema["$defs"][renderer.CANONICAL_JSON_DEFINITION]
    validator = _subschema_validator(schema, canonical)

    assert canonical["x-defenseclaw-null-policy"] == "reject"
    assert schema["x-defenseclaw-canonical-to-otlp"]["null_value_policy"] == "reject"
    for value in (False, True, -1, 1.5, "value", [], {}, ["nested", {"value": 1}]):
        assert validator.is_valid(value), value
    for value in (None, [None], {"value": None}, [1, {"nested": [None]}]):
        assert not validator.is_valid(value), value

    contexts = (
        canonical,
        schema["$defs"]["structural:envelope"]["properties"]["body"],
        schema["$defs"]["structural:trace_body"]["properties"]["attributes"],
    )
    for context in contexts:
        context_validator = _subschema_validator(schema, context)
        assert context_validator.is_valid(-(2**63))
        assert context_validator.is_valid(2**63 - 1)
        assert context_validator.is_valid(0.5)
        assert context_validator.is_valid(1e20)
    assert not renderer._runtime_numeric_arm_accepts(-(2**63) - 1, "int64")
    assert not renderer._runtime_numeric_arm_accepts(2**63, "int64")
    assert renderer._runtime_numeric_arm_accepts(1e20, "finite_double")


def test_structured_catalog_is_closed_immutable_and_published(
    renderer: ModuleType,
    view: Any,
    artifacts: Mapping[str, Any],
) -> None:
    index = renderer.build_candidate_render_index(view)
    schema = _json(artifacts, "telemetry.schema.json")
    catalog = _json(artifacts, "catalog.json")

    assert len(index.structured_types) == 21
    assert len(index.structured_bindings) == 4
    assert len(index.structured_property_dispositions) == 109
    assert tuple(index.structured_types) == renderer._STRUCTURED_TYPE_IDS
    assert len(schema["x-defenseclaw-structured-types"]) == 21
    assert len(schema["x-defenseclaw-structured-bindings"]) == 4
    assert len(schema["x-defenseclaw-structured-property-dispositions"]) == 109
    assert catalog["structured_types"] == schema["x-defenseclaw-structured-types"]
    assert catalog["structured_bindings"] == schema["x-defenseclaw-structured-bindings"]
    assert catalog["structured_property_dispositions"] == schema["x-defenseclaw-structured-property-dispositions"]
    assert all(f"structured:{type_id}" in schema["$defs"] for type_id in index.structured_types)
    assert "$type" not in json.dumps(catalog["structured_types"])
    assert "map[string]any" not in json.dumps(catalog["structured_types"])
    with pytest.raises(TypeError):
        index.structured_types["new"] = index.structured_types["gen_ai.text_part"]  # type: ignore[index]
    with pytest.raises(TypeError):
        index.structured_types["gen_ai.text_part"]["kind"] = "array"  # type: ignore[index]


def test_structured_schema_preserves_open_extras_tags_known_values_and_bounds(
    renderer: ModuleType,
    artifacts: Mapping[str, Any],
) -> None:
    schema = _json(artifacts, "telemetry.schema.json")
    definitions = schema["$defs"]
    input_messages = _subschema_validator(schema, definitions["structured:gen_ai.input_messages"])

    valid = [
        {
            "role": "provider.custom-role",
            "parts": [
                {"type": "text", "content": "hello", "provider_extra": {"nested": [1, "two"]}},
                {"type": "provider.custom-part", "opaque": {"ok": True}},
            ],
            "provider_message_extra": "kept",
        }
    ]
    assert input_messages.is_valid(valid)
    assert not input_messages.is_valid([{"role": "user", "parts": [{"type": "text", "content": None}]}])
    assert not input_messages.is_valid(
        [{"role": "user", "parts": [{"type": "text", "content": "x", "type_extra": None}]}]
    )
    assert not input_messages.is_valid([{"role": "user", "parts": [{"type": "text", "opaque": 1}]}])

    chat = definitions["structured:gen_ai.chat_message"]
    chat_validator = _subschema_validator(schema, chat)
    dynamic_256 = {f"extra_{index}": index for index in range(256)}
    assert chat_validator.is_valid({"role": "user", "parts": [], **dynamic_256})
    assert chat_validator.is_valid({"role": "user", "parts": [], "name": "Alice", **dynamic_256})
    assert not chat_validator.is_valid({"role": "user", "parts": [], **dynamic_256, "overflow": 1})
    assert chat["x-defenseclaw-max-dynamic-members"] == 256

    for definition_name, fixed in (
        ("structured:gen_ai.text_part", {"content": "hello"}),
        ("structured:gen_ai.generic_part", {}),
    ):
        validator = _subschema_validator(schema, definitions[definition_name])
        assert validator.is_valid({**fixed, **dynamic_256})
        assert not validator.is_valid({**fixed, **dynamic_256, "overflow": 1})
        assert validator.is_valid({**fixed, "type": "provider.part", **dynamic_256})
        assert not validator.is_valid({**fixed, "type": "provider.part", **dynamic_256, "overflow": 1})

    role = chat["properties"]["role"]
    assert role["x-defenseclaw-known-values"] == ["system", "user", "assistant", "tool"]
    assert role["x-defenseclaw-known-values-enforcement"] == "non-enforcing"
    assert "enum" not in role
    assert chat["properties"]["name"]["x-defenseclaw-sensitivity"] == "sensitive"
    assert chat["properties"]["name"]["x-defenseclaw-max-utf8-bytes"] == 512
    uri = definitions["structured:gen_ai.uri_part"]["properties"]["uri"]
    assert uri["x-defenseclaw-field-class"] == "path"
    assert uri["x-defenseclaw-sensitivity"] == "sensitive"
    assert uri["x-defenseclaw-max-utf8-bytes"] == 8192
    blob_content = definitions["structured:gen_ai.blob_part"]["properties"]["content"]
    assert blob_content["contentEncoding"] == "base64"
    assert blob_content["x-defenseclaw-upstream-format"] == "binary"
    assert blob_content["x-defenseclaw-encoding-annotation"] == "json-base64-bytes-v1"

    union = definitions["structured:gen_ai.message_part"]
    assert union["x-defenseclaw-discriminator"] == {
        "name": "type",
        "owner": "tagged_union",
        "serialized_once": True,
        "field_class": "identifier",
        "sensitivity": "internal",
        "normalization": {
            "effective_constraints": {"max_items": 256, "max_item_utf8_bytes": 4096, "max_utf8_bytes": 256},
            "id": "bounded-v1",
            "notes": None,
            "overrides": {"max_utf8_bytes": 256},
        },
    }
    assert definitions["structured:gen_ai.generic_part"]["x-defenseclaw-reserved-names"] == ["type"]

    canonical = definitions["structured:gen_ai.canonical_json"]
    assert canonical["x-defenseclaw-limits"] == renderer._CANONICAL_JSON_LIMITS
    assert canonical["x-defenseclaw-null-policy"] == "reject"
    assert canonical["oneOf"][4]["maxProperties"] == 256
    assert canonical["oneOf"][4]["x-defenseclaw-duplicate-name-policy"] == "reject"
    assert canonical["oneOf"][4]["x-defenseclaw-post-redaction-name-collision-policy"] == "reject"


def test_metric_number_schema_declares_runtime_typed_int64_and_finite_double_arms(renderer: ModuleType) -> None:
    schema = renderer._schema_type("metric_number")
    validator = jsonschema.Draft202012Validator(schema)

    assert validator.is_valid(-(2**63))
    assert validator.is_valid(2**63 - 1)
    assert validator.is_valid(1.5)
    assert validator.is_valid(1e20)
    assert schema["anyOf"][1]["x-defenseclaw-finite"] is True
    assert schema["x-defenseclaw-numeric-kind-runtime"] == "typed-int64-or-finite-double"
    assert renderer._runtime_numeric_arm_accepts(-(2**63), "int64")
    assert renderer._runtime_numeric_arm_accepts(2**63 - 1, "int64")
    assert not renderer._runtime_numeric_arm_accepts(-(2**63) - 1, "int64")
    assert not renderer._runtime_numeric_arm_accepts(2**63, "int64")
    assert renderer._runtime_numeric_arm_accepts(1e20, "finite_double")
    assert not renderer._runtime_numeric_arm_accepts(float("inf"), "finite_double")
    int64_family = jsonschema.Draft202012Validator(renderer._schema_type("int64"))
    assert int64_family.is_valid(-(2**63))
    assert int64_family.is_valid(2**63 - 1)
    assert not int64_family.is_valid(-(2**63) - 1)
    assert not int64_family.is_valid(2**63)
    with pytest.raises(ValueError, match="Out of range float values"):
        renderer._json_payload({"value": float("inf")})


def test_array_value_constraints_apply_to_each_element(renderer: ModuleType) -> None:
    strings = renderer._apply_constraints(
        renderer._schema_type("string[]"),
        {"enum": ["abc123"], "pattern": "abc[0-9]+"},
    )
    string_validator = jsonschema.Draft202012Validator(strings)

    assert strings["items"]["enum"] == ["abc123"]
    assert strings["items"]["pattern"] == r"^(?:abc[0-9]+)$(?![\s\S])"
    assert strings["items"]["x-defenseclaw-pattern-source"] == "abc[0-9]+"
    assert strings["items"]["x-defenseclaw-pattern-semantics"] == "portable-re2-full-match"
    assert string_validator.is_valid(["abc123"])
    assert not string_validator.is_valid(["prefix-abc123"])
    assert not string_validator.is_valid(["abc123-suffix"])
    assert not string_validator.is_valid(["abc123\n"])
    assert not string_validator.is_valid(["other"])

    numbers = renderer._apply_constraints(renderer._schema_type("int64[]"), {"min": 2, "max": 3})
    number_validator = jsonschema.Draft202012Validator(numbers)
    assert numbers["items"]["minimum"] == 2
    assert numbers["items"]["maximum"] == 3
    assert number_validator.is_valid([2, 3])
    assert not number_validator.is_valid([1, 2])
    assert not number_validator.is_valid([3, 4])


def test_full_match_constraints_cover_scalar_and_array_union_variants(renderer: ModuleType) -> None:
    schema = renderer._apply_constraints(
        {"oneOf": [renderer._schema_type("string"), renderer._schema_type("string[]")]},
        {"enum": ["abc123"], "pattern": "abc123"},
    )
    validator = jsonschema.Draft202012Validator(schema)

    assert validator.is_valid("abc123")
    assert validator.is_valid(["abc123"])
    assert not validator.is_valid("prefix-abc123")
    assert not validator.is_valid(["abc123-suffix"])
    assert not validator.is_valid("abc123\n")
    assert schema["oneOf"][0]["pattern"] == r"^(?:abc123)$(?![\s\S])"
    assert schema["oneOf"][1]["items"]["pattern"] == r"^(?:abc123)$(?![\s\S])"


@pytest.mark.parametrize(
    ("pattern", "accepted"),
    [
        (r"^[0-9a-f]{32}$", True),
        (r"\x61{0,1000}", True),
        (r"a++", False),
        (r"\d+", False),
        (r"\u0061", False),
        (r"\_", False),
        (r"a{,3}", False),
        (r"a{1001}", False),
    ],
)
def test_compiler_and_candidate_portable_pattern_policy_is_identical(
    renderer: ModuleType,
    generator: ModuleType,
    pattern: str,
    accepted: bool,
) -> None:
    if accepted:
        assert generator._validate_portable_pattern(pattern, "test.pattern") == pattern
        renderer._validate_portable_constraint_pattern(pattern, "test.pattern")
    else:
        with pytest.raises(generator.RegistryError):
            generator._validate_portable_pattern(pattern, "test.pattern")
        with pytest.raises(renderer.CandidateRenderError):
            renderer._validate_portable_constraint_pattern(pattern, "test.pattern")


def test_current_registry_patterns_pass_both_portable_validators(
    renderer: ModuleType,
    generator: ModuleType,
    view: Any,
) -> None:
    patterns: set[str] = set()

    def collect(value: Any) -> None:
        if isinstance(value, Mapping):
            if value.get("$type") == "NormalizationIR":
                fields = value["fields"]
                for key in ("overrides", "effective_constraints"):
                    pattern = fields[key].get("pattern")
                    if isinstance(pattern, str):
                        patterns.add(pattern)
            for item in value.values():
                collect(item)
        elif isinstance(value, tuple):
            for item in value:
                collect(item)

    collect(view.facts)
    assert patterns
    for pattern in patterns:
        assert generator._validate_portable_pattern(pattern, "registry.pattern") == pattern
        renderer._validate_portable_constraint_pattern(pattern, "registry.pattern")


def test_numeric_enum_declares_typed_runtime_membership_gate(
    renderer: ModuleType,
    generator: ModuleType,
) -> None:
    schema = renderer._apply_constraints(renderer._schema_type("double"), {"enum": [1]})

    assert jsonschema.Draft202012Validator(schema).is_valid(1.0)
    assert generator._constraints_accept(1.0, {"enum": (1,)}) is False
    assert schema["x-defenseclaw-enum-membership-semantics"] == "typed-json-scalar"
    assert schema["x-defenseclaw-enum-enforcement"] == "builder-runtime-typed-json-enum-gate"


def test_attribute_base_and_per_use_constraints_form_a_restrictive_conjunction(
    renderer: ModuleType,
) -> None:
    def attribute(field_type: str, effective: dict[str, Any]) -> Any:
        normalization_id = (
            "numeric-range-v1"
            if field_type in {"int64", "double"}
            else "structured-content-v1"
            if field_type == "object"
            else "bounded-v1"
        )
        return renderer.CandidateAttribute(
            "test.attribute",
            (field_type,),
            None,
            {
                "field_class": "metadata",
                "sensitivity": "internal",
                "owner": "defenseclaw",
                "normalization": {
                    "id": normalization_id,
                    "effective_constraints": effective,
                },
            },
        )

    strings = renderer._attribute_schema(
        attribute(
            "string[]",
            {
                "enum": ["abc123", "abc456"],
                "pattern": "abc[0-9]+",
                "max_items": 10,
                "max_utf8_bytes": 100,
                "max_item_utf8_bytes": 20,
            },
        ),
        {
            "enum": ["abc123"],
            "pattern": "abc[0-9]+",
            "max_items": 3,
            "max_utf8_bytes": 40,
            "max_item_utf8_bytes": 10,
        },
    )
    item = strings["items"]
    assert item["enum"] == ["abc123"]
    assert item["pattern"] == r"^(?:abc[0-9]+)$(?![\s\S])"
    assert "allOf" not in item
    assert strings["maxItems"] == 3
    assert strings["x-defenseclaw-max-items"] == 3
    assert strings["x-defenseclaw-max-utf8-bytes"] == 40
    assert strings["x-defenseclaw-max-item-utf8-bytes"] == 10
    validator = jsonschema.Draft202012Validator(strings)
    assert validator.is_valid(["abc123"])
    assert not validator.is_valid(["abc456"])

    number = renderer._attribute_schema(
        attribute("int64", {"min": 0, "max": 10}),
        {"min": 2, "max": 8},
    )
    assert number["minimum"] == 2
    assert number["maximum"] == 8

    structured = renderer._attribute_schema(
        attribute(
            "object",
            {"max_items": 10, "max_depth": 5, "max_properties": 20},
        ),
        {"max_items": 4, "max_depth": 2, "max_properties": 3},
    )
    assert structured["x-defenseclaw-max-items"] == 4
    assert structured["x-defenseclaw-max-depth"] == 2
    assert structured["x-defenseclaw-max-properties"] == 3
    assert structured["maxProperties"] == 3


def test_candidate_rejects_distinct_pattern_intersection(renderer: ModuleType) -> None:
    base = renderer._apply_constraints(renderer._schema_type("string"), {"pattern": "abc[0-9]+"})

    with pytest.raises(renderer.CandidateRenderError, match="pattern constraint intersection"):
        renderer._apply_constraints(base, {"pattern": "abc123"})


@pytest.mark.parametrize(
    ("field_type", "constraints"),
    [
        ("string", {"max_itmes": 1}),
        ("string", {"max_items": "one"}),
        ("string", {"min": 2, "max": 1}),
        ("int64", {"pattern": "[0-9]+"}),
        ("string", {"min": 1}),
        ("string[]", {"max_depth": 1}),
    ],
)
def test_apply_constraints_defensively_rejects_invalid_maps(
    renderer: ModuleType,
    field_type: str,
    constraints: dict[str, Any],
) -> None:
    with pytest.raises(renderer.CandidateRenderError):
        renderer._apply_constraints(renderer._schema_type(field_type), constraints)


def test_polymorphic_canonical_json_rejects_min_items_above_scalar_cardinality(
    renderer: ModuleType,
) -> None:
    with pytest.raises(renderer.CandidateRenderError, match="polymorphic JSON"):
        renderer._apply_constraints(
            {"$ref": f"#/$defs/{renderer.CANONICAL_JSON_DEFINITION}"},
            {"min_items": 2},
        )


def test_recursive_item_and_utf8_bounds_declare_required_runtime_gates(
    renderer: ModuleType,
    generator: ModuleType,
) -> None:
    nested_value = [{"items": [1, 2, 3]}]
    nested_schema = renderer._apply_constraints(
        {
            "type": "array",
            "items": {
                "type": "object",
                "additionalProperties": {"type": "array", "items": {"type": "integer"}},
            },
        },
        {"max_items": 3},
    )

    # JSON Schema can enforce the safe root-array subset, but the compiler's
    # recursive aggregate counts the root element, object member, and nested elements.
    assert jsonschema.Draft202012Validator(nested_schema).is_valid(nested_value)
    assert generator._constraints_accept(nested_value, {"max_items": 3}) is False
    assert nested_schema["maxItems"] == 3
    assert nested_schema["x-defenseclaw-max-items-semantics"] == "recursive-aggregate-members"
    assert nested_schema["x-defenseclaw-max-items-enforcement"] == ("builder-runtime-recursive-aggregate-gate")
    assert nested_schema["x-defenseclaw-json-schema-item-bound-scope"] == ("root-collection-safe-subset")

    total_bytes = renderer._apply_constraints(renderer._schema_type("string"), {"max_utf8_bytes": 3})
    leaf_bytes = renderer._apply_constraints(renderer._schema_type("string[]"), {"max_item_utf8_bytes": 3})
    assert jsonschema.Draft202012Validator(total_bytes).is_valid("éé")
    assert jsonschema.Draft202012Validator(leaf_bytes).is_valid(["éé"])
    assert generator._constraints_accept("éé", {"max_utf8_bytes": 3}) is False
    assert generator._constraints_accept(["éé"], {"max_item_utf8_bytes": 3}) is False
    assert total_bytes["x-defenseclaw-max-utf8-bytes-semantics"] == "raw-scalar-string-utf8"
    assert total_bytes["x-defenseclaw-max-utf8-bytes-enforcement"] == ("builder-runtime-shape-aware-utf8-byte-gate")
    aggregate_bytes = renderer._apply_constraints(renderer._schema_type("string[]"), {"max_utf8_bytes": 10})
    assert aggregate_bytes["x-defenseclaw-max-utf8-bytes-semantics"] == "canonical-json-utf8"
    assert leaf_bytes["x-defenseclaw-max-item-utf8-bytes-enforcement"] == ("builder-runtime-string-leaf-utf8-byte-gate")

    nested_object = {"outer": {"inner": {"leaf": 1}}}
    object_schema = renderer._apply_constraints(
        {"type": "object", "additionalProperties": True},
        {"max_depth": 1, "max_properties": 1},
    )
    assert jsonschema.Draft202012Validator(object_schema).is_valid(nested_object)
    assert generator._constraints_accept(nested_object, {"max_depth": 1}) is False
    assert generator._constraints_accept(nested_object, {"max_properties": 1}) is False
    assert object_schema["maxProperties"] == 1
    assert object_schema["x-defenseclaw-max-depth-enforcement"] == ("builder-runtime-container-depth-gate")
    assert object_schema["x-defenseclaw-max-properties-enforcement"] == (
        "builder-runtime-recursive-property-count-gate"
    )


@pytest.mark.parametrize(
    "mutation",
    [
        "normalization-unknown",
        "normalization-wrong-type",
        "normalization-scalar-min-items",
        "normalization-bogus-id",
        "normalization-forged-effective",
        "normalizer-catalog-forged",
        "local-attribute-timestamp",
        "direct-use-unknown",
        "direct-origin-mismatch",
        "direct-role-mismatch",
        "attribute-refs-mismatch",
        "resolution-order-mismatch",
        "resolved-use-unknown",
        "origin-wrong-type",
        "origin-resolved-mismatch",
        "typed-enum-origin-mismatch",
        "resolved-numeric-pattern",
        "resolved-string-min",
        "resolved-use-weakening",
        "requirement-origin-mismatch",
        "unknown-condition",
        "empty-condition",
        "resolved-use-nonportable-pattern",
    ],
)
def test_candidate_rejects_digest_consistent_constraint_contract_mutations(
    renderer: ModuleType,
    view: Any,
    mutation: str,
) -> None:
    facts = _copy_materialized(view.facts)
    domains = facts["fields"]["domains"]

    if mutation == "normalizer-catalog-forged":
        facts["fields"]["normalizers"][0]["fields"]["kind"] = "forged"
    elif mutation == "local-attribute-timestamp":
        attribute = next(item for domain in domains for item in domain["fields"]["attributes"])
        attribute["fields"]["field_type"] = "timestamp"
    elif mutation == "resolution-order-mismatch":
        facts["fields"]["group_resolution_order"] = tuple(reversed(facts["fields"]["group_resolution_order"]))
    elif mutation.startswith("normalization-"):
        attribute = next(
            item
            for domain in domains
            for item in domain["fields"]["attributes"]
            if mutation != "normalization-scalar-min-items"
            or (
                item["fields"]["field_type"] == "string"
                and item["fields"]["normalization"]["fields"]["id"] == "bounded-v1"
            )
        )
        normalization = attribute["fields"]["normalization"]["fields"]
        if mutation == "normalization-unknown":
            normalization["effective_constraints"]["max_itmes"] = 1
        elif mutation == "normalization-wrong-type":
            normalization["overrides"]["max_items"] = "one"
        elif mutation == "normalization-scalar-min-items":
            normalization["overrides"]["min_items"] = 2
            normalization["effective_constraints"]["min_items"] = 2
        elif mutation == "normalization-bogus-id":
            normalization["id"] = "bogus-v1"
        else:
            normalization["effective_constraints"]["max_utf8_bytes"] = 1
    elif mutation in {
        "direct-use-unknown",
        "direct-origin-mismatch",
        "direct-role-mismatch",
        "attribute-refs-mismatch",
    }:
        group = next(
            item
            for domain in domains
            for item in domain["fields"]["groups"]
            if (
                item["fields"]["id"] == "scope.core"
                if mutation in {"direct-origin-mismatch", "direct-role-mismatch", "attribute-refs-mismatch"}
                else bool(item["fields"]["attribute_uses"])
            )
        )
        if mutation == "direct-role-mismatch":
            group["fields"]["attribute_uses"][0]["fields"]["role"] = "body_fields"
        elif mutation == "attribute-refs-mismatch":
            group["fields"]["attribute_refs"] = group["fields"]["attribute_refs"][1:]
        else:
            group["fields"]["attribute_uses"][0]["fields"]["constraints"] = (
                {"max_utf8_bytes": 1} if mutation == "direct-origin-mismatch" else {"max_itmes": 1}
            )
    else:
        resolved_by_group = facts["fields"]["resolved_group_uses"]
        target_ref = {
            "resolved-numeric-pattern": "defenseclaw.guardrail.confidence",
            "resolved-string-min": "gen_ai.operation.name",
            "resolved-use-weakening": "gen_ai.operation.name",
        }.get(mutation)
        if target_ref is None:
            group_id = next(iter(resolved_by_group))
            resolved_use = resolved_by_group[group_id][0]
        else:
            group_id, resolved_use = next(
                (candidate_group, use)
                for candidate_group, uses in resolved_by_group.items()
                for use in uses
                if use["fields"]["ref"] == target_ref
            )
        group = next(
            item for domain in domains for item in domain["fields"]["groups"] if item["fields"]["id"] == group_id
        )
        group_use = next(
            use for use in group["fields"]["resolved_uses"] if use["fields"]["ref"] == resolved_use["fields"]["ref"]
        )
        duplicate_uses = (resolved_use, group_use)
        if mutation == "resolved-use-unknown":
            for use in duplicate_uses:
                use["fields"]["constraints"] = {"max_itmes": 1}
                use["fields"]["origins"][0]["fields"]["constraints"] = {"max_itmes": 1}
        elif mutation == "origin-wrong-type":
            for use in duplicate_uses:
                use["fields"]["constraints"] = {"max_items": 1}
                use["fields"]["origins"][0]["fields"]["constraints"] = {"max_items": "one"}
        elif mutation == "origin-resolved-mismatch":
            for use in duplicate_uses:
                use["fields"]["constraints"] = {"max_items": 2}
                use["fields"]["origins"][0]["fields"]["constraints"] = {"max_items": 1}
        elif mutation == "typed-enum-origin-mismatch":
            for use in duplicate_uses:
                use["fields"]["constraints"] = {"enum": (1,)}
                use["fields"]["origins"][0]["fields"]["constraints"] = {"enum": (True,)}
        elif mutation in {"resolved-numeric-pattern", "resolved-string-min", "resolved-use-weakening"}:
            constraints = (
                {"pattern": "[0-9]+"}
                if mutation == "resolved-numeric-pattern"
                else {"min": 1}
                if mutation == "resolved-string-min"
                else {"max_utf8_bytes": 1048576}
            )
            for use in duplicate_uses:
                use["fields"]["constraints"] = constraints
                for origin in use["fields"]["origins"]:
                    origin["fields"]["constraints"] = constraints
                    source_group = next(
                        item
                        for domain in domains
                        for item in domain["fields"]["groups"]
                        if item["fields"]["id"] == origin["fields"]["group_id"]
                    )
                    source_use = next(
                        item
                        for item in source_group["fields"]["attribute_uses"]
                        if item["fields"]["ref"] == resolved_use["fields"]["ref"]
                    )
                    source_use["fields"]["constraints"] = constraints
        elif mutation == "requirement-origin-mismatch":
            replacement = "optional" if resolved_use["fields"]["requirement_level"] == "required" else "required"
            for use in duplicate_uses:
                use["fields"]["requirement_level"] = replacement
                use["fields"]["conditional"] = None
        elif mutation in {"unknown-condition", "empty-condition"}:
            condition = "unknown.condition" if mutation == "unknown-condition" else ""
            for use in duplicate_uses:
                use["fields"]["requirement_level"] = "conditional"
                use["fields"]["conditional"] = condition
                for origin in use["fields"]["origins"]:
                    origin["fields"]["requirement_level"] = "conditional"
                    origin["fields"]["conditional"] = condition
        else:
            for use in duplicate_uses:
                use["fields"]["constraints"] = {"pattern": "a++"}
                use["fields"]["origins"][0]["fields"]["constraints"] = {"pattern": "a++"}

    with pytest.raises(renderer.CandidateRenderError):
        renderer.build_candidate_render_index(_retagged_view(renderer, view, facts))


@pytest.mark.parametrize(
    "mutation",
    [
        "nested-extra",
        "dangling-ref",
        "known-but-wrong-ref",
        "side-arm",
        "reserved-names",
        "canonical-limit",
        "binding-target",
        "missing-disposition",
        "known-values",
        "nullable-omission",
        "union-disposition-target",
        "content-sensitivity",
        "content-normalization",
        "discriminator-name",
        "discriminator-privacy",
        "dynamic-name-privacy",
        "dynamic-name-normalization",
        "canonical-encoding",
        "introduced-in",
        "encoding-annotation",
    ],
)
def test_candidate_rejects_digest_consistent_malformed_nested_structured_facts(
    renderer: ModuleType,
    view: Any,
    mutation: str,
) -> None:
    facts = _copy_materialized(view.facts)
    types = facts["fields"]["structured_types"]
    by_id = {item["fields"]["id"]: item for item in types}
    if mutation == "nested-extra":
        by_id["gen_ai.text_part"]["fields"]["fields"][0]["fields"]["scalar"]["fields"]["extra"] = True
    elif mutation == "dangling-ref":
        by_id["gen_ai.input_messages"]["fields"]["items_reference"]["fields"]["structured_ref"] = "gen_ai.missing"
    elif mutation == "known-but-wrong-ref":
        by_id["gen_ai.input_messages"]["fields"]["items_reference"]["fields"]["structured_ref"] = (
            "gen_ai.output_message"
        )
    elif mutation == "side-arm":
        by_id["gen_ai.input_messages"]["fields"]["fields"] = ()
    elif mutation == "reserved-names":
        by_id["gen_ai.generic_part"]["fields"]["effective_reserved_names"] = ()
    elif mutation == "canonical-limit":
        by_id["gen_ai.canonical_json"]["fields"]["canonical_json"]["fields"]["limits"]["fields"]["max_depth"] = 9
    elif mutation == "binding-target":
        binding = next(
            item
            for item in facts["fields"]["structured_bindings"]
            if item["fields"]["attribute"] == "gen_ai.output.messages"
        )
        binding["fields"]["structured_type"] = "gen_ai.input_messages"
    elif mutation == "missing-disposition":
        facts["fields"]["structured_property_dispositions"] = facts["fields"]["structured_property_dispositions"][:-1]
    elif mutation == "known-values":
        role = next(
            item for item in by_id["gen_ai.chat_message"]["fields"]["fields"] if item["fields"]["name"] == "role"
        )
        role["fields"]["scalar"]["fields"]["known_values"] = ("system", "user")
    elif mutation == "nullable-omission":
        name = next(
            item for item in by_id["gen_ai.chat_message"]["fields"]["fields"] if item["fields"]["name"] == "name"
        )
        name["fields"]["nullable_omission"] = False
    elif mutation == "union-disposition-target":
        disposition = next(
            item
            for item in facts["fields"]["structured_property_dispositions"]
            if item["fields"]["structured_type"] == "gen_ai.message_part" and item["fields"]["arm_id"] == "text"
        )
        disposition["fields"]["target_structured_type"] = "gen_ai.output_message"
    elif mutation == "content-sensitivity":
        by_id["gen_ai.text_part"]["fields"]["fields"][0]["fields"]["scalar"]["fields"]["sensitivity"] = "safe"
    elif mutation == "content-normalization":
        by_id["gen_ai.text_part"]["fields"]["fields"][0]["fields"]["scalar"]["fields"]["normalization"]["fields"][
            "id"
        ] = "identity-v1"
    elif mutation == "discriminator-name":
        by_id["gen_ai.message_part"]["fields"]["discriminator"]["fields"]["name"] = "kind"
    elif mutation == "discriminator-privacy":
        by_id["gen_ai.message_part"]["fields"]["discriminator"]["fields"]["sensitivity"] = "safe"
    elif mutation == "dynamic-name-privacy":
        by_id["gen_ai.tool_call_arguments"]["fields"]["dynamic_members"]["fields"]["name"]["fields"]["sensitivity"] = (
            "safe"
        )
    elif mutation == "dynamic-name-normalization":
        by_id["gen_ai.tool_call_arguments"]["fields"]["dynamic_members"]["fields"]["name"]["fields"]["normalization"][
            "fields"
        ]["id"] = "identifier-v1"
    elif mutation == "canonical-encoding":
        canonical = by_id["gen_ai.canonical_json"]["fields"]["canonical_json"]["fields"]
        canonical["public_encoding"] = "native_object"
        canonical["wire_encoding"] = "ordered_entries"
    elif mutation == "encoding-annotation":
        blob_content = next(
            item for item in by_id["gen_ai.blob_part"]["fields"]["fields"] if item["fields"]["name"] == "content"
        )
        blob_content["fields"]["scalar"]["fields"]["encoding_annotation"] = None
    else:
        by_id["gen_ai.text_part"]["fields"]["introduced_in"] = "telemetry-registry-v2"

    with pytest.raises(renderer.CandidateRenderError):
        renderer.build_candidate_render_index(_retagged_view(renderer, view, facts))


@pytest.mark.parametrize(
    "mutation",
    [
        "envelope-open",
        "field-privacy",
        "field-type",
        "field-required",
        "signal-arm-target",
        "relation",
        "derivation",
        "otlp-mapping",
    ],
)
def test_candidate_rejects_digest_consistent_structural_contract_retargeting(
    renderer: ModuleType,
    view: Any,
    mutation: str,
) -> None:
    facts = _copy_materialized(view.facts)
    contract = facts["fields"]["structural_contract"]["fields"]
    envelope = contract["envelope"]["fields"]
    first_field = envelope["fields"][0]["fields"]
    if mutation == "envelope-open":
        envelope["additional_properties"] = True
    elif mutation == "field-privacy":
        first_field["sensitivity"] = "critical"
    elif mutation == "field-type":
        first_field["field_type"] = "string"
    elif mutation == "field-required":
        first_field["required"] = False
    elif mutation == "signal-arm-target":
        contract["signal_arms"][0]["fields"]["payload_field"] = "instrument_data"
    elif mutation == "relation":
        contract["trace_relations"][0]["fields"]["right"] = "start_time_unix_nano"
    elif mutation == "derivation":
        contract["trace_derivations"][0]["fields"]["target_attribute"] = "defenseclaw.source"
    else:
        contract["canonical_to_otlp"]["fields"]["json_mapping"] = "retargeted-json-mapping"

    with pytest.raises(renderer.CandidateRenderError, match="structural contract is not canonical"):
        renderer.build_candidate_render_index(_retagged_view(renderer, view, facts))


def test_candidate_semantic_digests_ignore_only_tagged_normalization_notes(
    renderer: ModuleType,
    view: Any,
) -> None:
    facts = _copy_materialized(view.facts)
    structured = {item["fields"]["id"]: item for item in facts["fields"]["structured_types"]}
    structured_note = structured["gen_ai.text_part"]["fields"]["fields"][0]["fields"]["scalar"]["fields"][
        "normalization"
    ]["fields"]
    structural_note = facts["fields"]["structural_contract"]["fields"]["envelope"]["fields"]["fields"][0]["fields"][
        "normalization"
    ]["fields"]
    structured_note["notes"] = "Structured reviewer prose."
    structural_note["notes"] = "P-069 reviewer prose."

    index = renderer.build_candidate_render_index(_retagged_view(renderer, view, facts))

    assert index.structured_types["gen_ai.text_part"]["fields"][0]["scalar"]["normalization"]["notes"] == (
        "Structured reviewer prose."
    )
    assert (
        index.fields["structural_contract"]["fields"]["envelope"]["fields"]["fields"][0]["fields"]["normalization"][
            "fields"
        ]["notes"]
        == "P-069 reviewer prose."
    )


@pytest.mark.parametrize("surface", ["structured", "structural"])
@pytest.mark.parametrize("invalid_notes", [{"not": "prose"}, "x" * 4097])
def test_candidate_rejects_invalid_normalization_notes_even_when_semantically_ignored(
    renderer: ModuleType,
    view: Any,
    surface: str,
    invalid_notes: Any,
) -> None:
    facts = _copy_materialized(view.facts)
    if surface == "structured":
        structured = {item["fields"]["id"]: item for item in facts["fields"]["structured_types"]}
        notes = structured["gen_ai.text_part"]["fields"]["fields"][0]["fields"]["scalar"]["fields"]["normalization"][
            "fields"
        ]
    else:
        notes = facts["fields"]["structural_contract"]["fields"]["envelope"]["fields"]["fields"][0]["fields"][
            "normalization"
        ]["fields"]
    notes["notes"] = invalid_notes

    with pytest.raises(renderer.CandidateRenderError, match="normalization notes are invalid"):
        renderer.build_candidate_render_index(_retagged_view(renderer, view, facts))


@pytest.mark.parametrize(
    ("definition_name", "property_name", "expected_ref"),
    [
        pytest.param("structural:envelope", "body", "value:canonical_json", id="envelope-body"),
        pytest.param("structural:trace_body", "attributes", "value:canonical_json", id="trace-attributes"),
        pytest.param("structural:trace_resource", "attributes", "value:canonical_json", id="resource-attributes"),
        pytest.param("structural:trace_scope", "attributes", "value:canonical_json", id="scope-attributes"),
        pytest.param("structural:trace_event", "attributes", "value:canonical_json", id="event-attributes"),
        pytest.param("structural:trace_link", "attributes", "value:canonical_json", id="link-attributes"),
        pytest.param(
            "structural:metric_instrument_data",
            "attributes",
            "value:canonical_json",
            id="metric-attributes",
        ),
        pytest.param(
            "attribute:gen_ai.input.messages",
            None,
            "structured:gen_ai.input_messages",
            id="genai-input-messages",
        ),
        pytest.param(
            "attribute:gen_ai.output.messages",
            None,
            "structured:gen_ai.output_messages",
            id="genai-output-messages",
        ),
        pytest.param(
            "attribute:gen_ai.tool.call.arguments",
            None,
            "structured:gen_ai.tool_call_arguments",
            id="genai-tool-arguments",
        ),
        pytest.param(
            "attribute:gen_ai.tool.call.result",
            None,
            "structured:gen_ai.tool_call_result",
            id="genai-tool-result",
        ),
    ],
)
def test_every_canonical_json_context_rejects_direct_null(
    renderer: ModuleType,
    artifacts: Mapping[str, Any],
    definition_name: str,
    property_name: str | None,
    expected_ref: str,
) -> None:
    schema = _json(artifacts, "telemetry.schema.json")
    definition = schema["$defs"][definition_name]
    subject = definition if property_name is None else definition["properties"][property_name]

    assert subject["$ref"] == f"#/$defs/{expected_ref}"
    assert not _subschema_validator(schema, subject).is_valid(None)


@pytest.mark.parametrize("family_id", ["span.ai.discovery", "span.ai.discovery.detector"])
def test_eventless_ai_discovery_spans_require_events_to_be_absent(
    artifacts: Mapping[str, Any],
    family_id: str,
) -> None:
    schema = _json(artifacts, "telemetry.schema.json")
    record = _span_record_for_family(artifacts, schema, family_id)
    validator = _subschema_validator(schema, schema["$defs"][f"family:{family_id}"])

    assert "events" not in record["body"]
    assert validator.is_valid(record)


@pytest.mark.parametrize(
    ("family_id", "events"),
    [
        pytest.param("span.ai.discovery", [], id="discovery-empty"),
        pytest.param(
            "span.ai.discovery",
            [{"name": "arbitrary", "time_unix_nano": 1, "attributes": {}}],
            id="discovery-arbitrary",
        ),
        pytest.param("span.ai.discovery.detector", [], id="detector-empty"),
        pytest.param(
            "span.ai.discovery.detector",
            [{"name": "arbitrary", "time_unix_nano": 1, "attributes": {}}],
            id="detector-arbitrary",
        ),
    ],
)
def test_eventless_ai_discovery_spans_reject_empty_and_arbitrary_events(
    artifacts: Mapping[str, Any],
    family_id: str,
    events: list[dict[str, Any]],
) -> None:
    schema = _json(artifacts, "telemetry.schema.json")
    record = _span_record_for_family(artifacts, schema, family_id)
    record["body"]["events"] = events
    validator = _subschema_validator(schema, schema["$defs"][f"family:{family_id}"])

    assert not validator.is_valid(record)


def test_catalog_contains_portable_family_privacy_condition_lifecycle_and_compatibility_metadata(
    artifacts: Mapping[str, Any],
) -> None:
    catalog = _json(artifacts, "catalog.json")
    assert catalog["format"] == "defenseclaw-telemetry-catalog-v1"
    assert len(catalog["families"]) == 243
    assert len(catalog["attributes"]) == 325
    assert {item["signal"] for item in catalog["families"]} == {"logs", "traces", "metrics"}
    assert {item["id"] for item in catalog["compatibility_manifests"]} == {
        "galileo-rich-v2",
        "local-observability-v1",
        "openinference-v1",
    }

    families = {item["id"]: item for item in catalog["families"]}
    model = families["span.model.chat"]
    assert model["signal"] == "traces"
    assert model["bucket"] == "model.io"
    assert model["span"]["name_pattern"] == "chat {gen_ai.request.model}"
    assert model["outcome"]["requirement"] == "required"
    assert model["lifecycle"] == {
        "introduced_in": "telemetry-registry-v1",
        "deprecated_in": None,
        "removed_in": None,
    }
    assert {item["id"] for item in model["compatibility_profiles"]} == {
        "galileo-rich-v2",
        "local-observability-v1",
        "openinference-v1",
    }
    fields = {item["ref"]: item for item in model["fields"]}
    assert fields["gen_ai.input.messages"]["field_class"] == "content"
    assert fields["gen_ai.input.messages"]["sensitivity"] == "sensitive"
    assert fields["defenseclaw.connector.source"]["condition"] == "connector-known-v1"

    finding = families["log.finding.observed"]
    finding_fields = {item["ref"]: item for item in finding["fields"]}
    assert finding_fields["defenseclaw.guardrail.evidence_summary"]["field_class"] == "evidence"
    assert finding_fields["defenseclaw.finding.remediation"]["field_class"] == "reason"

    metric = families["metric.defenseclaw.connector.hook.latency"]
    assert metric["metric"] == {
        "instrument_name": "defenseclaw.connector.hook.latency",
        "instrument_type": "histogram",
        "value_type": "double",
        "unit": "ms",
        "temporality": "delta",
        "boundaries": [1, 2, 5, 10, 25, 50, 100, 250, 500, 1000, 2500, 5000, 10000],
        "cardinality_limit": 2048,
    }

    portable_text = json.dumps(catalog, sort_keys=True)
    for forbidden in ("dashboard_uid", "datasource_uid", "loki_query", "tempo_query", "normalized_prometheus"):
        assert forbidden not in portable_text
    assert all(
        item["availability"] == "pending" and item["path"] is None for item in catalog["compatibility_manifests"]
    )
    assert all(
        item["availability"] == "pending" and item["manifest"] is None
        for family in catalog["families"]
        for item in family["compatibility_profiles"]
    )


def test_normalized_example_and_otlp_manifests_cover_the_same_cases(
    view: Any,
    artifacts: Mapping[str, Any],
) -> None:
    examples = _json(artifacts, "examples/manifest.json")
    fixtures = _json(artifacts, "otlp-fixtures/manifest.json")
    assert examples["format"] == "defenseclaw-normalized-examples-v1"
    assert fixtures["format"] == "defenseclaw-otlp-fixture-manifest-v1"
    assert examples["materialized_view_sha256"] == view.typed_canonical_json_sha256
    assert fixtures["materialized_view_sha256"] == view.typed_canonical_json_sha256
    assert examples["conformance"]["scope"] == "canonical-schema-comparison-only"
    assert fixtures["conformance"]["builder_parity"] == "pending-source-inputs"
    assert [item["id"] for item in examples["cases"]] == [item["id"] for item in fixtures["cases"]]
    assert len(examples["cases"]) == 12
    assert fixtures["canonical_to_otlp"]["json_mapping"] == "opentelemetry_proto_json_v1"
    assert "$type" not in json.dumps(fixtures["canonical_to_otlp"])

    for entry in examples["cases"]:
        expected_parent = PurePosixPath("examples/valid" if entry["valid"] else "examples/invalid")
        assert PurePosixPath(entry["path"]).parent == expected_parent
        normalized = _json(artifacts, entry["path"])
        fixture = _json(artifacts, f"otlp-fixtures/cases/{entry['id']}.json")
        assert normalized["record"] == fixture["canonical_record"]
        assert normalized["valid"] == fixture["expect"]["accepted"]
        if not normalized["valid"]:
            assert fixture["expect"]["error_code"] == normalized["expected_error"]
    for entry in fixtures["cases"]:
        assert PurePosixPath(entry["path"]).parent == PurePosixPath("otlp-fixtures/cases")


def test_otlp_fixtures_render_direct_trace_projected_log_and_sdk_metric(
    artifacts: Mapping[str, Any],
) -> None:
    trace = _json(artifacts, "otlp-fixtures/cases/valid-model-chat-with-honest-missing-content-and-usage.json")
    trace_projection = trace["expect"]["projection"]
    assert trace_projection["mode"] == "direct_span"
    resource_spans = trace_projection["request"]["resourceSpans"][0]
    span = resource_spans["scopeSpans"][0]["spans"][0]
    assert span["traceId"] == base64.b64encode(
        bytes.fromhex(trace["canonical_record"]["correlation"]["trace_id"])
    ).decode("ascii")
    assert span["spanId"] == base64.b64encode(
        bytes.fromhex(trace["canonical_record"]["correlation"]["span_id"])
    ).decode("ascii")
    assert span["kind"] == 3
    assert span["startTimeUnixNano"] == "1783080000000000000"
    assert span["status"] == {"code": 1}
    assert resource_spans["schemaUrl"] == "https://opentelemetry.io/schemas/1.42.0"

    log = _json(artifacts, "otlp-fixtures/cases/valid-security-finding-with-derived-evidence.json")
    log_projection = log["expect"]["projection"]
    assert log_projection["mode"] == "projected_record_json_string"
    assert log_projection["request_root"] == "resourceLogs"
    assert json.loads(log_projection["projected_record_json"]) == log["canonical_record"]

    metric = _json(artifacts, "otlp-fixtures/cases/valid-hook-latency-metric.json")
    metric_projection = metric["expect"]["projection"]
    assert metric_projection["mode"] == "sdk_aggregation_required"
    assert metric_projection["request_root"] == "resourceMetrics"
    assert metric_projection["instrument"]["name"] == "defenseclaw.connector.hook.latency"
    assert metric_projection["instrument"]["value"] == 17.5


def test_catalog_markdown_is_searchable_and_uses_portable_names_first(artifacts: Mapping[str, Any]) -> None:
    markdown = artifacts[f"{PREFIX}/catalog.md"].payload.decode("utf-8")
    assert "# DefenseClaw Portable Telemetry Catalog (Candidate)" in markdown
    assert "## Namespace decision" in markdown
    assert "## Trace tree examples" in markdown
    assert "## Backend compatibility" in markdown
    assert "## Families" in markdown
    assert "## Redaction" in markdown
    assert "## Conformance scope" in markdown
    assert "builder facts and deterministic occurrence inputs" in markdown
    assert "`span.model.chat`" in markdown
    assert "`metric.defenseclaw.connector.hook.latency`" in markdown
    assert markdown.index("`gen_ai.operation.name`") < markdown.index("`defenseclaw.bucket`")


def test_renderer_rejects_non_view_stale_digest_and_incomplete_facts(
    renderer: ModuleType,
    generator: ModuleType,
    view: Any,
) -> None:
    ir = generator.compile_registry(ROOT)
    with pytest.raises(renderer.CandidateRenderError, match="requires MaterializedRegistryView"):
        renderer.render_candidate_artifacts(ir)
    with pytest.raises(renderer.CandidateRenderError, match="identity is invalid"):
        renderer.render_candidate_artifacts(dataclasses.replace(view, format="wrong"))
    with pytest.raises(renderer.CandidateRenderError, match="digest does not match"):
        renderer.render_candidate_artifacts(dataclasses.replace(view, typed_canonical_json_sha256="0" * 64))

    facts = _copy_materialized(view.facts)
    del facts["fields"]["conditions"]
    incomplete = _retagged_view(renderer, view, facts)
    with pytest.raises(renderer.CandidateRenderError, match="RegistryIR fields are incomplete"):
        renderer.render_candidate_artifacts(incomplete)


def test_renderer_rejects_incomplete_resolution_unknown_profiles_and_malformed_examples(
    renderer: ModuleType,
    view: Any,
) -> None:
    missing_resolution = _copy_materialized(view.facts)
    del missing_resolution["fields"]["resolved_group_uses"]["span.model.chat"]
    with pytest.raises(renderer.CandidateRenderError, match="resolved group uses are incomplete"):
        renderer.render_candidate_artifacts(_retagged_view(renderer, view, missing_resolution))

    unknown_profile = _copy_materialized(view.facts)
    domains = unknown_profile["fields"]["domains"]
    for domain in domains:
        for group in domain["fields"]["groups"]:
            if group["fields"]["id"] == "span.model.chat":
                group["fields"]["compatibility_profiles"] = ("unknown-profile",)
    with pytest.raises(renderer.CandidateRenderError, match="compatibility profile is unknown"):
        renderer.render_candidate_artifacts(_retagged_view(renderer, view, unknown_profile))

    malformed_example = _copy_materialized(view.facts)
    malformed_example["fields"]["examples"][0]["fields"]["record"]["signal"] = "logs"
    with pytest.raises(renderer.CandidateRenderError, match="example record is inconsistent"):
        renderer.render_candidate_artifacts(_retagged_view(renderer, view, malformed_example))

    malformed_occurrence = _copy_materialized(view.facts)
    malformed_occurrence["fields"]["examples"][0]["fields"]["builder_context"]["fields"]["occurrence"]["fields"][
        "record_id"
    ] = "not-the-record-id"
    with pytest.raises(renderer.CandidateRenderError, match="builder occurrence is inconsistent"):
        renderer.render_candidate_artifacts(_retagged_view(renderer, view, malformed_occurrence))

    malformed_rule = _copy_materialized(view.facts)
    malformed_rule["fields"]["mandatory_rule_catalog"]["fields"]["rules"][0]["fields"]["enforcement"]["fields"][
        "value"
    ] = False
    with pytest.raises(renderer.CandidateRenderError, match="constant mandatory rule is invalid"):
        renderer.render_candidate_artifacts(_retagged_view(renderer, view, malformed_rule))

    incomplete_structure = _copy_materialized(view.facts)
    del incomplete_structure["fields"]["structural_contract"]["fields"]["trace_body"]["fields"]["fields"]
    with pytest.raises(renderer.CandidateRenderError, match="structural contract is not canonical"):
        renderer.render_candidate_artifacts(_retagged_view(renderer, view, incomplete_structure))
