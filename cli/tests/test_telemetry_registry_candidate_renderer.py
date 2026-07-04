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
from pathlib import Path
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
    assert len(schema["$defs"]) == 593
    assert set(schema["x-defenseclaw-conditions"][0]) == {"description", "enforcement", "false_requirement", "id"}
    assert "$type" not in json.dumps(schema["x-defenseclaw-conditions"])
    assert len(schema["x-defenseclaw-conditions"]) == 7
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
        "span_name_pattern_rendering",
        "trace_cross_field_derivation_equality",
        "trace_time_order_relation",
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
        else:
            assert errors, example["id"]
            assert example["expected_error"]
            assert example["base_example"]
            assert example["mutation"]["kind"] == example["expected_error"]
            assert example["mutation"]["changes"]
    assert observed == {True: 7, False: 5}


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
        normalized = _json(artifacts, entry["path"])
        fixture = _json(artifacts, f"otlp-fixtures/cases/{entry['id']}.json")
        assert normalized["record"] == fixture["canonical_record"]
        assert normalized["valid"] == fixture["expect"]["accepted"]
        if not normalized["valid"]:
            assert fixture["expect"]["error_code"] == normalized["expected_error"]


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

    incomplete_structure = _copy_materialized(view.facts)
    del incomplete_structure["fields"]["structural_contract"]["fields"]["trace_body"]["fields"]["fields"]
    with pytest.raises(renderer.CandidateRenderError, match="StructuralObjectIR fields are incomplete"):
        renderer.render_candidate_artifacts(_retagged_view(renderer, view, incomplete_structure))
