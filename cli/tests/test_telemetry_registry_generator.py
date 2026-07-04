"""Focused provenance and failure-atomicity tests for the telemetry compiler."""

from __future__ import annotations

import copy
import hashlib
import importlib.util
import io
import json
import os
import subprocess
import sys
import tarfile
from collections.abc import Mapping
from pathlib import Path
from typing import Any

import pytest
import yaml

ROOT = Path(__file__).resolve().parents[2]
GENERATOR = ROOT / "scripts/generate_telemetry_registry.py"
UPDATER = ROOT / "scripts/update_telemetry_registry_upstream.py"

DEPENDENCIES = (
    (
        "otel_core",
        "https://github.com/open-telemetry/semantic-conventions",
        "v1.42.0",
        "otel-semconv-v1.42.0",
        "ae3a98640194ed405c4c797281502e4d3bd258b3",
        "otel-core.normalized.json",
        "service.name",
    ),
    (
        "otel_genai",
        "https://github.com/open-telemetry/semantic-conventions-genai",
        "test",
        "otel-genai-b028dceecdad117461a785c3af35315e7184e813",
        "b028dceecdad117461a785c3af35315e7184e813",
        "otel-genai.normalized.json",
        "gen_ai.operation.name",
    ),
    (
        "openinference",
        "https://github.com/Arize-ai/openinference",
        "0.1.30",
        "openinference-semantic-conventions-v0.1.30",
        "789d41974c08a9a13147977f28ef4142a07e2106",
        "openinference.normalized.json",
        "openinference.span.kind",
    ),
)

# Test-only review lock. Runtime validation derives this order from the registry source.
_CANONICAL_OUTCOME_ORDER = (
    "allowed",
    "applied",
    "approved",
    "attempted",
    "blocked",
    "cancelled",
    "completed",
    "denied",
    "failed",
    "no_change",
    "partial",
    "quarantined",
    "redacted",
    "rejected",
    "released",
    "revoked",
    "skipped",
    "terminated",
    "timed_out",
    "validated",
)
_REAL_FAMILY_OUTCOME_CONTRACT_DIGEST = "8cd00e119000c51f734d9948fa0df8cd06a0b91ceea5d7d210c33fe8ae79f078"
_CANONICAL_AGENT_PHASES = (
    "session",
    "planning",
    "model",
    "tool",
    "approval",
    "waiting",
    "responding",
    "maintenance",
    "completed",
    "failed",
    "interrupted",
    "observed",
)


def _sha256(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _grouped_outcome_contract_matrix(
    contracts: list[tuple[str, str, tuple[str, ...]]],
) -> tuple[tuple[str, tuple[str, ...], tuple[str, ...]], ...]:
    grouped: dict[tuple[str, tuple[str, ...]], list[str]] = {}
    for family_id, requirement, outcomes in contracts:
        grouped.setdefault((requirement, outcomes), []).append(family_id)
    return tuple(
        (requirement, outcomes, tuple(sorted(family_ids)))
        for (requirement, outcomes), family_ids in sorted(grouped.items())
    )


def _outcome_contract_digest(
    contracts: list[tuple[str, str, tuple[str, ...]]],
) -> str:
    matrix = _grouped_outcome_contract_matrix(contracts)
    return _sha256(json.dumps(matrix, separators=(",", ":")).encode())


def _write_yaml(path: Path, value: Any) -> None:
    if isinstance(value, dict) and isinstance(value.get("groups"), list):
        for group in value["groups"]:
            if isinstance(group, dict):
                group.setdefault("introduced_in", "telemetry-registry-v1")
    _write_yaml_raw(path, value)


def _write_yaml_raw(path: Path, value: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(yaml.safe_dump(value, sort_keys=False), encoding="utf-8")


def _snapshot(
    dependency_id: str,
    repository: str,
    revision: str,
    attribute: str,
) -> bytes:
    source_path = "model/registry.yaml"
    source_files = [{"path": source_path, "sha256": "a" * 64}]
    deprecated_shared = {
        "gen_ai.request.top_k",
        *(f"gen_ai.shared.deprecated.{index:03d}" for index in range(57)),
    }
    active_shared = {"aws.bedrock.guardrail.id", "aws.bedrock.knowledge_base.id"}
    legacy_core = {f"gen_ai.legacy.{index:03d}" for index in range(10)}
    if dependency_id == "otel_core":
        identifiers = (
            deprecated_shared
            | active_shared
            | legacy_core
            | {
                "service.name",
                "session.id",
                "user.id",
            }
        )
        identifiers |= {f"core.attribute.{index:04d}" for index in range(923 - len(identifiers))}
    elif dependency_id == "otel_genai":
        identifiers = deprecated_shared | active_shared | {attribute}
        identifiers |= {f"gen_ai.current.{index:03d}" for index in range(70 - len(identifiers))}
    else:
        identifiers = set()
    attributes = []
    for index, identifier in enumerate(sorted(identifiers)):
        deprecated = dependency_id == "otel_core" and identifier in (deprecated_shared | legacy_core)
        allowed_types = [
            "int64"
            if dependency_id == "otel_genai" and identifier == "gen_ai.request.top_k"
            else "double"
            if dependency_id == "otel_core" and identifier == "gen_ai.request.top_k"
            else "string"
        ]
        attributes.append(
            {
                "id": identifier,
                "allowed_types": allowed_types,
                "shape": "attribute",
                "stability": "deprecated" if deprecated else "development",
                "stability_source": "upstream",
                "source_pointer": f"{source_path}#/attributes/{index}",
                "enum": [],
                "deprecated": deprecated,
            }
        )
    if dependency_id == "openinference":
        source_files = [
            {
                "path": "python/openinference-semantic-conventions/src/openinference/semconv/resource/__init__.py",
                "sha256": "a" * 64,
            },
            {
                "path": "python/openinference-semantic-conventions/src/openinference/semconv/trace/__init__.py",
                "sha256": "b" * 64,
            },
            {
                "path": "python/openinference-semantic-conventions/src/openinference/semconv/version.py",
                "sha256": "c" * 64,
            },
            {"path": "spec/semantic_conventions.md", "sha256": "d" * 64},
        ]
        identifiers = {
            "openinference.span.kind",
            "input.value",
            "input.mime_type",
            "output.value",
            "output.mime_type",
            "metadata",
            "openinference.project.name",
            "session.id",
            "user.id",
        }
        identifiers |= {f"openinference.attribute.{index:03d}" for index in range(93 - len(identifiers))}
        attributes = [
            {
                "id": identifier,
                "allowed_types": ["string"],
                "shape": "attribute",
                "stability": "stable",
                "stability_source": "released_package_policy",
                "source_pointer": (
                    "python/openinference-semantic-conventions/src/openinference/semconv/"
                    f"resource/__init__.py#L{index + 1}"
                    if identifier == "openinference.project.name"
                    else f"spec/semantic_conventions.md#L{index + 1}"
                ),
                "enum": [],
                "deprecated": False,
            }
            for index, identifier in enumerate(sorted(identifiers))
        ]
    value = {
        "format_version": 1,
        "format": "defenseclaw-normalized-semconv-v1",
        "dependency_id": dependency_id,
        "repository": repository,
        "revision": revision,
        "source_archive": f"{repository}/archive/{revision}.tar.gz",
        "source_files": source_files,
        "attributes": attributes,
    }
    return (json.dumps(value, indent=2) + "\n").encode()


def _domain_sources() -> dict[str, dict[str, Any]]:
    domains = {
        "genai.yaml": {
            "schema_version": 1,
            "domain": "genai",
            "attributes": [
                {
                    "id": "defenseclaw.test.name",
                    "type": "string",
                    "brief": "A fixture-owned attribute.",
                    "examples": ["fixture"],
                    "stability": "development",
                    "owner": "defenseclaw",
                    "field_class": "metadata",
                    "sensitivity": "safe",
                    "cardinality": "low",
                    "normalization": {"id": "bounded-v1"},
                    "introduced_in": "telemetry-registry-v1",
                },
                {
                    "id": "defenseclaw.test.high",
                    "type": "string",
                    "brief": "A reviewed high-cardinality fixture attribute.",
                    "examples": ["fixture-high"],
                    "stability": "development",
                    "owner": "defenseclaw",
                    "field_class": "identifier",
                    "sensitivity": "internal",
                    "cardinality": "high",
                    "normalization": {"id": "bounded-v1"},
                    "introduced_in": "telemetry-registry-v1",
                },
            ],
            "attribute_extensions": [
                {
                    "ref": "gen_ai.operation.name",
                    "field_class": "metadata",
                    "sensitivity": "safe",
                    "cardinality": "low",
                    "normalization": {
                        "id": "enum-v1",
                        "overrides": {"enum": ["chat"]},
                    },
                }
            ],
            "groups": [
                {
                    "id": "span.model.chat",
                    "type": "span",
                    "brief": "A model chat call.",
                    "stability": "stable",
                    "extends": ["span.core"],
                    "attributes": [
                        {
                            "ref": "gen_ai.operation.name",
                            "requirement_level": "required",
                        }
                    ],
                    "span": {
                        "name_pattern": "chat {gen_ai.operation.name}",
                        "kinds": ["CLIENT"],
                        "status_rule": "technical_error_only",
                    },
                    "x-defenseclaw": {
                        "bucket": "model.io",
                        "family_schema_version": 1,
                        "outcome_requirement": "optional",
                        "allowed_outcomes": ["completed"],
                        "events": ["guardrail.decision"],
                        "route_selector": True,
                    },
                }
            ],
            "producer_identity_sets": [],
            "producer_mappings": [],
        },
        "security.yaml": {
            "schema_version": 1,
            "domain": "security",
            "attributes": [],
            "attribute_extensions": [],
            "groups": [
                {
                    "id": "event.guardrail.decision",
                    "type": "span_event",
                    "brief": "A bounded guardrail decision.",
                    "stability": "stable",
                }
            ],
            "producer_identity_sets": [],
            "producer_mappings": [],
        },
        "operations.yaml": {
            "schema_version": 1,
            "domain": "operations",
            "attributes": [],
            "attribute_extensions": [],
            "groups": [
                {
                    "id": "body.fixture",
                    "type": "body_group",
                    "brief": "A generated log body fixture.",
                    "stability": "development",
                },
                {
                    "id": "diagnostic.message",
                    "type": "log",
                    "brief": "A diagnostic message.",
                    "stability": "stable",
                    "extends": ["body.fixture"],
                    "log": {"event_name": "diagnostic.message"},
                    "x-defenseclaw": {
                        "bucket": "diagnostic",
                        "family_schema_version": 1,
                        "outcome_requirement": "forbidden",
                        "allowed_outcomes": [],
                    },
                },
            ],
            "producer_identity_sets": [],
            "producer_mappings": [],
        },
    }
    canonical_genai = yaml.safe_load((ROOT / "schemas/telemetry/v8/genai.yaml").read_text(encoding="utf-8"))
    for attribute_id in (
        "defenseclaw.bucket",
        "defenseclaw.outcome",
        "defenseclaw.span.family",
        "defenseclaw.span.family_schema_version",
        "defenseclaw.source",
        "defenseclaw.connector.source",
        "defenseclaw.config.generation",
        "defenseclaw.run.id",
        "defenseclaw.operation.id",
        "defenseclaw.agent.phase",
        "defenseclaw.agent.phase.previous",
        "defenseclaw.agent.phase.from",
        "defenseclaw.agent.phase.to",
        "defenseclaw.agent.phase.code",
        "defenseclaw.trace.schema_version",
        "defenseclaw.semantic_profile",
        "defenseclaw.link.relation",
    ):
        attribute = copy.deepcopy(next(item for item in canonical_genai["attributes"] if item["id"] == attribute_id))
        if attribute_id in {
            "defenseclaw.agent.phase",
            "defenseclaw.agent.phase.previous",
            "defenseclaw.agent.phase.from",
            "defenseclaw.agent.phase.to",
        }:
            attribute["normalization"] = {
                "id": "enum-v1",
                "overrides": {"enum": list(_CANONICAL_AGENT_PHASES)},
            }
        domains["genai.yaml"]["attributes"].append(attribute)
    for group_id in ("scope.core", "link.core", "span.core"):
        domains["genai.yaml"]["groups"].append(
            copy.deepcopy(next(item for item in canonical_genai["groups"] if item["id"] == group_id))
        )
    operations = domains["operations.yaml"]
    for index in range(74):
        operations["groups"].append(
            {
                "id": f"fixture.log.{index}",
                "type": "log",
                "brief": "A generated canonical fixture log.",
                "stability": "development",
                "extends": ["body.fixture"],
                "log": {"event_name": f"fixture.event.{index}"},
                "x-defenseclaw": {
                    "bucket": "diagnostic",
                    "family_schema_version": 1,
                    "outcome_requirement": "forbidden",
                    "allowed_outcomes": [],
                },
            }
        )
    for event_name in (
        "compact_end",
        "compact_start",
        "event",
        "hook_decision",
        "session_end",
        "session_start",
        "subagent_start",
        "subagent_stop",
        "tool_end",
        "tool_start",
        "turn_end",
        "turn_start",
    ):
        operations["groups"].append(
            {
                "id": f"fixture.compat.{event_name}",
                "type": "log",
                "brief": "A generated compatibility fixture log.",
                "stability": "development",
                "extends": ["body.fixture"],
                "log": {"event_name": event_name},
                "x-defenseclaw": {
                    "bucket": "agent.lifecycle",
                    "family_schema_version": 1,
                    "outcome_requirement": "forbidden",
                    "allowed_outcomes": [],
                },
            }
        )
    for index in range(24):
        operations["groups"].append(
            {
                "id": f"span.fixture.{index}",
                "type": "span",
                "brief": "A generated span fixture.",
                "stability": "development",
                "extends": ["span.core"],
                "span": {
                    "name_pattern": f"fixture.span.{index}",
                    "kinds": ["INTERNAL"],
                    "status_rule": "technical_error_only",
                },
                "x-defenseclaw": {
                    "bucket": "diagnostic",
                    "family_schema_version": 1,
                    "outcome_requirement": "optional",
                    "allowed_outcomes": ["completed"],
                },
            }
        )
    inventory = yaml.safe_load(
        (ROOT / "docs/design/observability-v8/current-state-inventory.yaml").read_text(encoding="utf-8")
    )
    registry = yaml.safe_load((ROOT / "schemas/telemetry/v8/registry.yaml").read_text(encoding="utf-8"))
    exception_families = {
        item["family"] for item in registry["metric_compatibility_profiles"][0]["high_cardinality_families"]
    }
    metric_items = inventory["classes"]["emitted_metrics"]["items"]
    for instrument_name, contract in metric_items.items():
        high_cardinality = instrument_name in exception_families
        metric: dict[str, Any] = {
            "instrument_name": instrument_name,
            "instrument_type": contract["type"],
            "value_type": "int64",
            "unit": contract["unit"],
            "description": "Generated metric fixture.",
            "temporality": "delta",
        }
        if not high_cardinality:
            metric["empty_labels_reason"] = "Fixture producer emits no instrument labels."
        group: dict[str, Any] = {
            "id": f"metric.{instrument_name}",
            "type": "metric",
            "brief": "Generated metric fixture.",
            "stability": "development",
            "metric": metric,
            "x-defenseclaw": {
                "bucket": "diagnostic",
                "family_schema_version": 1,
            },
        }
        if high_cardinality:
            group["attributes"] = [{"ref": "defenseclaw.test.high", "requirement_level": "required"}]
        operations["groups"].append(group)
    for producer, section, source in (
        ("gateway_event", "gateway_event_types", "gateway"),
        ("audit_action", "audit_actions", "audit"),
    ):
        for key in inventory["classes"][section]["items"].values():
            operations["producer_mappings"].append(
                {
                    "producer": producer,
                    "key": key,
                    "source": source,
                    "event_name_policy": "fixed",
                    "default_identity": {
                        "event_name": "diagnostic.message",
                        "bucket": "diagnostic",
                        "family": "diagnostic.message",
                    },
                    "severity_policy": "canonical_or_info",
                }
            )
    operations["groups"].insert(
        0,
        {
            "id": "resource.core",
            "type": "resource",
            "brief": "A fixture resource contract.",
            "stability": "stable",
        },
    )
    for domain in domains.values():
        for group in domain["groups"]:
            group["introduced_in"] = "telemetry-registry-v1"
    return domains


def _fixture_root(tmp_path: Path) -> Path:
    root = tmp_path / "repository"
    telemetry = root / "schemas/telemetry/v8"
    upstream = telemetry / "upstream"
    upstream.mkdir(parents=True)
    inventory_source = ROOT / "docs/design/observability-v8/current-state-inventory.yaml"
    inventory_target = root / "docs/design/observability-v8/current-state-inventory.yaml"
    inventory_target.parent.mkdir(parents=True)
    inventory = yaml.safe_load(inventory_source.read_text(encoding="utf-8"))
    registry_source = yaml.safe_load((ROOT / "schemas/telemetry/v8/registry.yaml").read_text(encoding="utf-8"))
    exception_families = {
        item["family"] for item in registry_source["metric_compatibility_profiles"][0]["high_cardinality_families"]
    }
    for instrument_name, contract in inventory["classes"]["emitted_metrics"]["items"].items():
        high_cardinality = instrument_name in exception_families
        contract["labels"] = ["defenseclaw.test.high"] if high_cardinality else []
        contract["callsites"] = ["internal/telemetry/metrics.go:1"]
        contract["dropped_by_current_global_v8_gate"] = []
        if high_cardinality:
            contract.pop("empty_labels_reason", None)
        else:
            contract["empty_labels_reason"] = "Fixture producer emits no instrument labels."
    _write_yaml(inventory_target, inventory)
    lock_dependencies: list[dict[str, Any]] = []
    for dependency_id, repository, version, profile, revision, filename, attribute in DEPENDENCIES:
        payload = _snapshot(dependency_id, repository, revision, attribute)
        (upstream / filename).write_bytes(payload)
        lock_dependencies.append(
            {
                "id": dependency_id,
                "repository": repository,
                "version": version,
                "profile_id": profile,
                "revision": revision,
                "snapshot": {
                    "path": f"schemas/telemetry/v8/upstream/{filename}",
                    "format": "defenseclaw-normalized-semconv-v1",
                    "sha256": _sha256(payload),
                },
            }
        )
    _write_yaml(
        telemetry / "semconv.lock.yaml",
        {"schema_version": 1, "dependencies": lock_dependencies},
    )
    metric_profile = copy.deepcopy(registry_source["metric_compatibility_profiles"])
    for item in metric_profile[0]["high_cardinality_families"]:
        item["labels"] = ["defenseclaw.test.high"]
    _write_yaml(
        telemetry / "registry.yaml",
        {
            "schema_version": 1,
            "registry_version": 1,
            "bucket_catalog_version": 1,
            "imports": ["genai.yaml", "security.yaml", "operations.yaml"],
            "dependency_lock": "schemas/telemetry/v8/semconv.lock.yaml",
            "examples": "examples.yaml",
            "semantic_profiles": [
                {
                    "id": "defenseclaw-genai-rich-v1",
                    "trace_schema_version": "defenseclaw-trace-v1",
                    "gen_ai_semconv_profile": DEPENDENCIES[1][3],
                    "openinference_profile": DEPENDENCIES[2][3],
                    "galileo_compatibility_profile": "galileo-rich-v2",
                }
            ],
            "normalizers": registry_source["normalizers"],
            "conditions": registry_source["conditions"],
            "value_catalogs": registry_source["value_catalogs"],
            "structural_contract": registry_source["structural_contract"],
            "metric_defaults": registry_source["metric_defaults"],
            "metric_compatibility_profiles": metric_profile,
        },
    )
    for name, value in _domain_sources().items():
        _write_yaml(telemetry / name, value)
    _write_yaml(
        telemetry / "examples.yaml",
        {
            "schema_version": 1,
            "examples": [
                {
                    "id": "model.chat.valid",
                    "valid": True,
                    "signal": "traces",
                    "family": "span.model.chat",
                    "description": "Small valid model trace.",
                    "record": {
                        "schema_version": 1,
                        "bucket_catalog_version": 1,
                        "timestamp": "2026-07-03T12:00:00Z",
                        "record_id": "fixture-record-1",
                        "bucket": "model.io",
                        "signal": "traces",
                        "event_name": "span.model.chat",
                        "span_name": "chat chat",
                        "source": "gateway",
                        "correlation": {
                            "trace_id": "0123456789abcdef0123456789abcdef",
                            "span_id": "0123456789abcdef",
                        },
                        "provenance": {
                            "producer": "defenseclaw",
                            "binary_version": "8.0.0",
                            "registry_schema_version": 1,
                            "config_generation": 1,
                        },
                        "body": {
                            "kind": "CLIENT",
                            "start_time_unix_nano": 1,
                            "end_time_unix_nano": 2,
                            "attributes": {
                                "defenseclaw.bucket": "model.io",
                                "defenseclaw.span.family": "span.model.chat",
                                "defenseclaw.span.family_schema_version": 1,
                                "defenseclaw.source": "gateway",
                                "defenseclaw.config.generation": 1,
                                "gen_ai.operation.name": "chat",
                            },
                            "status": {"code": "OK"},
                            "resource": {
                                "schema_url": "https://opentelemetry.io/schemas/1.42.0",
                                "attributes": {},
                            },
                            "scope": {
                                "name": "defenseclaw.telemetry",
                                "version": "8.0.0",
                                "schema_url": "https://defenseclaw.io/schemas/telemetry/v8",
                                "attributes": {
                                    "defenseclaw.trace.schema_version": "defenseclaw-trace-v1",
                                    "defenseclaw.semantic_profile": "defenseclaw-genai-rich-v1",
                                },
                            },
                        },
                        "field_classes": {
                            "/kind": "metadata",
                            "/start_time_unix_nano": "metadata",
                            "/end_time_unix_nano": "metadata",
                            "/attributes/defenseclaw.bucket": "metadata",
                            "/attributes/defenseclaw.span.family": "identifier",
                            "/attributes/defenseclaw.span.family_schema_version": "metadata",
                            "/attributes/defenseclaw.source": "identifier",
                            "/attributes/defenseclaw.config.generation": "metadata",
                            "/attributes/gen_ai.operation.name": "metadata",
                            "/status/code": "metadata",
                            "/resource/schema_url": "metadata",
                            "/resource/attributes": "metadata",
                            "/scope/name": "metadata",
                            "/scope/version": "metadata",
                            "/scope/schema_url": "metadata",
                            "/scope/attributes/defenseclaw.trace.schema_version": "metadata",
                            "/scope/attributes/defenseclaw.semantic_profile": "metadata",
                        },
                    },
                }
            ],
        },
    )
    return root


def _materialize_trace_attribute(root: Path, attribute: str, value: Any, field_class: str) -> None:
    """Keep the checked example valid when a test makes a trace attribute required."""
    examples_path = root / "schemas/telemetry/v8/examples.yaml"
    examples = yaml.safe_load(examples_path.read_text(encoding="utf-8"))
    record = examples["examples"][0]["record"]
    record["body"]["attributes"][attribute] = value
    record["field_classes"][f"/attributes/{attribute}"] = field_class
    _write_yaml(examples_path, examples)


def _run(root: Path, mode: str, *, environment: dict[str, str] | None = None) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, str(GENERATOR), mode, "--root", str(root)],
        cwd=ROOT,
        check=False,
        capture_output=True,
        text=True,
        timeout=60,
        env=environment,
    )


def _load_generator_module(name: str):
    spec = importlib.util.spec_from_file_location(name, GENERATOR)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def _mutate_snapshot(root: Path, dependency_id: str, mutate: Any) -> None:
    lock_path = root / "schemas/telemetry/v8/semconv.lock.yaml"
    lock = yaml.safe_load(lock_path.read_text(encoding="utf-8"))
    dependency = next(item for item in lock["dependencies"] if item["id"] == dependency_id)
    snapshot_path = root / dependency["snapshot"]["path"]
    snapshot = json.loads(snapshot_path.read_bytes())
    mutate(snapshot)
    snapshot["attributes"].sort(key=lambda item: item["id"])
    payload = (json.dumps(snapshot, indent=2) + "\n").encode()
    snapshot_path.write_bytes(payload)
    dependency["snapshot"]["sha256"] = _sha256(payload)
    _write_yaml(lock_path, lock)


def test_write_check_is_deterministic_and_offline(tmp_path: Path) -> None:
    root = _fixture_root(tmp_path)
    first = _run(root, "--write")
    assert first.returncode == 0, first.stderr
    manifest = root / "schemas/telemetry/generated/output-manifest.json"
    first_bytes = manifest.read_bytes()

    offline = dict(os.environ)
    offline.update(
        {
            "HTTP_PROXY": "http://127.0.0.1:9",
            "HTTPS_PROXY": "http://127.0.0.1:9",
            "ALL_PROXY": "http://127.0.0.1:9",
            "NO_PROXY": "",
        }
    )
    checked = _run(root, "--check", environment=offline)
    assert checked.returncode == 0, checked.stderr
    second = _run(root, "--write", environment=offline)
    assert second.returncode == 0, second.stderr
    assert manifest.read_bytes() == first_bytes
    parsed = json.loads(first_bytes)
    assert len(parsed["materialized_view_sha256"]) == 64
    assert set(parsed["materialized_view_sha256"]) <= set("0123456789abcdef")
    assert parsed["canonical_import_order"] == ["genai.yaml", "security.yaml", "operations.yaml"]
    assert [item["dependency_id"] for item in parsed["snapshots"]] == [
        "otel_core",
        "otel_genai",
        "openinference",
    ]
    assert parsed["upstream_ownership_transitions"] == [
        {
            "attribute": "gen_ai.request.top_k",
            "from_dependency": "otel_core",
            "to_dependency": "otel_genai",
            "from_allowed_types": ["double"],
            "to_allowed_types": ["int64"],
            "disposition": "breaking_type_correction_to_dedicated_genai",
        }
    ]
    assert parsed["upstream_compatibility_overlaps"] == [
        {
            "attribute": "session.id",
            "canonical_owner": "otel_core",
            "compatibility_provenance": "openinference",
        },
        {
            "attribute": "user.id",
            "canonical_owner": "otel_core",
            "compatibility_provenance": "openinference",
        },
    ]
    assert len(parsed["legacy_only_upstream_attributes"]) == 10


def test_snapshot_tampering_fails_without_partial_output(tmp_path: Path) -> None:
    root = _fixture_root(tmp_path)
    assert _run(root, "--write").returncode == 0
    manifest = root / "schemas/telemetry/generated/output-manifest.json"
    before = manifest.read_bytes()
    snapshot = root / "schemas/telemetry/v8/upstream/otel-genai.normalized.json"
    snapshot.write_bytes(snapshot.read_bytes() + b" ")

    result = _run(root, "--write")

    assert result.returncode == 1
    assert "snapshot digest mismatch" in result.stderr
    assert manifest.read_bytes() == before


def test_active_core_genai_overlap_must_be_identical(tmp_path: Path) -> None:
    root = _fixture_root(tmp_path)

    def mutate(snapshot: dict[str, Any]) -> None:
        target = next(item for item in snapshot["attributes"] if item["id"] == "aws.bedrock.guardrail.id")
        target["allowed_types"] = ["int64"]

    _mutate_snapshot(root, "otel_genai", mutate)
    result = _run(root, "--write")

    assert result.returncode == 1
    assert "active overlap is inconsistent" in result.stderr


def test_unreviewed_core_genai_type_migration_is_rejected(tmp_path: Path) -> None:
    root = _fixture_root(tmp_path)

    def mutate(snapshot: dict[str, Any]) -> None:
        target = next(item for item in snapshot["attributes"] if item["id"] == "gen_ai.shared.deprecated.000")
        target["allowed_types"] = ["int64"]

    _mutate_snapshot(root, "otel_genai", mutate)
    result = _run(root, "--write")

    assert result.returncode == 1
    assert "unreviewed type migration" in result.stderr


def test_only_reviewed_openinference_core_overlaps_are_accepted(tmp_path: Path) -> None:
    root = _fixture_root(tmp_path)

    def mismatch(snapshot: dict[str, Any]) -> None:
        target = next(item for item in snapshot["attributes"] if item["id"] == "session.id")
        target["allowed_types"] = ["int64"]

    _mutate_snapshot(root, "openinference", mismatch)
    result = _run(root, "--write")
    assert result.returncode == 1
    assert "OpenInference overlap type mismatch" in result.stderr

    root = _fixture_root(tmp_path / "unexpected")

    def unexpected(snapshot: dict[str, Any]) -> None:
        target = next(item for item in snapshot["attributes"] if item["id"] == "openinference.attribute.000")
        target["id"] = "service.name"

    _mutate_snapshot(root, "openinference", unexpected)
    result = _run(root, "--write")
    assert result.returncode == 1
    assert "unexpected OpenInference overlap" in result.stderr


def test_legacy_only_core_genai_attribute_cannot_satisfy_group_ref(tmp_path: Path) -> None:
    root = _fixture_root(tmp_path)
    path = root / "schemas/telemetry/v8/genai.yaml"
    document = yaml.safe_load(path.read_text(encoding="utf-8"))
    document["groups"][0]["attributes"][0]["ref"] = "gen_ai.legacy.000"
    document["attribute_extensions"][0]["ref"] = "gen_ai.legacy.000"
    _write_yaml(path, document)

    result = _run(root, "--write")

    assert result.returncode == 1
    assert "unknown attribute reference" in result.stderr


def test_openinference_source_tuple_tamper_fails_with_recomputed_digest(tmp_path: Path) -> None:
    root = _fixture_root(tmp_path)

    def mutate(snapshot: dict[str, Any]) -> None:
        snapshot["source_files"][0]["path"] = "python/instrumentation/decoy.py"

    _mutate_snapshot(root, "openinference", mutate)
    result = _run(root, "--write")

    assert result.returncode == 1
    assert "non-authoritative OpenInference source" in result.stderr


def test_unknown_attribute_reference_fails_closed(tmp_path: Path) -> None:
    root = _fixture_root(tmp_path)
    path = root / "schemas/telemetry/v8/genai.yaml"
    path.write_text(
        path.read_text(encoding="utf-8").replace("gen_ai.operation.name", "gen_ai.unknown"),
        encoding="utf-8",
    )

    result = _run(root, "--write")

    assert result.returncode == 1
    assert "unknown attribute reference" in result.stderr
    assert not (root / "schemas/telemetry/generated").exists()


def test_producer_identity_must_match_canonical_family(tmp_path: Path) -> None:
    root = _fixture_root(tmp_path)
    path = root / "schemas/telemetry/v8/operations.yaml"
    document = yaml.safe_load(path.read_text(encoding="utf-8"))
    document["producer_mappings"][0]["default_identity"]["bucket"] = "platform.health"
    _write_yaml(path, document)

    result = _run(root, "--write")

    assert result.returncode == 1
    assert "family bucket mismatch" in result.stderr


def test_only_legacy_audit_identity_may_be_compatibility_only(tmp_path: Path) -> None:
    root = _fixture_root(tmp_path)
    path = root / "schemas/telemetry/v8/operations.yaml"
    document = yaml.safe_load(path.read_text(encoding="utf-8"))
    identity = document["producer_mappings"][0]["default_identity"]
    identity.pop("family")
    identity["compatibility_only"] = True
    _write_yaml(path, document)

    result = _run(root, "--write")

    assert result.returncode == 1
    assert "must use legacy.audit.*" in result.stderr


def test_semantic_profile_tuple_is_immutable(tmp_path: Path) -> None:
    root = _fixture_root(tmp_path)
    path = root / "schemas/telemetry/v8/registry.yaml"
    document = yaml.safe_load(path.read_text(encoding="utf-8"))
    document["semantic_profiles"][0]["galileo_compatibility_profile"] = "galileo-rich-v3"
    _write_yaml(path, document)

    result = _run(root, "--write")

    assert result.returncode == 1
    assert "profile tuple does not match" in result.stderr


def test_upstream_attribute_extension_is_required_exactly_once(tmp_path: Path) -> None:
    root = _fixture_root(tmp_path)
    path = root / "schemas/telemetry/v8/genai.yaml"
    document = yaml.safe_load(path.read_text(encoding="utf-8"))
    document["attribute_extensions"] = []
    _write_yaml(path, document)

    result = _run(root, "--write")

    assert result.returncode == 1
    assert "coverage mismatch missing=['gen_ai.operation.name']" in result.stderr


@pytest.mark.parametrize(
    ("field_class", "cardinality", "expected"),
    [
        ("metadata", "high", "high-cardinality coverage mismatch"),
        ("content", "bounded", "unsafe label attribute defenseclaw.test.name"),
        ("credential", "low", "unsafe label attribute defenseclaw.test.name"),
    ],
)
def test_metric_labels_reject_high_cardinality_or_sensitive_classes(
    tmp_path: Path,
    field_class: str,
    cardinality: str,
    expected: str,
) -> None:
    root = _fixture_root(tmp_path)
    genai_path = root / "schemas/telemetry/v8/genai.yaml"
    genai = yaml.safe_load(genai_path.read_text(encoding="utf-8"))
    genai["attributes"][0]["field_class"] = field_class
    genai["attributes"][0]["cardinality"] = cardinality
    _write_yaml(genai_path, genai)
    operations_path = root / "schemas/telemetry/v8/operations.yaml"
    operations = yaml.safe_load(operations_path.read_text(encoding="utf-8"))
    metric_group = next(
        group
        for group in operations["groups"]
        if group.get("metric", {}).get("instrument_name") == "defenseclaw.activity.diff_entries"
    )
    metric_group["attributes"] = [{"ref": "defenseclaw.test.name", "requirement_level": "required"}]
    metric_group["metric"].pop("empty_labels_reason")
    _write_yaml(operations_path, operations)
    inventory_path = root / "docs/design/observability-v8/current-state-inventory.yaml"
    inventory = yaml.safe_load(inventory_path.read_text(encoding="utf-8"))
    contract = inventory["classes"]["emitted_metrics"]["items"]["defenseclaw.activity.diff_entries"]
    contract["labels"] = ["defenseclaw.test.name"]
    contract.pop("empty_labels_reason")
    _write_yaml(inventory_path, inventory)

    result = _run(root, "--write")

    assert result.returncode == 1
    assert expected in result.stderr


def test_non_upstream_genai_name_requires_projection_alias_lifecycle(tmp_path: Path) -> None:
    root = _fixture_root(tmp_path)
    path = root / "schemas/telemetry/v8/genai.yaml"
    document = yaml.safe_load(path.read_text(encoding="utf-8"))
    alias = copy.deepcopy(document["attributes"][0])
    alias.update(
        {
            "id": "gen_ai.test.legacy",
            "stability": "deprecated",
            "deprecated_in": "telemetry-registry-v1",
        }
    )
    document["attributes"].append(alias)
    _write_yaml(path, document)
    result = _run(root, "--write")
    assert result.returncode == 1
    assert "must be a projection-only alias" in result.stderr

    alias.update(
        {
            "projection_only": True,
            "alias_of": "defenseclaw.test.name",
            "deprecated_in": "telemetry-registry-v1",
            "removed_in": "telemetry-registry-v2",
            "legacy_bindings": [{"source": "fixture", "disposition": "compatibility_alias"}],
        }
    )
    document["attributes"][-1] = alias
    _write_yaml(path, document)
    result = _run(root, "--write")
    assert result.returncode == 0, result.stderr


def test_span_events_use_public_names_not_internal_group_ids(tmp_path: Path) -> None:
    root = _fixture_root(tmp_path)
    path = root / "schemas/telemetry/v8/genai.yaml"
    document = yaml.safe_load(path.read_text(encoding="utf-8"))
    document["groups"][0]["x-defenseclaw"]["events"] = ["event.guardrail.decision"]
    _write_yaml(path, document)

    result = _run(root, "--write")

    assert result.returncode == 1
    assert "public names without event. prefix" in result.stderr


def test_invalid_top_level_example_requires_derived_mutation(tmp_path: Path) -> None:
    root = _fixture_root(tmp_path)
    path = root / "schemas/telemetry/v8/examples.yaml"
    document = yaml.safe_load(path.read_text(encoding="utf-8"))
    document["examples"].append(
        {
            "id": "legacy.audit.invalid",
            "valid": False,
            "signal": "logs",
            "description": "Producer-only compatibility identity is not a family.",
            "record": {"event_name": "legacy.audit.scan"},
            "expected_error": "unknown_family",
        }
    )
    _write_yaml(path, document)

    result = _run(root, "--write")

    assert result.returncode == 1
    assert "base_example, and mutation" in result.stderr


@pytest.mark.parametrize(
    ("mutation", "expected"),
    [
        (
            lambda invalid: invalid["mutation"]["changes"][0].__setitem__("op", "remove"),
            "value: required for add/replace and forbidden for remove",
        ),
        (
            lambda invalid: invalid["mutation"]["changes"][0].pop("value"),
            "value: required for add/replace and forbidden for remove",
        ),
        (
            lambda invalid: invalid["mutation"]["changes"][0].__setitem__("path", "record/event_name"),
            "must be an RFC6901 pointer",
        ),
        (
            lambda invalid: invalid["mutation"]["changes"][0].__setitem__("path", "/description"),
            "root must be signal, family, or record",
        ),
        (
            lambda invalid: invalid["mutation"]["changes"][0].__setitem__("path", "/record/event_name~2invalid"),
            "invalid RFC6901 escape",
        ),
        (
            lambda invalid: invalid["record"].__setitem__("event_name", "another.invalid.name"),
            "derived vector does not equal checked-in invalid example",
        ),
        (
            lambda invalid: invalid.__setitem__("base_example", "not.an.earlier.valid.example"),
            "must reference an earlier valid example",
        ),
    ],
)
def test_invalid_example_mutation_grammar_is_mechanical_and_exact(
    tmp_path: Path,
    mutation: Any,
    expected: str,
) -> None:
    root = _fixture_root(tmp_path)
    path = root / "schemas/telemetry/v8/examples.yaml"
    document = yaml.safe_load(path.read_text(encoding="utf-8"))
    valid = document["examples"][0]
    invalid_record = copy.deepcopy(valid["record"])
    invalid_record["event_name"] = "invalid.event.name"
    invalid = {
        "id": "model.chat.invalid.event-name",
        "valid": False,
        "signal": "traces",
        "family": "span.model.chat",
        "description": "A mechanically derived invalid event-name vector.",
        "record": invalid_record,
        "expected_error": "family_event_name_mismatch",
        "base_example": valid["id"],
        "mutation": {
            "kind": "family_event_name_mismatch",
            "changes": [
                {
                    "op": "replace",
                    "path": "/record/event_name",
                    "value": "invalid.event.name",
                }
            ],
        },
    }
    mutation(invalid)
    document["examples"].append(invalid)
    _write_yaml(path, document)

    result = _run(root, "--write")

    assert result.returncode == 1
    assert expected in result.stderr


def test_direct_upstream_bytes_type_compiles_losslessly(tmp_path: Path) -> None:
    root = _fixture_root(tmp_path)

    def mutate(snapshot: dict[str, Any]) -> None:
        target = next(item for item in snapshot["attributes"] if item["id"] == "gen_ai.operation.name")
        target["allowed_types"] = ["bytes"]

    _mutate_snapshot(root, "otel_genai", mutate)
    domain_path = root / "schemas/telemetry/v8/genai.yaml"
    domain = yaml.safe_load(domain_path.read_text(encoding="utf-8"))
    domain["attribute_extensions"][0]["normalization"] = {"id": "bounded-v1"}
    _write_yaml(domain_path, domain)

    result = _run(root, "--write")

    assert result.returncode == 0, result.stderr


def test_metric_string_label_rejects_disallowed_normalizer(tmp_path: Path) -> None:
    root = _fixture_root(tmp_path)
    domain_path = root / "schemas/telemetry/v8/genai.yaml"
    domain = yaml.safe_load(domain_path.read_text(encoding="utf-8"))
    domain["attributes"][0]["normalization"] = {"id": "digest-v1"}
    _write_yaml(domain_path, domain)
    operations_path = root / "schemas/telemetry/v8/operations.yaml"
    operations = yaml.safe_load(operations_path.read_text(encoding="utf-8"))
    metric_group = next(
        group
        for group in operations["groups"]
        if group.get("metric", {}).get("instrument_name") == "defenseclaw.activity.diff_entries"
    )
    metric_group["attributes"] = [{"ref": "defenseclaw.test.name", "requirement_level": "required"}]
    metric_group["metric"].pop("empty_labels_reason")
    _write_yaml(operations_path, operations)
    inventory_path = root / "docs/design/observability-v8/current-state-inventory.yaml"
    inventory = yaml.safe_load(inventory_path.read_text(encoding="utf-8"))
    contract = inventory["classes"]["emitted_metrics"]["items"]["defenseclaw.activity.diff_entries"]
    contract["labels"] = ["defenseclaw.test.name"]
    contract.pop("empty_labels_reason")
    _write_yaml(inventory_path, inventory)

    result = _run(root, "--write")

    assert result.returncode == 1
    assert "uses unbounded normalizer digest-v1" in result.stderr


@pytest.mark.parametrize(
    ("field", "value", "expected"),
    [
        ("instrument_type", "summary", "instrument_type: unsupported value"),
        ("value_type", "float32", "value_type: unsupported value"),
        ("temporality", "sometimes", "temporality: unsupported value"),
    ],
)
def test_metric_vocabulary_is_closed(
    tmp_path: Path,
    field: str,
    value: str,
    expected: str,
) -> None:
    root = _fixture_root(tmp_path)
    path = root / "schemas/telemetry/v8/operations.yaml"
    document = yaml.safe_load(path.read_text(encoding="utf-8"))
    metric_group = next(group for group in document["groups"] if group["type"] == "metric")
    metric_group["metric"][field] = value
    _write_yaml(path, document)

    result = _run(root, "--write")

    assert result.returncode == 1
    assert expected in result.stderr


@pytest.mark.parametrize(
    ("field", "value", "expected"),
    [
        ("instrument_type", "gauge", "instrument_type 'gauge' differs from current inventory"),
        ("unit", "widgets", "unit 'widgets' differs from current inventory"),
    ],
)
def test_metric_type_and_unit_match_current_inventory(
    tmp_path: Path,
    field: str,
    value: str,
    expected: str,
) -> None:
    root = _fixture_root(tmp_path)
    path = root / "schemas/telemetry/v8/operations.yaml"
    document = yaml.safe_load(path.read_text(encoding="utf-8"))
    metric_group = next(
        group
        for group in document["groups"]
        if group.get("metric", {}).get("instrument_name") == "defenseclaw.activity.diff_entries"
    )
    metric_group["metric"][field] = value
    _write_yaml(path, document)

    result = _run(root, "--write")

    assert result.returncode == 1
    assert expected in result.stderr


@pytest.mark.parametrize(
    ("instrument", "boundaries", "expected"),
    [
        ("defenseclaw.activity.total", [1, 2], "allowed only for histograms"),
        ("gen_ai.client.operation.duration", [1, 1], "strictly ascending"),
        ("gen_ai.client.operation.duration", [1, float("nan")], "expected finite number"),
        ("gen_ai.client.operation.duration", [True, 2], "expected finite number"),
    ],
)
def test_metric_boundaries_are_histogram_only_finite_and_ascending(
    tmp_path: Path,
    instrument: str,
    boundaries: list[object],
    expected: str,
) -> None:
    root = _fixture_root(tmp_path)
    for domain_name in ("genai", "security", "operations"):
        path = root / f"schemas/telemetry/v8/{domain_name}.yaml"
        document = yaml.safe_load(path.read_text(encoding="utf-8"))
        target = next(
            (group for group in document["groups"] if group.get("metric", {}).get("instrument_name") == instrument),
            None,
        )
        if target is not None:
            target["metric"]["boundaries"] = boundaries
            _write_yaml(path, document)
            break
    else:
        raise AssertionError(f"fixture metric missing: {instrument}")

    result = _run(root, "--write")

    assert result.returncode == 1
    assert expected in result.stderr


@pytest.mark.parametrize(
    ("field_type", "normalization"),
    [
        ("boolean[]", {"id": "identity-v1"}),
        (
            "int64[]",
            {"id": "numeric-range-v1", "overrides": {"min": 0, "max": 10}},
        ),
    ],
)
def test_numeric_and_boolean_arrays_require_explicit_max_items(
    tmp_path: Path,
    field_type: str,
    normalization: dict[str, Any],
) -> None:
    root = _fixture_root(tmp_path)
    path = root / "schemas/telemetry/v8/genai.yaml"
    document = yaml.safe_load(path.read_text(encoding="utf-8"))
    attribute = copy.deepcopy(document["attributes"][0])
    attribute.update(
        {
            "id": "defenseclaw.test.array",
            "type": field_type,
            "examples": [[]],
            "normalization": normalization,
        }
    )
    document["attributes"].append(attribute)
    _write_yaml(path, document)

    result = _run(root, "--write")

    assert result.returncode == 1
    assert "arrays require an explicit max_items bound" in result.stderr

    document = yaml.safe_load(path.read_text(encoding="utf-8"))
    document["attributes"][-1]["normalization"].setdefault("overrides", {})["max_items"] = 16
    _write_yaml(path, document)
    result = _run(root, "--write")
    assert result.returncode == 0, result.stderr


@pytest.mark.parametrize(
    ("constraints", "expected"),
    [
        ({"pattern": "(?=chat)"}, "outside the portable RE2 subset"),
        ({"min": 1}, "numeric constraint is incompatible"),
        ({"max_utf8_bytes": 8192}, "max_utf8_bytes weakens normalization"),
        ({"enum": [True]}, "constraint enum type is incompatible"),
    ],
)
def test_per_use_constraints_are_typed_portable_and_restrictive(
    tmp_path: Path,
    constraints: dict[str, Any],
    expected: str,
) -> None:
    root = _fixture_root(tmp_path)
    path = root / "schemas/telemetry/v8/genai.yaml"
    document = yaml.safe_load(path.read_text(encoding="utf-8"))
    document["groups"][0]["attributes"][0]["constraints"] = constraints
    _write_yaml(path, document)

    result = _run(root, "--write")

    assert result.returncode == 1
    assert expected in result.stderr


def test_per_use_constraints_are_preserved_in_compiler_ir(tmp_path: Path) -> None:
    root = _fixture_root(tmp_path)
    path = root / "schemas/telemetry/v8/genai.yaml"
    document = yaml.safe_load(path.read_text(encoding="utf-8"))
    constraints = {"enum": ["chat"], "max_utf8_bytes": 64, "pattern": "^chat$"}
    document["groups"][0]["attributes"][0]["constraints"] = constraints
    _write_yaml(path, document)
    module = _load_generator_module("telemetry_registry_generator_test")

    ir = module.compile_registry(root)
    group = next(group for domain in ir.domains for group in domain.groups if group.id == "span.model.chat")

    assert dict(group.attribute_uses[0].constraints) == {
        "enum": ("chat",),
        "max_utf8_bytes": 64,
        "pattern": "^chat$",
    }


def test_compiler_ir_preserves_every_validated_public_contract(tmp_path: Path) -> None:
    root = _fixture_root(tmp_path)
    genai_path = root / "schemas/telemetry/v8/genai.yaml"
    genai = yaml.safe_load(genai_path.read_text(encoding="utf-8"))
    attribute = genai["attributes"][0]
    attribute.update(
        {
            "brief": "Preserved attribute brief.",
            "examples": ["fixture", "value"],
            "introduced_in": "telemetry-registry-v1",
            "normalization": {
                "id": "bounded-v1",
                "overrides": {"max_utf8_bytes": 128},
                "notes": "Preserved normalization note.",
            },
            "legacy_bindings": [
                {
                    "source": "fixture.explicit-null",
                    "disposition": "preserved",
                    "details": None,
                },
                {"source": "fixture.absent", "disposition": "preserved"},
            ],
        }
    )
    genai["attribute_extensions"][0]["normalization"]["notes"] = "Preserved extension normalization note."
    span = genai["groups"][0]
    span["brief"] = "Preserved span brief."
    span["attributes"][0].update(
        {
            "requirement_level": "conditional",
            "conditional": "operation-terminal-v1",
            "constraints": {
                "enum": ["chat"],
                "max_utf8_bytes": 64,
                "pattern": "^chat$",
            },
        }
    )
    span["x-defenseclaw"].update(
        {
            "allowed_outcomes": ["completed", "failed"],
            "link_relations": ["caused_by"],
            "mandatory_floor": ["always"],
            "route_selector": False,
            "compatibility_profiles": ["local-observability-v1"],
            "legacy_bindings": [
                {
                    "source": "fixture.span",
                    "disposition": "preserved",
                    "details": {"nested": ["stable"]},
                }
            ],
        }
    )
    _write_yaml(genai_path, genai)

    operations_path = root / "schemas/telemetry/v8/operations.yaml"
    operations = yaml.safe_load(operations_path.read_text(encoding="utf-8"))
    body = next(group for group in operations["groups"] if group["id"] == "body.fixture")
    body["body_fields"] = [
        {
            "ref": "defenseclaw.test.name",
            "requirement_level": "optional",
            "constraints": {"max_utf8_bytes": 64},
        }
    ]
    metric = next(
        group
        for group in operations["groups"]
        if group.get("metric", {}).get("instrument_name") == "defenseclaw.activity.diff_entries"
    )
    metric["metric"]["description"] = "Preserved metric description."
    metric["metric"]["boundaries"] = [1, 2, 4]
    mapping = operations["producer_mappings"][0]
    identity = copy.deepcopy(mapping["default_identity"])
    mapping["event_name_policy"] = "context_optional"
    mapping["allowed_context_identity_set"] = "fixture-contexts"
    mapping["mandatory_rules"] = ["always"]
    mapping["companion_rules"] = ["enforcement_when_enforced"]
    mapping["compatibility"] = {
        "introduced_in": "telemetry-registry-v1",
        "legacy_event_prefix": "legacy.audit",
        "disposition": "translate_to_v8",
        "removal_version": "telemetry-registry-v2",
    }
    operations["producer_identity_sets"] = [{"id": "fixture-contexts", "identities": [identity]}]
    _write_yaml(operations_path, operations)

    examples_path = root / "schemas/telemetry/v8/examples.yaml"
    examples = yaml.safe_load(examples_path.read_text(encoding="utf-8"))
    invalid_record = copy.deepcopy(examples["examples"][0]["record"])
    invalid_record["bucket"] = "tool.activity"
    invalid_record["body"]["attributes"]["defenseclaw.bucket"] = "tool.activity"
    examples["examples"].append(
        {
            "id": "fixture.invalid",
            "valid": False,
            "signal": "traces",
            "family": "span.model.chat",
            "base_example": "model.chat.valid",
            "mutation": {
                "kind": "family_bucket_mismatch",
                "changes": [
                    {"op": "replace", "path": "/record/bucket", "value": "tool.activity"},
                    {
                        "op": "replace",
                        "path": "/record/body/attributes/defenseclaw.bucket",
                        "value": "tool.activity",
                    },
                ],
            },
            "description": "Preserved invalid example.",
            "record": invalid_record,
            "expected_error": "family_bucket_mismatch",
        }
    )
    _write_yaml(examples_path, examples)

    module = _load_generator_module("telemetry_registry_full_ir_test")
    ir = module.compile_registry(root)
    domains = {domain.domain: domain for domain in ir.domains}
    genai_ir = domains["genai"]
    operations_ir = domains["operations"]
    attribute_ir = next(item for item in genai_ir.attributes if item.id == "defenseclaw.test.name")
    span_ir = next(group for group in genai_ir.groups if group.id == "span.model.chat")
    body_ir = next(group for group in operations_ir.groups if group.id == "body.fixture")
    log_ir = next(group for group in operations_ir.groups if group.id == "diagnostic.message")
    metric_ir = next(
        group for group in operations_ir.groups if group.instrument_name == "defenseclaw.activity.diff_entries"
    )
    mapping_ir = operations_ir.producer_mappings[0]

    assert ir.registry_path == "schemas/telemetry/v8/registry.yaml"
    assert ir.dependency_lock_path == "schemas/telemetry/v8/semconv.lock.yaml"
    assert ir.examples_path == "examples.yaml"
    assert ir.metric_cardinality_limit == 2048
    assert ir.semantic_profiles[0].trace_schema_version == "defenseclaw-trace-v1"
    assert ir.metric_compatibility_profile.derived_spanmetrics.pipeline == "spanmetrics/agent360"
    assert ir.metric_compatibility_profile.derived_spanmetrics.dimensions_cache_size == 10000
    assert ir.normalizers[1].allowed_overrides[:2] == (
        "max_utf8_bytes",
        "max_item_utf8_bytes",
    )

    core = next(dependency for dependency in ir.dependencies if dependency.id == "otel_core")
    assert core.snapshot.source_archive.endswith(f"/{core.revision}.tar.gz")
    assert core.snapshot.format_version == 1
    assert core.snapshot.format == "defenseclaw-normalized-semconv-v1"
    assert core.snapshot.source_files[0].path == "model/registry.yaml"
    assert len(core.snapshot.source_files[0].sha256) == 64
    assert core.snapshot.attributes[0].stability_source == "upstream"
    ownership = {item.ref: item.owner for item in ir.upstream_attribute_ownership}
    assert ownership["service.name"] == "otel"
    assert ownership["gen_ai.operation.name"] == "otel_genai"
    assert ownership["openinference.project.name"] == "openinference_compatibility"

    assert attribute_ir.brief == "Preserved attribute brief."
    assert attribute_ir.examples[1] == "value"
    assert attribute_ir.introduced_in == "telemetry-registry-v1"
    assert dict(attribute_ir.normalization.overrides) == {"max_utf8_bytes": 128}
    assert attribute_ir.normalization.notes == "Preserved normalization note."
    assert attribute_ir.legacy_bindings is not None
    assert attribute_ir.legacy_bindings[0].details_present is True
    assert attribute_ir.legacy_bindings[0].details is None
    assert attribute_ir.legacy_bindings[1].details_present is False
    assert genai_ir.attribute_extensions[0].normalization.notes == ("Preserved extension normalization note.")

    assert span_ir.brief == "Preserved span brief."
    assert span_ir.stability == "stable"
    assert span_ir.span_kinds == ("CLIENT",)
    assert span_ir.span_status_rule == "technical_error_only"
    assert span_ir.attribute_uses[0].role == "attributes"
    assert span_ir.attribute_uses[0].requirement_level == "conditional"
    assert span_ir.attribute_uses[0].conditional == "operation-terminal-v1"
    assert body_ir.attribute_uses[0].role == "body_fields"
    assert body_ir.resolved_uses[0].role == "body_fields"
    assert span_ir.allowed_outcomes == ("completed", "failed")
    assert span_ir.outcome_requirement == "optional"
    assert span_ir.event_refs == ("guardrail.decision",)
    assert span_ir.link_relations == ("caused_by",)
    assert span_ir.mandatory_floor == ("always",)
    assert span_ir.route_selector is False
    assert span_ir.compatibility_profiles == ("local-observability-v1",)
    assert span_ir.family_schema_version == 1
    assert span_ir.bucket == "model.io"
    assert span_ir.legacy_bindings is not None
    assert span_ir.legacy_bindings[0].details["nested"] == ("stable",)
    assert log_ir.event_name == "diagnostic.message"
    assert log_ir.brief == "A diagnostic message."
    assert log_ir.stability == "stable"
    assert log_ir.outcome_requirement == "forbidden"
    assert log_ir.allowed_outcomes == ()

    assert metric_ir.instrument_type == "histogram"
    assert metric_ir.metric_description == "Preserved metric description."
    assert metric_ir.metric_boundaries == (1, 2, 4)
    assert metric_ir.family_schema_version == 1
    assert metric_ir.bucket == "diagnostic"
    assert metric_ir.outcome_requirement is None
    assert metric_ir.allowed_outcomes is None
    assert mapping_ir.source == "gateway"
    assert mapping_ir.severity_policy == "canonical_or_info"
    assert mapping_ir.mandatory_rules == ("always",)
    assert mapping_ir.companion_rules == ("enforcement_when_enforced",)
    assert mapping_ir.context_identity_set_id == "fixture-contexts"
    assert mapping_ir.compatibility is not None
    assert mapping_ir.compatibility.removal_version == "telemetry-registry-v2"
    assert operations_ir.producer_identity_sets[0].id == "fixture-contexts"
    assert mapping_ir.default_identity == operations_ir.producer_identity_sets[0].identities[0]

    assert len(ir.examples) == 2
    assert ir.examples[0].valid is True
    assert ir.examples[0].field_classes["/attributes/gen_ai.operation.name"] == "metadata"
    assert ir.examples[1].valid is False
    assert ir.examples[1].expected_error == "family_bucket_mismatch"
    assert ir.examples[1].base_example == "model.chat.valid"
    assert ir.examples[1].mutation is not None
    assert ir.examples[1].mutation.changes[0].path == "/record/bucket"
    assert ir.examples[1].record["bucket"] == "tool.activity"
    assert dict(ir.examples[1].field_classes) == {}

    with pytest.raises(TypeError):
        attribute_ir.normalization.overrides["max_utf8_bytes"] = 1024
    with pytest.raises(TypeError):
        span_ir.attribute_uses[0].constraints["max_utf8_bytes"] = 1024
    with pytest.raises(TypeError):
        ir.normalizers[1].default_constraints["max_utf8_bytes"] = 1024
    with pytest.raises(TypeError):
        ir.metric_compatibility_profile.high_cardinality_families["mutated"] = ()
    with pytest.raises(TypeError):
        ir.examples[0].field_classes["/mutated"] = "metadata"
    assert span_ir.legacy_bindings is not None
    assert span_ir.legacy_bindings[0].details is not None
    with pytest.raises(TypeError):
        span_ir.legacy_bindings[0].details["nested"] = ()
    with pytest.raises(TypeError):
        ir.examples[0].record["mutated"] = True


def test_mapping_bearing_ir_classes_are_explicitly_equality_only() -> None:
    module = _load_generator_module("telemetry_registry_hash_contract_test")
    equality_only = (
        module.NormalizerIR,
        module.NormalizationIR,
        module.LegacyBindingIR,
        module.AttributeIR,
        module.AttributeExtensionIR,
        module.MetricCompatibilityProfileIR,
        module.AttributeUseIR,
        module.AttributeUseOriginIR,
        module.ResolvedAttributeUseIR,
        module.GroupIR,
        module.DomainIR,
        module.ExampleIR,
        module.RegistryIR,
    )

    assert all(cls.__hash__ is None for cls in equality_only)


def test_unknown_upstream_owner_mapping_fails_with_registry_error() -> None:
    module = _load_generator_module("telemetry_registry_owner_error_test")

    with pytest.raises(module.RegistryError, match="no public attribute-owner mapping"):
        module._public_upstream_owner("unknown_dependency")


@pytest.mark.parametrize(
    "surface",
    [
        "attribute",
        "normalization",
        "attribute_extension",
        "attribute_use",
        "span",
        "metric",
        "x_defenseclaw",
        "producer_mapping",
        "producer_identity",
        "compatibility",
        "example",
    ],
)
def test_compiler_ir_source_surfaces_reject_unknown_keys(
    tmp_path: Path,
    surface: str,
) -> None:
    root = _fixture_root(tmp_path)
    if surface in {
        "attribute",
        "normalization",
        "attribute_extension",
        "attribute_use",
        "span",
    }:
        path = root / "schemas/telemetry/v8/genai.yaml"
        document = yaml.safe_load(path.read_text(encoding="utf-8"))
        target = {
            "attribute": document["attributes"][0],
            "normalization": document["attributes"][0]["normalization"],
            "attribute_extension": document["attribute_extensions"][0],
            "attribute_use": document["groups"][0]["attributes"][0],
            "span": document["groups"][0]["span"],
        }[surface]
    elif surface in {"metric", "x_defenseclaw", "producer_mapping", "producer_identity", "compatibility"}:
        path = root / "schemas/telemetry/v8/operations.yaml"
        document = yaml.safe_load(path.read_text(encoding="utf-8"))
        metric = next(group for group in document["groups"] if group["type"] == "metric")
        mapping = document["producer_mappings"][0]
        if surface == "compatibility":
            mapping["compatibility"] = {"unexpected": "value"}
            target = None
        else:
            target = {
                "metric": metric["metric"],
                "x_defenseclaw": metric["x-defenseclaw"],
                "producer_mapping": mapping,
                "producer_identity": mapping["default_identity"],
            }[surface]
    else:
        path = root / "schemas/telemetry/v8/examples.yaml"
        document = yaml.safe_load(path.read_text(encoding="utf-8"))
        target = document["examples"][0]
    if target is not None:
        target["unexpected"] = "value"
    _write_yaml(path, document)

    result = _run(root, "--write")

    assert result.returncode == 1
    assert "unknown keys ['unexpected']" in result.stderr


@pytest.mark.parametrize(
    ("surface", "value", "expected"),
    [
        ("allowed_outcomes", ["invented"], "unknown outcome"),
        ("link_relations", ["parent_of"], "unknown relation"),
        ("compatibility_profiles", ["unknown-v1"], "unknown profile"),
        ("span_kinds", ["client"], "unsupported OTel span kind"),
    ],
)
def test_group_runtime_vocabularies_are_closed(
    tmp_path: Path,
    surface: str,
    value: list[str],
    expected: str,
) -> None:
    root = _fixture_root(tmp_path)
    path = root / "schemas/telemetry/v8/genai.yaml"
    document = yaml.safe_load(path.read_text(encoding="utf-8"))
    if surface == "span_kinds":
        document["groups"][0]["span"]["kinds"] = value
    else:
        document["groups"][0]["x-defenseclaw"][surface] = value
    _write_yaml(path, document)

    result = _run(root, "--write")

    assert result.returncode == 1
    assert expected in result.stderr


@pytest.mark.parametrize(
    ("requirement_level", "include_clause", "expected"),
    [
        ("conditional", False, "required for conditional fields"),
        ("required", True, "allowed only for conditional fields"),
        ("recommended", True, "allowed only for conditional fields"),
        ("optional", True, "allowed only for conditional fields"),
    ],
)
def test_attribute_use_conditional_clause_is_exactly_coupled_to_level(
    tmp_path: Path,
    requirement_level: str,
    include_clause: bool,
    expected: str,
) -> None:
    root = _fixture_root(tmp_path)
    path = root / "schemas/telemetry/v8/genai.yaml"
    document = yaml.safe_load(path.read_text(encoding="utf-8"))
    use = document["groups"][0]["attributes"][0]
    use["requirement_level"] = requirement_level
    if include_clause:
        use["conditional"] = "only for the fixture condition"
    else:
        use.pop("conditional", None)
    _write_yaml(path, document)

    result = _run(root, "--write")

    assert result.returncode == 1
    assert expected in result.stderr


@pytest.mark.parametrize(
    ("mutation", "expected"),
    [
        ("missing_requirement", "require outcome_requirement and allowed_outcomes"),
        ("missing_allowed", "require outcome_requirement and allowed_outcomes"),
        ("forbidden_nonempty", "forbidden outcome requires an empty"),
        ("required_empty", "required/optional outcome requires nonempty"),
        ("out_of_order", "must follow defenseclaw.outcome order"),
        ("globally_broad", "globally broad allowed_outcomes is forbidden"),
    ],
)
def test_log_span_outcome_contract_is_exact(
    tmp_path: Path,
    mutation: str,
    expected: str,
) -> None:
    root = _fixture_root(tmp_path)
    path = root / "schemas/telemetry/v8/genai.yaml"
    document = yaml.safe_load(path.read_text(encoding="utf-8"))
    extension = document["groups"][0]["x-defenseclaw"]
    vocabulary = next(attribute for attribute in document["attributes"] if attribute["id"] == "defenseclaw.outcome")[
        "normalization"
    ]["overrides"]["enum"]
    if mutation == "missing_requirement":
        extension.pop("outcome_requirement")
    elif mutation == "missing_allowed":
        extension.pop("allowed_outcomes")
    elif mutation == "forbidden_nonempty":
        extension["outcome_requirement"] = "forbidden"
        extension["allowed_outcomes"] = ["completed"]
    elif mutation == "required_empty":
        extension["outcome_requirement"] = "required"
        extension["allowed_outcomes"] = []
    elif mutation == "out_of_order":
        extension["allowed_outcomes"] = ["completed", "allowed"]
    else:
        extension["allowed_outcomes"] = list(vocabulary)
    _write_yaml(path, document)

    result = _run(root, "--write")

    assert result.returncode == 1
    assert expected in result.stderr


@pytest.mark.parametrize("key", ["outcome_requirement", "allowed_outcomes"])
def test_metric_forbids_envelope_outcome_contract(tmp_path: Path, key: str) -> None:
    root = _fixture_root(tmp_path)
    path = root / "schemas/telemetry/v8/operations.yaml"
    document = yaml.safe_load(path.read_text(encoding="utf-8"))
    metric = next(group for group in document["groups"] if group["type"] == "metric")
    metric["x-defenseclaw"][key] = "optional" if key == "outcome_requirement" else ["completed"]
    _write_yaml(path, document)

    result = _run(root, "--write")

    assert result.returncode == 1
    assert "outcome contract is allowed only on logs/spans" in result.stderr


def test_allowed_outcome_order_is_derived_from_canonical_source(tmp_path: Path) -> None:
    root = _fixture_root(tmp_path)
    path = root / "schemas/telemetry/v8/genai.yaml"
    document = yaml.safe_load(path.read_text(encoding="utf-8"))
    outcome = next(attribute for attribute in document["attributes"] if attribute["id"] == "defenseclaw.outcome")
    vocabulary = outcome["normalization"]["overrides"]["enum"]
    vocabulary.remove("completed")
    vocabulary.insert(0, "completed")
    document["groups"][0]["x-defenseclaw"]["allowed_outcomes"] = [
        "completed",
        "allowed",
    ]
    _write_yaml(path, document)
    registry_path = root / "schemas/telemetry/v8/registry.yaml"
    registry = yaml.safe_load(registry_path.read_text(encoding="utf-8"))
    structural_outcome = next(
        field for field in registry["structural_contract"]["envelope"]["fields"] if field["name"] == "outcome"
    )
    structural_outcome["normalization"]["overrides"]["enum"] = list(vocabulary)
    _write_yaml(registry_path, registry)

    result = _run(root, "--write")

    assert result.returncode == 0, result.stderr


def test_real_family_outcome_contract_matrix_is_exact() -> None:
    module = _load_generator_module("telemetry_registry_real_outcome_contract_test")
    ir = module.compile_registry(ROOT)
    attributes = {attribute.id: attribute for domain in ir.domains for attribute in domain.attributes}
    outcome_order = attributes["defenseclaw.outcome"].normalization.effective_constraints["enum"]
    families = [group for domain in ir.domains for group in domain.groups if group.type in {"log", "span"}]

    assert outcome_order == _CANONICAL_OUTCOME_ORDER
    assert sum(group.type == "log" for group in families) == 87
    assert sum(group.type == "span" for group in families) == 25
    assert len(families) == len({group.id for group in families}) == 112
    assert all(group.outcome_requirement is not None for group in families)
    assert all(group.allowed_outcomes is not None for group in families)

    contracts = [(group.id, group.outcome_requirement, group.allowed_outcomes) for group in families]
    matrix = _grouped_outcome_contract_matrix(contracts)
    family_counts = {
        requirement: sum(
            len(family_ids) for matrix_requirement, _, family_ids in matrix if matrix_requirement == requirement
        )
        for requirement in {item[0] for item in matrix}
    }

    assert len(matrix) == 46
    assert family_counts == {"forbidden": 10, "required": 102}
    assert _outcome_contract_digest(contracts) == _REAL_FAMILY_OUTCOME_CONTRACT_DIGEST


def test_real_family_outcome_contract_digest_detects_single_family_drift() -> None:
    module = _load_generator_module("telemetry_registry_outcome_drift_lock_test")
    ir = module.compile_registry(ROOT)
    contracts = [
        (group.id, group.outcome_requirement, group.allowed_outcomes)
        for domain in ir.domains
        for group in domain.groups
        if group.type in {"log", "span"}
    ]
    required_index = next(index for index, (_, requirement, _) in enumerate(contracts) if requirement == "required")
    multi_outcome_index = next(index for index, (_, _, outcomes) in enumerate(contracts) if len(outcomes) > 1)

    broadened = list(contracts)
    family_id, requirement, _ = broadened[required_index]
    broadened[required_index] = (family_id, requirement, _CANONICAL_OUTCOME_ORDER[:-1])

    requirement_drift = list(contracts)
    family_id, _, outcomes = requirement_drift[required_index]
    requirement_drift[required_index] = (family_id, "optional", outcomes)

    subset_drift = list(contracts)
    family_id, requirement, outcomes = subset_drift[multi_outcome_index]
    subset_drift[multi_outcome_index] = (family_id, requirement, outcomes[:-1])

    assert _outcome_contract_digest(contracts) == _REAL_FAMILY_OUTCOME_CONTRACT_DIGEST
    assert {
        _outcome_contract_digest(broadened),
        _outcome_contract_digest(requirement_drift),
        _outcome_contract_digest(subset_drift),
    }.isdisjoint({_REAL_FAMILY_OUTCOME_CONTRACT_DIGEST})


def test_group_resolution_deduplicates_diamond_origins_and_strengthens(tmp_path: Path) -> None:
    root = _fixture_root(tmp_path)
    path = root / "schemas/telemetry/v8/genai.yaml"
    document = yaml.safe_load(path.read_text(encoding="utf-8"))
    document["groups"].extend(
        [
            {
                "id": "diamond.base",
                "type": "attribute_group",
                "brief": "Diamond base.",
                "stability": "development",
                "attributes": [
                    {
                        "ref": "defenseclaw.test.name",
                        "requirement_level": "optional",
                        "constraints": {"max_utf8_bytes": 128},
                    }
                ],
            },
            {
                "id": "diamond.left",
                "type": "attribute_group",
                "brief": "Diamond left.",
                "stability": "development",
                "extends": ["diamond.base"],
                "attributes": [
                    {
                        "ref": "defenseclaw.test.name",
                        "requirement_level": "recommended",
                        "constraints": {"max_utf8_bytes": 64},
                    }
                ],
            },
            {
                "id": "diamond.right",
                "type": "attribute_group",
                "brief": "Diamond right.",
                "stability": "development",
                "extends": ["diamond.base"],
                "attributes": [
                    {
                        "ref": "defenseclaw.test.name",
                        "requirement_level": "required",
                        "constraints": {"max_utf8_bytes": 96},
                    }
                ],
            },
        ]
    )
    document["groups"][0]["extends"] = ["span.core", "diamond.left", "diamond.right"]
    _write_yaml(path, document)
    _materialize_trace_attribute(root, "defenseclaw.test.name", "fixture", "metadata")
    module = _load_generator_module("telemetry_registry_diamond_test")

    ir = module.compile_registry(root)
    span = next(group for domain in ir.domains for group in domain.groups if group.id == "span.model.chat")
    use = next(item for item in span.resolved_uses if item.ref == "defenseclaw.test.name")

    assert use.role == "attributes"
    assert use.requirement_level == "required"
    assert dict(use.constraints) == {"max_utf8_bytes": 64}
    assert tuple(origin.group_id for origin in use.origins) == (
        "diamond.base",
        "diamond.left",
        "diamond.right",
    )
    assert len(ir.group_resolution_order) == len(set(ir.group_resolution_order))
    position = {group_id: index for index, group_id in enumerate(ir.group_resolution_order)}
    assert position["diamond.base"] < position["diamond.left"] < position["span.model.chat"]
    assert position["diamond.base"] < position["diamond.right"] < position["span.model.chat"]
    assert ir.resolved_group_uses[span.id] == span.resolved_uses


def test_body_group_transposes_direct_and_inherited_uses_for_logs(tmp_path: Path) -> None:
    root = _fixture_root(tmp_path)
    path = root / "schemas/telemetry/v8/operations.yaml"
    document = yaml.safe_load(path.read_text(encoding="utf-8"))
    body = next(group for group in document["groups"] if group["id"] == "body.fixture")
    document["groups"].append(
        {
            "id": "body.source",
            "type": "attribute_group",
            "brief": "Body source.",
            "stability": "development",
            "attributes": [{"ref": "defenseclaw.test.name", "requirement_level": "optional"}],
        }
    )
    body["extends"] = ["body.source"]
    body["body_fields"] = [{"ref": "defenseclaw.test.name", "requirement_level": "required"}]
    _write_yaml(path, document)
    module = _load_generator_module("telemetry_registry_body_transpose_test")

    ir = module.compile_registry(root)
    log = next(group for domain in ir.domains for group in domain.groups if group.id == "diagnostic.message")
    use = next(item for item in log.resolved_uses if item.ref == "defenseclaw.test.name")

    assert use.role == "body_fields"
    assert use.requirement_level == "required"
    assert tuple((origin.group_id, origin.role) for origin in use.origins) == (
        ("body.source", "attributes"),
        ("body.fixture", "body_fields"),
    )


@pytest.mark.parametrize(
    ("mutation", "expected"),
    [
        ("span_body_parent", "incompatible body_group parent"),
        ("attribute_body_direct", "body_fields are not allowed for attribute_group"),
        ("log_no_parent", "log must extend exactly one body_group"),
        ("log_two_parents", "log must extend exactly one body_group"),
        ("log_attribute_parent", "incompatible attribute_group parent"),
    ],
)
def test_group_resolution_rejects_role_and_log_parent_ambiguity(
    tmp_path: Path,
    mutation: str,
    expected: str,
) -> None:
    root = _fixture_root(tmp_path)
    if mutation == "span_body_parent":
        path = root / "schemas/telemetry/v8/genai.yaml"
        document = yaml.safe_load(path.read_text(encoding="utf-8"))
        document["groups"][0]["extends"] = ["span.core", "body.fixture"]
    else:
        path = root / "schemas/telemetry/v8/operations.yaml"
        document = yaml.safe_load(path.read_text(encoding="utf-8"))
        log = next(group for group in document["groups"] if group["id"] == "diagnostic.message")
        if mutation == "attribute_body_direct":
            document["groups"].append(
                {
                    "id": "invalid.attribute.role",
                    "type": "attribute_group",
                    "brief": "Invalid role.",
                    "stability": "development",
                    "body_fields": [{"ref": "defenseclaw.test.name", "requirement_level": "optional"}],
                }
            )
        elif mutation == "log_no_parent":
            log["extends"] = []
        elif mutation == "log_two_parents":
            document["groups"].append(
                {
                    "id": "body.fixture.two",
                    "type": "body_group",
                    "brief": "Second body.",
                    "stability": "development",
                }
            )
            log["extends"] = ["body.fixture", "body.fixture.two"]
        else:
            document["groups"].append(
                {
                    "id": "attribute.fixture.parent",
                    "type": "attribute_group",
                    "brief": "Attribute parent.",
                    "stability": "development",
                }
            )
            log["extends"] = ["attribute.fixture.parent"]
    _write_yaml(path, document)

    result = _run(root, "--write")

    assert result.returncode == 1
    assert expected in result.stderr


def test_group_resolution_rejects_cycles_even_when_unreferenced(tmp_path: Path) -> None:
    root = _fixture_root(tmp_path)
    path = root / "schemas/telemetry/v8/genai.yaml"
    document = yaml.safe_load(path.read_text(encoding="utf-8"))
    document["groups"].extend(
        [
            {
                "id": "cycle.one",
                "type": "attribute_group",
                "brief": "Cycle one.",
                "stability": "development",
                "extends": ["cycle.two"],
            },
            {
                "id": "cycle.two",
                "type": "attribute_group",
                "brief": "Cycle two.",
                "stability": "development",
                "extends": ["cycle.one"],
            },
        ]
    )
    _write_yaml(path, document)

    result = _run(root, "--write")

    assert result.returncode == 1
    assert "inheritance cycle" in result.stderr


@pytest.mark.parametrize(
    ("requirements", "conditionals", "expected_level", "expected_conditional", "error"),
    [
        (("optional", "recommended"), (None, None), "recommended", None, None),
        (
            ("conditional", "conditional"),
            ("connector-known-v1", "connector-known-v1"),
            "conditional",
            "connector-known-v1",
            None,
        ),
        (
            ("conditional", "conditional", "required"),
            ("connector-known-v1", "operation-terminal-v1", None),
            "required",
            None,
            None,
        ),
        (
            ("conditional", "conditional"),
            ("connector-known-v1", "operation-terminal-v1"),
            None,
            None,
            "conflicting dominant conditional",
        ),
    ],
)
def test_requirement_lattice_and_conditional_clause_merge(
    tmp_path: Path,
    requirements: tuple[str, ...],
    conditionals: tuple[str | None, ...],
    expected_level: str | None,
    expected_conditional: str | None,
    error: str | None,
) -> None:
    root = _fixture_root(tmp_path)
    path = root / "schemas/telemetry/v8/genai.yaml"
    document = yaml.safe_load(path.read_text(encoding="utf-8"))
    parents: list[str] = []
    for index, (requirement, conditional) in enumerate(zip(requirements, conditionals, strict=True)):
        group_id = f"lattice.{index}"
        use: dict[str, Any] = {
            "ref": "defenseclaw.test.name",
            "requirement_level": requirement,
        }
        if conditional is not None:
            use["conditional"] = conditional
        document["groups"].append(
            {
                "id": group_id,
                "type": "attribute_group",
                "brief": "Lattice parent.",
                "stability": "development",
                "attributes": [use],
            }
        )
        parents.append(group_id)
    document["groups"][0]["extends"] = ["span.core", *parents]
    _write_yaml(path, document)
    if error is not None:
        result = _run(root, "--write")
        assert result.returncode == 1
        assert error in result.stderr
        return
    if expected_level == "required":
        _materialize_trace_attribute(root, "defenseclaw.test.name", "fixture", "metadata")
    module = _load_generator_module(f"telemetry_registry_lattice_{len(requirements)}")
    ir = module.compile_registry(root)
    span = next(group for domain in ir.domains for group in domain.groups if group.id == "span.model.chat")
    use = next(item for item in span.resolved_uses if item.ref == "defenseclaw.test.name")
    assert use.requirement_level == expected_level
    assert use.conditional == expected_conditional


def test_constraint_intersection_is_restrictive_and_deterministic(tmp_path: Path) -> None:
    root = _fixture_root(tmp_path)
    path = root / "schemas/telemetry/v8/genai.yaml"
    document = yaml.safe_load(path.read_text(encoding="utf-8"))
    document["groups"].extend(
        [
            {
                "id": "constraints.left",
                "type": "attribute_group",
                "brief": "Constraint left.",
                "stability": "development",
                "attributes": [
                    {
                        "ref": "defenseclaw.test.name",
                        "requirement_level": "optional",
                        "constraints": {
                            "enum": ["alpha", "beta", "gamma"],
                            "pattern": "^[a-z]+$",
                            "max_utf8_bytes": 128,
                        },
                    }
                ],
            },
            {
                "id": "constraints.right",
                "type": "attribute_group",
                "brief": "Constraint right.",
                "stability": "development",
                "attributes": [
                    {
                        "ref": "defenseclaw.test.name",
                        "requirement_level": "recommended",
                        "constraints": {
                            "enum": ["gamma", "beta"],
                            "pattern": "^[a-z]+$",
                            "max_utf8_bytes": 64,
                        },
                    }
                ],
            },
        ]
    )
    document["groups"][0]["extends"] = ["span.core", "constraints.left", "constraints.right"]
    _write_yaml(path, document)
    module = _load_generator_module("telemetry_registry_constraint_merge_test")

    ir = module.compile_registry(root)
    span = next(group for domain in ir.domains for group in domain.groups if group.id == "span.model.chat")
    use = next(item for item in span.resolved_uses if item.ref == "defenseclaw.test.name")

    assert dict(use.constraints) == {
        "enum": ("beta", "gamma"),
        "pattern": "^[a-z]+$",
        "max_utf8_bytes": 64,
    }


def test_structured_constraint_intersection_uses_lower_depth_and_property_limits(
    tmp_path: Path,
) -> None:
    root = _fixture_root(tmp_path)
    path = root / "schemas/telemetry/v8/genai.yaml"
    document = yaml.safe_load(path.read_text(encoding="utf-8"))
    document["attributes"].append(
        {
            "id": "defenseclaw.test.object",
            "type": "object",
            "brief": "Structured merge fixture.",
            "examples": [{"fixture": "value"}],
            "stability": "development",
            "owner": "defenseclaw",
            "field_class": "metadata",
            "sensitivity": "safe",
            "cardinality": "bounded",
            "normalization": {"id": "structured-content-v1"},
            "introduced_in": "telemetry-registry-v1",
        }
    )
    parents = []
    for index, constraints in enumerate(
        (
            {"max_depth": 7, "max_properties": 100},
            {"max_depth": 4, "max_properties": 60},
        )
    ):
        group_id = f"structured.constraints.{index}"
        document["groups"].append(
            {
                "id": group_id,
                "type": "attribute_group",
                "brief": "Structured constraints.",
                "stability": "development",
                "attributes": [
                    {
                        "ref": "defenseclaw.test.object",
                        "requirement_level": "optional",
                        "constraints": constraints,
                    }
                ],
            }
        )
        parents.append(group_id)
    document["groups"][0]["extends"] = ["span.core", *parents]
    _write_yaml(path, document)
    module = _load_generator_module("telemetry_registry_structured_constraint_test")

    ir = module.compile_registry(root)
    span = next(group for domain in ir.domains for group in domain.groups if group.id == "span.model.chat")
    use = next(item for item in span.resolved_uses if item.ref == "defenseclaw.test.object")

    assert dict(use.constraints) == {"max_depth": 4, "max_properties": 60}


def test_enum_intersection_preserves_bool_int_and_float_type_identity() -> None:
    module = _load_generator_module("telemetry_registry_enum_type_identity_test")

    def origin(group_id: str, values: list[bool | int | float]) -> Any:
        return module.AttributeUseOriginIR(
            group_id,
            "attributes",
            "optional",
            None,
            module._freeze_mapping({"enum": values}),
        )

    merged = module._intersect_use_constraints(
        "enum.identity",
        "defenseclaw.test.scalar",
        (
            origin("enum.left", [True, 1, 1.0]),
            origin("enum.right", [1.0, 1, True]),
        ),
    )

    assert merged["enum"] == (True, 1, 1.0)
    assert tuple(type(value) for value in merged["enum"]) == (bool, int, float)
    for left, right in ((True, 1), (1, 1.0), (True, 1.0)):
        with pytest.raises(module.RegistryError, match="empty enum intersection"):
            module._intersect_use_constraints(
                "enum.noncollision",
                "defenseclaw.test.scalar",
                (origin("enum.left", [left]), origin("enum.right", [right])),
            )


@pytest.mark.parametrize(
    ("left", "right", "expected"),
    [
        ({"enum": ["alpha"]}, {"enum": ["beta"]}, "empty enum intersection"),
        ({"pattern": "^alpha$"}, {"pattern": "^beta$"}, "nonrepresentable pattern"),
    ],
)
def test_constraint_intersection_rejects_empty_or_nonrepresentable(
    tmp_path: Path,
    left: dict[str, Any],
    right: dict[str, Any],
    expected: str,
) -> None:
    root = _fixture_root(tmp_path)
    path = root / "schemas/telemetry/v8/genai.yaml"
    document = yaml.safe_load(path.read_text(encoding="utf-8"))
    parents = []
    for index, constraints in enumerate((left, right)):
        group_id = f"invalid.constraints.{index}"
        document["groups"].append(
            {
                "id": group_id,
                "type": "attribute_group",
                "brief": "Invalid constraints.",
                "stability": "development",
                "attributes": [
                    {
                        "ref": "defenseclaw.test.name",
                        "requirement_level": "optional",
                        "constraints": constraints,
                    }
                ],
            }
        )
        parents.append(group_id)
    document["groups"][0]["extends"] = ["span.core", *parents]
    _write_yaml(path, document)

    result = _run(root, "--write")

    assert result.returncode == 1
    assert expected in result.stderr


def test_constraint_intersection_rejects_inconsistent_numeric_range(tmp_path: Path) -> None:
    root = _fixture_root(tmp_path)
    path = root / "schemas/telemetry/v8/genai.yaml"
    document = yaml.safe_load(path.read_text(encoding="utf-8"))
    document["attributes"].append(
        {
            "id": "defenseclaw.test.number",
            "type": "int64",
            "brief": "Numeric merge fixture.",
            "examples": [50],
            "stability": "development",
            "owner": "defenseclaw",
            "field_class": "metadata",
            "sensitivity": "safe",
            "cardinality": "bounded",
            "normalization": {
                "id": "numeric-range-v1",
                "overrides": {"min": 0, "max": 100},
            },
            "introduced_in": "telemetry-registry-v1",
        }
    )
    document["groups"].extend(
        [
            {
                "id": "range.minimum",
                "type": "attribute_group",
                "brief": "Range minimum.",
                "stability": "development",
                "attributes": [
                    {
                        "ref": "defenseclaw.test.number",
                        "requirement_level": "optional",
                        "constraints": {"min": 80},
                    }
                ],
            },
            {
                "id": "range.maximum",
                "type": "attribute_group",
                "brief": "Range maximum.",
                "stability": "development",
                "attributes": [
                    {
                        "ref": "defenseclaw.test.number",
                        "requirement_level": "optional",
                        "constraints": {"max": 40},
                    }
                ],
            },
        ]
    )
    document["groups"][0]["extends"] = ["span.core", "range.minimum", "range.maximum"]
    _write_yaml(path, document)

    result = _run(root, "--write")

    assert result.returncode == 1
    assert "inconsistent min/max intersection" in result.stderr


@pytest.mark.parametrize(
    ("left", "right", "expected"),
    [
        (
            {"min_items": 5},
            {"max_items": 3},
            "inconsistent min_items/max_items intersection",
        ),
        (
            {"max_utf8_bytes": 10},
            {"max_item_utf8_bytes": 20},
            "incompatible UTF-8 bounds",
        ),
    ],
)
def test_constraint_intersection_rejects_inconsistent_collection_bounds(
    tmp_path: Path,
    left: dict[str, Any],
    right: dict[str, Any],
    expected: str,
) -> None:
    root = _fixture_root(tmp_path)
    path = root / "schemas/telemetry/v8/genai.yaml"
    document = yaml.safe_load(path.read_text(encoding="utf-8"))
    attribute = copy.deepcopy(document["attributes"][0])
    attribute.update(
        {
            "id": "defenseclaw.test.names",
            "type": "string[]",
            "examples": [["fixture"]],
        }
    )
    document["attributes"].append(attribute)
    parents = []
    for index, constraints in enumerate((left, right)):
        group_id = f"invalid.collection.constraints.{index}"
        document["groups"].append(
            {
                "id": group_id,
                "type": "attribute_group",
                "brief": "Invalid collection constraints.",
                "stability": "development",
                "attributes": [
                    {
                        "ref": "defenseclaw.test.names",
                        "requirement_level": "optional",
                        "constraints": constraints,
                    }
                ],
            }
        )
        parents.append(group_id)
    document["groups"][0]["extends"] = ["span.core", *parents]
    _write_yaml(path, document)

    result = _run(root, "--write")

    assert result.returncode == 1
    assert expected in result.stderr


def test_real_registry_resolves_once_with_zero_ambiguity() -> None:
    module = _load_generator_module("telemetry_registry_real_resolution_test")

    ir = module.compile_registry(ROOT)
    groups = {group.id: group for domain in ir.domains for group in domain.groups}
    positions = {group_id: index for index, group_id in enumerate(ir.group_resolution_order)}
    materialized_order = ir.materialized_view.facts["fields"]["group_resolution_order"]

    assert len(ir.group_resolution_order) == len(groups) == len(ir.resolved_group_uses)
    assert len(set(ir.group_resolution_order)) == len(groups)
    assert materialized_order == ir.group_resolution_order
    for group in groups.values():
        assert group.resolved_uses == ir.resolved_group_uses[group.id]
        assert len({use.ref for use in group.resolved_uses}) == len(group.resolved_uses)
        assert all(positions[parent] < positions[group.id] for parent in group.extends)
        if group.type == "log":
            assert len(group.extends) == 1
            assert groups[group.extends[0]].type == "body_group"
            assert all(use.role == "body_fields" for use in group.resolved_uses)
        elif group.type in {"span", "resource", "metric", "span_event"}:
            assert all(use.role == "attributes" for use in group.resolved_uses)


def test_span_name_placeholder_rejects_high_cardinality_attribute(tmp_path: Path) -> None:
    root = _fixture_root(tmp_path)
    domain_path = root / "schemas/telemetry/v8/genai.yaml"
    domain = yaml.safe_load(domain_path.read_text(encoding="utf-8"))
    domain["attribute_extensions"][0]["cardinality"] = "high"
    _write_yaml(domain_path, domain)

    result = _run(root, "--write")

    assert result.returncode == 1
    assert "unsafe name placeholder gen_ai.operation.name" in result.stderr


def test_valid_example_field_class_map_is_complete_and_exact(tmp_path: Path) -> None:
    root = _fixture_root(tmp_path)
    examples_path = root / "schemas/telemetry/v8/examples.yaml"
    examples = yaml.safe_load(examples_path.read_text(encoding="utf-8"))
    examples["examples"][0]["record"]["field_classes"] = {}
    _write_yaml(examples_path, examples)

    result = _run(root, "--write")

    assert result.returncode == 1
    assert "field_classes: coverage mismatch" in result.stderr
    assert "/attributes/gen_ai.operation.name" in result.stderr


def test_real_registry_has_exact_authoritative_family_counts() -> None:
    groups: list[dict[str, Any]] = []
    for domain in ("genai", "security", "operations"):
        document = yaml.safe_load((ROOT / f"schemas/telemetry/v8/{domain}.yaml").read_text(encoding="utf-8"))
        groups.extend(document["groups"])

    assert sum(group["type"] == "span" for group in groups) == 25
    assert sum(group["type"] == "metric" for group in groups) == 131


def test_named_producer_identity_set_resolves_to_explicit_contexts(tmp_path: Path) -> None:
    root = _fixture_root(tmp_path)
    path = root / "schemas/telemetry/v8/operations.yaml"
    document = yaml.safe_load(path.read_text(encoding="utf-8"))
    mapping = document["producer_mappings"][0]
    identity = mapping.pop("default_identity")
    mapping["event_name_policy"] = "context_required"
    mapping["allowed_context_identity_set"] = "diagnostic-context"
    document["producer_identity_sets"] = [{"id": "diagnostic-context", "identities": [identity]}]
    _write_yaml(path, document)

    result = _run(root, "--write")

    assert result.returncode == 0, result.stderr


@pytest.mark.parametrize(
    ("mode", "expected"),
    [
        ("unknown", "unknown set"),
        ("empty", "expected nonempty sequence"),
        ("duplicate", "duplicate identity"),
        ("unreferenced", "unreferenced producer identity sets"),
        ("fixed_ref", "not allowed for fixed policy"),
    ],
)
def test_named_producer_identity_sets_reject_ambiguous_shapes(
    tmp_path: Path,
    mode: str,
    expected: str,
) -> None:
    root = _fixture_root(tmp_path)
    path = root / "schemas/telemetry/v8/operations.yaml"
    document = yaml.safe_load(path.read_text(encoding="utf-8"))
    mapping = document["producer_mappings"][0]
    identity = dict(mapping["default_identity"])
    identities = [] if mode == "empty" else [identity]
    if mode == "duplicate":
        identities.append(dict(identity))
    if mode != "unknown":
        document["producer_identity_sets"] = [{"id": "diagnostic-context", "identities": identities}]
    if mode == "unknown":
        mapping.pop("default_identity")
        mapping["event_name_policy"] = "context_required"
        mapping["allowed_context_identity_set"] = "missing-context"
    elif mode == "fixed_ref":
        mapping["allowed_context_identity_set"] = "diagnostic-context"
    elif mode != "unreferenced":
        mapping.pop("default_identity")
        mapping["event_name_policy"] = "context_required"
        mapping["allowed_context_identity_set"] = "diagnostic-context"
    _write_yaml(path, document)

    result = _run(root, "--write")

    assert result.returncode == 1
    assert expected in result.stderr


@pytest.mark.parametrize(
    ("suffix", "expected"),
    [
        ("\nschema_version: 1\n", "duplicate YAML key"),
        ("\nunknown_key: true\n", "unknown keys"),
        ("\nbase: &base {value: 1}\nmerged: {<<: *base}\n", "anchors and aliases"),
        ("\ntagged: !defenseclaw value\n", "explicit YAML tags"),
    ],
)
def test_strict_yaml_rejects_ambiguous_or_unknown_input(
    tmp_path: Path,
    suffix: str,
    expected: str,
) -> None:
    root = _fixture_root(tmp_path)
    registry = root / "schemas/telemetry/v8/registry.yaml"
    registry.write_text(registry.read_text(encoding="utf-8") + suffix, encoding="utf-8")

    result = _run(root, "--write")

    assert result.returncode == 1
    assert expected in result.stderr
    assert not (root / "schemas/telemetry/generated").exists()


def test_strict_yaml_rejects_invalid_utf8(tmp_path: Path) -> None:
    root = _fixture_root(tmp_path)
    registry = root / "schemas/telemetry/v8/registry.yaml"
    registry.write_bytes(registry.read_bytes() + b"\xff")

    result = _run(root, "--write")

    assert result.returncode == 1
    assert "invalid UTF-8" in result.stderr


def test_check_detects_extra_and_stale_outputs(tmp_path: Path) -> None:
    root = _fixture_root(tmp_path)
    assert _run(root, "--write").returncode == 0
    generated = root / "schemas/telemetry/generated"
    extra = generated / "unowned.json"
    extra.write_text("{}\n", encoding="utf-8")
    result = _run(root, "--check")
    assert result.returncode == 1
    assert "extra=['unowned.json']" in result.stderr
    extra.unlink()
    manifest = generated / "output-manifest.json"
    manifest.write_bytes(manifest.read_bytes() + b" ")
    result = _run(root, "--check")
    assert result.returncode == 1
    assert "stale=['output-manifest.json']" in result.stderr
    assert manifest.is_file()
    assert not any(generated.parent.glob(".telemetry-generated-stage-*"))

    assert _run(root, "--write").returncode == 0
    manifest.unlink()
    result = _run(root, "--check")
    assert result.returncode == 1
    assert "missing=['output-manifest.json']" in result.stderr
    assert not manifest.exists()
    assert not any(generated.parent.glob(".telemetry-generated-stage-*"))


def _upstream_archive(path: Path, *, malformed_yaml: bool = False) -> None:
    source = (
        b"attributes:\n  - key: [unterminated\n"
        if malformed_yaml
        else b"""\
file_format: definition/2
attributes:
  - key: gen_ai.test.attribute
    type: string
    brief: Test attribute.
    stability: development
  - key: gen_ai.test.any_value
    type: any
    brief: Structured any value.
    stability: development
  - key: gen_ai.test.bytes
    type: bytes
    brief: Opaque bytes value.
    stability: development
"""
    )
    with tarfile.open(path, "w:gz") as archive:
        info = tarfile.TarInfo("semantic-conventions-genai/model/gen-ai/registry.yaml")
        info.size = len(source)
        archive.addfile(info, io.BytesIO(source))


def _openinference_archive(
    path: Path,
    *,
    version_value: str = "0.1.30",
    unknown_type: bool = False,
    malformed_header: bool = False,
    constants_mismatch: bool = False,
    reverse_members: bool = False,
) -> None:
    resource = b'class ResourceAttributes:\n    PROJECT_NAME = "openinference.project.name"\n'
    version = f'__version__ = "{version_value}"\n'.encode()
    typed = {
        "input.value": "String",
        "input.mime_type": "String",
        "output.value": "String",
        "output.mime_type": "String",
        "openinference.span.kind": "String",
        "llm.token_count.total": "Integer",
        "llm.cost.total": "Float",
        "tag.tags": "List of strings",
        "embedding.vector": "List of floats",
        "message_content.image": "Image Object",
        "llm.tools": "List of objects<sup>†</sup>",
        "metadata": "JSON String",
        "document.id": "String/Integer",
    }
    for index in range(79):
        typed[f"fixture.attribute.{index:03d}"] = "String"
    assert len(typed) == 92
    constants_only = {
        "completion.text",
        "llm.cost.completion_details",
        "llm.cost.prompt_details",
        "llm.token_count.prompt_details",
        "llm.token_count.prompt_details.cache_input",
        "prompt.text",
    }
    if constants_mismatch:
        constants_only.remove("prompt.text")
    trace_lines = ["class SpanAttributes:"]
    for index, identifier in enumerate(sorted(set(typed) | constants_only)):
        trace_lines.append(f'    ATTRIBUTE_{index} = "{identifier}"')
    trace = ("\n".join(trace_lines) + "\n").encode()
    table_only = {
        "exception.escaped": "Boolean",
        "exception.message": "String",
        "exception.stacktrace": "String",
        "exception.type": "String",
    }
    table_rows = [
        "## Reserved Attributes",
        "",
        (
            "| Name | Type | Example | Description |"
            if malformed_header
            else "| Attribute | Type | Example | Description |"
        ),
        "| --- | --- | --- | --- |",
    ]
    for identifier, type_name in sorted({**typed, **table_only}.items()):
        if unknown_type and identifier == "input.value":
            type_name = "Opaque Mystery"
        table_rows.append(f"| `{identifier}` | {type_name} | `value` | Fixture. |")
    table_rows.extend(["", "## Next Section", ""])
    specification = "\n".join(table_rows).encode()
    foreign = b"""\
class InstrumentationAliases:
    FOREIGN = "gen_ai.operation.name"
"""
    files = {
        "openinference/python/openinference-semantic-conventions/src/openinference/semconv/resource/__init__.py": resource,
        "openinference/python/openinference-semantic-conventions/src/openinference/semconv/trace/__init__.py": trace,
        "openinference/python/openinference-semantic-conventions/src/openinference/semconv/version.py": version,
        "openinference/spec/semantic_conventions.md": specification,
        "openinference/python/instrumentation/example.py": foreign,
    }
    archive_items = list(files.items())
    if reverse_members:
        archive_items.reverse()
    with tarfile.open(path, "w:gz") as archive:
        for name, source in archive_items:
            info = tarfile.TarInfo(name)
            info.size = len(source)
            archive.addfile(info, io.BytesIO(source))


def test_explicit_updater_derives_snapshot_from_local_pinned_archive(tmp_path: Path) -> None:
    root = _fixture_root(tmp_path)
    archive = tmp_path / "genai.tar.gz"
    _upstream_archive(archive)
    result = subprocess.run(
        [
            sys.executable,
            str(UPDATER),
            "--write",
            "--root",
            str(root),
            "--dependency",
            "otel_genai",
            "--archive",
            f"otel_genai={archive}",
        ],
        cwd=ROOT,
        check=False,
        capture_output=True,
        text=True,
        timeout=60,
    )
    assert result.returncode == 0, result.stderr
    snapshot_path = root / "schemas/telemetry/v8/upstream/otel-genai.normalized.json"
    snapshot = json.loads(snapshot_path.read_bytes())
    assert [item["id"] for item in snapshot["attributes"]] == [
        "gen_ai.test.any_value",
        "gen_ai.test.attribute",
        "gen_ai.test.bytes",
    ]
    any_value = next(item for item in snapshot["attributes"] if item["id"] == "gen_ai.test.any_value")
    assert any_value["allowed_types"] == []
    assert any_value["shape"] == "any_value"
    bytes_value = next(item for item in snapshot["attributes"] if item["id"] == "gen_ai.test.bytes")
    assert bytes_value["allowed_types"] == ["bytes"]
    assert bytes_value["shape"] == "attribute"
    lock = yaml.safe_load((root / "schemas/telemetry/v8/semconv.lock.yaml").read_text(encoding="utf-8"))
    dependency = next(item for item in lock["dependencies"] if item["id"] == "otel_genai")
    assert dependency["snapshot"]["sha256"] == _sha256(snapshot_path.read_bytes())


def test_updater_rejects_malformed_yaml_with_source_context(tmp_path: Path) -> None:
    root = _fixture_root(tmp_path)
    archive = tmp_path / "malformed-genai.tar.gz"
    _upstream_archive(archive, malformed_yaml=True)

    result = subprocess.run(
        [
            sys.executable,
            str(UPDATER),
            "--write",
            "--root",
            str(root),
            "--dependency",
            "otel_genai",
            "--archive",
            f"otel_genai={archive}",
        ],
        cwd=ROOT,
        check=False,
        capture_output=True,
        text=True,
        timeout=60,
    )

    assert result.returncode == 1
    assert "model/gen-ai/registry.yaml: parse failure" in result.stderr


def test_checked_in_otel_any_values_preserve_any_value_shape() -> None:
    expected = {
        "otel-core-v1.42.0.normalized.json": "feature_flag.result.value",
        "otel-genai-b028dceecdad117461a785c3af35315e7184e813.normalized.json": "gen_ai.input.messages",
    }
    for filename, identifier in expected.items():
        snapshot = json.loads((ROOT / "schemas/telemetry/v8/upstream" / filename).read_bytes())
        attribute = next(item for item in snapshot["attributes"] if item["id"] == identifier)
        assert attribute["allowed_types"] == []
        assert attribute["shape"] == "any_value"


def test_checked_in_upstream_privacy_extensions_are_explicit() -> None:
    extensions: dict[str, dict[str, Any]] = {}
    for domain in ("genai", "security", "operations"):
        document = yaml.safe_load((ROOT / f"schemas/telemetry/v8/{domain}.yaml").read_text(encoding="utf-8"))
        for extension in document["attribute_extensions"]:
            assert extension["ref"] not in extensions
            extensions[extension["ref"]] = extension
    for reference in (
        "gen_ai.input.messages",
        "gen_ai.output.messages",
        "gen_ai.tool.call.arguments",
        "gen_ai.tool.call.result",
    ):
        assert extensions[reference]["field_class"] == "content"
        assert extensions[reference]["sensitivity"] == "sensitive"
        assert extensions[reference]["cardinality"] == "high"
    assert extensions["exception.message"]["field_class"] == "error"
    assert extensions["exception.message"]["sensitivity"] == "sensitive"
    assert extensions["url.full"]["field_class"] == "path"
    assert extensions["url.full"]["sensitivity"] == "sensitive"


def test_openinference_updater_uses_only_authoritative_semconv_package(tmp_path: Path) -> None:
    root = _fixture_root(tmp_path)
    archive = tmp_path / "openinference.tar.gz"
    _openinference_archive(archive)
    result = subprocess.run(
        [
            sys.executable,
            str(UPDATER),
            "--write",
            "--root",
            str(root),
            "--dependency",
            "openinference",
            "--archive",
            f"openinference={archive}",
        ],
        cwd=ROOT,
        check=False,
        capture_output=True,
        text=True,
        timeout=60,
    )

    assert result.returncode == 0, result.stderr
    snapshot_path = root / "schemas/telemetry/v8/upstream/openinference.normalized.json"
    snapshot = json.loads(snapshot_path.read_bytes())
    assert [item["path"] for item in snapshot["source_files"]] == [
        "python/openinference-semantic-conventions/src/openinference/semconv/resource/__init__.py",
        "python/openinference-semantic-conventions/src/openinference/semconv/trace/__init__.py",
        "python/openinference-semantic-conventions/src/openinference/semconv/version.py",
        "spec/semantic_conventions.md",
    ]
    identifiers = {item["id"] for item in snapshot["attributes"]}
    assert {
        "openinference.span.kind",
        "input.value",
        "input.mime_type",
        "output.value",
        "output.mime_type",
    }.issubset(identifiers)
    assert not any(identifier.startswith("gen_ai.") for identifier in identifiers)
    attributes = {item["id"]: item for item in snapshot["attributes"]}
    assert attributes["llm.token_count.total"]["allowed_types"] == ["int64"]
    assert attributes["llm.cost.total"]["allowed_types"] == ["double"]
    assert attributes["tag.tags"]["allowed_types"] == ["string[]"]
    assert attributes["embedding.vector"]["allowed_types"] == ["double[]"]
    assert attributes["document.id"]["allowed_types"] == ["string", "int64"]
    assert attributes["message_content.image"]["shape"] == "object_prefix"
    assert attributes["message_content.image"]["allowed_types"] == []
    assert attributes["llm.tools"]["shape"] == "indexed_prefix"
    assert attributes["llm.tools"]["allowed_types"] == []
    assert "metadata" in attributes
    assert "openinference.project.name" in attributes
    assert not any(identifier.startswith("exception.") for identifier in attributes)


def test_openinference_updater_rejects_package_version_mismatch(tmp_path: Path) -> None:
    root = _fixture_root(tmp_path)
    archive = tmp_path / "openinference.tar.gz"
    _openinference_archive(archive, version_value="0.1.31")

    result = subprocess.run(
        [
            sys.executable,
            str(UPDATER),
            "--write",
            "--root",
            str(root),
            "--dependency",
            "openinference",
            "--archive",
            f"openinference={archive}",
        ],
        cwd=ROOT,
        check=False,
        capture_output=True,
        text=True,
        timeout=60,
    )

    assert result.returncode == 1
    assert "package version does not match lock" in result.stderr


@pytest.mark.parametrize(
    ("option", "expected"),
    [
        ("unknown_type", "unsupported Reserved Attributes type"),
        ("malformed_header", "expected one Reserved Attributes table"),
        ("constants_mismatch", "expected 99 canonical constants"),
    ],
)
def test_openinference_updater_rejects_malformed_authority(
    tmp_path: Path,
    option: str,
    expected: str,
) -> None:
    root = _fixture_root(tmp_path)
    archive = tmp_path / "openinference.tar.gz"
    _openinference_archive(archive, **{option: True})
    result = subprocess.run(
        [
            sys.executable,
            str(UPDATER),
            "--write",
            "--root",
            str(root),
            "--dependency",
            "openinference",
            "--archive",
            f"openinference={archive}",
        ],
        cwd=ROOT,
        check=False,
        capture_output=True,
        text=True,
        timeout=60,
    )

    assert result.returncode == 1
    assert expected in result.stderr


def test_openinference_archive_member_order_does_not_change_snapshot(tmp_path: Path) -> None:
    snapshots: list[bytes] = []
    for index, reverse in enumerate((False, True)):
        root = _fixture_root(tmp_path / str(index))
        archive = tmp_path / f"openinference-{index}.tar.gz"
        _openinference_archive(archive, reverse_members=reverse)
        result = subprocess.run(
            [
                sys.executable,
                str(UPDATER),
                "--write",
                "--root",
                str(root),
                "--dependency",
                "openinference",
                "--archive",
                f"openinference={archive}",
            ],
            cwd=ROOT,
            check=False,
            capture_output=True,
            text=True,
            timeout=60,
        )
        assert result.returncode == 0, result.stderr
        snapshots.append((root / "schemas/telemetry/v8/upstream/openinference.normalized.json").read_bytes())

    assert snapshots[0] == snapshots[1]


def test_updater_validation_failure_preserves_all_existing_bytes(tmp_path: Path) -> None:
    root = _fixture_root(tmp_path)
    archive = tmp_path / "genai.tar.gz"
    _upstream_archive(archive)
    invalid = tmp_path / "invalid-openinference.tar.gz"
    invalid.write_bytes(b"not a tar archive")
    lock_path = root / "schemas/telemetry/v8/semconv.lock.yaml"
    snapshot_path = root / "schemas/telemetry/v8/upstream/otel-genai.normalized.json"
    before = {lock_path: lock_path.read_bytes(), snapshot_path: snapshot_path.read_bytes()}

    result = subprocess.run(
        [
            sys.executable,
            str(UPDATER),
            "--write",
            "--root",
            str(root),
            "--dependency",
            "otel_genai",
            "--dependency",
            "openinference",
            "--archive",
            f"otel_genai={archive}",
            "--archive",
            f"openinference={invalid}",
        ],
        cwd=ROOT,
        check=False,
        capture_output=True,
        text=True,
        timeout=60,
    )

    assert result.returncode == 1
    assert {path: path.read_bytes() for path in before} == before


def test_structural_contract_ir_is_closed_lossless_and_runtime_bound(tmp_path: Path) -> None:
    root = _fixture_root(tmp_path)
    module = _load_generator_module("telemetry_registry_structural_contract")

    ir = module.compile_registry(root)

    contract = ir.structural_contract
    assert contract.id == "defenseclaw.canonical-record"
    assert contract.version == 1
    assert contract.additional_properties is False
    assert contract.runtime_binding.record == "internal/observability.Record"
    assert contract.runtime_binding.schema_derived_constructor == ("internal/observability.newSchemaDerivedRecord")
    assert contract.runtime_binding.schema_derived_log_constructor == (
        "internal/observability.newSchemaDerivedLogRecord"
    )
    assert dict(contract.limits.values) == {
        "record_id_utf8_bytes": 512,
        "correlation_id_utf8_bytes": 512,
        "span_name_utf8_bytes": 512,
        "binary_version_utf8_bytes": 256,
        "provenance_hex_ascii_bytes": 128,
        "stable_token_ascii_bytes": 128,
        "payload_depth": 32,
        "payload_members": 8192,
        "payload_encoded_bytes": 1048576,
        "record_encoded_bytes": 4194304,
    }
    assert tuple(field.name for field in contract.trace_body.fields) == (
        "kind",
        "start_time_unix_nano",
        "end_time_unix_nano",
        "parent_span_id",
        "status",
        "resource",
        "scope",
        "attributes",
        "dropped_attributes_count",
        "events",
        "dropped_events_count",
        "links",
        "dropped_links_count",
    )
    trace_fields = {field.name: field for field in contract.trace_body.fields}
    assert trace_fields["start_time_unix_nano"].field_type == "uint64"
    assert trace_fields["start_time_unix_nano"].otlp_target == "startTimeUnixNano"
    assert trace_fields["attributes"].semantic_ref == "registry.family_attributes"
    assert trace_fields["resource"].otlp_target is None
    assert trace_fields["scope"].otlp_target is None
    assert contract.trace_relations[0].left == "start_time_unix_nano"
    assert contract.trace_relations[0].right == "end_time_unix_nano"
    assert {
        (
            item.target_attribute,
            item.source,
            item.equality,
            item.presence,
        )
        for item in contract.trace_derivations
    } == {
        ("defenseclaw.bucket", "envelope.bucket", "typed-json-exact", "when-registered"),
        ("defenseclaw.span.family", "family.id", "typed-json-exact", "when-registered"),
        (
            "defenseclaw.span.family_schema_version",
            "family.family_schema_version",
            "typed-json-exact",
            "when-registered",
        ),
        ("defenseclaw.source", "envelope.source", "typed-json-exact", "when-registered"),
        (
            "defenseclaw.config.generation",
            "provenance.config_generation",
            "typed-json-exact",
            "when-registered",
        ),
        (
            "defenseclaw.outcome",
            "envelope.outcome",
            "typed-json-exact",
            "when-registered-and-source-present",
        ),
    }
    assert {field.name for field in contract.trace_body.fields}.isdisjoint(
        {"trace_id", "span_id", "name", "traceId", "spanId"}
    )
    assert tuple(field.name for field in contract.metric_instrument_data.fields) == (
        "value",
        "attributes",
    )
    assert contract.metric_instrument_data.fields[0].field_type == "metric_number"
    assert contract.metric_instrument_data.fields[0].semantic_ref == "registry.metric_value"
    assert [(arm.signal, arm.payload_field) for arm in contract.signal_arms] == [
        ("logs", "body"),
        ("traces", "body"),
        ("metrics", "instrument_data"),
    ]
    assert tuple(condition.id for condition in ir.conditions) == (
        "connector-known-v1",
        "operation-terminal-v1",
        "technical-failure-v1",
        "guardrail-terminal-decision-available-v1",
        "security-severity-available-v1",
        "judge-output-parse-failed-v1",
        "admin-principal-known-v1",
    )
    assert all(condition.enforcement.kind == "builder_fact" for condition in ir.conditions)
    assert {condition.false_requirement for condition in ir.conditions} == {"forbidden", "optional"}
    phase_catalog = ir.value_catalogs[0]
    assert phase_catalog.id == "agent-phase-v1"
    assert phase_catalog.kind == "string-int64-bijection"
    assert phase_catalog.value_attributes == (
        "defenseclaw.agent.phase",
        "defenseclaw.agent.phase.previous",
        "defenseclaw.agent.phase.from",
        "defenseclaw.agent.phase.to",
    )
    assert phase_catalog.paired_value_attribute == "defenseclaw.agent.phase"
    assert tuple((entry.value, entry.code) for entry in phase_catalog.entries) == tuple(
        (phase, index) for index, phase in enumerate(_CANONICAL_AGENT_PHASES, 1)
    )
    assert phase_catalog.compatibility.code == 0
    assert phase_catalog.compatibility.value == "unknown"
    assert phase_catalog.compatibility.canonical_emittable is False
    assert dict(contract.canonical_to_otlp.object_contexts)["trace_link"].endswith("links[]")
    assert dict(contract.canonical_to_otlp.field_context_overrides) == {
        "trace_resource.schema_url": "ResourceSpans",
        "trace_scope.schema_url": "ResourceSpans.scopeSpans[]",
    }
    assert ("uint32", "intValue") in contract.canonical_to_otlp.any_value_mapping
    assert contract.canonical_to_otlp.any_value_mapping[-1] == ("object", "kvlistValue")
    with pytest.raises(TypeError):
        contract.limits.values["payload_depth"] = 8


def test_family_schema_version_materializes_as_uint32_with_exact_otlp_projection() -> None:
    module = _load_generator_module("telemetry_registry_family_schema_version_uint32")

    ir = module.compile_registry(ROOT)
    attribute = next(
        attribute
        for domain in ir.domains
        for attribute in domain.attributes
        if attribute.id == "defenseclaw.span.family_schema_version"
    )
    assert attribute.field_type == "uint32"
    assert dict(attribute.normalization.effective_constraints) == {
        "min": 1,
        "max": 2**32 - 1,
    }
    assert module._attribute_type_accepts(2**32 - 1, attribute.field_type)
    assert not module._attribute_type_accepts(2**32, attribute.field_type)

    materialized_domains = ir.materialized_view.facts["fields"]["domains"]
    materialized_genai = next(domain for domain in materialized_domains if domain["fields"]["domain"] == "genai")
    materialized_attribute = next(
        candidate
        for candidate in materialized_genai["fields"]["attributes"]
        if candidate["fields"]["id"] == "defenseclaw.span.family_schema_version"
    )
    assert materialized_attribute["fields"]["field_type"] == "uint32"
    assert ("uint32", "intValue") in ir.structural_contract.canonical_to_otlp.any_value_mapping
    assert 2**32 - 1 <= 2**63 - 1


def test_family_schema_version_above_uint32_is_rejected_before_rendering(tmp_path: Path) -> None:
    root = _fixture_root(tmp_path)
    path = root / "schemas/telemetry/v8/genai.yaml"
    document = yaml.safe_load(path.read_text(encoding="utf-8"))
    document["groups"][0]["x-defenseclaw"]["family_schema_version"] = 2**32
    _write_yaml(path, document)

    result = _run(root, "--write")

    assert result.returncode == 1
    assert "x-defenseclaw.family_schema_version: expected integer in [1, 4294967295]" in result.stderr


@pytest.mark.parametrize(
    ("mutation", "expected"),
    [
        (
            lambda registry: registry["structural_contract"]["trace"]["body"]["fields"][1].__setitem__(
                "name", "startTimeUnixNano"
            ),
            "canonical structural names must be snake_case",
        ),
        (
            lambda registry: registry["structural_contract"]["correlation"]["fields"][4]["otlp"].__setitem__(
                "target", "wrongTraceId"
            ),
            "typed OTLP mapping mismatch",
        ),
    ],
)
def test_structural_contract_drift_fails_closed(
    tmp_path: Path,
    mutation: Any,
    expected: str,
) -> None:
    root = _fixture_root(tmp_path)
    path = root / "schemas/telemetry/v8/registry.yaml"
    registry = yaml.safe_load(path.read_text(encoding="utf-8"))
    mutation(registry)
    _write_yaml(path, registry)

    result = _run(root, "--write")

    assert result.returncode == 1
    assert expected in result.stderr


@pytest.mark.parametrize(
    ("mutation", "expected"),
    [
        (
            lambda contract: contract["canonical_to_otlp"]["field_context_overrides"].__setitem__(
                "trace_resource.schema_url", "ResourceSpans.resource"
            ),
            "field_context_overrides: differs from OTLP field placement",
        ),
        (
            lambda contract: contract["canonical_to_otlp"]["span_kind_mapping"][4].__setitem__("otlp", 4),
            "span_kind_mapping: differs from OTLP v1",
        ),
        (
            lambda contract: contract["canonical_to_otlp"]["any_value_mapping"][0].__setitem__(
                "otlp_arm", "stringValue"
            ),
            "any_value_mapping: differs from OTLP AnyValue v1",
        ),
    ],
)
def test_otlp_protocol_representation_is_closed(
    tmp_path: Path,
    mutation: Any,
    expected: str,
) -> None:
    root = _fixture_root(tmp_path)
    path = root / "schemas/telemetry/v8/registry.yaml"
    registry = yaml.safe_load(path.read_text(encoding="utf-8"))
    mutation(registry["structural_contract"])
    _write_yaml(path, registry)

    result = _run(root, "--write")

    assert result.returncode == 1
    assert expected in result.stderr


@pytest.mark.parametrize(
    ("field_path", "mutation", "expected"),
    [
        (
            ("envelope", "outcome"),
            lambda field: field.__setitem__("field_class", "identifier"),
            "semantic attribute mismatch",
        ),
        (
            ("correlation", "trace_id"),
            lambda field: field["normalization"]["overrides"].__setitem__("max_utf8_bytes", 31),
            "semantic-format mismatch",
        ),
    ],
)
def test_structural_semantic_bindings_reject_local_drift(
    tmp_path: Path,
    field_path: tuple[str, str],
    mutation: Any,
    expected: str,
) -> None:
    root = _fixture_root(tmp_path)
    path = root / "schemas/telemetry/v8/registry.yaml"
    registry = yaml.safe_load(path.read_text(encoding="utf-8"))
    object_name, field_name = field_path
    fields = registry["structural_contract"][object_name]["fields"]
    mutation(next(field for field in fields if field["name"] == field_name))
    _write_yaml(path, registry)

    result = _run(root, "--write")

    assert result.returncode == 1
    assert expected in result.stderr


def test_runtime_limits_are_source_owned_not_mirrored_in_compiler(tmp_path: Path) -> None:
    root = _fixture_root(tmp_path)
    path = root / "schemas/telemetry/v8/registry.yaml"
    registry = yaml.safe_load(path.read_text(encoding="utf-8"))
    registry["structural_contract"]["limits"]["payload_depth"] = 31
    _write_yaml(path, registry)
    module = _load_generator_module("telemetry_registry_source_owned_limits")

    ir = module.compile_registry(root)

    assert ir.structural_contract.limits.values["payload_depth"] == 31


def test_conditional_use_requires_registered_stable_condition_id(tmp_path: Path) -> None:
    root = _fixture_root(tmp_path)
    path = root / "schemas/telemetry/v8/genai.yaml"
    domain = yaml.safe_load(path.read_text(encoding="utf-8"))
    domain["groups"][0]["attributes"][0].update({"requirement_level": "conditional", "conditional": "connector known"})
    _write_yaml(path, domain)

    result = _run(root, "--write")

    assert result.returncode == 1
    assert "unknown condition ID" in result.stderr


@pytest.mark.parametrize(
    ("mutation", "expected"),
    [
        (
            lambda conditions: conditions[1]["enforcement"].__setitem__("fact", conditions[0]["enforcement"]["fact"]),
            "duplicate builder fact",
        ),
        (
            lambda conditions: conditions[0].__setitem__("false_requirement", "required"),
            "false_requirement: unsupported value",
        ),
    ],
)
def test_condition_builder_facts_and_false_semantics_are_closed(
    tmp_path: Path,
    mutation: Any,
    expected: str,
) -> None:
    root = _fixture_root(tmp_path)
    path = root / "schemas/telemetry/v8/registry.yaml"
    registry = yaml.safe_load(path.read_text(encoding="utf-8"))
    mutation(registry["conditions"])
    _write_yaml(path, registry)

    result = _run(root, "--write")

    assert result.returncode == 1
    assert expected in result.stderr


def test_signal_family_requires_explicit_lifecycle(tmp_path: Path) -> None:
    root = _fixture_root(tmp_path)
    path = root / "schemas/telemetry/v8/genai.yaml"
    domain = yaml.safe_load(path.read_text(encoding="utf-8"))
    domain["groups"][0].pop("introduced_in")
    _write_yaml_raw(path, domain)

    result = _run(root, "--write")

    assert result.returncode == 1
    assert "introduced_in: required for every group" in result.stderr


@pytest.mark.parametrize(
    "attribute_id",
    [
        "defenseclaw.agent.phase",
        "defenseclaw.agent.phase.previous",
        "defenseclaw.agent.phase.from",
        "defenseclaw.agent.phase.to",
    ],
)
def test_phase_value_catalog_binds_every_value_attribute_enum(
    tmp_path: Path,
    attribute_id: str,
) -> None:
    root = _fixture_root(tmp_path)
    path = root / "schemas/telemetry/v8/genai.yaml"
    domain = yaml.safe_load(path.read_text(encoding="utf-8"))
    phase = next(item for item in domain["attributes"] if item["id"] == attribute_id)
    phase["normalization"]["overrides"]["enum"].append("invented")
    _write_yaml(path, domain)

    result = _run(root, "--write")

    assert result.returncode == 1
    assert "must use the exact catalog enum" in result.stderr


def test_phase_value_catalog_binds_code_range(tmp_path: Path) -> None:
    root = _fixture_root(tmp_path)
    path = root / "schemas/telemetry/v8/genai.yaml"
    domain = yaml.safe_load(path.read_text(encoding="utf-8"))
    phase_code = next(item for item in domain["attributes"] if item["id"] == "defenseclaw.agent.phase.code")
    phase_code["normalization"]["overrides"]["min"] = 0
    _write_yaml(path, domain)

    result = _run(root, "--write")

    assert result.returncode == 1
    assert "code attribute must use the exact catalog range" in result.stderr


def test_removed_group_cannot_remain_route_selectable(tmp_path: Path) -> None:
    root = _fixture_root(tmp_path)
    path = root / "schemas/telemetry/v8/genai.yaml"
    domain = yaml.safe_load(path.read_text(encoding="utf-8"))
    group = domain["groups"][0]
    group.update(
        {
            "stability": "deprecated",
            "deprecated_in": "telemetry-registry-v1",
            "removed_in": "telemetry-registry-v2",
        }
    )
    _write_yaml(path, domain)
    registry_path = root / "schemas/telemetry/v8/registry.yaml"
    registry = yaml.safe_load(registry_path.read_text(encoding="utf-8"))
    registry["registry_version"] = 2
    _write_yaml(registry_path, registry)

    result = _run(root, "--write")

    assert result.returncode == 1
    assert "removed group cannot remain route-selectable" in result.stderr


@pytest.mark.parametrize(
    ("value", "constraints"),
    [
        ({"outer": {"inner": "value"}}, {"max_depth": 0}),
        ({"outer": {"inner": "value"}}, {"max_properties": 1}),
        ({"outer": [1, 2]}, {"max_items": 2}),
        ({"outer": "four"}, {"max_item_utf8_bytes": 3}),
        ({"outer": "value"}, {"max_utf8_bytes": 8}),
        ({"outer": float("nan")}, {}),
    ],
)
def test_recursive_normalization_rejects_every_structured_bound(
    value: Any,
    constraints: dict[str, Any],
) -> None:
    module = _load_generator_module("telemetry_registry_recursive_normalization")

    assert module._constraints_accept(value, constraints) is False


# Produced by internal/observability.NewValue (marshalMinimalJSON) and kept here
# as cross-language byte-accounting goldens for the registry compiler.
_GO_CANONICAL_JSON_GOLDENS = (
    ("float-1e-6", {"n": 1e-6}, '{"n":1e-6}'),
    ("float-1e-7", {"n": 1e-7}, '{"n":1e-7}'),
    ("float-1e20", {"n": 1e20}, '{"n":1e20}'),
    ("float-1e21", {"n": 1e21}, '{"n":1e21}'),
    ("negative-zero", {"n": -0.0}, '{"n":0}'),
    ("int-million", {"n": 1_000_000}, '{"n":1e6}'),
    ("int-max", {"n": 2**63 - 1}, '{"n":9223372036854775807}'),
    ("html-line-separators", {"text": "<>&\u2028\u2029"}, '{"text":"<>&\u2028\u2029"}'),
    (
        "nested-key-and-string-escapes",
        {
            "z/key": ["line\n", 'quote"', "slash\\"],
            "a~key": {"control": "\b\f\r\t\u0001"},
        },
        '{"a~key":{"control":"\\b\\f\\r\\t\\u0001"},"z/key":["line\\n","quote\\"","slash\\\\"]}',
    ),
)


@pytest.mark.parametrize(
    ("name", "value", "expected"),
    _GO_CANONICAL_JSON_GOLDENS,
    ids=[item[0] for item in _GO_CANONICAL_JSON_GOLDENS],
)
def test_structured_byte_budget_matches_go_canonical_json_at_n_and_n_plus_one(
    name: str,
    value: Any,
    expected: str,
) -> None:
    del name
    module = _load_generator_module("telemetry_registry_go_canonical_json")
    expected_bytes = expected.encode("utf-8")

    assert module._canonical_json_bytes(value) == expected_bytes
    assert module._constraints_accept(value, {"max_utf8_bytes": len(expected_bytes)}) is True
    assert module._constraints_accept(value, {"max_utf8_bytes": len(expected_bytes) - 1}) is False


def test_array_types_validate_every_item_and_finite_numbers() -> None:
    module = _load_generator_module("telemetry_registry_array_item_types")

    assert module._attribute_type_accepts(["one", "two"], "string[]") is True
    assert module._attribute_type_accepts(["one", 2], "string[]") is False
    assert module._attribute_type_accepts([1, 2**63], "int64[]") is False
    assert module._attribute_type_accepts([1.0, float("inf")], "double[]") is False


@pytest.mark.parametrize("owner", ["local", "upstream"])
def test_materialized_examples_enforce_declared_dynamic_attribute_types(
    tmp_path: Path,
    owner: str,
) -> None:
    root = _fixture_root(tmp_path)
    path = root / "schemas/telemetry/v8/genai.yaml"
    domain = yaml.safe_load(path.read_text(encoding="utf-8"))
    group = domain["groups"][0]
    examples_path = root / "schemas/telemetry/v8/examples.yaml"
    examples = yaml.safe_load(examples_path.read_text(encoding="utf-8"))
    record = examples["examples"][0]["record"]
    if owner == "local":
        attribute = next(item for item in domain["attributes"] if item["id"] == "defenseclaw.test.name")
        attribute["type"] = "string[]"
        attribute["examples"] = [["fixture"]]
        attribute["normalization"] = {
            "id": "bounded-v1",
            "overrides": {"max_utf8_bytes": 128, "max_item_utf8_bytes": 64, "max_items": 4},
        }
        reference = "defenseclaw.test.name"
        value = ["valid", 7]
    else:
        reference = "gen_ai.current.000"
        domain["attribute_extensions"].append(
            {
                "ref": reference,
                "field_class": "metadata",
                "sensitivity": "safe",
                "cardinality": "low",
                "normalization": {"id": "bounded-v1", "overrides": {"max_utf8_bytes": 128}},
            }
        )
        value = 7
    group["attributes"].append({"ref": reference, "requirement_level": "required"})
    record["body"]["attributes"][reference] = value
    for pointer in _load_generator_module("telemetry_registry_type_pointer")._json_leaf_pointers(
        value,
        f"/attributes/{reference}",
    ):
        record["field_classes"][pointer] = "metadata"
    _write_yaml(path, domain)
    _write_yaml(examples_path, examples)

    result = _run(root, "--write")

    assert result.returncode == 1
    assert "dynamic_attribute_value_invalid" in result.stderr


@pytest.mark.parametrize(
    ("mutation", "expected"),
    [
        (
            lambda attribute: attribute.__setitem__("examples", [7]),
            "value does not match declared attribute type",
        ),
        (
            lambda attribute: attribute.__setitem__("examples", [None]),
            "value does not match declared attribute type",
        ),
        (
            lambda attribute: attribute.update(
                {
                    "examples": ["12345"],
                    "normalization": {
                        "id": "bounded-v1",
                        "overrides": {"max_utf8_bytes": 4},
                    },
                }
            ),
            "value violates declared normalization",
        ),
        (
            lambda attribute: attribute.update(
                {
                    "type": "string[]",
                    "examples": [["valid", 7]],
                    "normalization": {
                        "id": "bounded-v1",
                        "overrides": {
                            "max_utf8_bytes": 128,
                            "max_item_utf8_bytes": 64,
                            "max_items": 4,
                        },
                    },
                }
            ),
            "value does not match declared attribute type",
        ),
        (
            lambda attribute: attribute.update(
                {
                    "type": "object",
                    "examples": [{"nested": {"deeper": {}}}],
                    "normalization": {
                        "id": "structured-content-v1",
                        "overrides": {
                            "max_utf8_bytes": 128,
                            "max_item_utf8_bytes": 64,
                            "max_items": 4,
                            "max_depth": 1,
                            "max_properties": 4,
                        },
                    },
                }
            ),
            "value violates declared normalization",
        ),
    ],
)
def test_local_attribute_examples_are_executable_typed_metadata(
    tmp_path: Path,
    mutation: Any,
    expected: str,
) -> None:
    root = _fixture_root(tmp_path)
    path = root / "schemas/telemetry/v8/genai.yaml"
    domain = yaml.safe_load(path.read_text(encoding="utf-8"))
    attribute = next(item for item in domain["attributes"] if item["id"] == "defenseclaw.test.name")
    mutation(attribute)
    _write_yaml(path, domain)

    result = _run(root, "--write")

    assert result.returncode == 1
    assert expected in result.stderr


def test_field_class_derivation_matches_go_leaf_and_rfc6901_rules(tmp_path: Path) -> None:
    module = _load_generator_module("telemetry_registry_recursive_field_classes")
    value = {"a/b": {"~x": [None, "value"]}, "empty": {}}
    assert module._json_leaf_pointers(value) == (
        "/a~1b/~0x/0",
        "/a~1b/~0x/1",
        "/empty",
    )

    root = _fixture_root(tmp_path)
    domain_path = root / "schemas/telemetry/v8/genai.yaml"
    domain = yaml.safe_load(domain_path.read_text(encoding="utf-8"))
    attribute = next(item for item in domain["attributes"] if item["id"] == "defenseclaw.test.name")
    attribute["type"] = "object"
    attribute["examples"] = [{}]
    attribute["normalization"] = {
        "id": "structured-content-v1",
        "overrides": {
            "max_utf8_bytes": 1024,
            "max_item_utf8_bytes": 64,
            "max_items": 16,
            "max_depth": 4,
            "max_properties": 8,
        },
    }
    domain["groups"][0]["attributes"].append({"ref": "defenseclaw.test.name", "requirement_level": "required"})
    _write_yaml(domain_path, domain)
    examples_path = root / "schemas/telemetry/v8/examples.yaml"
    examples = yaml.safe_load(examples_path.read_text(encoding="utf-8"))
    record = examples["examples"][0]["record"]
    record["body"]["attributes"]["defenseclaw.test.name"] = value
    prefix = "/attributes/defenseclaw.test.name"
    for pointer in module._json_leaf_pointers(value, prefix):
        record["field_classes"][pointer] = "metadata"
    _write_yaml(examples_path, examples)

    accepted = _run(root, "--write")
    assert accepted.returncode == 0, accepted.stderr

    examples = yaml.safe_load(examples_path.read_text(encoding="utf-8"))
    classes = examples["examples"][0]["record"]["field_classes"]
    for pointer in tuple(classes):
        if pointer.startswith(prefix):
            classes.pop(pointer)
    classes[prefix] = "metadata"
    _write_yaml(examples_path, examples)
    rejected = _run(root, "--write")
    assert rejected.returncode == 1
    assert "coverage mismatch" in rejected.stderr


def test_every_pseudo_semantic_ref_is_required_exactly_once(tmp_path: Path) -> None:
    root = _fixture_root(tmp_path)
    path = root / "schemas/telemetry/v8/registry.yaml"
    registry = yaml.safe_load(path.read_text(encoding="utf-8"))
    event_name = next(
        field for field in registry["structural_contract"]["envelope"]["fields"] if field["name"] == "event_name"
    )
    event_name.pop("semantic_ref")
    _write_yaml(path, registry)

    result = _run(root, "--write")

    assert result.returncode == 1
    assert "missing pseudo semantic_ref" in result.stderr


def test_invalid_mutation_projection_uses_typed_json_equality(tmp_path: Path) -> None:
    root = _fixture_root(tmp_path)
    path = root / "schemas/telemetry/v8/examples.yaml"
    document = yaml.safe_load(path.read_text(encoding="utf-8"))
    valid = document["examples"][0]
    invalid_record = copy.deepcopy(valid["record"])
    invalid_record["body"]["start_time_unix_nano"] = 1.0
    document["examples"].append(
        {
            "id": "model.chat.typed-projection.invalid",
            "valid": False,
            "signal": "traces",
            "family": "span.model.chat",
            "description": "Integer and double JSON values are not projection-equal.",
            "record": invalid_record,
            "expected_error": "structural_field_value_invalid",
            "base_example": valid["id"],
            "mutation": {
                "kind": "structural_field_value_invalid",
                "changes": [
                    {
                        "op": "replace",
                        "path": "/record/body/start_time_unix_nano",
                        "value": 1,
                    }
                ],
            },
        }
    )
    _write_yaml(path, document)

    result = _run(root, "--write")

    assert result.returncode == 1
    assert "derived vector does not equal" in result.stderr


def test_invalid_example_must_have_exactly_one_stable_error(tmp_path: Path) -> None:
    root = _fixture_root(tmp_path)
    path = root / "schemas/telemetry/v8/examples.yaml"
    document = yaml.safe_load(path.read_text(encoding="utf-8"))
    valid = document["examples"][0]
    invalid_record = copy.deepcopy(valid["record"])
    invalid_record["bucket"] = "diagnostic"
    invalid_record["event_name"] = "invalid.event.name"
    invalid_record["field_classes"]["/kind"] = "content"
    document["examples"].append(
        {
            "id": "model.chat.two-errors.invalid",
            "valid": False,
            "signal": "traces",
            "family": "span.model.chat",
            "description": "Two independent errors cannot masquerade as one negative vector.",
            "record": invalid_record,
            "expected_error": "family_event_name_mismatch",
            "base_example": valid["id"],
            "mutation": {
                "kind": "family_event_name_mismatch",
                "changes": [
                    {"op": "replace", "path": "/record/bucket", "value": "diagnostic"},
                    {
                        "op": "replace",
                        "path": "/record/event_name",
                        "value": "invalid.event.name",
                    },
                    {
                        "op": "replace",
                        "path": "/record/field_classes/~1kind",
                        "value": "content",
                    },
                ],
            },
        }
    )
    _write_yaml(path, document)

    result = _run(root, "--write")

    assert result.returncode == 1
    assert "expected only 'family_event_name_mismatch'" in result.stderr
    assert "family_bucket_mismatch" in result.stderr
    assert "field_class_classification_mismatch" in result.stderr


def test_signal_root_mutation_is_replayed_as_part_of_the_typed_vector(tmp_path: Path) -> None:
    root = _fixture_root(tmp_path)
    path = root / "schemas/telemetry/v8/examples.yaml"
    document = yaml.safe_load(path.read_text(encoding="utf-8"))
    valid = document["examples"][0]
    log_record = {
        "schema_version": 1,
        "bucket_catalog_version": 1,
        "timestamp": "2026-07-03T12:00:00Z",
        "record_id": "fixture-log-invalid-signal",
        "bucket": "diagnostic",
        "signal": "traces",
        "event_name": "diagnostic.message",
        "source": "gateway",
        "correlation": {},
        "provenance": {
            "producer": "defenseclaw",
            "binary_version": "8.0.0",
            "registry_schema_version": 1,
            "config_generation": 1,
        },
        "body": {},
        "mandatory": False,
        "field_classes": {"": "metadata"},
    }
    document["examples"].append(
        {
            "id": "diagnostic.signal-root.invalid",
            "valid": False,
            "signal": "logs",
            "family": "diagnostic.message",
            "description": "The vector signal discriminator is replayed, not ignored.",
            "record": log_record,
            "expected_error": "example_signal_mismatch",
            "base_example": valid["id"],
            "mutation": {
                "kind": "example_signal_mismatch",
                "changes": [
                    {"op": "replace", "path": "/signal", "value": "logs"},
                    {"op": "replace", "path": "/family", "value": "diagnostic.message"},
                    {"op": "replace", "path": "/record", "value": copy.deepcopy(log_record)},
                ],
            },
        }
    )
    _write_yaml(path, document)

    result = _run(root, "--write")

    assert result.returncode == 0, result.stderr


@pytest.mark.parametrize(
    ("mutation", "expected"),
    [
        (lambda group: group.__setitem__("introduced_in", "v1"), "expected telemetry-registry-vN"),
        (
            lambda group: group.update(
                {
                    "stability": "deprecated",
                    "deprecated_in": "telemetry-registry-v1",
                    "removed_in": "telemetry-registry-v1",
                }
            ),
            "removed_in: must follow deprecated_in",
        ),
    ],
)
def test_lifecycle_versions_are_semantic_and_strictly_ordered(
    tmp_path: Path,
    mutation: Any,
    expected: str,
) -> None:
    root = _fixture_root(tmp_path)
    path = root / "schemas/telemetry/v8/genai.yaml"
    domain = yaml.safe_load(path.read_text(encoding="utf-8"))
    mutation(domain["groups"][0])
    _write_yaml(path, domain)

    result = _run(root, "--write")

    assert result.returncode == 1
    assert expected in result.stderr


def test_future_removal_remains_active_until_its_registry_version(tmp_path: Path) -> None:
    root = _fixture_root(tmp_path)
    path = root / "schemas/telemetry/v8/genai.yaml"
    domain = yaml.safe_load(path.read_text(encoding="utf-8"))
    domain["groups"][0].update(
        {
            "stability": "deprecated",
            "deprecated_in": "telemetry-registry-v1",
            "removed_in": "telemetry-registry-v2",
        }
    )
    _write_yaml(path, domain)

    result = _run(root, "--write")

    assert result.returncode == 0, result.stderr


def test_removed_non_signal_group_without_route_selector_is_historical_only(tmp_path: Path) -> None:
    root = _fixture_root(tmp_path)
    path = root / "schemas/telemetry/v8/genai.yaml"
    domain = yaml.safe_load(path.read_text(encoding="utf-8"))
    domain["groups"].append(
        {
            "id": "historical.attributes",
            "type": "attribute_group",
            "brief": "A removed non-signal group.",
            "stability": "deprecated",
            "introduced_in": "telemetry-registry-v1",
            "deprecated_in": "telemetry-registry-v1",
            "removed_in": "telemetry-registry-v2",
            "attributes": [],
        }
    )
    _write_yaml(path, domain)
    registry_path = root / "schemas/telemetry/v8/registry.yaml"
    registry = yaml.safe_load(registry_path.read_text(encoding="utf-8"))
    registry["registry_version"] = 2
    _write_yaml(registry_path, registry)
    module = _load_generator_module("telemetry_registry_historical_non_signal")

    ir = module.compile_registry(root)

    assert all(
        group.id != "historical.attributes" for compiled_domain in ir.domains for group in compiled_domain.groups
    )


def test_active_group_cannot_reference_removed_attribute(tmp_path: Path) -> None:
    root = _fixture_root(tmp_path)
    path = root / "schemas/telemetry/v8/genai.yaml"
    domain = yaml.safe_load(path.read_text(encoding="utf-8"))
    attribute = next(item for item in domain["attributes"] if item["id"] == "defenseclaw.test.name")
    attribute.update(
        {
            "stability": "deprecated",
            "deprecated_in": "telemetry-registry-v1",
            "removed_in": "telemetry-registry-v2",
        }
    )
    domain["groups"][0]["attributes"].append({"ref": "defenseclaw.test.name", "requirement_level": "optional"})
    _write_yaml(path, domain)
    registry_path = root / "schemas/telemetry/v8/registry.yaml"
    registry = yaml.safe_load(registry_path.read_text(encoding="utf-8"))
    registry["registry_version"] = 2
    _write_yaml(registry_path, registry)

    result = _run(root, "--write")

    assert result.returncode == 1
    assert "unknown attribute reference" in result.stderr


def test_removed_family_cannot_be_used_by_current_examples(tmp_path: Path) -> None:
    root = _fixture_root(tmp_path)
    domain_path = root / "schemas/telemetry/v8/genai.yaml"
    domain = yaml.safe_load(domain_path.read_text(encoding="utf-8"))
    retired = copy.deepcopy(domain["groups"][0])
    retired.update(
        {
            "id": "span.retired.fixture",
            "stability": "deprecated",
            "deprecated_in": "telemetry-registry-v1",
            "removed_in": "telemetry-registry-v2",
        }
    )
    retired["x-defenseclaw"]["route_selector"] = False
    domain["groups"].append(retired)
    _write_yaml(domain_path, domain)
    registry_path = root / "schemas/telemetry/v8/registry.yaml"
    registry = yaml.safe_load(registry_path.read_text(encoding="utf-8"))
    registry["registry_version"] = 2
    _write_yaml(registry_path, registry)
    examples_path = root / "schemas/telemetry/v8/examples.yaml"
    examples = yaml.safe_load(examples_path.read_text(encoding="utf-8"))
    retired_example = copy.deepcopy(examples["examples"][0])
    retired_example["id"] = "retired.family.current.invalid"
    retired_example["family"] = "span.retired.fixture"
    examples["examples"].append(retired_example)
    _write_yaml(examples_path, examples)

    result = _run(root, "--write")

    assert result.returncode == 1
    assert "family: unknown family" in result.stderr


def test_normalizer_bounds_are_source_owned_not_literal_cloned(tmp_path: Path) -> None:
    root = _fixture_root(tmp_path)
    path = root / "schemas/telemetry/v8/registry.yaml"
    registry = yaml.safe_load(path.read_text(encoding="utf-8"))
    bounded = next(item for item in registry["normalizers"] if item["id"] == "bounded-v1")
    bounded["default_constraints"]["max_utf8_bytes"] = 4095
    _write_yaml(path, registry)
    module = _load_generator_module("telemetry_registry_source_owned_normalizer")

    ir = module.compile_registry(root)

    compiled = next(item for item in ir.normalizers if item.id == "bounded-v1")
    assert compiled.default_constraints["max_utf8_bytes"] == 4095


def test_materialized_registry_view_is_complete_recursive_and_immutable(tmp_path: Path) -> None:
    root = _fixture_root(tmp_path)
    module = _load_generator_module("telemetry_registry_materialized_view")

    ir = module.compile_registry(root)
    view = ir.materialized_view

    assert view.format == "defenseclaw-materialized-registry-view-v1"
    assert len(view.typed_canonical_json_sha256) == 64
    typed_bytes = module._canonical_json_bytes(module._typed_materialized_node(view.facts))
    assert (
        view.typed_canonical_json_sha256
        == hashlib.sha256(module.MATERIALIZED_VIEW_DIGEST_DOMAIN + typed_bytes).hexdigest()
    )
    registry_field_names = {
        field.name for field in module.dataclass_fields(module.RegistryIR) if field.name != "materialized_view"
    }
    assert set(view.facts["fields"]) == registry_field_names
    assert view.facts["$type"] == "RegistryIR"
    assert view.facts["fields"]["structural_contract"]["$type"] == "StructuralContractIR"
    assert view.facts["fields"]["examples"][0]["$type"] == "ExampleIR"

    observed_keys: set[str] = set()

    def assert_frozen(value: Any) -> None:
        assert not isinstance(value, (dict, list, set))
        assert not module.is_dataclass(value)
        if isinstance(value, Mapping):
            observed_keys.update(value)
            for child in value.values():
                assert_frozen(child)
        elif isinstance(value, tuple):
            for child in value:
                assert_frozen(child)

    assert_frozen(view.facts)
    assert {"field_class", "sensitivity", "introduced_in", "canonical_to_otlp"} <= observed_keys
    with pytest.raises(TypeError):
        view.facts["new"] = "mutable"
    with pytest.raises(TypeError):
        view.facts["fields"]["schema_version"] = 2

    registry_values = {
        field.name: getattr(ir, field.name)
        for field in module.dataclass_fields(module.RegistryIR)
        if field.name != "materialized_view"
    }
    reversed_values = dict(reversed(tuple(registry_values.items())))
    rebuilt = module._build_materialized_registry_view(reversed_values)
    assert rebuilt.facts == view.facts
    assert rebuilt.typed_canonical_json_sha256 == view.typed_canonical_json_sha256


def test_materialized_digest_is_typed_and_hash_seed_deterministic(tmp_path: Path) -> None:
    root = _fixture_root(tmp_path)
    module = _load_generator_module("telemetry_registry_materialized_digest")
    typed_values = {
        module._canonical_json_bytes(module._typed_materialized_node({"value": value})) for value in (b"1", "1", 1, 1.0)
    }
    assert len(typed_values) == 4
    assert module._freeze_json(b"\x00\xff") == b"\x00\xff"
    assert module._typed_materialized_node(b"\x00\xff") == ("bytes", "00ff")
    assert module._materialize_registry_fact(b"\x00\xff") == b"\x00\xff"

    observed: list[str] = []
    for seed in ("1", "8675309"):
        environment = dict(os.environ)
        environment["PYTHONHASHSEED"] = seed
        result = _run(root, "--write", environment=environment)
        assert result.returncode == 0, result.stderr
        manifest = json.loads((root / "schemas/telemetry/generated/output-manifest.json").read_text(encoding="utf-8"))
        observed.append(manifest["materialized_view_sha256"])
    assert len(set(observed)) == 1


def test_real_registry_materialized_digest_is_hash_seed_deterministic() -> None:
    probe = """
import importlib.util
import sys
from pathlib import Path

generator = Path(sys.argv[1])
root = Path(sys.argv[2])
spec = importlib.util.spec_from_file_location("telemetry_registry_real_seed_probe", generator)
if spec is None or spec.loader is None:
    raise RuntimeError("unable to load telemetry registry generator")
module = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = module
spec.loader.exec_module(module)
print(module.compile_registry(root).materialized_view.typed_canonical_json_sha256)
"""
    observed: list[str] = []
    for seed in ("1", "8675309"):
        environment = dict(os.environ)
        environment["PYTHONHASHSEED"] = seed
        result = subprocess.run(
            [sys.executable, "-c", probe, str(GENERATOR), str(ROOT)],
            cwd=ROOT,
            env=environment,
            capture_output=True,
            text=True,
            check=False,
        )
        assert result.returncode == 0, result.stderr
        observed.append(result.stdout.strip())
    assert len(set(observed)) == 1
    assert len(observed[0]) == 64


def test_materialized_digest_preserves_ordered_registry_sequences(tmp_path: Path) -> None:
    root = _fixture_root(tmp_path)
    module = _load_generator_module("telemetry_registry_materialized_ordered_sequences")
    ir = module.compile_registry(root)
    registry_values = {
        field.name: getattr(ir, field.name)
        for field in module.dataclass_fields(module.RegistryIR)
        if field.name != "materialized_view"
    }
    ordered_fields = (
        "imports",
        "input_digests",
        "dependencies",
        "normalizers",
        "conditions",
        "domains",
        "group_resolution_order",
        "upstream_attribute_ownership",
    )

    for field_name in ordered_fields:
        original = registry_values[field_name]
        assert isinstance(original, tuple) and len(original) > 1
        reordered = dict(registry_values)
        reordered[field_name] = tuple(reversed(original))
        rebuilt = module._build_materialized_registry_view(reordered)
        assert rebuilt.typed_canonical_json_sha256 != ir.materialized_view.typed_canonical_json_sha256

    second_example = module.replace(ir.examples[0], id="model.chat.valid.second")
    first_examples = dict(registry_values, examples=(ir.examples[0], second_example))
    second_examples = dict(registry_values, examples=(second_example, ir.examples[0]))
    assert (
        module._build_materialized_registry_view(first_examples).typed_canonical_json_sha256
        != module._build_materialized_registry_view(second_examples).typed_canonical_json_sha256
    )


def test_materialized_digest_preserves_nested_fields_uses_arms_and_changes(tmp_path: Path) -> None:
    root = _fixture_root(tmp_path)
    module = _load_generator_module("telemetry_registry_materialized_nested_order")
    ir = module.compile_registry(root)
    registry_values = {
        field.name: getattr(ir, field.name)
        for field in module.dataclass_fields(module.RegistryIR)
        if field.name != "materialized_view"
    }

    envelope = ir.structural_contract.envelope
    reordered_contract = module.replace(
        ir.structural_contract,
        envelope=module.replace(envelope, fields=tuple(reversed(envelope.fields))),
    )
    fields_values = dict(registry_values, structural_contract=reordered_contract)
    assert (
        module._build_materialized_registry_view(fields_values).typed_canonical_json_sha256
        != ir.materialized_view.typed_canonical_json_sha256
    )

    reordered_contract = module.replace(
        ir.structural_contract,
        signal_arms=tuple(reversed(ir.structural_contract.signal_arms)),
    )
    arms_values = dict(registry_values, structural_contract=reordered_contract)
    assert (
        module._build_materialized_registry_view(arms_values).typed_canonical_json_sha256
        != ir.materialized_view.typed_canonical_json_sha256
    )

    domain_index, domain, group_index, group = next(
        (domain_index, domain, group_index, group)
        for domain_index, domain in enumerate(ir.domains)
        for group_index, group in enumerate(domain.groups)
        if len(group.attribute_uses) > 1
    )
    changed_groups = list(domain.groups)
    changed_groups[group_index] = module.replace(group, attribute_uses=tuple(reversed(group.attribute_uses)))
    changed_domains = list(ir.domains)
    changed_domains[domain_index] = module.replace(domain, groups=tuple(changed_groups))
    uses_values = dict(registry_values, domains=tuple(changed_domains))
    assert (
        module._build_materialized_registry_view(uses_values).typed_canonical_json_sha256
        != ir.materialized_view.typed_canonical_json_sha256
    )

    changes = (
        module.ExampleMutationChangeIR("replace", "/record/bucket", True, "model.io"),
        module.ExampleMutationChangeIR("remove", "/record/outcome", False, None),
    )
    first_example = module.replace(
        ir.examples[0],
        mutation=module.ExampleMutationIR("single_fault", changes),
    )
    second_example = module.replace(
        first_example,
        mutation=module.ExampleMutationIR("single_fault", tuple(reversed(changes))),
    )
    first_values = dict(registry_values, examples=(first_example, *ir.examples[1:]))
    second_values = dict(registry_values, examples=(second_example, *ir.examples[1:]))
    assert (
        module._build_materialized_registry_view(first_values).typed_canonical_json_sha256
        != module._build_materialized_registry_view(second_values).typed_canonical_json_sha256
    )


def test_materialized_digest_canonicalizes_declared_set_fields_only(tmp_path: Path) -> None:
    root = _fixture_root(tmp_path)
    module = _load_generator_module("telemetry_registry_materialized_declared_sets")
    ir = module.compile_registry(root)
    registry_values = {
        field.name: getattr(ir, field.name)
        for field in module.dataclass_fields(module.RegistryIR)
        if field.name != "materialized_view"
    }
    normalizer_index, normalizer = next(
        (index, item) for index, item in enumerate(ir.normalizers) if len(item.allowed_overrides) > 1
    )
    changed_normalizers = list(ir.normalizers)
    changed_normalizers[normalizer_index] = module.replace(
        normalizer,
        allowed_overrides=tuple(reversed(normalizer.allowed_overrides)),
    )
    reordered = dict(registry_values, normalizers=tuple(changed_normalizers))
    assert (
        module._build_materialized_registry_view(reordered).typed_canonical_json_sha256
        == ir.materialized_view.typed_canonical_json_sha256
    )
    changed_normalizers[normalizer_index] = module.replace(
        normalizer,
        allowed_overrides=normalizer.allowed_overrides[:-1],
    )
    membership_changed = dict(registry_values, normalizers=tuple(changed_normalizers))
    assert (
        module._build_materialized_registry_view(membership_changed).typed_canonical_json_sha256
        != ir.materialized_view.typed_canonical_json_sha256
    )

    snapshot = module.SnapshotAttribute(
        "fixture",
        ("string", "int64"),
        "attribute",
        "stable",
        "upstream",
        "fixture#/attribute",
        (),
        False,
    )
    reversed_snapshot = module.replace(snapshot, allowed_types=tuple(reversed(snapshot.allowed_types)))
    assert module._materialize_registry_fact(snapshot) == module._materialize_registry_fact(reversed_snapshot)


@pytest.mark.parametrize(
    ("mutation", "expected"),
    [
        (
            lambda contract: contract["trace"]["derivations"].pop(),
            "trace.derivations: binding inventory mismatch",
        ),
        (
            lambda contract: contract["trace"]["derivations"][0].__setitem__("equality", "string-coercion"),
            "trace.derivations: binding inventory mismatch",
        ),
        (
            lambda contract: contract.__setitem__("derivations", contract["trace"].pop("derivations")),
            "registry.structural_contract: unknown keys ['derivations']",
        ),
    ],
)
def test_trace_derivations_are_complete_exact_and_trace_scoped(
    tmp_path: Path,
    mutation: Any,
    expected: str,
) -> None:
    root = _fixture_root(tmp_path)
    path = root / "schemas/telemetry/v8/registry.yaml"
    registry = yaml.safe_load(path.read_text(encoding="utf-8"))
    mutation(registry["structural_contract"])
    _write_yaml(path, registry)

    result = _run(root, "--write")

    assert result.returncode == 1
    assert expected in result.stderr


@pytest.mark.parametrize(
    ("object_name", "field_name", "expected"),
    [
        ("envelope", "bucket", "structural contract envelope: missing field bucket"),
        (
            "provenance",
            "config_generation",
            "structural contract provenance: missing field config_generation",
        ),
    ],
)
def test_trace_derivation_source_field_lookup_fails_with_safe_registry_error(
    tmp_path: Path,
    object_name: str,
    field_name: str,
    expected: str,
) -> None:
    root = _fixture_root(tmp_path)
    module = _load_generator_module(f"telemetry_registry_missing_derivation_source_{object_name}")
    ir = module.compile_registry(root)
    object_ir = getattr(ir.structural_contract, object_name)
    broken_object = module.replace(
        object_ir,
        fields=tuple(field for field in object_ir.fields if field.name != field_name),
    )
    broken_contract = module.replace(ir.structural_contract, **{object_name: broken_object})
    groups = {group.id: group for domain in ir.domains for group in domain.groups}
    attributes = {attribute.id: attribute for domain in ir.domains for attribute in domain.attributes}

    with pytest.raises(module.RegistryError, match=expected):
        module._validate_structural_contract_bindings(
            broken_contract,
            ir.schema_version,
            ir.bucket_catalog_version,
            ir.semantic_profiles,
            groups,
            attributes,
        )


@pytest.mark.parametrize("mutation", ["unavailable", "source_type_mismatch"])
def test_trace_derivation_target_must_be_available_and_source_typed(
    tmp_path: Path,
    mutation: str,
) -> None:
    root = _fixture_root(tmp_path)
    path = root / "schemas/telemetry/v8/genai.yaml"
    document = yaml.safe_load(path.read_text(encoding="utf-8"))
    target = next(
        attribute for attribute in document["attributes"] if attribute["id"] == "defenseclaw.span.family_schema_version"
    )
    if mutation == "unavailable":
        target["projection_only"] = True
        target["legacy_bindings"] = [
            {
                "source": "fixture",
                "disposition": "generated_compatibility_alias",
            }
        ]
        expected = "trace derivation trace-family-schema-version-equality-v1: target attribute is unavailable"
    else:
        target["type"] = "int64"
        target["normalization"]["overrides"]["max"] = 2**63 - 1
        expected = "trace derivation trace-family-schema-version-equality-v1: source/target type mismatch"
    _write_yaml(path, document)

    result = _run(root, "--write")

    assert result.returncode == 1
    assert expected in result.stderr


@pytest.mark.parametrize("mutation", ["wrong_condition", "wrong_requirement"])
def test_span_outcome_derivation_requires_exact_source_presence_semantics(
    tmp_path: Path,
    mutation: str,
) -> None:
    root = _fixture_root(tmp_path)
    path = root / "schemas/telemetry/v8/genai.yaml"
    document = yaml.safe_load(path.read_text(encoding="utf-8"))
    span_core = next(group for group in document["groups"] if group["id"] == "span.core")
    outcome = next(use for use in span_core["attributes"] if use["ref"] == "defenseclaw.outcome")
    if mutation == "wrong_condition":
        outcome["conditional"] = "connector-known-v1"
    else:
        outcome["requirement_level"] = "optional"
        outcome.pop("conditional")
    _write_yaml(path, document)

    result = _run(root, "--write")

    assert result.returncode == 1
    assert (
        "trace derivation target defenseclaw.outcome must resolve with exact "
        "operation-terminal-v1 source-presence semantics"
    ) in result.stderr


def test_span_forbidden_outcome_cannot_retain_inherited_outcome_derivation(tmp_path: Path) -> None:
    root = _fixture_root(tmp_path)
    path = root / "schemas/telemetry/v8/genai.yaml"
    document = yaml.safe_load(path.read_text(encoding="utf-8"))
    span = next(group for group in document["groups"] if group["type"] == "span")
    span["x-defenseclaw"]["outcome_requirement"] = "forbidden"
    span["x-defenseclaw"]["allowed_outcomes"] = []
    _write_yaml(path, document)

    result = _run(root, "--write")

    assert result.returncode == 1
    assert ("forbidden outcome cannot resolve trace derivation target defenseclaw.outcome") in result.stderr


def test_unexampled_span_must_resolve_every_registered_trace_derivation(tmp_path: Path) -> None:
    root = _fixture_root(tmp_path)
    path = root / "schemas/telemetry/v8/operations.yaml"
    operations = yaml.safe_load(path.read_text(encoding="utf-8"))
    span = next(item for item in operations["groups"] if item["id"] == "span.fixture.0")
    span["extends"].remove("span.core")
    _write_yaml(path, operations)

    result = _run(root, "--write")

    assert result.returncode == 1
    assert (
        "group span.fixture.0: trace derivation target defenseclaw.bucket must resolve as an unconditional "
        "required attribute"
    ) in result.stderr


def test_manifest_check_detects_materialized_digest_drift(tmp_path: Path) -> None:
    root = _fixture_root(tmp_path)
    assert _run(root, "--write").returncode == 0
    manifest_path = root / "schemas/telemetry/generated/output-manifest.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    manifest["materialized_view_sha256"] = "0" * 64
    manifest_path.write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")

    result = _run(root, "--check")

    assert result.returncode == 1
    assert "stale=['output-manifest.json']" in result.stderr
