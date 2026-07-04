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


def _sha256(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _write_yaml(path: Path, value: Any) -> None:
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
        identifiers = deprecated_shared | active_shared | legacy_core | {
            "service.name",
            "session.id",
            "user.id",
        }
        identifiers |= {
            f"core.attribute.{index:04d}" for index in range(923 - len(identifiers))
        }
    elif dependency_id == "otel_genai":
        identifiers = deprecated_shared | active_shared | {attribute}
        identifiers |= {
            f"gen_ai.current.{index:03d}" for index in range(70 - len(identifiers))
        }
    else:
        identifiers = set()
    attributes = []
    for index, identifier in enumerate(sorted(identifiers)):
        deprecated = dependency_id == "otel_core" and identifier in (
            deprecated_shared | legacy_core
        )
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
        identifiers |= {
            f"openinference.attribute.{index:03d}" for index in range(93 - len(identifiers))
        }
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
            for index, identifier in enumerate(
                sorted(identifiers)
            )
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
                    "attributes": [
                        {
                            "ref": "gen_ai.operation.name",
                            "requirement_level": "required",
                        }
                    ],
                    "span": {
                        "name_pattern": "chat {gen_ai.operation.name}",
                        "kinds": ["client"],
                        "status_rule": "technical_error_only",
                    },
                    "x-defenseclaw": {
                        "bucket": "model.io",
                        "family_schema_version": 1,
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
                    "id": "diagnostic.message",
                    "type": "log",
                    "brief": "A diagnostic message.",
                    "stability": "stable",
                    "log": {"event_name": "diagnostic.message"},
                    "x-defenseclaw": {
                        "bucket": "diagnostic",
                        "family_schema_version": 1,
                    },
                }
            ],
            "producer_identity_sets": [],
            "producer_mappings": [],
        },
    }
    operations = domains["operations.yaml"]
    for index in range(74):
        operations["groups"].append(
            {
                "id": f"fixture.log.{index}",
                "type": "log",
                "brief": "A generated canonical fixture log.",
                "stability": "development",
                "log": {"event_name": f"fixture.event.{index}"},
                "x-defenseclaw": {
                    "bucket": "diagnostic",
                    "family_schema_version": 1,
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
                "log": {"event_name": event_name},
                "x-defenseclaw": {
                    "bucket": "agent.lifecycle",
                    "family_schema_version": 1,
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
                "span": {
                    "name_pattern": f"fixture.span.{index}",
                    "kinds": ["internal"],
                    "status_rule": "technical_error_only",
                },
                "x-defenseclaw": {
                    "bucket": "diagnostic",
                    "family_schema_version": 1,
                },
            }
        )
    inventory = yaml.safe_load(
        (ROOT / "docs/design/observability-v8/current-state-inventory.yaml").read_text(
            encoding="utf-8"
        )
    )
    registry = yaml.safe_load(
        (ROOT / "schemas/telemetry/v8/registry.yaml").read_text(encoding="utf-8")
    )
    exception_families = {
        item["family"]
        for item in registry["metric_compatibility_profiles"][0][
            "high_cardinality_families"
        ]
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
            group["attributes"] = [
                {"ref": "defenseclaw.test.high", "requirement_level": "required"}
            ]
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
    registry_source = yaml.safe_load(
        (ROOT / "schemas/telemetry/v8/registry.yaml").read_text(encoding="utf-8")
    )
    exception_families = {
        item["family"]
        for item in registry_source["metric_compatibility_profiles"][0][
            "high_cardinality_families"
        ]
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
                        "body": {"attributes": {"gen_ai.operation.name": "chat"}},
                        "field_classes": {
                            "/body/attributes/gen_ai.operation.name": "metadata"
                        },
                    },
                }
            ],
        },
    )
    return root


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
        target = next(
            item for item in snapshot["attributes"] if item["id"] == "aws.bedrock.guardrail.id"
        )
        target["allowed_types"] = ["int64"]

    _mutate_snapshot(root, "otel_genai", mutate)
    result = _run(root, "--write")

    assert result.returncode == 1
    assert "active overlap is inconsistent" in result.stderr


def test_unreviewed_core_genai_type_migration_is_rejected(tmp_path: Path) -> None:
    root = _fixture_root(tmp_path)

    def mutate(snapshot: dict[str, Any]) -> None:
        target = next(
            item
            for item in snapshot["attributes"]
            if item["id"] == "gen_ai.shared.deprecated.000"
        )
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
        target = next(
            item
            for item in snapshot["attributes"]
            if item["id"] == "openinference.attribute.000"
        )
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
        if group.get("metric", {}).get("instrument_name")
        == "defenseclaw.activity.diff_entries"
    )
    metric_group["attributes"] = [
        {"ref": "defenseclaw.test.name", "requirement_level": "required"}
    ]
    metric_group["metric"].pop("empty_labels_reason")
    _write_yaml(operations_path, operations)
    inventory_path = root / "docs/design/observability-v8/current-state-inventory.yaml"
    inventory = yaml.safe_load(inventory_path.read_text(encoding="utf-8"))
    contract = inventory["classes"]["emitted_metrics"]["items"][
        "defenseclaw.activity.diff_entries"
    ]
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
    alias.update({"id": "gen_ai.test.legacy", "stability": "deprecated"})
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
            "legacy_bindings": [
                {"source": "fixture", "disposition": "compatibility_alias"}
            ],
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


def test_invalid_top_level_example_may_omit_family(tmp_path: Path) -> None:
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

    assert result.returncode == 0, result.stderr


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
        if group.get("metric", {}).get("instrument_name")
        == "defenseclaw.activity.diff_entries"
    )
    metric_group["attributes"] = [
        {"ref": "defenseclaw.test.name", "requirement_level": "required"}
    ]
    metric_group["metric"].pop("empty_labels_reason")
    _write_yaml(operations_path, operations)
    inventory_path = root / "docs/design/observability-v8/current-state-inventory.yaml"
    inventory = yaml.safe_load(inventory_path.read_text(encoding="utf-8"))
    contract = inventory["classes"]["emitted_metrics"]["items"][
        "defenseclaw.activity.diff_entries"
    ]
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
        if group.get("metric", {}).get("instrument_name")
        == "defenseclaw.activity.diff_entries"
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
            (
                group
                for group in document["groups"]
                if group.get("metric", {}).get("instrument_name") == instrument
            ),
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
    document["attributes"][-1]["normalization"].setdefault("overrides", {})[
        "max_items"
    ] = 16
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
    spec = importlib.util.spec_from_file_location("telemetry_registry_generator_test", GENERATOR)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)

    ir = module.compile_registry(root)
    group = next(
        group
        for domain in ir.domains
        for group in domain.groups
        if group.id == "span.model.chat"
    )

    assert group.attribute_uses[0].constraints == constraints


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
    assert "/body/attributes/gen_ai.operation.name" in result.stderr


def test_real_registry_has_exact_authoritative_family_counts() -> None:
    groups: list[dict[str, Any]] = []
    for domain in ("genai", "security", "operations"):
        document = yaml.safe_load(
            (ROOT / f"schemas/telemetry/v8/{domain}.yaml").read_text(encoding="utf-8")
        )
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
    document["producer_identity_sets"] = [
        {"id": "diagnostic-context", "identities": [identity]}
    ]
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
        document["producer_identity_sets"] = [
            {"id": "diagnostic-context", "identities": identities}
        ]
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
    source = b"attributes:\n  - key: [unterminated\n" if malformed_yaml else b"""\
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
    foreign = b'''\
class InstrumentationAliases:
    FOREIGN = "gen_ai.operation.name"
'''
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
        snapshot = json.loads(
            (ROOT / "schemas/telemetry/v8/upstream" / filename).read_bytes()
        )
        attribute = next(item for item in snapshot["attributes"] if item["id"] == identifier)
        assert attribute["allowed_types"] == []
        assert attribute["shape"] == "any_value"


def test_checked_in_upstream_privacy_extensions_are_explicit() -> None:
    extensions: dict[str, dict[str, Any]] = {}
    for domain in ("genai", "security", "operations"):
        document = yaml.safe_load(
            (ROOT / f"schemas/telemetry/v8/{domain}.yaml").read_text(encoding="utf-8")
        )
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
        snapshots.append(
            (root / "schemas/telemetry/v8/upstream/openinference.normalized.json").read_bytes()
        )

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
