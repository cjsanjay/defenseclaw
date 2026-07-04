#!/usr/bin/env python3
# Copyright 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: Apache-2.0
"""Compile and verify DefenseClaw's canonical telemetry-registry inputs.

Normal compiler execution is deliberately offline. Upstream semantic-convention
sources are represented by normalized, digest-pinned snapshots created only by
``update_telemetry_registry_upstream.py``.

P5-WP01 owns only the input/provenance contract and a deterministic output
manifest. Later P5 work extends the renderer set without adding another compiler.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import math
import os
import re
import shutil
import string
import sys
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Final

import yaml

GENERATOR_VERSION: Final = 1
NORMALIZED_SNAPSHOT_FORMAT: Final = "defenseclaw-normalized-semconv-v1"
EXPECTED_IMPORTS: Final = ("genai.yaml", "security.yaml", "operations.yaml")
EXPECTED_DEPENDENCIES: Final = ("otel_core", "otel_genai", "openinference")
EXPECTED_SNAPSHOT_ATTRIBUTE_COUNTS: Final = {
    "otel_core": 923,
    "otel_genai": 70,
    "openinference": 93,
}
EXPECTED_UPSTREAM_TYPE_MIGRATIONS: Final = {
    "gen_ai.request.top_k": (
        ("double",),
        ("int64",),
        "breaking_type_correction_to_dedicated_genai",
    )
}
EXPECTED_DOMAINS: Final = ("genai", "security", "operations")
EXPECTED_REPOSITORIES: Final = {
    "otel_core": "https://github.com/open-telemetry/semantic-conventions",
    "otel_genai": "https://github.com/open-telemetry/semantic-conventions-genai",
    "openinference": "https://github.com/Arize-ai/openinference",
}
EXPECTED_OPENINFERENCE_SOURCES: Final = (
    "python/openinference-semantic-conventions/src/openinference/semconv/resource/__init__.py",
    "python/openinference-semantic-conventions/src/openinference/semconv/trace/__init__.py",
    "python/openinference-semantic-conventions/src/openinference/semconv/version.py",
    "spec/semantic_conventions.md",
)
REQUIRED_OPENINFERENCE_ATTRIBUTES: Final = frozenset(
    {
        "openinference.span.kind",
        "input.value",
        "input.mime_type",
        "output.value",
        "output.mime_type",
        "metadata",
        "openinference.project.name",
    }
)
EXPECTED_SEMANTIC_PROFILE: Final = {
    "id": "defenseclaw-genai-rich-v1",
    "trace_schema_version": "defenseclaw-trace-v1",
    "gen_ai_semconv_profile": "otel-genai-b028dceecdad117461a785c3af35315e7184e813",
    "openinference_profile": "openinference-semantic-conventions-v0.1.30",
    "galileo_compatibility_profile": "galileo-rich-v2",
}
EXPECTED_BUCKETS: Final = frozenset(
    {
        "compliance.activity",
        "security.finding",
        "guardrail.evaluation",
        "enforcement.action",
        "model.io",
        "tool.activity",
        "asset.scan",
        "asset.lifecycle",
        "network.egress",
        "agent.lifecycle",
        "ai.discovery",
        "telemetry.ingest",
        "platform.health",
        "diagnostic",
    }
)
EXPECTED_DOTTED_LOG_IDENTITIES: Final = 75
EXPECTED_SPAN_FAMILIES: Final = 25
EXPECTED_METRIC_FAMILIES: Final = 131
EXPECTED_COMPATIBILITY_LOG_IDENTITIES: Final = frozenset(
    {
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
    }
)
EXPECTED_PRODUCER_COUNTS: Final = {"gateway_event": 14, "audit_action": 188}
OUTPUT_MANIFEST = Path("schemas/telemetry/generated/output-manifest.json")

EXPECTED_NORMALIZERS: Final = (
    {
        "id": "identity-v1",
        "kind": "identity",
        "default_constraints": {},
        "allowed_overrides": ["min_items", "max_items"],
    },
    {
        "id": "bounded-v1",
        "kind": "bounded",
        "default_constraints": {
            "max_utf8_bytes": 4096,
            "max_item_utf8_bytes": 4096,
            "max_items": 256,
        },
        "allowed_overrides": [
            "max_utf8_bytes",
            "max_item_utf8_bytes",
            "min_items",
            "max_items",
            "pattern",
        ],
    },
    {
        "id": "enum-v1",
        "kind": "enum",
        "default_constraints": {"max_utf8_bytes": 256},
        "allowed_overrides": ["enum", "max_utf8_bytes"],
    },
    {
        "id": "identifier-v1",
        "kind": "identifier",
        "default_constraints": {
            "max_utf8_bytes": 256,
            "pattern": "^[A-Za-z0-9][A-Za-z0-9._:/-]*$",
        },
        "allowed_overrides": ["max_utf8_bytes", "pattern"],
    },
    {
        "id": "numeric-range-v1",
        "kind": "numeric_range",
        "default_constraints": {},
        "allowed_overrides": ["min", "max", "min_items", "max_items"],
    },
    {
        "id": "structured-content-v1",
        "kind": "structured_content",
        "default_constraints": {
            "max_utf8_bytes": 65536,
            "max_item_utf8_bytes": 4096,
            "max_items": 256,
            "max_depth": 8,
            "max_properties": 256,
        },
        "allowed_overrides": [
            "max_utf8_bytes",
            "max_item_utf8_bytes",
            "min_items",
            "max_items",
            "max_depth",
            "max_properties",
        ],
    },
    {
        "id": "redacted-content-v1",
        "kind": "redacted_content",
        "default_constraints": {
            "max_utf8_bytes": 65536,
            "max_item_utf8_bytes": 4096,
            "max_items": 256,
            "max_depth": 8,
            "max_properties": 256,
        },
        "allowed_overrides": [
            "max_utf8_bytes",
            "max_item_utf8_bytes",
            "min_items",
            "max_items",
            "max_depth",
            "max_properties",
        ],
    },
    {
        "id": "path-v1",
        "kind": "path",
        "default_constraints": {"max_utf8_bytes": 4096},
        "allowed_overrides": ["max_utf8_bytes"],
    },
    {
        "id": "url-v1",
        "kind": "url",
        "default_constraints": {"max_utf8_bytes": 8192},
        "allowed_overrides": ["max_utf8_bytes"],
    },
    {
        "id": "digest-v1",
        "kind": "digest",
        "default_constraints": {
            "max_utf8_bytes": 256,
            "pattern": "^[A-Za-z0-9][A-Za-z0-9:+._/-]*$",
        },
        "allowed_overrides": ["max_utf8_bytes", "pattern"],
    },
)
EXPECTED_METRIC_CARDINALITY_LIMIT: Final = 2048
EXPECTED_METRIC_PROFILE_LIMITS: Final = {
    "dimensions_cache_size": 10000,
    "resource_metrics_cache_size": 1000,
    "series_expiration": "24h",
}

_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_REVISION = re.compile(r"^[0-9a-f]{40}$")
_ID = re.compile(r"^[A-Za-z][A-Za-z0-9_.:/-]{0,255}$")
_FIELD_TYPE = frozenset(
    {
        "string",
        "boolean",
        "int64",
        "double",
        "string[]",
        "boolean[]",
        "int64[]",
        "double[]",
        "bytes",
        "object",
        "array",
    }
)
_STABILITY = frozenset({"development", "stable", "deprecated"})
_OWNER = frozenset({"otel", "otel_genai", "openinference_compatibility", "defenseclaw"})
_FIELD_CLASS = frozenset(
    {"metadata", "identifier", "content", "reason", "evidence", "error", "path", "credential"}
)
_SENSITIVITY = frozenset({"safe", "internal", "sensitive", "critical"})
_CARDINALITY = frozenset({"low", "bounded", "high"})
_METRIC_INSTRUMENT_TYPES = frozenset({"counter", "gauge", "histogram", "updowncounter"})
_METRIC_VALUE_TYPES = frozenset({"int64", "double"})
_METRIC_TEMPORALITIES = frozenset({"delta", "cumulative", "unspecified"})
_CONSTRAINT_KEYS = frozenset(
    {
        "enum",
        "pattern",
        "min",
        "max",
        "min_items",
        "max_items",
        "max_utf8_bytes",
        "max_item_utf8_bytes",
        "max_depth",
        "max_properties",
    }
)
_GROUP_TYPE = frozenset(
    {"attribute_group", "body_group", "resource", "span_event", "log", "span", "metric"}
)
_SIGNAL_BY_GROUP_TYPE = {"log": "logs", "span": "traces", "metric": "metrics"}
_MANDATORY_RULES = frozenset(
    {
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
    }
)
_COMPANION_RULES = frozenset(
    {
        "enforcement_when_enforced",
        "asset_lifecycle_on_state_change",
        "finding_per_observation",
    }
)
_SEVERITY_POLICIES = frozenset(
    {
        "canonical_or_info",
        "finding_required",
        "evaluation",
        "failure_or_source",
        "malformed_or_source",
    }
)


class RegistryError(ValueError):
    """Safe compiler error containing source paths and schema keys only."""


class _StrictLoader(yaml.SafeLoader):
    pass


def _construct_mapping(loader: _StrictLoader, node: yaml.MappingNode, deep: bool = False) -> dict[Any, Any]:
    result: dict[Any, Any] = {}
    for key_node, value_node in node.value:
        key = loader.construct_object(key_node, deep=deep)
        if not isinstance(key, str):
            raise RegistryError("YAML mapping keys must be strings")
        if key == "<<":
            raise RegistryError("YAML merge keys are not allowed")
        if key in result:
            raise RegistryError(f"duplicate YAML key {key!r}")
        result[key] = loader.construct_object(value_node, deep=deep)
    return result


_StrictLoader.add_constructor(
    yaml.resolver.BaseResolver.DEFAULT_MAPPING_TAG,
    _construct_mapping,
)


def _read_utf8(path: Path) -> tuple[bytes, str]:
    try:
        raw = path.read_bytes()
    except OSError as exc:
        raise RegistryError(f"cannot read {path}: {exc.strerror or exc.__class__.__name__}") from exc
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise RegistryError(f"{path}: invalid UTF-8") from exc
    if text.startswith("\ufeff"):
        raise RegistryError(f"{path}: UTF-8 BOM is not allowed")
    return raw, text


def load_yaml_strict(path: Path) -> dict[str, Any]:
    _, text = _read_utf8(path)
    try:
        for token in yaml.scan(text):
            if isinstance(token, (yaml.tokens.AnchorToken, yaml.tokens.AliasToken)):
                raise RegistryError(f"{path}: YAML anchors and aliases are not allowed")
            if isinstance(token, yaml.tokens.TagToken):
                raise RegistryError(f"{path}: explicit YAML tags are not allowed")
        value = yaml.load(text, Loader=_StrictLoader)
    except RegistryError:
        raise
    except yaml.YAMLError as exc:
        raise RegistryError(f"{path}: invalid YAML") from exc
    if not isinstance(value, dict):
        raise RegistryError(f"{path}: document root must be a mapping")
    return value


def load_json_strict(path: Path) -> dict[str, Any]:
    _, text = _read_utf8(path)

    def pairs(items: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, value in items:
            if key in result:
                raise RegistryError(f"{path}: duplicate JSON key {key!r}")
            result[key] = value
        return result

    try:
        value = json.loads(text, object_pairs_hook=pairs)
    except RegistryError:
        raise
    except json.JSONDecodeError as exc:
        raise RegistryError(f"{path}: invalid JSON") from exc
    if not isinstance(value, dict):
        raise RegistryError(f"{path}: document root must be an object")
    return value


def _exact_keys(value: dict[str, Any], required: set[str], optional: set[str], path: str) -> None:
    missing = required - value.keys()
    unknown = value.keys() - required - optional
    if missing:
        raise RegistryError(f"{path}: missing keys {sorted(missing)}")
    if unknown:
        raise RegistryError(f"{path}: unknown keys {sorted(unknown)}")


def _integer(value: Any, path: str, *, minimum: int = 1) -> int:
    if type(value) is not int or value < minimum:
        raise RegistryError(f"{path}: expected integer >= {minimum}")
    return value


def _string(value: Any, path: str, *, pattern: re.Pattern[str] | None = None) -> str:
    if not isinstance(value, str) or not value or len(value.encode("utf-8")) > 4096:
        raise RegistryError(f"{path}: expected a nonempty bounded string")
    if pattern is not None and not pattern.fullmatch(value):
        raise RegistryError(f"{path}: invalid string syntax")
    return value


def _string_list(value: Any, path: str, *, allow_empty: bool = True) -> tuple[str, ...]:
    if not isinstance(value, list) or (not allow_empty and not value):
        raise RegistryError(f"{path}: expected a string sequence")
    result: list[str] = []
    seen: set[str] = set()
    for index, item in enumerate(value):
        item = _string(item, f"{path}[{index}]")
        if item in seen:
            raise RegistryError(f"{path}: duplicate value")
        result.append(item)
        seen.add(item)
    return tuple(result)


def _safe_relative(root: Path, value: str, path: str, *, prefix: Path) -> tuple[Path, str]:
    if "\\" in value:
        raise RegistryError(f"{path}: paths must use forward slashes")
    relative = Path(value)
    if relative.is_absolute() or ".." in relative.parts or relative == Path("."):
        raise RegistryError(f"{path}: path must remain repository-relative")
    repository_path = (root / relative).resolve()
    allowed = (root / prefix).resolve()
    try:
        repository_path.relative_to(allowed)
    except ValueError as exc:
        raise RegistryError(f"{path}: path leaves {prefix.as_posix()}") from exc
    return repository_path, relative.as_posix()


def _sha256(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


@dataclass(frozen=True, slots=True)
class InputDigest:
    path: str
    sha256: str


@dataclass(frozen=True, slots=True)
class SnapshotAttribute:
    id: str
    allowed_types: tuple[str, ...]
    shape: str
    stability: str
    source_pointer: str
    enum: tuple[str, ...]
    deprecated: bool


@dataclass(frozen=True, slots=True)
class SnapshotIR:
    dependency_id: str
    repository: str
    revision: str
    path: str
    sha256: str
    attributes: tuple[SnapshotAttribute, ...]


@dataclass(frozen=True, slots=True)
class DependencyIR:
    id: str
    repository: str
    version: str
    profile_id: str
    revision: str
    snapshot: SnapshotIR


@dataclass(frozen=True, slots=True)
class NormalizerIR:
    id: str
    kind: str
    default_constraints: dict[str, Any]
    allowed_overrides: frozenset[str]


@dataclass(frozen=True, slots=True)
class NormalizationIR:
    id: str
    effective_constraints: dict[str, Any]


@dataclass(frozen=True, slots=True)
class AttributeIR:
    id: str
    field_type: str
    alias_of: str | None
    owner: str
    stability: str
    deprecated_in: str | None
    removed_in: str | None
    projection_only: bool
    field_class: str
    sensitivity: str
    cardinality: str
    normalization: NormalizationIR


@dataclass(frozen=True, slots=True)
class AttributeExtensionIR:
    ref: str
    field_class: str
    sensitivity: str
    cardinality: str
    normalization: NormalizationIR


@dataclass(frozen=True, slots=True)
class MetricProjectionIR:
    profile: str
    mappings: tuple[tuple[str, str], ...]


@dataclass(frozen=True, slots=True)
class MetricCompatibilityProfileIR:
    id: str
    high_cardinality_families: dict[str, frozenset[str]]


@dataclass(frozen=True, slots=True)
class MetricInventoryIR:
    instrument_type: str
    unit: str
    labels: frozenset[str]
    empty_labels_reason: str | None


@dataclass(frozen=True, slots=True)
class AttributeUseIR:
    ref: str
    requirement_level: str
    conditional: str | None
    constraints: dict[str, Any]


@dataclass(frozen=True, slots=True)
class GroupIR:
    id: str
    type: str
    extends: tuple[str, ...]
    attribute_uses: tuple[AttributeUseIR, ...]
    attribute_refs: tuple[str, ...]
    event_refs: tuple[str, ...]
    event_name: str | None
    bucket: str | None
    span_name_pattern: str | None
    instrument_name: str | None
    instrument_type: str | None
    metric_value_type: str | None
    metric_unit: str | None
    metric_temporality: str | None
    metric_boundaries: tuple[int | float, ...] | None
    empty_labels_reason: str | None
    metric_projections: tuple[MetricProjectionIR, ...]


@dataclass(frozen=True, slots=True)
class ProducerIdentityIR:
    event_name: str
    bucket: str
    family: str | None
    compatibility_only: bool


@dataclass(frozen=True, slots=True)
class ProducerMappingIR:
    producer: str
    key: str
    event_name_policy: str
    default_identity: ProducerIdentityIR | None
    allowed_context_identities: tuple[ProducerIdentityIR, ...]


@dataclass(frozen=True, slots=True)
class DomainIR:
    domain: str
    path: str
    attributes: tuple[AttributeIR, ...]
    attribute_extensions: tuple[AttributeExtensionIR, ...]
    groups: tuple[GroupIR, ...]
    producer_mappings: tuple[ProducerMappingIR, ...]


@dataclass(frozen=True, slots=True)
class RegistryIR:
    schema_version: int
    registry_version: int
    bucket_catalog_version: int
    imports: tuple[str, ...]
    input_digests: tuple[InputDigest, ...]
    dependencies: tuple[DependencyIR, ...]
    normalizers: tuple[NormalizerIR, ...]
    metric_compatibility_profile: MetricCompatibilityProfileIR
    domains: tuple[DomainIR, ...]
    legacy_only_upstream_attributes: tuple[str, ...]


def _parse_snapshot(
    root: Path,
    dependency: dict[str, Any],
    dependency_path: str,
) -> SnapshotIR:
    snapshot = dependency["snapshot"]
    if not isinstance(snapshot, dict):
        raise RegistryError(f"{dependency_path}.snapshot: expected mapping")
    _exact_keys(snapshot, {"path", "format", "sha256"}, set(), f"{dependency_path}.snapshot")
    if snapshot["format"] != NORMALIZED_SNAPSHOT_FORMAT:
        raise RegistryError(f"{dependency_path}.snapshot.format: unsupported format")
    expected_digest = _string(snapshot["sha256"], f"{dependency_path}.snapshot.sha256", pattern=_SHA256)
    snapshot_path, snapshot_relative = _safe_relative(
        root,
        _string(snapshot["path"], f"{dependency_path}.snapshot.path"),
        f"{dependency_path}.snapshot.path",
        prefix=Path("schemas/telemetry/v8/upstream"),
    )
    raw, _ = _read_utf8(snapshot_path)
    actual_digest = _sha256(raw)
    if actual_digest != expected_digest:
        raise RegistryError(f"{dependency_path}.snapshot.sha256: snapshot digest mismatch")
    document = load_json_strict(snapshot_path)
    _exact_keys(
        document,
        {
            "format_version",
            "format",
            "dependency_id",
            "repository",
            "revision",
            "source_archive",
            "source_files",
            "attributes",
        },
        set(),
        snapshot_relative,
    )
    if _integer(document["format_version"], f"{snapshot_relative}.format_version") != 1:
        raise RegistryError(f"{snapshot_relative}.format_version: unsupported version")
    if document["format"] != NORMALIZED_SNAPSHOT_FORMAT:
        raise RegistryError(f"{snapshot_relative}.format: unsupported format")
    dependency_id = _string(dependency["id"], f"{dependency_path}.id", pattern=_ID)
    repository = _string(dependency["repository"], f"{dependency_path}.repository")
    if EXPECTED_REPOSITORIES.get(dependency_id) != repository:
        raise RegistryError(f"{dependency_path}.repository: not the pinned primary upstream")
    revision = _string(dependency["revision"], f"{dependency_path}.revision", pattern=_REVISION)
    for key, expected in (
        ("dependency_id", dependency_id),
        ("repository", repository),
        ("revision", revision),
    ):
        if document[key] != expected:
            raise RegistryError(f"{snapshot_relative}.{key}: lock/snapshot mismatch")
    archive = _string(document["source_archive"], f"{snapshot_relative}.source_archive")
    if revision not in archive or not archive.startswith(repository.rstrip("/") + "/archive/"):
        raise RegistryError(f"{snapshot_relative}.source_archive: must name the pinned primary revision")
    source_files = document["source_files"]
    if not isinstance(source_files, list) or not source_files:
        raise RegistryError(f"{snapshot_relative}.source_files: expected nonempty sequence")
    source_paths: list[str] = []
    for index, item in enumerate(source_files):
        item_path = f"{snapshot_relative}.source_files[{index}]"
        if not isinstance(item, dict):
            raise RegistryError(f"{item_path}: expected object")
        _exact_keys(item, {"path", "sha256"}, set(), item_path)
        source_paths.append(_string(item["path"], f"{item_path}.path"))
        _string(item["sha256"], f"{item_path}.sha256", pattern=_SHA256)
    if source_paths != sorted(set(source_paths)):
        raise RegistryError(f"{snapshot_relative}.source_files: paths must be sorted and unique")
    if dependency_id == "openinference" and tuple(source_paths) != EXPECTED_OPENINFERENCE_SOURCES:
        raise RegistryError(f"{snapshot_relative}.source_files: non-authoritative OpenInference source")
    raw_attributes = document["attributes"]
    if not isinstance(raw_attributes, list) or not raw_attributes:
        raise RegistryError(f"{snapshot_relative}.attributes: expected nonempty sequence")
    attributes: list[SnapshotAttribute] = []
    for index, item in enumerate(raw_attributes):
        item_path = f"{snapshot_relative}.attributes[{index}]"
        if not isinstance(item, dict):
            raise RegistryError(f"{item_path}: expected object")
        _exact_keys(
            item,
            {
                "id",
                "allowed_types",
                "shape",
                "stability",
                "stability_source",
                "source_pointer",
                "enum",
                "deprecated",
            },
            set(),
            item_path,
        )
        attribute_id = _string(item["id"], f"{item_path}.id", pattern=_ID)
        allowed_types = _string_list(item["allowed_types"], f"{item_path}.allowed_types")
        shape = _string(item["shape"], f"{item_path}.shape")
        if shape not in {"attribute", "any_value", "indexed_prefix", "object_prefix"}:
            raise RegistryError(f"{item_path}.shape: unsupported normalized field shape")
        direct_types = {
            "string",
            "boolean",
            "int64",
            "double",
            "string[]",
            "boolean[]",
            "int64[]",
            "double[]",
            "bytes",
        }
        if shape == "attribute":
            if not allowed_types or not set(allowed_types).issubset(direct_types):
                raise RegistryError(f"{item_path}.allowed_types: unsupported direct wire type")
            if len(allowed_types) > 1 and allowed_types != ("string", "int64"):
                raise RegistryError(f"{item_path}.allowed_types: unsupported wire union")
        elif allowed_types:
            raise RegistryError(f"{item_path}.allowed_types: non-attribute shapes have no direct wire type")
        stability = _string(item["stability"], f"{item_path}.stability")
        if stability not in _STABILITY:
            raise RegistryError(f"{item_path}.stability: unsupported stability")
        stability_source = _string(item["stability_source"], f"{item_path}.stability_source")
        expected_stability_source = (
            "released_package_policy" if dependency_id == "openinference" else "upstream"
        )
        if stability_source != expected_stability_source:
            raise RegistryError(f"{item_path}.stability_source: unexpected provenance policy")
        pointer = _string(item["source_pointer"], f"{item_path}.source_pointer")
        pointer_source = pointer.split("#", 1)[0]
        if pointer_source not in source_paths or "#" not in pointer:
            raise RegistryError(f"{item_path}.source_pointer: does not resolve to source_files")
        enum = _string_list(item["enum"], f"{item_path}.enum")
        if type(item["deprecated"]) is not bool:
            raise RegistryError(f"{item_path}.deprecated: expected boolean")
        attributes.append(
            SnapshotAttribute(
                id=attribute_id,
                allowed_types=allowed_types,
                shape=shape,
                stability=stability,
                source_pointer=pointer,
                enum=enum,
                deprecated=item["deprecated"],
            )
        )
    ids = [item.id for item in attributes]
    if ids != sorted(set(ids)):
        raise RegistryError(f"{snapshot_relative}.attributes: IDs must be sorted and unique")
    expected_count = EXPECTED_SNAPSHOT_ATTRIBUTE_COUNTS[dependency_id]
    if len(attributes) != expected_count:
        raise RegistryError(f"{snapshot_relative}.attributes: expected {expected_count} attributes")
    if dependency_id == "openinference":
        if any(attribute_id.startswith("gen_ai.") for attribute_id in ids):
            raise RegistryError(f"{snapshot_relative}.attributes: foreign gen_ai.* ownership")
        missing = REQUIRED_OPENINFERENCE_ATTRIBUTES - set(ids)
        if missing:
            raise RegistryError(
                f"{snapshot_relative}.attributes: missing required OpenInference attributes {sorted(missing)}"
            )
        for attribute in attributes:
            expected_source = (
                EXPECTED_OPENINFERENCE_SOURCES[0]
                if attribute.id == "openinference.project.name"
                else "spec/semantic_conventions.md"
            )
            if not attribute.source_pointer.startswith(expected_source + "#"):
                raise RegistryError(
                    f"{snapshot_relative}.attributes: OpenInference source pointer policy mismatch"
                )
    return SnapshotIR(
        dependency_id=dependency_id,
        repository=repository,
        revision=revision,
        path=snapshot_relative,
        sha256=actual_digest,
        attributes=tuple(attributes),
    )


def _parse_lock(root: Path, relative: str) -> tuple[tuple[DependencyIR, ...], InputDigest]:
    path, normalized = _safe_relative(
        root,
        relative,
        "registry.dependency_lock",
        prefix=Path("schemas/telemetry/v8"),
    )
    document = load_yaml_strict(path)
    _exact_keys(document, {"schema_version", "dependencies"}, set(), normalized)
    if _integer(document["schema_version"], f"{normalized}.schema_version") != 1:
        raise RegistryError(f"{normalized}.schema_version: unsupported version")
    raw_dependencies = document["dependencies"]
    if not isinstance(raw_dependencies, list):
        raise RegistryError(f"{normalized}.dependencies: expected sequence")
    dependencies: list[DependencyIR] = []
    for index, item in enumerate(raw_dependencies):
        item_path = f"{normalized}.dependencies[{index}]"
        if not isinstance(item, dict):
            raise RegistryError(f"{item_path}: expected mapping")
        _exact_keys(
            item,
            {"id", "repository", "version", "profile_id", "revision", "snapshot"},
            set(),
            item_path,
        )
        snapshot = _parse_snapshot(root, item, item_path)
        dependencies.append(
            DependencyIR(
                id=snapshot.dependency_id,
                repository=snapshot.repository,
                version=_string(item["version"], f"{item_path}.version"),
                profile_id=_string(item["profile_id"], f"{item_path}.profile_id", pattern=_ID),
                revision=snapshot.revision,
                snapshot=snapshot,
            )
        )
    ids = tuple(item.id for item in dependencies)
    if ids != EXPECTED_DEPENDENCIES:
        raise RegistryError(f"{normalized}.dependencies: expected canonical order {EXPECTED_DEPENDENCIES}")
    raw, _ = _read_utf8(path)
    return tuple(dependencies), InputDigest(normalized, _sha256(raw))


def _parse_producer_inventory(
    root: Path,
) -> tuple[dict[str, frozenset[str]], dict[str, MetricInventoryIR], InputDigest]:
    relative = "docs/design/observability-v8/current-state-inventory.yaml"
    path, normalized = _safe_relative(
        root,
        relative,
        "producer_inventory",
        prefix=Path("docs/design/observability-v8"),
    )
    document = load_yaml_strict(path)
    if document.get("inventory_version") != 1 or not isinstance(document.get("classes"), dict):
        raise RegistryError(f"{normalized}: unsupported producer inventory")
    classes = document["classes"]
    result: dict[str, frozenset[str]] = {}
    for producer, section_name in (
        ("gateway_event", "gateway_event_types"),
        ("audit_action", "audit_actions"),
    ):
        section = classes.get(section_name)
        if not isinstance(section, dict) or not isinstance(section.get("items"), dict):
            raise RegistryError(f"{normalized}.classes.{section_name}.items: expected mapping")
        values = tuple(
            _string(value, f"{normalized}.classes.{section_name}.items.{constant}", pattern=_ID)
            for constant, value in section["items"].items()
        )
        if len(values) != len(set(values)):
            raise RegistryError(f"{normalized}.classes.{section_name}.items: duplicate producer key")
        if len(values) != EXPECTED_PRODUCER_COUNTS[producer]:
            raise RegistryError(
                f"{normalized}.classes.{section_name}.items: expected "
                f"{EXPECTED_PRODUCER_COUNTS[producer]} entries"
            )
        result[producer] = frozenset(values)
    metrics_section = classes.get("emitted_metrics")
    if not isinstance(metrics_section, dict) or not isinstance(metrics_section.get("items"), dict):
        raise RegistryError(f"{normalized}.classes.emitted_metrics.items: expected mapping")
    metric_inventory: dict[str, MetricInventoryIR] = {}
    for instrument, item in metrics_section["items"].items():
        item_path = f"{normalized}.classes.emitted_metrics.items.{instrument}"
        _string(instrument, f"{item_path}.name", pattern=_ID)
        if not isinstance(item, dict):
            raise RegistryError(f"{item_path}: expected mapping")
        _exact_keys(
            item,
            {"type", "unit", "labels", "callsites", "dropped_by_current_global_v8_gate"},
            {"empty_labels_reason"},
            item_path,
        )
        instrument_type = _string(item["type"], f"{item_path}.type")
        if instrument_type not in _METRIC_INSTRUMENT_TYPES:
            raise RegistryError(f"{item_path}.type: unsupported metric instrument type")
        unit = _string(item["unit"], f"{item_path}.unit")
        labels = frozenset(_string_list(item["labels"], f"{item_path}.labels"))
        _string_list(item["callsites"], f"{item_path}.callsites", allow_empty=False)
        dropped = set(
            _string_list(
                item["dropped_by_current_global_v8_gate"],
                f"{item_path}.dropped_by_current_global_v8_gate",
            )
        )
        if not dropped.issubset(labels):
            raise RegistryError(
                f"{item_path}.dropped_by_current_global_v8_gate: expected a subset of labels"
            )
        empty_reason = None
        if "empty_labels_reason" in item:
            empty_reason = _string(item["empty_labels_reason"], f"{item_path}.empty_labels_reason")
        if bool(labels) == bool(empty_reason):
            requirement = "forbidden" if labels else "required"
            raise RegistryError(f"{item_path}.empty_labels_reason: {requirement}")
        metric_inventory[instrument] = MetricInventoryIR(
            instrument_type,
            unit,
            labels,
            empty_reason,
        )
    if len(metric_inventory) != EXPECTED_METRIC_FAMILIES:
        raise RegistryError(
            f"{normalized}.classes.emitted_metrics.items: expected "
            f"{EXPECTED_METRIC_FAMILIES} entries"
        )
    raw, _ = _read_utf8(path)
    return result, metric_inventory, InputDigest(normalized, _sha256(raw))


def _validate_json_compatible(value: Any, path: str, *, depth: int = 0) -> None:
    if depth > 8:
        raise RegistryError(f"{path}: compatibility details exceed maximum depth")
    if value is None or type(value) in {bool, int, float, str}:
        if isinstance(value, float) and not math.isfinite(value):
            raise RegistryError(f"{path}: non-finite numbers are not allowed")
        if isinstance(value, str) and len(value.encode("utf-8")) > 4096:
            raise RegistryError(f"{path}: string exceeds maximum length")
        return
    if isinstance(value, list):
        if len(value) > 256:
            raise RegistryError(f"{path}: sequence exceeds maximum length")
        for index, item in enumerate(value):
            _validate_json_compatible(item, f"{path}[{index}]", depth=depth + 1)
        return
    if isinstance(value, dict):
        if len(value) > 256:
            raise RegistryError(f"{path}: object exceeds maximum size")
        for key, item in value.items():
            _string(key, f"{path}.key")
            _validate_json_compatible(item, f"{path}.{key}", depth=depth + 1)
        return
    raise RegistryError(f"{path}: unsupported compatibility-details value")


def _validate_portable_pattern(value: Any, path: str) -> str:
    pattern = _string(value, path)
    if "(?" in pattern or re.search(r"\\(?:[1-9]|g|k)", pattern):
        raise RegistryError(f"{path}: pattern uses syntax outside the portable RE2 subset")
    try:
        re.compile(pattern)
    except re.error as exc:
        raise RegistryError(f"{path}: invalid pattern") from exc
    return pattern


def _validate_constraint_map(value: Any, path: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise RegistryError(f"{path}: expected mapping")
    unknown = value.keys() - _CONSTRAINT_KEYS
    if unknown:
        raise RegistryError(f"{path}: unknown keys {sorted(unknown)}")
    result: dict[str, Any] = {}
    for key, item in value.items():
        item_path = f"{path}.{key}"
        if item is None:
            raise RegistryError(f"{item_path}: null cannot remove a constraint")
        if key == "enum":
            if not isinstance(item, list) or not item:
                raise RegistryError(f"{item_path}: expected nonempty JSON-scalar sequence")
            normalized: list[str | bool | int | float] = []
            seen: set[tuple[type[Any], Any]] = set()
            for index, entry in enumerate(item):
                if type(entry) not in {str, bool, int, float} or (
                    type(entry) is float and not math.isfinite(entry)
                ):
                    raise RegistryError(f"{item_path}[{index}]: expected finite JSON scalar")
                marker = (type(entry), entry)
                if marker in seen:
                    raise RegistryError(f"{item_path}: duplicate enum value")
                seen.add(marker)
                normalized.append(entry)
            result[key] = normalized
        elif key == "pattern":
            result[key] = _validate_portable_pattern(item, item_path)
        elif key in {
            "min_items",
            "max_items",
            "max_utf8_bytes",
            "max_item_utf8_bytes",
            "max_depth",
            "max_properties",
        }:
            minimum = 0 if key == "min_items" else 1
            result[key] = _integer(item, item_path, minimum=minimum)
        else:
            if type(item) not in {int, float} or (
                type(item) is float and not math.isfinite(item)
            ):
                raise RegistryError(f"{item_path}: expected finite number")
            result[key] = item
    if "min" in result and "max" in result and result["min"] > result["max"]:
        raise RegistryError(f"{path}: min exceeds max")
    if (
        "min_items" in result
        and "max_items" in result
        and result["min_items"] > result["max_items"]
    ):
        raise RegistryError(f"{path}: min_items exceeds max_items")
    return result


def _parse_normalizer_catalog(value: Any, path: str) -> tuple[NormalizerIR, ...]:
    if not isinstance(value, list):
        raise RegistryError(f"{path}: expected sequence")
    parsed: list[NormalizerIR] = []
    for index, item in enumerate(value):
        item_path = f"{path}[{index}]"
        if not isinstance(item, dict):
            raise RegistryError(f"{item_path}: expected mapping")
        _exact_keys(
            item,
            {"id", "kind", "default_constraints", "allowed_overrides"},
            set(),
            item_path,
        )
        normalizer_id = _string(item["id"], f"{item_path}.id", pattern=_ID)
        kind = _string(item["kind"], f"{item_path}.kind", pattern=_ID)
        defaults = _validate_constraint_map(
            item["default_constraints"],
            f"{item_path}.default_constraints",
        )
        overrides = _string_list(item["allowed_overrides"], f"{item_path}.allowed_overrides")
        if not set(overrides).issubset(_CONSTRAINT_KEYS):
            raise RegistryError(f"{item_path}.allowed_overrides: unknown constraint")
        parsed.append(NormalizerIR(normalizer_id, kind, defaults, frozenset(overrides)))
    if value != list(EXPECTED_NORMALIZERS):
        raise RegistryError(f"{path}: catalog differs from the canonical v1 contract")
    return tuple(parsed)


def _validate_normalization_compatibility(
    normalization: NormalizationIR,
    field_types: tuple[str, ...],
    shape: str,
    path: str,
) -> None:
    kind = normalization.id.removesuffix("-v1").replace("-", "_")
    types = set(field_types)
    scalar_strings = {"string", "string[]"}
    numeric = {"int64", "double", "int64[]", "double[]"}
    if kind == "identity":
        compatible = bool(types) and types.issubset({"boolean", "boolean[]"})
    elif kind == "bounded":
        compatible = bool(types) and types.issubset(scalar_strings | {"bytes"})
    elif kind in {"enum", "identifier"}:
        compatible = bool(types) and types.issubset(scalar_strings)
    elif kind == "numeric_range":
        compatible = bool(types) and types.issubset(numeric)
    elif kind in {"structured_content", "redacted_content"}:
        compatible = shape in {"any_value", "indexed_prefix", "object_prefix"} or (
            bool(types)
            and types.issubset({"string", "string[]", "bytes", "object", "array"})
        )
    elif kind in {"path", "url", "digest"}:
        compatible = types == {"string"}
    else:
        compatible = False
    if not compatible:
        raise RegistryError(
            f"{path}.id: {normalization.id} is incompatible with types={sorted(types)} shape={shape}"
        )
    effective = normalization.effective_constraints
    if kind == "enum" and "enum" not in effective:
        raise RegistryError(f"{path}.overrides.enum: required for enum-v1")
    if kind == "numeric_range":
        if not {"min", "max"}.issubset(effective):
            raise RegistryError(f"{path}.overrides: numeric-range-v1 requires min and max")
        if types & {"int64", "int64[]"} and any(
            type(effective[key]) is not int for key in ("min", "max")
        ):
            raise RegistryError(f"{path}.overrides: int64 bounds must be exact integers")
    if kind in {"structured_content", "redacted_content"}:
        required = {
            "max_utf8_bytes",
            "max_item_utf8_bytes",
            "max_items",
            "max_depth",
            "max_properties",
        }
        if not required.issubset(effective):
            raise RegistryError(f"{path}: structured normalizer lacks mandatory bounds")
    if types & {"string[]"} and (
        "max_items" not in effective or "max_item_utf8_bytes" not in effective
    ):
        raise RegistryError(f"{path}: string arrays require item-count and per-item byte bounds")
    if types & {"boolean[]", "int64[]", "double[]"} and "max_items" not in effective:
        raise RegistryError(f"{path}: arrays require an explicit max_items bound")


def _parse_normalization(
    value: Any,
    path: str,
    normalizers: dict[str, NormalizerIR],
    *,
    field_types: tuple[str, ...] | None = None,
    shape: str = "attribute",
) -> NormalizationIR:
    if not isinstance(value, dict):
        raise RegistryError(f"{path}: expected mapping")
    _exact_keys(value, {"id"}, {"overrides", "notes"}, path)
    normalizer_id = _string(value["id"], f"{path}.id", pattern=_ID)
    catalog = normalizers.get(normalizer_id)
    if catalog is None:
        raise RegistryError(f"{path}.id: unknown normalizer")
    overrides = _validate_constraint_map(value.get("overrides", {}), f"{path}.overrides")
    disallowed = overrides.keys() - catalog.allowed_overrides
    if disallowed:
        raise RegistryError(f"{path}.overrides: disallowed keys {sorted(disallowed)}")
    if "notes" in value:
        _string(value["notes"], f"{path}.notes")
    effective = dict(catalog.default_constraints)
    effective.update(overrides)
    _validate_constraint_map(effective, f"{path}.effective_constraints")
    normalization = NormalizationIR(normalizer_id, effective)
    if field_types is not None:
        _validate_normalization_compatibility(normalization, field_types, shape, path)
    return normalization


def _parse_attribute_definition(
    value: Any,
    path: str,
    normalizers: dict[str, NormalizerIR],
) -> AttributeIR:
    if not isinstance(value, dict):
        raise RegistryError(f"{path}: expected mapping")
    required = {
        "id",
        "type",
        "brief",
        "examples",
        "stability",
        "owner",
        "field_class",
        "sensitivity",
        "cardinality",
        "normalization",
        "introduced_in",
    }
    optional = {
        "deprecated_in",
        "removed_in",
        "alias_of",
        "projection_only",
        "legacy_bindings",
    }
    _exact_keys(value, required, optional, path)
    attribute_id = _string(value["id"], f"{path}.id", pattern=_ID)
    if value["type"] not in _FIELD_TYPE:
        raise RegistryError(f"{path}.type: unsupported field type")
    field_type = value["type"]
    _string(value["brief"], f"{path}.brief")
    if not isinstance(value["examples"], list):
        raise RegistryError(f"{path}.examples: expected sequence")
    for index, example in enumerate(value["examples"]):
        _validate_json_compatible(example, f"{path}.examples[{index}]")
    for key, allowed in (
        ("stability", _STABILITY),
        ("owner", _OWNER),
        ("field_class", _FIELD_CLASS),
        ("sensitivity", _SENSITIVITY),
        ("cardinality", _CARDINALITY),
    ):
        if value[key] not in allowed:
            raise RegistryError(f"{path}.{key}: unsupported value")
    normalization = _parse_normalization(
        value["normalization"],
        f"{path}.normalization",
        normalizers,
        field_types=(field_type,),
    )
    _string(value["introduced_in"], f"{path}.introduced_in", pattern=_ID)
    deprecated_in = None
    removed_in = None
    if "deprecated_in" in value:
        deprecated_in = _string(value["deprecated_in"], f"{path}.deprecated_in", pattern=_ID)
    if "removed_in" in value:
        removed_in = _string(value["removed_in"], f"{path}.removed_in", pattern=_ID)
    alias = None
    if "alias_of" in value:
        alias = _string(value["alias_of"], f"{path}.alias_of", pattern=_ID)
    projection_only = value.get("projection_only", False)
    if type(projection_only) is not bool:
        raise RegistryError(f"{path}.projection_only: expected boolean")
    if "legacy_bindings" in value:
        _parse_legacy_bindings(value["legacy_bindings"], f"{path}.legacy_bindings")
    if projection_only and "legacy_bindings" not in value:
        raise RegistryError(f"{path}.legacy_bindings: required for projection-only aliases")
    return AttributeIR(
        attribute_id,
        field_type,
        alias,
        value["owner"],
        value["stability"],
        deprecated_in,
        removed_in,
        projection_only,
        value["field_class"],
        value["sensitivity"],
        value["cardinality"],
        normalization,
    )


def _parse_attribute_extension(
    value: Any,
    path: str,
    normalizers: dict[str, NormalizerIR],
) -> AttributeExtensionIR:
    if not isinstance(value, dict):
        raise RegistryError(f"{path}: expected mapping")
    _exact_keys(
        value,
        {"ref", "field_class", "sensitivity", "cardinality", "normalization"},
        set(),
        path,
    )
    ref = _string(value["ref"], f"{path}.ref", pattern=_ID)
    for key, allowed in (
        ("field_class", _FIELD_CLASS),
        ("sensitivity", _SENSITIVITY),
        ("cardinality", _CARDINALITY),
    ):
        if value[key] not in allowed:
            raise RegistryError(f"{path}.{key}: unsupported value")
    normalization = _parse_normalization(
        value["normalization"],
        f"{path}.normalization",
        normalizers,
    )
    return AttributeExtensionIR(
        ref,
        value["field_class"],
        value["sensitivity"],
        value["cardinality"],
        normalization,
    )


def _parse_attribute_uses(value: Any, path: str) -> tuple[AttributeUseIR, ...]:
    if value is None:
        return ()
    if not isinstance(value, list):
        raise RegistryError(f"{path}: expected sequence")
    result: list[AttributeUseIR] = []
    for index, item in enumerate(value):
        item_path = f"{path}[{index}]"
        if not isinstance(item, dict):
            raise RegistryError(f"{item_path}: expected mapping")
        _exact_keys(item, {"ref", "requirement_level"}, {"conditional", "constraints"}, item_path)
        reference = _string(item["ref"], f"{item_path}.ref", pattern=_ID)
        requirement_level = item["requirement_level"]
        if requirement_level not in {"required", "recommended", "optional", "conditional"}:
            raise RegistryError(f"{item_path}.requirement_level: unsupported value")
        if requirement_level == "conditional" and "conditional" not in item:
            raise RegistryError(f"{item_path}.conditional: required for conditional fields")
        conditional = None
        if "conditional" in item:
            conditional = _string(item["conditional"], f"{item_path}.conditional")
        constraints: dict[str, Any] = {}
        if "constraints" in item:
            constraints = _validate_constraint_map(
                item["constraints"],
                f"{item_path}.constraints",
            )
        result.append(AttributeUseIR(reference, requirement_level, conditional, constraints))
    if len(result) != len({item.ref for item in result}):
        raise RegistryError(f"{path}: duplicate attribute reference")
    return tuple(result)


def _parse_legacy_bindings(value: Any, path: str) -> None:
    if not isinstance(value, list):
        raise RegistryError(f"{path}: expected sequence")
    for index, item in enumerate(value):
        item_path = f"{path}[{index}]"
        if not isinstance(item, dict):
            raise RegistryError(f"{item_path}: expected mapping")
        _exact_keys(item, {"source", "disposition"}, {"details"}, item_path)
        _string(item["source"], f"{item_path}.source")
        _string(item["disposition"], f"{item_path}.disposition", pattern=_ID)
        if "details" in item:
            _validate_json_compatible(item["details"], f"{item_path}.details")


def _parse_metric_projections(value: Any, path: str) -> tuple[MetricProjectionIR, ...]:
    if not isinstance(value, list):
        raise RegistryError(f"{path}: expected sequence")
    projections: list[MetricProjectionIR] = []
    seen_profiles: set[str] = set()
    for index, item in enumerate(value):
        item_path = f"{path}[{index}]"
        if not isinstance(item, dict):
            raise RegistryError(f"{item_path}: expected mapping")
        _exact_keys(item, {"profile", "mappings"}, set(), item_path)
        profile = _string(item["profile"], f"{item_path}.profile", pattern=_ID)
        if profile in seen_profiles:
            raise RegistryError(f"{path}: duplicate profile")
        if profile != "local-observability-v1":
            raise RegistryError(f"{item_path}.profile: unknown metric compatibility profile")
        mappings = item["mappings"]
        if not isinstance(mappings, list) or not mappings:
            raise RegistryError(f"{item_path}.mappings: expected nonempty sequence")
        parsed: list[tuple[str, str]] = []
        seen_refs: set[str] = set()
        seen_labels: set[str] = set()
        for mapping_index, mapping in enumerate(mappings):
            mapping_path = f"{item_path}.mappings[{mapping_index}]"
            if not isinstance(mapping, dict):
                raise RegistryError(f"{mapping_path}: expected mapping")
            _exact_keys(mapping, {"ref", "label"}, set(), mapping_path)
            reference = _string(mapping["ref"], f"{mapping_path}.ref", pattern=_ID)
            label = _string(mapping["label"], f"{mapping_path}.label", pattern=_ID)
            if reference in seen_refs:
                raise RegistryError(f"{item_path}.mappings: duplicate ref")
            if label in seen_labels:
                raise RegistryError(f"{item_path}.mappings: duplicate projected label")
            if reference == label:
                raise RegistryError(f"{mapping_path}: identity projection must be omitted")
            seen_refs.add(reference)
            seen_labels.add(label)
            parsed.append((reference, label))
        seen_profiles.add(profile)
        projections.append(MetricProjectionIR(profile, tuple(parsed)))
    return tuple(projections)


def _parse_group(value: Any, path: str) -> GroupIR:
    if not isinstance(value, dict):
        raise RegistryError(f"{path}: expected mapping")
    _exact_keys(
        value,
        {"id", "type", "brief", "stability"},
        {"extends", "attributes", "body_fields", "span", "log", "metric", "x-defenseclaw"},
        path,
    )
    group_id = _string(value["id"], f"{path}.id", pattern=_ID)
    group_type = _string(value["type"], f"{path}.type")
    if group_type not in _GROUP_TYPE:
        raise RegistryError(f"{path}.type: unsupported group type")
    _string(value["brief"], f"{path}.brief")
    if value["stability"] not in _STABILITY:
        raise RegistryError(f"{path}.stability: unsupported stability")
    extends = _string_list(value.get("extends", []), f"{path}.extends")
    attribute_uses = _parse_attribute_uses(value.get("attributes"), f"{path}.attributes")
    attribute_uses += _parse_attribute_uses(value.get("body_fields"), f"{path}.body_fields")
    attribute_refs = tuple(item.ref for item in attribute_uses)
    span_name_pattern: str | None = None
    if "span" in value:
        if group_type != "span" or not isinstance(value["span"], dict):
            raise RegistryError(f"{path}.span: allowed only on span groups")
        _exact_keys(value["span"], {"name_pattern", "kinds", "status_rule"}, set(), f"{path}.span")
        span_name_pattern = _string(
            value["span"]["name_pattern"],
            f"{path}.span.name_pattern",
        )
        _string_list(value["span"]["kinds"], f"{path}.span.kinds", allow_empty=False)
        _string(value["span"]["status_rule"], f"{path}.span.status_rule")
    elif group_type == "span":
        raise RegistryError(f"{path}.span: required for span groups")
    event_name: str | None = None
    if "log" in value:
        if group_type != "log" or not isinstance(value["log"], dict):
            raise RegistryError(f"{path}.log: allowed only on log groups")
        _exact_keys(value["log"], {"event_name"}, set(), f"{path}.log")
        event_name = _string(value["log"]["event_name"], f"{path}.log.event_name", pattern=_ID)
    elif group_type == "log":
        raise RegistryError(f"{path}.log: required for log groups")
    instrument_name: str | None = None
    instrument_type: str | None = None
    metric_value_type: str | None = None
    metric_unit: str | None = None
    metric_temporality: str | None = None
    metric_boundaries: tuple[int | float, ...] | None = None
    empty_labels_reason: str | None = None
    metric_projections: tuple[MetricProjectionIR, ...] = ()
    if "metric" in value:
        if group_type != "metric" or not isinstance(value["metric"], dict):
            raise RegistryError(f"{path}.metric: allowed only on metric groups")
        _exact_keys(
            value["metric"],
            {"instrument_name", "instrument_type", "value_type", "unit", "description", "temporality"},
            {"boundaries", "empty_labels_reason", "label_projections"},
            f"{path}.metric",
        )
        for key in ("instrument_name", "instrument_type", "value_type", "unit", "description", "temporality"):
            _string(value["metric"][key], f"{path}.metric.{key}")
        instrument_name = value["metric"]["instrument_name"]
        instrument_type = value["metric"]["instrument_type"]
        metric_value_type = value["metric"]["value_type"]
        metric_unit = value["metric"]["unit"]
        metric_temporality = value["metric"]["temporality"]
        if instrument_type not in _METRIC_INSTRUMENT_TYPES:
            raise RegistryError(f"{path}.metric.instrument_type: unsupported value")
        if metric_value_type not in _METRIC_VALUE_TYPES:
            raise RegistryError(f"{path}.metric.value_type: unsupported value")
        if metric_temporality not in _METRIC_TEMPORALITIES:
            raise RegistryError(f"{path}.metric.temporality: unsupported value")
        if "empty_labels_reason" in value["metric"]:
            empty_labels_reason = _string(
                value["metric"]["empty_labels_reason"],
                f"{path}.metric.empty_labels_reason",
            )
        if "label_projections" in value["metric"]:
            metric_projections = _parse_metric_projections(
                value["metric"]["label_projections"],
                f"{path}.metric.label_projections",
            )
        if "boundaries" in value["metric"]:
            boundaries = value["metric"]["boundaries"]
            if not isinstance(boundaries, list):
                raise RegistryError(f"{path}.metric.boundaries: expected sequence")
            if instrument_type != "histogram":
                raise RegistryError(f"{path}.metric.boundaries: allowed only for histograms")
            parsed_boundaries: list[int | float] = []
            for boundary_index, boundary in enumerate(boundaries):
                boundary_path = f"{path}.metric.boundaries[{boundary_index}]"
                if type(boundary) not in {int, float} or (
                    type(boundary) is float and not math.isfinite(boundary)
                ):
                    raise RegistryError(f"{boundary_path}: expected finite number")
                if parsed_boundaries and boundary <= parsed_boundaries[-1]:
                    raise RegistryError(
                        f"{path}.metric.boundaries: values must be strictly ascending"
                    )
                parsed_boundaries.append(boundary)
            metric_boundaries = tuple(parsed_boundaries)
    elif group_type == "metric":
        raise RegistryError(f"{path}.metric: required for metric groups")
    event_refs: tuple[str, ...] = ()
    bucket: str | None = None
    if "x-defenseclaw" in value:
        extension = value["x-defenseclaw"]
        if not isinstance(extension, dict):
            raise RegistryError(f"{path}.x-defenseclaw: expected mapping")
        _exact_keys(
            extension,
            set(),
            {
                "bucket",
                "family_schema_version",
                "allowed_outcomes",
                "events",
                "link_relations",
                "mandatory_floor",
                "route_selector",
                "compatibility_profiles",
                "legacy_bindings",
            },
            f"{path}.x-defenseclaw",
        )
        if "bucket" in extension:
            bucket = _string(extension["bucket"], f"{path}.x-defenseclaw.bucket", pattern=_ID)
            if bucket not in EXPECTED_BUCKETS:
                raise RegistryError(f"{path}.x-defenseclaw.bucket: unknown catalog-v1 bucket")
        if "family_schema_version" in extension:
            _integer(extension["family_schema_version"], f"{path}.x-defenseclaw.family_schema_version")
        for key in ("allowed_outcomes", "events", "link_relations", "compatibility_profiles"):
            if key in extension:
                values = _string_list(extension[key], f"{path}.x-defenseclaw.{key}")
                if key == "events":
                    event_refs = values
        if "mandatory_floor" in extension:
            mandatory_floor = _string_list(
                extension["mandatory_floor"],
                f"{path}.x-defenseclaw.mandatory_floor",
            )
            if not set(mandatory_floor).issubset(_MANDATORY_RULES):
                raise RegistryError(f"{path}.x-defenseclaw.mandatory_floor: unknown rule")
        if "route_selector" in extension and type(extension["route_selector"]) is not bool:
            raise RegistryError(f"{path}.x-defenseclaw.route_selector: expected boolean")
        if "legacy_bindings" in extension:
            _parse_legacy_bindings(extension["legacy_bindings"], f"{path}.x-defenseclaw.legacy_bindings")
    if group_type in _SIGNAL_BY_GROUP_TYPE:
        if bucket is None:
            raise RegistryError(f"{path}.x-defenseclaw.bucket: required for signal families")
        if not isinstance(value.get("x-defenseclaw"), dict) or "family_schema_version" not in value["x-defenseclaw"]:
            raise RegistryError(f"{path}.x-defenseclaw.family_schema_version: required for signal families")
    return GroupIR(
        group_id,
        group_type,
        extends,
        attribute_uses,
        attribute_refs,
        event_refs,
        event_name,
        bucket,
        span_name_pattern,
        instrument_name,
        instrument_type,
        metric_value_type,
        metric_unit,
        metric_temporality,
        metric_boundaries,
        empty_labels_reason,
        metric_projections,
    )


def _parse_producer_identity(value: Any, path: str) -> ProducerIdentityIR:
    if not isinstance(value, dict):
        raise RegistryError(f"{path}: expected mapping")
    _exact_keys(value, {"event_name", "bucket"}, {"family", "compatibility_only"}, path)
    event_name = _string(value["event_name"], f"{path}.event_name", pattern=_ID)
    bucket = _string(value["bucket"], f"{path}.bucket", pattern=_ID)
    if bucket not in EXPECTED_BUCKETS:
        raise RegistryError(f"{path}.bucket: unknown catalog-v1 bucket")
    family = None
    if "family" in value:
        family = _string(value["family"], f"{path}.family", pattern=_ID)
    compatibility_only = value.get("compatibility_only", False)
    if type(compatibility_only) is not bool:
        raise RegistryError(f"{path}.compatibility_only: expected boolean")
    if compatibility_only:
        if not event_name.startswith("legacy.audit."):
            raise RegistryError(f"{path}.event_name: compatibility-only identity must use legacy.audit.*")
        if family is not None:
            raise RegistryError(f"{path}.family: compatibility-only identity must not define a family")
    else:
        if "compatibility_only" in value:
            raise RegistryError(f"{path}.compatibility_only: omit false compatibility marker")
        if family is None:
            raise RegistryError(f"{path}.family: required for canonical identity")
    return ProducerIdentityIR(event_name, bucket, family, compatibility_only)


def _parse_producer_identity_sets(
    value: Any,
    path: str,
) -> dict[str, tuple[ProducerIdentityIR, ...]]:
    if not isinstance(value, list):
        raise RegistryError(f"{path}: expected sequence")
    result: dict[str, tuple[ProducerIdentityIR, ...]] = {}
    for index, item in enumerate(value):
        item_path = f"{path}[{index}]"
        if not isinstance(item, dict):
            raise RegistryError(f"{item_path}: expected mapping")
        _exact_keys(item, {"id", "identities"}, set(), item_path)
        set_id = _string(item["id"], f"{item_path}.id", pattern=_ID)
        if set_id in result:
            raise RegistryError(f"{item_path}.id: duplicate producer identity set")
        identities = item["identities"]
        if not isinstance(identities, list) or not identities:
            raise RegistryError(f"{item_path}.identities: expected nonempty sequence")
        parsed = tuple(
            _parse_producer_identity(identity, f"{item_path}.identities[{identity_index}]")
            for identity_index, identity in enumerate(identities)
        )
        keys = [(identity.event_name, identity.bucket) for identity in parsed]
        if len(keys) != len(set(keys)):
            raise RegistryError(f"{item_path}.identities: duplicate identity")
        result[set_id] = parsed
    return result


def _parse_producer_mappings(
    value: Any,
    identity_sets: dict[str, tuple[ProducerIdentityIR, ...]],
    path: str,
) -> tuple[ProducerMappingIR, ...]:
    if not isinstance(value, list):
        raise RegistryError(f"{path}: expected sequence")
    seen: set[tuple[str, str]] = set()
    mappings: list[ProducerMappingIR] = []
    used_identity_sets: set[str] = set()
    for index, item in enumerate(value):
        item_path = f"{path}[{index}]"
        if not isinstance(item, dict):
            raise RegistryError(f"{item_path}: expected mapping")
        _exact_keys(
            item,
            {"producer", "key", "source", "event_name_policy", "severity_policy"},
            {
                "default_identity",
                "allowed_context_identity_set",
                "mandatory_rules",
                "companion_rules",
                "compatibility",
            },
            item_path,
        )
        producer = _string(item["producer"], f"{item_path}.producer", pattern=_ID)
        if producer not in {"gateway_event", "audit_action"}:
            raise RegistryError(f"{item_path}.producer: unsupported producer")
        key = _string(item["key"], f"{item_path}.key", pattern=_ID)
        identity = (producer, key)
        if identity in seen:
            raise RegistryError(f"{item_path}: duplicate producer mapping")
        seen.add(identity)
        _string(item["source"], f"{item_path}.source", pattern=_ID)
        policy = _string(item["event_name_policy"], f"{item_path}.event_name_policy", pattern=_ID)
        if policy not in {"fixed", "context_optional", "context_required"}:
            raise RegistryError(f"{item_path}.event_name_policy: unsupported policy")
        default = item.get("default_identity")
        context_set_id = item.get("allowed_context_identity_set")
        if policy in {"fixed", "context_optional"} and default is None:
            raise RegistryError(f"{item_path}.default_identity: required for {policy} policy")
        parsed_default = (
            _parse_producer_identity(default, f"{item_path}.default_identity")
            if default is not None
            else None
        )
        if policy == "context_required" and default is not None:
            raise RegistryError(f"{item_path}.default_identity: not allowed for context_required policy")
        if policy in {"context_optional", "context_required"} and context_set_id is None:
            raise RegistryError(f"{item_path}.allowed_context_identity_set: required for {policy} policy")
        if policy == "fixed" and context_set_id is not None:
            raise RegistryError(f"{item_path}.allowed_context_identity_set: not allowed for fixed policy")
        parsed_contexts: tuple[ProducerIdentityIR, ...] = ()
        if context_set_id is not None:
            context_set_id = _string(
                context_set_id,
                f"{item_path}.allowed_context_identity_set",
                pattern=_ID,
            )
            if context_set_id not in identity_sets:
                raise RegistryError(f"{item_path}.allowed_context_identity_set: unknown set")
            used_identity_sets.add(context_set_id)
            parsed_contexts = identity_sets[context_set_id]
        severity_policy = _string(item["severity_policy"], f"{item_path}.severity_policy", pattern=_ID)
        if severity_policy not in _SEVERITY_POLICIES:
            raise RegistryError(f"{item_path}.severity_policy: unknown policy")
        for key_name in ("mandatory_rules", "companion_rules"):
            if key_name in item:
                rules = _string_list(item[key_name], f"{item_path}.{key_name}")
                allowed = _MANDATORY_RULES if key_name == "mandatory_rules" else _COMPANION_RULES
                if not set(rules).issubset(allowed):
                    raise RegistryError(f"{item_path}.{key_name}: unknown rule")
        if "compatibility" in item:
            compatibility = item["compatibility"]
            if not isinstance(compatibility, dict):
                raise RegistryError(f"{item_path}.compatibility: expected mapping")
            _exact_keys(
                compatibility,
                set(),
                {"introduced_in", "legacy_event_prefix", "disposition", "removal_version"},
                f"{item_path}.compatibility",
            )
            for name, raw in compatibility.items():
                _string(raw, f"{item_path}.compatibility.{name}", pattern=_ID)
        mappings.append(
            ProducerMappingIR(
                producer,
                key,
                policy,
                parsed_default,
                parsed_contexts,
            )
        )
    unreferenced = sorted(set(identity_sets) - used_identity_sets)
    if unreferenced:
        raise RegistryError(f"{path}: unreferenced producer identity sets {unreferenced}")
    return tuple(mappings)


def _parse_domain(
    root: Path,
    relative: str,
    expected_domain: str,
    normalizers: dict[str, NormalizerIR],
) -> tuple[DomainIR, InputDigest]:
    path, normalized = _safe_relative(
        root,
        f"schemas/telemetry/v8/{relative}",
        f"registry.imports.{relative}",
        prefix=Path("schemas/telemetry/v8"),
    )
    document = load_yaml_strict(path)
    _exact_keys(
        document,
        {
            "schema_version",
            "domain",
            "attributes",
            "attribute_extensions",
            "groups",
            "producer_identity_sets",
            "producer_mappings",
        },
        set(),
        normalized,
    )
    if _integer(document["schema_version"], f"{normalized}.schema_version") != 1:
        raise RegistryError(f"{normalized}.schema_version: unsupported version")
    if document["domain"] != expected_domain:
        raise RegistryError(f"{normalized}.domain: expected {expected_domain}")
    raw_attributes = document["attributes"]
    if not isinstance(raw_attributes, list):
        raise RegistryError(f"{normalized}.attributes: expected sequence")
    attributes = tuple(
        _parse_attribute_definition(item, f"{normalized}.attributes[{index}]", normalizers)
        for index, item in enumerate(raw_attributes)
    )
    raw_extensions = document["attribute_extensions"]
    if not isinstance(raw_extensions, list):
        raise RegistryError(f"{normalized}.attribute_extensions: expected sequence")
    attribute_extensions = tuple(
        _parse_attribute_extension(
            item,
            f"{normalized}.attribute_extensions[{index}]",
            normalizers,
        )
        for index, item in enumerate(raw_extensions)
    )
    raw_groups = document["groups"]
    if not isinstance(raw_groups, list):
        raise RegistryError(f"{normalized}.groups: expected sequence")
    groups = tuple(_parse_group(item, f"{normalized}.groups[{index}]") for index, item in enumerate(raw_groups))
    identity_sets = _parse_producer_identity_sets(
        document["producer_identity_sets"],
        f"{normalized}.producer_identity_sets",
    )
    producer_mappings = _parse_producer_mappings(
        document["producer_mappings"],
        identity_sets,
        f"{normalized}.producer_mappings",
    )
    for label, values in (
        ("attributes", [item.id for item in attributes]),
        ("attribute_extensions", [item.ref for item in attribute_extensions]),
        ("groups", [item.id for item in groups]),
    ):
        if len(values) != len(set(values)):
            raise RegistryError(f"{normalized}.{label}: duplicate ID")
    raw, _ = _read_utf8(path)
    return DomainIR(
        expected_domain,
        normalized,
        attributes,
        attribute_extensions,
        groups,
        producer_mappings,
    ), InputDigest(normalized, _sha256(raw))


def _resolved_attributes(groups: dict[str, GroupIR], group_id: str) -> frozenset[str]:
    references = set(groups[group_id].attribute_refs)
    for parent in groups[group_id].extends:
        references.update(_resolved_attributes(groups, parent))
    return frozenset(references)


def _rfc6901_token(value: str) -> str:
    return value.replace("~", "~0").replace("/", "~1")


def _validate_example_field_classes(
    record: Any,
    signal: str,
    family: str,
    path: str,
    groups: dict[str, GroupIR],
    local_attributes: dict[str, AttributeIR],
    upstream_extensions: dict[str, AttributeExtensionIR],
) -> None:
    if not isinstance(record, dict):
        raise RegistryError(f"{path}: expected mapping")
    field_classes = record.get("field_classes")
    if not isinstance(field_classes, dict):
        raise RegistryError(f"{path}.field_classes: expected mapping")
    group = groups[family]
    resolved = _resolved_attributes(groups, family)
    reverse_projection: dict[str, str] = {}
    for projection in group.metric_projections:
        if projection.profile == "local-observability-v1":
            reverse_projection = {label: reference for reference, label in projection.mappings}
    if signal == "traces":
        parent = record.get("body")
        dynamic = parent.get("attributes") if isinstance(parent, dict) else None
        prefix = "/body/attributes/"
    elif signal == "logs":
        dynamic = record.get("body")
        prefix = "/body/"
    else:
        parent = record.get("instrument_data")
        dynamic = parent.get("attributes") if isinstance(parent, dict) else None
        prefix = "/instrument_data/attributes/"
    if not isinstance(dynamic, dict):
        raise RegistryError(f"{path}: valid {signal} example has no dynamic attribute mapping")
    expected: dict[str, str] = {}
    for wire_name in dynamic:
        if not isinstance(wire_name, str):
            raise RegistryError(f"{path}: dynamic attribute names must be strings")
        reference = reverse_projection.get(wire_name, wire_name)
        if reference not in resolved:
            raise RegistryError(f"{path}: unregistered dynamic field {wire_name!r}")
        local = local_attributes.get(reference)
        extension = upstream_extensions.get(reference)
        if local is not None:
            field_class = local.field_class
        elif extension is not None:
            field_class = extension.field_class
        else:
            raise RegistryError(f"{path}: dynamic field {wire_name!r} has no privacy metadata")
        expected[prefix + _rfc6901_token(wire_name)] = field_class
    observed: dict[str, str] = {}
    for pointer, field_class in field_classes.items():
        if not isinstance(pointer, str) or not pointer.startswith("/"):
            raise RegistryError(f"{path}.field_classes: keys must be RFC6901 pointers")
        if field_class not in _FIELD_CLASS:
            raise RegistryError(f"{path}.field_classes.{pointer}: unknown field class")
        observed[pointer] = field_class
    if observed != expected:
        missing = sorted(expected.keys() - observed.keys())
        extra = sorted(observed.keys() - expected.keys())
        mismatched = sorted(
            pointer
            for pointer in expected.keys() & observed.keys()
            if expected[pointer] != observed[pointer]
        )
        raise RegistryError(
            f"{path}.field_classes: coverage mismatch "
            f"missing={missing} extra={extra} mismatched={mismatched}"
        )


def _parse_examples(
    root: Path,
    relative: str,
    group_signals: dict[str, str],
    groups: dict[str, GroupIR],
    local_attributes: dict[str, AttributeIR],
    upstream_extensions: dict[str, AttributeExtensionIR],
) -> InputDigest:
    path, normalized = _safe_relative(
        root,
        f"schemas/telemetry/v8/{relative}",
        "registry.examples",
        prefix=Path("schemas/telemetry/v8"),
    )
    document = load_yaml_strict(path)
    _exact_keys(document, {"schema_version", "examples"}, set(), normalized)
    if _integer(document["schema_version"], f"{normalized}.schema_version") != 1:
        raise RegistryError(f"{normalized}.schema_version: unsupported version")
    examples = document["examples"]
    if not isinstance(examples, list):
        raise RegistryError(f"{normalized}.examples: expected sequence")
    seen: set[str] = set()
    for index, item in enumerate(examples):
        item_path = f"{normalized}.examples[{index}]"
        if not isinstance(item, dict):
            raise RegistryError(f"{item_path}: expected mapping")
        _exact_keys(
            item,
            {"id", "valid", "signal", "description"},
            {"family", "record", "expected_error"},
            item_path,
        )
        example_id = _string(item["id"], f"{item_path}.id", pattern=_ID)
        if example_id in seen:
            raise RegistryError(f"{item_path}.id: duplicate example")
        seen.add(example_id)
        if type(item["valid"]) is not bool:
            raise RegistryError(f"{item_path}.valid: expected boolean")
        signal = _string(item["signal"], f"{item_path}.signal")
        if signal not in {"logs", "traces", "metrics"}:
            raise RegistryError(f"{item_path}.signal: unsupported signal")
        family = None
        if "family" in item:
            family = _string(item["family"], f"{item_path}.family", pattern=_ID)
            if family not in group_signals:
                raise RegistryError(f"{item_path}.family: unknown family")
            if group_signals[family] != signal:
                raise RegistryError(f"{item_path}.signal: family belongs to another signal")
        _string(item["description"], f"{item_path}.description")
        if item["valid"]:
            if family is None or "record" not in item or "expected_error" in item:
                raise RegistryError(f"{item_path}: valid example requires family and record only")
        elif "expected_error" not in item or "record" not in item:
            raise RegistryError(f"{item_path}: invalid example requires record and expected_error")
        if "expected_error" in item:
            _string(item["expected_error"], f"{item_path}.expected_error", pattern=_ID)
        if "record" in item:
            _validate_json_compatible(item["record"], f"{item_path}.record")
        if item["valid"]:
            assert family is not None
            _validate_example_field_classes(
                item["record"],
                signal,
                family,
                f"{item_path}.record",
                groups,
                local_attributes,
                upstream_extensions,
            )
    raw, _ = _read_utf8(path)
    return InputDigest(normalized, _sha256(raw))


def _parse_metric_settings(
    defaults: Any,
    profiles: Any,
) -> MetricCompatibilityProfileIR:
    if not isinstance(defaults, dict):
        raise RegistryError("registry.metric_defaults: expected mapping")
    _exact_keys(defaults, {"cardinality_limit"}, set(), "registry.metric_defaults")
    if (
        _integer(defaults["cardinality_limit"], "registry.metric_defaults.cardinality_limit")
        != EXPECTED_METRIC_CARDINALITY_LIMIT
    ):
        raise RegistryError("registry.metric_defaults.cardinality_limit: expected 2048")
    if not isinstance(profiles, list) or len(profiles) != 1 or not isinstance(profiles[0], dict):
        raise RegistryError("registry.metric_compatibility_profiles: expected one profile")
    profile = profiles[0]
    _exact_keys(
        profile,
        {"id", "high_cardinality_families", "derived_spanmetrics"},
        set(),
        "registry.metric_compatibility_profiles[0]",
    )
    if profile["id"] != "local-observability-v1":
        raise RegistryError("registry.metric_compatibility_profiles[0].id: unexpected profile")
    families = profile["high_cardinality_families"]
    if not isinstance(families, list):
        raise RegistryError(
            "registry.metric_compatibility_profiles[0].high_cardinality_families: expected sequence"
        )
    observed: dict[str, frozenset[str]] = {}
    for index, item in enumerate(families):
        item_path = f"registry.metric_compatibility_profiles[0].high_cardinality_families[{index}]"
        if not isinstance(item, dict):
            raise RegistryError(f"{item_path}: expected mapping")
        _exact_keys(item, {"family", "labels"}, set(), item_path)
        family = _string(item["family"], f"{item_path}.family", pattern=_ID)
        labels = frozenset(_string_list(item["labels"], f"{item_path}.labels", allow_empty=False))
        if family in observed:
            raise RegistryError(f"{item_path}.family: duplicate family")
        observed[family] = labels
    if len(observed) != 8:
        raise RegistryError(
            "registry.metric_compatibility_profiles[0].high_cardinality_families: "
            "expected the eight reviewed application families"
        )
    spanmetrics = profile["derived_spanmetrics"]
    if not isinstance(spanmetrics, dict):
        raise RegistryError(
            "registry.metric_compatibility_profiles[0].derived_spanmetrics: expected mapping"
        )
    _exact_keys(
        spanmetrics,
        {
            "pipeline",
            "dimensions_cache_size",
            "resource_metrics_cache_size",
            "series_expiration",
        },
        set(),
        "registry.metric_compatibility_profiles[0].derived_spanmetrics",
    )
    expected_spanmetrics = {"pipeline": "spanmetrics/agent360", **EXPECTED_METRIC_PROFILE_LIMITS}
    if spanmetrics != expected_spanmetrics:
        raise RegistryError(
            "registry.metric_compatibility_profiles[0].derived_spanmetrics: "
            "must preserve the pinned Collector limits"
        )
    return MetricCompatibilityProfileIR("local-observability-v1", observed)


def compile_registry(root: Path) -> RegistryIR:
    root = root.resolve()
    registry_path = root / "schemas/telemetry/v8/registry.yaml"
    registry = load_yaml_strict(registry_path)
    _exact_keys(
        registry,
        {
            "schema_version",
            "registry_version",
            "bucket_catalog_version",
            "imports",
            "dependency_lock",
            "examples",
            "semantic_profiles",
            "normalizers",
            "metric_defaults",
            "metric_compatibility_profiles",
        },
        set(),
        "schemas/telemetry/v8/registry.yaml",
    )
    schema_version = _integer(registry["schema_version"], "registry.schema_version")
    if schema_version != 1:
        raise RegistryError("registry.schema_version: unsupported version")
    registry_version = _integer(registry["registry_version"], "registry.registry_version")
    bucket_catalog_version = _integer(registry["bucket_catalog_version"], "registry.bucket_catalog_version")
    imports = _string_list(registry["imports"], "registry.imports", allow_empty=False)
    if imports != EXPECTED_IMPORTS:
        raise RegistryError(f"registry.imports: expected canonical order {EXPECTED_IMPORTS}")
    lock_relative = _string(registry["dependency_lock"], "registry.dependency_lock")
    if lock_relative != "schemas/telemetry/v8/semconv.lock.yaml":
        raise RegistryError("registry.dependency_lock: unexpected path")
    dependencies, lock_digest = _parse_lock(root, lock_relative)
    producer_inventory, metric_inventory, inventory_digest = _parse_producer_inventory(root)
    normalizers = _parse_normalizer_catalog(registry["normalizers"], "registry.normalizers")
    normalizers_by_id = {item.id: item for item in normalizers}
    metric_compatibility_profile = _parse_metric_settings(
        registry["metric_defaults"],
        registry["metric_compatibility_profiles"],
    )
    profiles = registry["semantic_profiles"]
    if not isinstance(profiles, list) or len(profiles) != 1 or not isinstance(profiles[0], dict):
        raise RegistryError("registry.semantic_profiles: expected one profile")
    profile = profiles[0]
    _exact_keys(
        profile,
        {
            "id",
            "trace_schema_version",
            "gen_ai_semconv_profile",
            "openinference_profile",
            "galileo_compatibility_profile",
        },
        set(),
        "registry.semantic_profiles[0]",
    )
    for key, value in profile.items():
        _string(value, f"registry.semantic_profiles[0].{key}", pattern=_ID)
    if profile != EXPECTED_SEMANTIC_PROFILE:
        raise RegistryError("registry.semantic_profiles[0]: profile tuple does not match defenseclaw-genai-rich-v1")
    dependency_by_id = {item.id: item for item in dependencies}
    if profile["gen_ai_semconv_profile"] != dependency_by_id["otel_genai"].profile_id:
        raise RegistryError("registry.semantic_profiles[0].gen_ai_semconv_profile: lock mismatch")
    if profile["openinference_profile"] != dependency_by_id["openinference"].profile_id:
        raise RegistryError("registry.semantic_profiles[0].openinference_profile: lock mismatch")
    domains: list[DomainIR] = []
    domain_digests: list[InputDigest] = []
    for relative, expected_domain in zip(imports, EXPECTED_DOMAINS, strict=True):
        domain, digest = _parse_domain(root, relative, expected_domain, normalizers_by_id)
        domains.append(domain)
        domain_digests.append(digest)
    attribute_owners: dict[str, str] = {}
    upstream_attributes: dict[str, tuple[str, SnapshotAttribute]] = {}
    core_genai_overlaps = 0
    core_genai_deprecated_overlaps = 0
    openinference_core_overlaps: set[str] = set()
    observed_type_migrations: dict[str, tuple[tuple[str, ...], tuple[str, ...], str]] = {}
    for dependency in dependencies:
        for attribute in dependency.snapshot.attributes:
            prior = upstream_attributes.get(attribute.id)
            if prior is not None:
                prior_dependency, prior_attribute = prior
                if prior_dependency == "otel_core" and dependency.id == "openinference":
                    if attribute.id not in {"session.id", "user.id"}:
                        raise RegistryError(
                            f"upstream attribute {attribute.id}: unexpected OpenInference overlap"
                        )
                    if (prior_attribute.allowed_types, prior_attribute.shape) != (
                        attribute.allowed_types,
                        attribute.shape,
                    ):
                        raise RegistryError(
                            f"upstream attribute {attribute.id}: OpenInference overlap type mismatch"
                        )
                    openinference_core_overlaps.add(attribute.id)
                    continue
                if prior_dependency != "otel_core" or dependency.id != "otel_genai":
                    raise RegistryError(
                        f"upstream attribute {attribute.id}: duplicate dependency ownership"
                    )
                prior_shape = (
                    prior_attribute.allowed_types,
                    prior_attribute.shape,
                    prior_attribute.stability,
                    prior_attribute.enum,
                    prior_attribute.deprecated,
                )
                current_shape = (
                    attribute.allowed_types,
                    attribute.shape,
                    attribute.stability,
                    attribute.enum,
                    attribute.deprecated,
                )
                if prior_attribute.deprecated:
                    core_genai_deprecated_overlaps += 1
                    if prior_attribute.stability != "deprecated" or attribute.deprecated:
                        raise RegistryError(
                            f"upstream attribute {attribute.id}: invalid GenAI ownership transition"
                        )
                    if prior_attribute.allowed_types != attribute.allowed_types:
                        disposition = EXPECTED_UPSTREAM_TYPE_MIGRATIONS.get(attribute.id)
                        if disposition is None:
                            raise RegistryError(
                                f"upstream attribute {attribute.id}: unreviewed type migration"
                            )
                        observed_type_migrations[attribute.id] = (
                            prior_attribute.allowed_types,
                            attribute.allowed_types,
                            disposition[2],
                        )
                elif prior_shape != current_shape:
                    raise RegistryError(
                        f"upstream attribute {attribute.id}: active overlap is inconsistent"
                    )
                core_genai_overlaps += 1
            upstream_attributes[attribute.id] = (dependency.id, attribute)
            attribute_owners[attribute.id] = (
                "openinference_compatibility"
                if dependency.id == "openinference"
                else dependency.id
            )
    if core_genai_overlaps != 60 or core_genai_deprecated_overlaps != 58:
        raise RegistryError("upstream GenAI ownership overlap inventory changed")
    if openinference_core_overlaps != {"session.id", "user.id"}:
        raise RegistryError("upstream OpenInference/core overlap inventory changed")
    if observed_type_migrations != EXPECTED_UPSTREAM_TYPE_MIGRATIONS:
        raise RegistryError("upstream reviewed type-migration inventory changed")
    legacy_core_genai = {
        attribute_id
        for attribute_id, (dependency_id, attribute) in upstream_attributes.items()
        if dependency_id == "otel_core"
        and attribute.deprecated
        and attribute_id.startswith("gen_ai.")
    }
    if len(legacy_core_genai) != 10:
        raise RegistryError("upstream legacy-only core GenAI inventory changed")
    for attribute_id, (dependency_id, attribute) in tuple(upstream_attributes.items()):
        if (
            dependency_id == "otel_core"
            and attribute.deprecated
            and attribute_id.startswith("gen_ai.")
        ):
            del upstream_attributes[attribute_id]
            del attribute_owners[attribute_id]
    local_attributes: dict[str, AttributeIR] = {}
    for domain in domains:
        for attribute in domain.attributes:
            if attribute.id in attribute_owners:
                raise RegistryError(f"attribute {attribute.id}: duplicate ownership")
            attribute_owners[attribute.id] = domain.domain
            local_attributes[attribute.id] = attribute
    group_owners: dict[str, GroupIR] = {}
    for domain in domains:
        for group in domain.groups:
            if group.id in group_owners:
                raise RegistryError(f"group {group.id}: duplicate ownership")
            group_owners[group.id] = group
    log_event_names = [
        group.event_name
        for group in group_owners.values()
        if group.type == "log" and group.event_name is not None
    ]
    if len(log_event_names) != len(set(log_event_names)):
        raise RegistryError("log families: duplicate event_name")
    compatibility_names = set(log_event_names) & EXPECTED_COMPATIBILITY_LOG_IDENTITIES
    if compatibility_names != EXPECTED_COMPATIBILITY_LOG_IDENTITIES:
        raise RegistryError("log families: compatibility identity inventory mismatch")
    dotted_names = set(log_event_names) - compatibility_names
    if len(dotted_names) != EXPECTED_DOTTED_LOG_IDENTITIES or any(
        "." not in name for name in dotted_names
    ):
        raise RegistryError(
            f"log families: expected {EXPECTED_DOTTED_LOG_IDENTITIES} canonical dotted identities"
        )
    span_families = [group for group in group_owners.values() if group.type == "span"]
    if len(span_families) != EXPECTED_SPAN_FAMILIES:
        raise RegistryError(
            f"span families: expected {EXPECTED_SPAN_FAMILIES}, found {len(span_families)}"
        )
    producer_keys: dict[str, set[str]] = {producer: set() for producer in EXPECTED_PRODUCER_COUNTS}
    for domain in domains:
        for mapping in domain.producer_mappings:
            if mapping.key in producer_keys[mapping.producer]:
                raise RegistryError(f"producer mapping: duplicate {mapping.producer}/{mapping.key}")
            producer_keys[mapping.producer].add(mapping.key)
    for producer, expected in producer_inventory.items():
        if producer_keys[producer] != expected:
            missing = sorted(expected - producer_keys[producer])
            extra = sorted(producer_keys[producer] - expected)
            raise RegistryError(
                f"producer mappings {producer}: inventory mismatch missing={missing} extra={extra}"
            )
    for domain in domains:
        for attribute in domain.attributes:
            if attribute.alias_of is not None and attribute.alias_of not in attribute_owners:
                raise RegistryError(f"attribute {attribute.id}: unknown alias_of reference")
            if attribute.projection_only:
                target = local_attributes.get(attribute.alias_of or "")
                if (
                    attribute.alias_of is None
                    or target is None
                    or target.projection_only
                    or attribute.stability != "deprecated"
                    or attribute.deprecated_in is None
                    or attribute.removed_in is None
                    or attribute.owner != "defenseclaw"
                ):
                    raise RegistryError(
                        f"attribute {attribute.id}: invalid projection-only alias lifecycle"
                    )
            elif attribute.alias_of is not None:
                raise RegistryError(f"attribute {attribute.id}: aliases must be projection-only")
            if attribute.id.startswith("gen_ai."):
                if (
                    not attribute.projection_only
                    or attribute.alias_of is None
                    or not attribute.alias_of.startswith("defenseclaw.")
                ):
                    raise RegistryError(
                        f"attribute {attribute.id}: non-upstream gen_ai.* must be a projection-only alias"
                    )
        for group in domain.groups:
            for parent in group.extends:
                if parent not in group_owners:
                    raise RegistryError(f"group {group.id}: unknown extends reference")
            for reference in group.attribute_refs:
                if reference not in attribute_owners:
                    raise RegistryError(f"group {group.id}: unknown attribute reference")
                local_attribute = local_attributes.get(reference)
                if local_attribute is not None and local_attribute.projection_only:
                    raise RegistryError(
                        f"group {group.id}: projection-only alias cannot be a canonical field"
                    )
            for event in group.event_refs:
                if event.startswith("event."):
                    raise RegistryError(
                        f"group {group.id}: events must use public names without event. prefix"
                    )
                target = group_owners.get(f"event.{event}")
                if target is None or target.type != "span_event":
                    raise RegistryError(f"group {group.id}: unknown span-event reference")
        for mapping in domain.producer_mappings:
            identities = (
                (() if mapping.default_identity is None else (mapping.default_identity,))
                + mapping.allowed_context_identities
            )
            for identity in identities:
                if identity.compatibility_only:
                    continue
                target = group_owners.get(identity.family or "")
                if target is None or target.type != "log":
                    raise RegistryError(f"producer mapping: unknown log family {identity.family}")
                if target.event_name != identity.event_name:
                    raise RegistryError(
                        f"producer mapping {identity.event_name}: family event_name mismatch"
                    )
                if target.bucket != identity.bucket:
                    raise RegistryError(f"producer mapping {identity.event_name}: family bucket mismatch")
    upstream_extensions: dict[str, AttributeExtensionIR] = {}
    for domain in domains:
        for extension in domain.attribute_extensions:
            if extension.ref in upstream_extensions:
                raise RegistryError(f"attribute extension {extension.ref}: duplicate extension")
            if extension.ref not in upstream_attributes:
                raise RegistryError(
                    f"attribute extension {extension.ref}: expected canonical upstream attribute"
                )
            upstream = upstream_attributes[extension.ref][1]
            _validate_normalization_compatibility(
                extension.normalization,
                upstream.allowed_types,
                upstream.shape,
                f"attribute extension {extension.ref}.normalization",
            )
            upstream_extensions[extension.ref] = extension
    referenced_upstream = {
        reference
        for group in group_owners.values()
        for reference in group.attribute_refs
        if reference in upstream_attributes
    }
    if set(upstream_extensions) != referenced_upstream:
        missing = sorted(referenced_upstream - set(upstream_extensions))
        unreferenced = sorted(set(upstream_extensions) - referenced_upstream)
        raise RegistryError(
            f"attribute extensions: coverage mismatch missing={missing} unreferenced={unreferenced}"
        )
    _validate_attribute_use_constraints(
        group_owners,
        local_attributes,
        upstream_extensions,
        upstream_attributes,
    )
    _validate_alias_cycles(domains)
    _validate_group_cycles(group_owners)
    _validate_metric_attribute_safety(
        group_owners,
        local_attributes,
        upstream_extensions,
        upstream_attributes,
        metric_compatibility_profile,
        metric_inventory,
    )
    _validate_span_name_patterns(group_owners, local_attributes, upstream_extensions)
    group_signals = {
        group.id: _SIGNAL_BY_GROUP_TYPE[group.type]
        for group in group_owners.values()
        if group.type in _SIGNAL_BY_GROUP_TYPE
    }
    examples_relative = _string(registry["examples"], "registry.examples")
    if examples_relative != "examples.yaml":
        raise RegistryError("registry.examples: expected examples.yaml")
    examples_digest = _parse_examples(
        root,
        examples_relative,
        group_signals,
        group_owners,
        local_attributes,
        upstream_extensions,
    )
    registry_raw, _ = _read_utf8(registry_path)
    registry_digest = InputDigest("schemas/telemetry/v8/registry.yaml", _sha256(registry_raw))
    input_digests = (
        registry_digest,
        *domain_digests,
        lock_digest,
        inventory_digest,
        examples_digest,
    )
    return RegistryIR(
        schema_version=schema_version,
        registry_version=registry_version,
        bucket_catalog_version=bucket_catalog_version,
        imports=imports,
        input_digests=tuple(input_digests),
        dependencies=dependencies,
        normalizers=normalizers,
        metric_compatibility_profile=metric_compatibility_profile,
        domains=tuple(domains),
        legacy_only_upstream_attributes=tuple(sorted(legacy_core_genai)),
    )


def _validate_group_cycles(groups: dict[str, GroupIR]) -> None:
    visiting: set[str] = set()
    visited: set[str] = set()

    def visit(group_id: str) -> None:
        if group_id in visiting:
            raise RegistryError(f"group {group_id}: inheritance cycle")
        if group_id in visited:
            return
        visiting.add(group_id)
        for parent in groups[group_id].extends:
            visit(parent)
        visiting.remove(group_id)
        visited.add(group_id)

    for group_id in sorted(groups):
        visit(group_id)


def _validate_alias_cycles(domains: list[DomainIR]) -> None:
    aliases = {
        attribute.id: attribute.alias_of
        for domain in domains
        for attribute in domain.attributes
        if attribute.alias_of is not None
    }
    for start in sorted(aliases):
        seen: set[str] = set()
        current: str | None = start
        while current in aliases:
            if current in seen:
                raise RegistryError(f"attribute {start}: alias cycle")
            seen.add(current)
            current = aliases[current]


def _validate_attribute_use_constraints(
    groups: dict[str, GroupIR],
    local_attributes: dict[str, AttributeIR],
    upstream_extensions: dict[str, AttributeExtensionIR],
    upstream_attributes: dict[str, tuple[str, SnapshotAttribute]],
) -> None:
    numeric_types = {"int64", "double", "int64[]", "double[]"}
    array_types = {"string[]", "boolean[]", "int64[]", "double[]", "array"}
    string_types = {"string", "string[]"}
    for group in groups.values():
        for use in group.attribute_uses:
            if not use.constraints:
                continue
            local = local_attributes.get(use.ref)
            extension = upstream_extensions.get(use.ref)
            if local is not None:
                field_types = (local.field_type,)
                shape = "attribute"
                normalization = local.normalization
            elif extension is not None:
                upstream = upstream_attributes[use.ref][1]
                field_types = upstream.allowed_types
                shape = upstream.shape
                normalization = extension.normalization
            else:
                raise RegistryError(
                    f"group {group.id}: constrained attribute {use.ref} has no metadata"
                )
            types = set(field_types)
            structured = shape in {"any_value", "indexed_prefix", "object_prefix"} or bool(
                types & {"object", "array"}
            )
            constraints = use.constraints
            if "enum" in constraints:
                enum_types = types or {"object"}
                for value in constraints["enum"]:
                    compatible = (
                        (type(value) is str and bool(enum_types & string_types))
                        or (type(value) is bool and bool(enum_types & {"boolean", "boolean[]"}))
                        or (type(value) is int and bool(enum_types & numeric_types))
                        or (
                            type(value) is float
                            and bool(enum_types & {"double", "double[]"})
                        )
                    )
                    if not compatible:
                        raise RegistryError(
                            f"group {group.id}: constraint enum type is incompatible with {use.ref}"
                        )
            if "pattern" in constraints and not types.issubset(string_types):
                raise RegistryError(
                    f"group {group.id}: pattern constraint is incompatible with {use.ref}"
                )
            if ({"min", "max"} & constraints.keys()) and not types.issubset(numeric_types):
                raise RegistryError(
                    f"group {group.id}: numeric constraint is incompatible with {use.ref}"
                )
            if types & {"int64", "int64[]"} and any(
                key in constraints and type(constraints[key]) is not int
                for key in ("min", "max")
            ):
                raise RegistryError(
                    f"group {group.id}: int64 use constraints must be exact integers for {use.ref}"
                )
            if ({"min_items", "max_items"} & constraints.keys()) and not (
                bool(types & array_types) or structured
            ):
                raise RegistryError(
                    f"group {group.id}: item constraint is incompatible with {use.ref}"
                )
            if ({"max_utf8_bytes"} & constraints.keys()) and not (
                bool(types & (string_types | {"bytes"})) or structured
            ):
                raise RegistryError(
                    f"group {group.id}: byte constraint is incompatible with {use.ref}"
                )
            if ({"max_item_utf8_bytes"} & constraints.keys()) and not (
                "string[]" in types or structured
            ):
                raise RegistryError(
                    f"group {group.id}: per-item byte constraint is incompatible with {use.ref}"
                )
            if ({"max_depth", "max_properties"} & constraints.keys()) and not structured:
                raise RegistryError(
                    f"group {group.id}: structured constraint is incompatible with {use.ref}"
                )
            effective = normalization.effective_constraints
            for maximum in (
                "max",
                "max_items",
                "max_utf8_bytes",
                "max_item_utf8_bytes",
                "max_depth",
                "max_properties",
            ):
                if (
                    maximum in constraints
                    and maximum in effective
                    and constraints[maximum] > effective[maximum]
                ):
                    raise RegistryError(
                        f"group {group.id}: {maximum} weakens normalization for {use.ref}"
                    )
            for minimum in ("min", "min_items"):
                if (
                    minimum in constraints
                    and minimum in effective
                    and constraints[minimum] < effective[minimum]
                ):
                    raise RegistryError(
                        f"group {group.id}: {minimum} weakens normalization for {use.ref}"
                    )
            if "enum" in constraints and "enum" in effective and not set(
                constraints["enum"]
            ).issubset(effective["enum"]):
                raise RegistryError(
                    f"group {group.id}: enum constraint weakens normalization for {use.ref}"
                )


def _validate_metric_attribute_safety(
    groups: dict[str, GroupIR],
    local_attributes: dict[str, AttributeIR],
    upstream_extensions: dict[str, AttributeExtensionIR],
    upstream_attributes: dict[str, tuple[str, SnapshotAttribute]],
    compatibility_profile: MetricCompatibilityProfileIR,
    metric_inventory: dict[str, MetricInventoryIR],
) -> None:
    cache: dict[str, frozenset[str]] = {}

    def resolved(group_id: str) -> frozenset[str]:
        if group_id in cache:
            return cache[group_id]
        group = groups[group_id]
        references = set(group.attribute_refs)
        for parent in group.extends:
            references.update(resolved(parent))
        cache[group_id] = frozenset(references)
        return cache[group_id]

    metric_groups = [group for group in groups.values() if group.type == "metric"]
    instruments = [group.instrument_name for group in metric_groups]
    if None in instruments or len(instruments) != len(set(instruments)):
        raise RegistryError("metric families: instrument names must be present and unique")
    if set(instruments) != set(metric_inventory):
        raise RegistryError("metric families: current-state inventory instrument mismatch")
    profile_exceptions: dict[str, frozenset[str]] = {}
    prohibited_classes = {"content", "credential", "path", "evidence", "reason", "error"}
    for group in metric_groups:
        assert group.instrument_name is not None
        if group.id != f"metric.{group.instrument_name}":
            raise RegistryError(f"metric {group.id}: family ID must be metric.<instrument_name>")
        labels = resolved(group.id)
        if bool(labels) == bool(group.empty_labels_reason):
            requirement = "forbidden" if labels else "required"
            raise RegistryError(
                f"metric {group.id}: empty_labels_reason is {requirement} for this label set"
            )
        projections_by_profile = {item.profile: item for item in group.metric_projections}
        projection = projections_by_profile.get(compatibility_profile.id)
        projected = set(labels)
        if projection is not None:
            mappings = dict(projection.mappings)
            unknown = mappings.keys() - labels
            if unknown:
                raise RegistryError(
                    f"metric {group.id}: projection references unknown labels {sorted(unknown)}"
                )
            projected = {mappings.get(reference, reference) for reference in labels}
            if len(projected) != len(labels):
                raise RegistryError(f"metric {group.id}: projected label collision")
        inventory = metric_inventory[group.instrument_name]
        if group.instrument_type != inventory.instrument_type:
            raise RegistryError(
                f"metric {group.id}: instrument_type {group.instrument_type!r} differs from "
                f"current inventory {inventory.instrument_type!r}"
            )
        if group.metric_unit != inventory.unit:
            raise RegistryError(
                f"metric {group.id}: unit {group.metric_unit!r} differs from "
                f"current inventory {inventory.unit!r}"
            )
        if projected != inventory.labels:
            raise RegistryError(
                f"metric {group.id}: local-observability label mismatch "
                f"missing={sorted(inventory.labels - projected)} extra={sorted(projected - inventory.labels)}"
            )
        if group.empty_labels_reason != inventory.empty_labels_reason:
            raise RegistryError(f"metric {group.id}: empty-label reason differs from inventory")
        high_labels: set[str] = set()
        for reference in labels:
            local = local_attributes.get(reference)
            extension = upstream_extensions.get(reference)
            if local is not None:
                field_class = local.field_class
                cardinality = local.cardinality
                normalization = local.normalization
                field_types = (local.field_type,)
                if not reference.startswith("defenseclaw."):
                    raise RegistryError(
                        f"metric {group.id}: local canonical label {reference} must use defenseclaw.*"
                    )
            elif extension is not None:
                field_class = extension.field_class
                cardinality = extension.cardinality
                normalization = extension.normalization
                field_types = upstream_attributes[reference][1].allowed_types
            else:
                raise RegistryError(f"metric {group.id}: attribute {reference} has no privacy metadata")
            if field_class in prohibited_classes:
                raise RegistryError(
                    f"metric {group.id}: unsafe label attribute {reference} "
                    f"class={field_class} cardinality={cardinality}"
                )
            if cardinality == "high":
                high_labels.add(reference)
            if set(field_types) & {"string", "string[]"}:
                if normalization.id not in {"enum-v1", "bounded-v1", "identifier-v1"}:
                    raise RegistryError(
                        f"metric {group.id}: string label {reference} uses unbounded normalizer "
                        f"{normalization.id}"
                    )
                if "max_utf8_bytes" not in normalization.effective_constraints:
                    raise RegistryError(
                        f"metric {group.id}: string label {reference} lacks max_utf8_bytes"
                    )
        if high_labels:
            profile_exceptions[group.instrument_name] = labels
    if profile_exceptions != compatibility_profile.high_cardinality_families:
        missing = sorted(profile_exceptions.keys() - compatibility_profile.high_cardinality_families.keys())
        extra = sorted(compatibility_profile.high_cardinality_families.keys() - profile_exceptions.keys())
        mismatched = sorted(
            family
            for family in profile_exceptions.keys() & compatibility_profile.high_cardinality_families.keys()
            if profile_exceptions[family] != compatibility_profile.high_cardinality_families[family]
        )
        raise RegistryError(
            "metric compatibility profile: high-cardinality coverage mismatch "
            f"missing={missing} extra={extra} mismatched={mismatched}"
        )


def _validate_span_name_patterns(
    groups: dict[str, GroupIR],
    local_attributes: dict[str, AttributeIR],
    upstream_extensions: dict[str, AttributeExtensionIR],
) -> None:
    cache: dict[str, frozenset[str]] = {}

    def resolved(group_id: str) -> frozenset[str]:
        if group_id in cache:
            return cache[group_id]
        group = groups[group_id]
        references = set(group.attribute_refs)
        for parent in group.extends:
            references.update(resolved(parent))
        cache[group_id] = frozenset(references)
        return cache[group_id]

    prohibited_classes = {"content", "credential", "path", "evidence", "reason", "error"}
    formatter = string.Formatter()
    for group in groups.values():
        if group.type != "span" or group.span_name_pattern is None:
            continue
        available = resolved(group.id)
        try:
            parts = tuple(formatter.parse(group.span_name_pattern))
        except ValueError as exc:
            raise RegistryError(f"span {group.id}: invalid name pattern") from exc
        for _, placeholder, format_spec, conversion in parts:
            if placeholder is None:
                continue
            if (
                not _ID.fullmatch(placeholder)
                or format_spec
                or conversion is not None
                or placeholder not in available
            ):
                raise RegistryError(
                    f"span {group.id}: unresolved or transformed name placeholder {placeholder!r}"
                )
            local = local_attributes.get(placeholder)
            extension = upstream_extensions.get(placeholder)
            if local is not None:
                field_class = local.field_class
                cardinality = local.cardinality
            elif extension is not None:
                field_class = extension.field_class
                cardinality = extension.cardinality
            else:
                raise RegistryError(f"span {group.id}: name placeholder has no privacy metadata")
            if cardinality == "high" or field_class in prohibited_classes:
                raise RegistryError(
                    f"span {group.id}: unsafe name placeholder {placeholder} "
                    f"class={field_class} cardinality={cardinality}"
                )


def render_outputs(ir: RegistryIR) -> dict[Path, bytes]:
    manifest = {
        "format_version": 1,
        "generated_by": "scripts/generate_telemetry_registry.py",
        "generator_version": GENERATOR_VERSION,
        "registry_schema_version": ir.schema_version,
        "registry_version": ir.registry_version,
        "bucket_catalog_version": ir.bucket_catalog_version,
        "canonical_import_order": list(ir.imports),
        "inputs": [
            {"path": item.path, "sha256": item.sha256}
            for item in ir.input_digests
        ],
        "snapshots": [
            {
                "dependency_id": dependency.id,
                "path": dependency.snapshot.path,
                "sha256": dependency.snapshot.sha256,
            }
            for dependency in ir.dependencies
        ],
        "upstream_ownership_transitions": [
            {
                "attribute": attribute_id,
                "from_dependency": "otel_core",
                "to_dependency": "otel_genai",
                "from_allowed_types": list(disposition[0]),
                "to_allowed_types": list(disposition[1]),
                "disposition": disposition[2],
            }
            for attribute_id, disposition in sorted(EXPECTED_UPSTREAM_TYPE_MIGRATIONS.items())
        ],
        "upstream_compatibility_overlaps": [
            {
                "attribute": attribute_id,
                "canonical_owner": "otel_core",
                "compatibility_provenance": "openinference",
            }
            for attribute_id in ("session.id", "user.id")
        ],
        "legacy_only_upstream_attributes": list(ir.legacy_only_upstream_attributes),
        "outputs": [OUTPUT_MANIFEST.as_posix()],
    }
    encoded = (json.dumps(manifest, ensure_ascii=False, indent=2) + "\n").encode("utf-8")
    return {OUTPUT_MANIFEST: encoded}


def _render_to_directory(outputs: dict[Path, bytes], directory: Path) -> None:
    for relative, payload in outputs.items():
        target = directory / relative.relative_to("schemas/telemetry/generated")
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(payload)


def check_outputs(root: Path, outputs: dict[Path, bytes]) -> None:
    target_root = root / "schemas/telemetry/generated"
    expected = {path.relative_to("schemas/telemetry/generated") for path in outputs}
    actual = (
        {path.relative_to(target_root) for path in target_root.rglob("*") if path.is_file()}
        if target_root.is_dir()
        else set()
    )
    missing = sorted(path.as_posix() for path in expected - actual)
    extra = sorted(path.as_posix() for path in actual - expected)
    stale: list[str] = []
    for relative in sorted(expected & actual, key=lambda item: item.as_posix()):
        expected_bytes = outputs[Path("schemas/telemetry/generated") / relative]
        if (target_root / relative).read_bytes() != expected_bytes:
            stale.append(relative.as_posix())
    if missing or extra or stale:
        raise RegistryError(
            f"generated output drift: missing={missing}, extra={extra}, stale={stale}; "
            "run scripts/generate_telemetry_registry.py --write"
        )


def write_outputs(root: Path, outputs: dict[Path, bytes]) -> None:
    parent = root / "schemas/telemetry"
    parent.mkdir(parents=True, exist_ok=True)
    target = parent / "generated"
    stage = Path(tempfile.mkdtemp(prefix=".telemetry-generated-stage-", dir=parent))
    backup = parent / ".telemetry-generated-backup"
    try:
        _render_to_directory(outputs, stage)
        if backup.exists():
            raise RegistryError("stale telemetry generated-output backup exists")
        if target.exists():
            os.replace(target, backup)
        try:
            os.replace(stage, target)
        except BaseException:
            if backup.exists() and not target.exists():
                os.replace(backup, target)
            raise
        if backup.exists():
            shutil.rmtree(backup)
    finally:
        if stage.exists():
            shutil.rmtree(stage)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--write", action="store_true", help="write deterministic generated outputs")
    mode.add_argument("--check", action="store_true", help="fail when generated outputs drift")
    parser.add_argument("--root", type=Path, default=Path(__file__).resolve().parent.parent)
    args = parser.parse_args(argv)
    try:
        ir = compile_registry(args.root)
        outputs = render_outputs(ir)
        if args.write:
            write_outputs(args.root.resolve(), outputs)
        else:
            check_outputs(args.root.resolve(), outputs)
    except (RegistryError, OSError) as exc:
        print(f"telemetry registry generation failed: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
