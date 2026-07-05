#!/usr/bin/env python3
# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# SPDX-License-Identifier: Apache-2.0
"""Strict, lossless reader for the pinned public-schema migration baseline.

This module owns the baseline's pure trust boundary: bounded JSON parsing,
lossless number lexemes, canonical rendering, exact resource inventory and
identity, schema-subset checks, offline reference closure, and resource digest
binding.  It deliberately performs no Git or worktree I/O beyond reading the
selected baseline file.
"""

from __future__ import annotations

import hashlib
import json
import re
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path
from types import MappingProxyType
from typing import Any, NoReturn, TypeAlias

BASELINE_FORMAT_VERSION = 1
CANONICALIZATION_ID = "defenseclaw-lossless-json-v1"
RESOURCE_DIGEST_DOMAIN = b"defenseclaw-public-schema-resource-v1\x00"
GENERATED_SCHEMA_MARKER_KEY = "x-defenseclaw-generated"
MAX_JSON_DEPTH = 128
MAX_JSON_NODES = 250_000
FULL_COMMIT_RE = re.compile(r"^[0-9a-fA-F]{40}$")
EPOCH_RE = re.compile(r"^[a-z0-9][a-z0-9._-]{0,127}$")
HEX_OID_RE = re.compile(r"^[0-9a-f]{40}(?:[0-9a-f]{24})?$")

DRAFT_2020_12 = "https://json-schema.org/draft/2020-12/schema"
DRAFT_07 = "http://json-schema.org/draft-07/schema#"

PUBLIC_SCHEMA_IDENTITIES: tuple[tuple[str, str, str], ...] = (
    (
        "schemas/activity-event.json",
        DRAFT_2020_12,
        "https://defenseclaw.io/schemas/activity-event.json",
    ),
    (
        "schemas/audit-event.json",
        DRAFT_2020_12,
        "https://defenseclaw.io/schemas/audit-event.json",
    ),
    (
        "schemas/gateway-event-envelope.json",
        DRAFT_2020_12,
        "https://defenseclaw.io/schemas/gateway-event-envelope.json",
    ),
    (
        "schemas/hook-audit-envelope.json",
        DRAFT_2020_12,
        "https://defenseclaw.io/schemas/hook-audit-envelope.json",
    ),
    (
        "schemas/network-egress-event.json",
        DRAFT_07,
        "https://github.com/cisco-ai-defense/defenseclaw/schemas/network-egress-event.json",
    ),
    (
        "schemas/otel/agent-lifecycle-event.schema.json",
        DRAFT_2020_12,
        "https://defenseclaw.dev/schemas/otel/agent-lifecycle-event.schema.json",
    ),
    (
        "schemas/otel/asset-lifecycle-event.schema.json",
        DRAFT_2020_12,
        "https://defenseclaw.dev/schemas/otel/asset-lifecycle-event.schema.json",
    ),
    (
        "schemas/otel/connector-telemetry-event.schema.json",
        DRAFT_2020_12,
        "https://defenseclaw.dev/schemas/otel/connector-telemetry-event.schema.json",
    ),
    (
        "schemas/otel/galileo-export-profile.schema.json",
        DRAFT_2020_12,
        "https://defenseclaw.dev/schemas/otel/galileo-export-profile.schema.json",
    ),
    (
        "schemas/otel/metrics.schema.json",
        DRAFT_2020_12,
        "https://defenseclaw.dev/schemas/otel/metrics.schema.json",
    ),
    (
        "schemas/otel/resource.schema.json",
        DRAFT_2020_12,
        "https://defenseclaw.dev/schemas/otel/resource.schema.json",
    ),
    (
        "schemas/otel/runtime-agent-span.schema.json",
        DRAFT_2020_12,
        "https://defenseclaw.dev/schemas/otel/runtime-agent-span.schema.json",
    ),
    (
        "schemas/otel/runtime-alert-event.schema.json",
        DRAFT_2020_12,
        "https://defenseclaw.dev/schemas/otel/runtime-alert-event.schema.json",
    ),
    (
        "schemas/otel/runtime-approval-span.schema.json",
        DRAFT_2020_12,
        "https://defenseclaw.dev/schemas/otel/runtime-approval-span.schema.json",
    ),
    (
        "schemas/otel/runtime-llm-span.schema.json",
        DRAFT_2020_12,
        "https://defenseclaw.dev/schemas/otel/runtime-llm-span.schema.json",
    ),
    (
        "schemas/otel/runtime-tool-span.schema.json",
        DRAFT_2020_12,
        "https://defenseclaw.dev/schemas/otel/runtime-tool-span.schema.json",
    ),
    (
        "schemas/otel/scan-finding-event.schema.json",
        DRAFT_2020_12,
        "https://defenseclaw.dev/schemas/otel/scan-finding-event.schema.json",
    ),
    (
        "schemas/otel/scan-result-event.schema.json",
        DRAFT_2020_12,
        "https://defenseclaw.dev/schemas/otel/scan-result-event.schema.json",
    ),
    (
        "schemas/scan-event.json",
        DRAFT_2020_12,
        "https://defenseclaw.io/schemas/scan-event.json",
    ),
    (
        "schemas/scan-finding-event.json",
        DRAFT_2020_12,
        "https://defenseclaw.io/schemas/scan-finding-event.json",
    ),
    (
        "schemas/scan-result.json",
        DRAFT_2020_12,
        "https://defenseclaw.io/schemas/scan-result.json",
    ),
)

IDENTITY_BY_PATH = {path: (dialect, schema_id) for path, dialect, schema_id in PUBLIC_SCHEMA_IDENTITIES}
PATH_BY_SCHEMA_ID = {schema_id: path for path, _dialect, schema_id in PUBLIC_SCHEMA_IDENTITIES}

CANONICALIZATION_DESCRIPTOR = {
    "id": CANONICALIZATION_ID,
    "object_keys": "unicode-code-point-order",
    "arrays": "source-order",
    "strings": "no-unicode-normalization",
    "numbers": "original-token",
    "encoding": "utf-8",
    "line_endings": "lf",
    "trailing_newline": True,
}


class BaselineError(RuntimeError):
    """A bounded structural diagnostic that excludes raw source content."""


@dataclass(frozen=True, slots=True)
class RawNumber:
    """A syntactically valid JSON number retained as its original token."""

    token: str


JSONScalar: TypeAlias = None | bool | int | str | RawNumber
ImmutableJSON: TypeAlias = JSONScalar | tuple["ImmutableJSON", ...] | Mapping[str, "ImmutableJSON"]


@dataclass(frozen=True, slots=True)
class PublicSchemaSource:
    """Pinned Git source identity recorded by the baseline."""

    commit: str
    tree: str


@dataclass(frozen=True, slots=True)
class PublicSchemaResource:
    """One validated public schema with deeply immutable lossless JSON."""

    path: str
    dialect: str
    schema_id: str
    document: ImmutableJSON
    git_blob_oid: str
    source_sha256: str
    canonical_sha256: str
    number_lexemes: Mapping[str, str]


@dataclass(frozen=True, slots=True)
class PublicSchemaBaseline:
    """Typed immutable view of a fully validated baseline."""

    baseline_sha256: str
    format_version: int
    authority: str
    baseline_id: str
    canonicalization: Mapping[str, ImmutableJSON]
    source: PublicSchemaSource
    resources: tuple[PublicSchemaResource, ...]

    def resource(self, path: str) -> PublicSchemaResource:
        """Return the exact pinned resource or raise ``KeyError``."""

        for resource in self.resources:
            if resource.path == path:
                return resource
        raise KeyError(path)


def _fail(message: str) -> NoReturn:
    raise BaselineError(message)


def _reject_constant(_token: str) -> NoReturn:
    _fail("non-finite JSON numbers are forbidden")


def _pairs_without_duplicates(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            _fail("duplicate JSON object keys are forbidden")
        result[key] = value
    return result


def _validate_json_structure(value: Any) -> None:
    """Bound traversal and reject values outside the lossless JSON model."""

    stack: list[tuple[Any, int]] = [(value, 0)]
    nodes = 0
    while stack:
        item, depth = stack.pop()
        nodes += 1
        if nodes > MAX_JSON_NODES:
            _fail("JSON structure exceeds the node limit")
        if depth > MAX_JSON_DEPTH:
            _fail("JSON structure exceeds the depth limit")
        if isinstance(item, RawNumber) or item is None or isinstance(item, bool):
            continue
        if isinstance(item, int) and not isinstance(item, bool):
            continue
        if isinstance(item, float):
            _fail("native floating-point values are forbidden in canonical JSON")
        if isinstance(item, str):
            if any(0xD800 <= ord(character) <= 0xDFFF for character in item):
                _fail("lone Unicode surrogates are forbidden")
            continue
        if isinstance(item, list):
            stack.extend((child, depth + 1) for child in reversed(item))
            continue
        if isinstance(item, dict):
            for key, child in reversed(tuple(item.items())):
                if not isinstance(key, str):
                    _fail("JSON object keys must be strings")
                if any(0xD800 <= ord(character) <= 0xDFFF for character in key):
                    _fail("lone Unicode surrogates are forbidden")
                stack.append((child, depth + 1))
            continue
        _fail(f"unsupported JSON value type {type(item).__name__}")


def parse_lossless_json(raw: bytes, source: str) -> Any:
    """Parse strict UTF-8 JSON without converting number tokens to floats."""

    try:
        text = raw.decode("utf-8", errors="strict")
    except UnicodeDecodeError as exc:
        raise BaselineError(f"{source}: invalid UTF-8: {exc.reason}") from exc
    try:
        value = json.loads(
            text,
            object_pairs_hook=_pairs_without_duplicates,
            parse_int=RawNumber,
            parse_float=RawNumber,
            parse_constant=_reject_constant,
        )
    except BaselineError:
        raise
    except RecursionError as exc:
        raise BaselineError(f"{source}: JSON structure exceeds the parser depth limit") from exc
    except (json.JSONDecodeError, ValueError, OverflowError) as exc:
        raise BaselineError(f"{source}: invalid JSON structure") from exc
    _validate_json_structure(value)
    return value


def _escape_pointer(token: str) -> str:
    return token.replace("~", "~0").replace("/", "~1")


def _json_string(value: str) -> str:
    return json.dumps(value, ensure_ascii=False, allow_nan=False)


def render_lossless_json(value: Any, *, pretty: bool) -> bytes:
    """Render deterministic JSON while emitting ``RawNumber`` verbatim."""

    _validate_json_structure(value)

    def render(item: Any, depth: int) -> str:
        if isinstance(item, RawNumber):
            return item.token
        if item is None:
            return "null"
        if item is True:
            return "true"
        if item is False:
            return "false"
        if isinstance(item, int):
            return str(item)
        if isinstance(item, float):
            _fail("native floating-point values are forbidden in canonical JSON")
        if isinstance(item, str):
            return _json_string(item)
        if isinstance(item, list):
            if not item:
                return "[]"
            rendered = [render(child, depth + 1) for child in item]
            if not pretty:
                return "[" + ",".join(rendered) + "]"
            prefix = "  " * (depth + 1)
            return "[\n" + prefix + (",\n" + prefix).join(rendered) + "\n" + "  " * depth + "]"
        if isinstance(item, dict):
            if not item:
                return "{}"
            keys = sorted(item)
            if not pretty:
                return "{" + ",".join(f"{_json_string(key)}:{render(item[key], depth + 1)}" for key in keys) + "}"
            prefix = "  " * (depth + 1)
            entries = [f"{_json_string(key)}: {render(item[key], depth + 1)}" for key in keys]
            return "{\n" + prefix + (",\n" + prefix).join(entries) + "\n" + "  " * depth + "}"
        _fail(f"unsupported JSON value type {type(item).__name__}")

    try:
        return (render(value, 0) + ("\n" if pretty else "")).encode("utf-8")
    except RecursionError as exc:  # defensive: the explicit bound is lower
        raise BaselineError("JSON structure exceeds the renderer depth limit") from exc


def number_lexemes(value: Any, pointer: str = "") -> dict[str, str]:
    """Return the exact number token at every JSON Pointer."""

    result: dict[str, str] = {}
    stack: list[tuple[Any, str]] = [(value, pointer)]
    while stack:
        item, item_pointer = stack.pop()
        if isinstance(item, RawNumber):
            result[item_pointer] = item.token
        elif isinstance(item, list):
            stack.extend((child, f"{item_pointer}/{index}") for index, child in reversed(tuple(enumerate(item))))
        elif isinstance(item, dict):
            stack.extend(
                (child, f"{item_pointer}/{_escape_pointer(key)}") for key, child in reversed(tuple(item.items()))
            )
    return result


def _sha256(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def resource_digest(path: str, dialect: str, schema_id: str, document: Any) -> str:
    """Bind canonical schema bytes to their path and public identity."""

    canonical = render_lossless_json(document, pretty=False)
    preimage = b"".join(
        (
            RESOURCE_DIGEST_DOMAIN,
            path.encode("utf-8"),
            b"\x00",
            dialect.encode("utf-8"),
            b"\x00",
            schema_id.encode("utf-8"),
            b"\x00",
            canonical,
        )
    )
    return _sha256(preimage)


def _expect_string(document: dict[str, Any], key: str, path: str) -> str:
    value = document.get(key)
    if not isinstance(value, str):
        _fail(f"{path}: {key} must be a string")
    return value


def validate_identity(document: Any, path: str) -> tuple[str, str]:
    """Validate the exact dialect and schema identity for ``path``."""

    if not isinstance(document, dict):
        _fail(f"{path}: schema root must be an object")
    expected_dialect, expected_id = IDENTITY_BY_PATH[path]
    dialect = _expect_string(document, "$schema", path)
    schema_id = _expect_string(document, "$id", path)
    if dialect != expected_dialect:
        _fail(f"{path}: unexpected JSON Schema dialect")
    if schema_id != expected_id:
        _fail(f"{path}: unexpected schema identity")
    return dialect, schema_id


def validate_schema_subset(document: dict[str, Any], path: str) -> None:
    """Reject generated recursion and unsupported identity/base semantics."""

    if GENERATED_SCHEMA_MARKER_KEY in document:
        _fail(f"{path}: generated public-view sources cannot seed a baseline")
    unsupported = {
        "$anchor",
        "$dynamicAnchor",
        "$dynamicRef",
        "$recursiveAnchor",
        "$recursiveRef",
    }
    stack: list[tuple[Any, bool]] = [(document, True)]
    while stack:
        item, root = stack.pop()
        if isinstance(item, dict):
            for key in item:
                if key in unsupported:
                    _fail(f"{path}: unsupported recursive, dynamic, or anchor keyword")
                if not root and key in {"$id", "$schema"}:
                    _fail(f"{path}: nested schema identity/base rebasing is unsupported")
            stack.extend((child, False) for child in reversed(tuple(item.values())))
        elif isinstance(item, list):
            stack.extend((child, False) for child in reversed(item))


def _resolve_pointer(document: Any, fragment: str, source: str) -> None:
    if fragment == "":
        return
    if not fragment.startswith("/"):
        _fail(f"{source}: non-pointer reference fragments are unsupported")
    if "%" in fragment:
        _fail(f"{source}: percent-encoded reference fragments are unsupported")
    current = document
    for encoded in fragment[1:].split("/"):
        if re.search(r"~(?![01])", encoded):
            _fail(f"{source}: invalid JSON Pointer escape")
        token = encoded.replace("~1", "/").replace("~0", "~")
        if isinstance(current, dict) and token in current:
            current = current[token]
        elif isinstance(current, list) and re.fullmatch(r"0|[1-9][0-9]*", token):
            index = int(token)
            if index >= len(current):
                _fail(f"{source}: unresolved JSON Pointer fragment")
            current = current[index]
        else:
            _fail(f"{source}: unresolved JSON Pointer fragment")


def _walk_references(value: Any, source: str) -> list[str]:
    references: list[str] = []
    stack = [value]
    while stack:
        item = stack.pop()
        if isinstance(item, dict):
            for key, child in item.items():
                if key == "$ref":
                    if not isinstance(child, str):
                        _fail(f"{source}: $ref must be a string")
                    references.append(child)
                stack.append(child)
        elif isinstance(item, list):
            stack.extend(reversed(item))
    return references


def validate_reference_closure(resources: list[dict[str, Any]]) -> None:
    """Require every reference to resolve within the pinned inventory."""

    documents = {resource["path"]: resource["document"] for resource in resources}
    for resource in resources:
        source_path = resource["path"]
        for reference in _walk_references(resource["document"], source_path):
            if reference.startswith("#"):
                target_path = source_path
                fragment = reference[1:]
            else:
                if "#" in reference:
                    base, fragment = reference.split("#", 1)
                else:
                    base, fragment = reference, ""
                target_path = PATH_BY_SCHEMA_ID.get(base, "")
                if not target_path:
                    _fail(f"{source_path}: reference leaves the pinned offline resource set")
            _resolve_pointer(documents[target_path], fragment, source_path)


def _expect_exact_keys(value: dict[str, Any], expected: set[str], context: str) -> None:
    actual = set(value)
    if actual != expected:
        _fail(f"{context}: object key set does not match the pinned format")


def _native_integer(value: Any, context: str) -> int:
    if isinstance(value, RawNumber) and re.fullmatch(r"(?:0|[1-9][0-9]*)", value.token):
        return int(value.token)
    if isinstance(value, int) and not isinstance(value, bool):
        return value
    _fail(f"{context}: expected a nonnegative integer")


def _read_baseline_bytes(path: Path) -> bytes:
    try:
        return path.read_bytes()
    except OSError as exc:
        raise BaselineError(f"cannot read baseline {path}: {exc}") from exc


def _decode_baseline_document(raw: bytes, source: str) -> dict[str, Any]:
    value = parse_lossless_json(raw, source)
    if not isinstance(value, dict):
        _fail("baseline root must be an object")
    if raw != render_lossless_json(value, pretty=True):
        _fail("baseline bytes are not in canonical lossless JSON form")
    return value


def load_baseline_document(path: Path) -> dict[str, Any]:
    """Read canonical lossless baseline bytes without weakening shape checks."""

    return _decode_baseline_document(_read_baseline_bytes(path), str(path))


def validate_baseline_shape(baseline: dict[str, Any]) -> None:
    """Validate the exact baseline and every resource binding."""

    _expect_exact_keys(
        baseline,
        {
            "authority",
            "baseline_id",
            "canonicalization",
            "format_version",
            "resources",
            "source",
        },
        "baseline",
    )
    if _native_integer(baseline["format_version"], "baseline.format_version") != BASELINE_FORMAT_VERSION:
        _fail("unsupported baseline format version")
    if baseline["authority"] != "pre_cutover":
        _fail("baseline authority is not pre_cutover")
    baseline_id = baseline["baseline_id"]
    if not isinstance(baseline_id, str) or not EPOCH_RE.fullmatch(baseline_id):
        _fail("baseline has an invalid epoch ID")
    canonicalization = baseline["canonicalization"]
    if canonicalization != CANONICALIZATION_DESCRIPTOR:
        _fail("baseline canonicalization descriptor drift")
    source = baseline["source"]
    if not isinstance(source, dict):
        _fail("baseline.source must be an object")
    _expect_exact_keys(source, {"commit", "tree"}, "baseline.source")
    if not isinstance(source["commit"], str) or not FULL_COMMIT_RE.fullmatch(source["commit"]):
        _fail("baseline source commit is invalid")
    if not isinstance(source["tree"], str) or not HEX_OID_RE.fullmatch(source["tree"]):
        _fail("baseline source tree is invalid")
    resources = baseline["resources"]
    if not isinstance(resources, list):
        _fail("baseline.resources must be an array")
    expected_paths = [item[0] for item in PUBLIC_SCHEMA_IDENTITIES]
    actual_paths = [item.get("path") if isinstance(item, dict) else None for item in resources]
    if actual_paths != expected_paths:
        _fail("baseline does not contain the exact ordered 21-schema inventory")
    for resource in resources:
        if not isinstance(resource, dict):
            _fail("baseline resource must be an object")
        _expect_exact_keys(
            resource,
            {
                "canonical_sha256",
                "dialect",
                "document",
                "git_blob_oid",
                "number_lexemes",
                "path",
                "schema_id",
                "source_sha256",
            },
            f"resource {resource.get('path', '<unknown>')}",
        )
        path = resource["path"]
        dialect, schema_id = validate_identity(resource["document"], path)
        validate_schema_subset(resource["document"], path)
        if resource["dialect"] != dialect or resource["schema_id"] != schema_id:
            _fail(f"{path}: duplicated identity metadata drift")
        if not isinstance(resource["git_blob_oid"], str) or not HEX_OID_RE.fullmatch(resource["git_blob_oid"]):
            _fail(f"{path}: invalid Git blob object ID")
        for digest_key in ("canonical_sha256", "source_sha256"):
            digest = resource[digest_key]
            if not isinstance(digest, str) or not re.fullmatch(r"[0-9a-f]{64}", digest):
                _fail(f"{path}: invalid {digest_key}")
        expected_lexemes = number_lexemes(resource["document"])
        if resource["number_lexemes"] != expected_lexemes:
            _fail(f"{path}: number-lexeme index drift")
        expected_digest = resource_digest(path, dialect, schema_id, resource["document"])
        if resource["canonical_sha256"] != expected_digest:
            _fail(f"{path}: canonical resource digest drift")
    validate_reference_closure(resources)


def _freeze_json(value: Any) -> ImmutableJSON:
    if isinstance(value, dict):
        return MappingProxyType({key: _freeze_json(child) for key, child in value.items()})
    if isinstance(value, list):
        return tuple(_freeze_json(child) for child in value)
    return value


def _typed_baseline(document: dict[str, Any], baseline_sha256: str) -> PublicSchemaBaseline:
    source = document["source"]
    resources = tuple(
        PublicSchemaResource(
            path=resource["path"],
            dialect=resource["dialect"],
            schema_id=resource["schema_id"],
            document=_freeze_json(resource["document"]),
            git_blob_oid=resource["git_blob_oid"],
            source_sha256=resource["source_sha256"],
            canonical_sha256=resource["canonical_sha256"],
            number_lexemes=MappingProxyType(dict(resource["number_lexemes"])),
        )
        for resource in document["resources"]
    )
    return PublicSchemaBaseline(
        baseline_sha256=baseline_sha256,
        format_version=_native_integer(document["format_version"], "baseline.format_version"),
        authority=document["authority"],
        baseline_id=document["baseline_id"],
        canonicalization=MappingProxyType(
            {key: _freeze_json(value) for key, value in document["canonicalization"].items()}
        ),
        source=PublicSchemaSource(commit=source["commit"], tree=source["tree"]),
        resources=resources,
    )


def load_public_schema_baseline(path: Path) -> PublicSchemaBaseline:
    """Return a typed, deeply immutable, fully validated baseline."""

    raw = _read_baseline_bytes(path)
    return load_public_schema_baseline_bytes(raw, str(path))


def load_public_schema_baseline_bytes(raw: bytes, source: str) -> PublicSchemaBaseline:
    """Validate one in-memory baseline and bind its exact canonical byte digest."""

    document = _decode_baseline_document(raw, source)
    validate_baseline_shape(document)
    return _typed_baseline(document, _sha256(raw))
