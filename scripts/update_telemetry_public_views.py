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

"""Create and verify the immutable public-schema migration baseline.

This utility is deliberately separate from the telemetry registry compiler.
It reads each migration source from one fully-qualified Git commit, never from
the worktree.  The resulting file is an inert migration input until a later
change explicitly imports it into the registry.

The JSON reader is lossless for number tokens.  In particular, values such as
``0.0``, ``-0``, large integers, and exponent spellings are not routed through
an IEEE-754 value before they are hashed or rendered.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import subprocess
import sys
import tempfile
from collections.abc import Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Any, NoReturn

BASELINE_FORMAT_VERSION = 1
DEFAULT_BASELINE_ID = "public-schemas-v7"
DEFAULT_BASELINE_PATH = Path("schemas/telemetry/v8/baselines/public-schemas-v7.normalized.json")
CANONICALIZATION_ID = "defenseclaw-lossless-json-v1"
RESOURCE_DIGEST_DOMAIN = b"defenseclaw-public-schema-resource-v1\x00"
GENERATED_OUTPUT_MANIFEST_PATH = "schemas/telemetry/generated/output-manifest.json"
GENERATED_SCHEMA_MARKER_KEY = "x-defenseclaw-generated"
GIT_TIMEOUT_SECONDS = 15.0
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


@dataclass(frozen=True)
class RawNumber:
    """A syntactically valid JSON number retained as its original token."""

    token: str


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


def _number_lexemes(value: Any, pointer: str = "") -> dict[str, str]:
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


def _resource_digest(path: str, dialect: str, schema_id: str, document: Any) -> str:
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


def _git(
    root: Path,
    arguments: Sequence[str],
    *,
    binary: bool = False,
) -> bytes | str:
    command = [
        "git",
        "-c",
        "credential.interactive=never",
        "-C",
        str(root),
        *arguments,
    ]
    environment = {
        "PATH": os.environ.get("PATH", os.defpath),
        "GIT_CONFIG_GLOBAL": os.devnull,
        "GIT_CONFIG_NOSYSTEM": "1",
        "GIT_OPTIONAL_LOCKS": "0",
        "GIT_TERMINAL_PROMPT": "0",
        "GCM_INTERACTIVE": "Never",
        "LANG": "C",
        "LC_ALL": "C",
    }
    for name in ("COMSPEC", "PATHEXT", "SYSTEMROOT", "TEMP", "TMP", "TMPDIR", "WINDIR"):
        value = os.environ.get(name)
        if value:
            environment[name] = value
    try:
        result = subprocess.run(
            command,
            check=False,
            capture_output=True,
            text=not binary,
            timeout=GIT_TIMEOUT_SECONDS,
            env=environment,
        )
    except subprocess.TimeoutExpired as exc:
        raise BaselineError("Git object lookup timed out") from exc
    except OSError as exc:
        raise BaselineError("cannot execute Git") from exc
    if result.returncode != 0:
        raise BaselineError("Git object lookup failed")
    return result.stdout


def _required_git_text(root: Path, arguments: Sequence[str]) -> str:
    result = _git(root, arguments)
    if not isinstance(result, str):  # defensive type narrowing
        _fail("Git returned an unexpected result type")
    return result


def _validated_commit(root: Path, source_ref: str) -> tuple[str, str]:
    if not FULL_COMMIT_RE.fullmatch(source_ref):
        _fail("source-ref must be a full 40-hex commit ID")
    commit = source_ref.lower()
    object_type = _required_git_text(root, ["cat-file", "-t", commit]).strip()
    if object_type != "commit":
        _fail(f"source-ref names a {object_type!r} object, not a commit")
    tree = _required_git_text(root, ["rev-parse", f"{commit}^{{tree}}"]).strip()
    if not HEX_OID_RE.fullmatch(tree):
        _fail("Git returned an invalid tree object ID")
    return commit, tree


def _read_git_blob(root: Path, commit: str, path: str) -> tuple[str, bytes]:
    object_spec = f"{commit}:{path}"
    blob_oid = _required_git_text(root, ["rev-parse", object_spec]).strip()
    if not HEX_OID_RE.fullmatch(blob_oid):
        _fail(f"{path}: Git returned an invalid blob object ID")
    object_type = _required_git_text(root, ["cat-file", "-t", blob_oid]).strip()
    if object_type != "blob":
        _fail(f"{path}: source object is not a blob")
    raw = _git(root, ["cat-file", "blob", blob_oid], binary=True)
    if not isinstance(raw, bytes):  # defensive type narrowing
        _fail(f"{path}: Git returned a non-binary blob")
    return blob_oid, raw


def _read_optional_git_blob(root: Path, commit: str, path: str) -> bytes | None:
    listing = _git(
        root,
        ["ls-tree", "-z", "--full-tree", commit, "--", path],
        binary=True,
    )
    if not isinstance(listing, bytes):
        _fail("Git returned an unexpected tree-listing type")
    if listing == b"":
        return None
    entries = [entry for entry in listing.split(b"\x00") if entry]
    if len(entries) != 1 or b"\t" not in entries[0]:
        _fail("Git returned an invalid optional tree entry")
    header, listed_path = entries[0].split(b"\t", 1)
    fields = header.split(b" ")
    if len(fields) != 3:
        _fail("Git returned an invalid optional tree entry")
    _mode, object_type, raw_blob_oid = fields
    try:
        listed_path_text = listed_path.decode("utf-8", errors="strict")
        blob_oid = raw_blob_oid.decode("ascii", errors="strict")
        object_type_text = object_type.decode("ascii", errors="strict")
    except UnicodeDecodeError as exc:
        raise BaselineError("Git returned an invalid optional tree entry") from exc
    if listed_path_text != path or object_type_text != "blob":
        _fail("Git optional tree entry does not identify the expected blob")
    if not HEX_OID_RE.fullmatch(blob_oid):
        _fail("Git returned an invalid optional blob object ID")
    raw = _git(root, ["cat-file", "blob", blob_oid], binary=True)
    if not isinstance(raw, bytes):
        _fail("Git returned an unexpected optional blob type")
    return raw


def _generated_authority_paths(manifest: Any) -> set[str]:
    if not isinstance(manifest, dict):
        _fail("generated output manifest root must be an object")
    declared: set[str] = set()

    authority_paths = manifest.get("generated_authority_paths", [])
    if authority_paths is not None:
        if not isinstance(authority_paths, list):
            _fail("generated output manifest authority paths must be an array")
        if not all(isinstance(path, str) for path in authority_paths):
            _fail("generated output manifest authority path must be a string")
        declared.update(authority_paths)

    outputs = manifest.get("outputs", [])
    if outputs is not None:
        if not isinstance(outputs, list):
            _fail("generated output manifest outputs must be an array")
        for output in outputs:
            if isinstance(output, str):
                declared.add(output)
            elif isinstance(output, dict):
                path = output.get("path", output.get("output_path"))
                authority = output.get("authority", "generated")
                if path is not None and not isinstance(path, str):
                    _fail("generated output manifest output path must be a string")
                if authority == "generated" and path is not None:
                    declared.add(path)
            else:
                _fail("generated output manifest output entry has an invalid shape")

    public_views = manifest.get("public_views", [])
    if public_views is not None:
        if not isinstance(public_views, list):
            _fail("generated output manifest public views must be an array")
        for view in public_views:
            if not isinstance(view, dict):
                _fail("generated output manifest public view must be an object")
            path = view.get("output_path")
            authority = view.get("authority")
            if path is not None and not isinstance(path, str):
                _fail("generated output manifest public-view path must be a string")
            if authority == "generated" and path is not None:
                declared.add(path)
    return declared


def _reject_generated_source_commit(root: Path, commit: str) -> None:
    raw = _read_optional_git_blob(root, commit, GENERATED_OUTPUT_MANIFEST_PATH)
    if raw is None:
        return
    manifest = parse_lossless_json(raw, f"{commit}:{GENERATED_OUTPUT_MANIFEST_PATH}")
    generated = _generated_authority_paths(manifest)
    public_paths = set(IDENTITY_BY_PATH)
    if generated & public_paths:
        _fail("source commit declares a public schema as generated authority")


def _expect_string(document: dict[str, Any], key: str, path: str) -> str:
    value = document.get(key)
    if not isinstance(value, str):
        _fail(f"{path}: {key} must be a string")
    return value


def _validate_identity(document: Any, path: str) -> tuple[str, str]:
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


def _validate_schema_subset(document: dict[str, Any], path: str) -> None:
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


def _validate_reference_closure(resources: list[dict[str, Any]]) -> None:
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


def _make_resource(root: Path, commit: str, path: str) -> dict[str, Any]:
    blob_oid, raw = _read_git_blob(root, commit, path)
    document = parse_lossless_json(raw, f"{commit}:{path}")
    dialect, schema_id = _validate_identity(document, path)
    _validate_schema_subset(document, path)
    return {
        "canonical_sha256": _resource_digest(path, dialect, schema_id, document),
        "dialect": dialect,
        "document": document,
        "git_blob_oid": blob_oid,
        "number_lexemes": _number_lexemes(document),
        "path": path,
        "schema_id": schema_id,
        "source_sha256": _sha256(raw),
    }


def build_baseline(root: Path, source_ref: str, baseline_id: str) -> dict[str, Any]:
    if not EPOCH_RE.fullmatch(baseline_id):
        _fail("baseline ID must be a lowercase, filesystem-safe epoch token")
    commit, tree = _validated_commit(root, source_ref)
    _reject_generated_source_commit(root, commit)
    resources = [_make_resource(root, commit, path) for path, _dialect, _schema_id in PUBLIC_SCHEMA_IDENTITIES]
    _validate_reference_closure(resources)
    return {
        "authority": "pre_cutover",
        "baseline_id": baseline_id,
        "canonicalization": dict(CANONICALIZATION_DESCRIPTOR),
        "format_version": BASELINE_FORMAT_VERSION,
        "resources": resources,
        "source": {"commit": commit, "tree": tree},
    }


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


def _load_baseline(path: Path) -> dict[str, Any]:
    try:
        raw = path.read_bytes()
    except OSError as exc:
        raise BaselineError(f"cannot read baseline {path}: {exc}") from exc
    value = parse_lossless_json(raw, str(path))
    if not isinstance(value, dict):
        _fail("baseline root must be an object")
    if raw != render_lossless_json(value, pretty=True):
        _fail("baseline bytes are not in canonical lossless JSON form")
    return value


def _validate_baseline_shape(baseline: dict[str, Any]) -> None:
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
    if _native_integer(baseline["format_version"], "baseline.format_version") != 1:
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
        dialect, schema_id = _validate_identity(resource["document"], path)
        _validate_schema_subset(resource["document"], path)
        if resource["dialect"] != dialect or resource["schema_id"] != schema_id:
            _fail(f"{path}: duplicated identity metadata drift")
        if not isinstance(resource["git_blob_oid"], str) or not HEX_OID_RE.fullmatch(resource["git_blob_oid"]):
            _fail(f"{path}: invalid Git blob object ID")
        for digest_key in ("canonical_sha256", "source_sha256"):
            digest = resource[digest_key]
            if not isinstance(digest, str) or not re.fullmatch(r"[0-9a-f]{64}", digest):
                _fail(f"{path}: invalid {digest_key}")
        expected_lexemes = _number_lexemes(resource["document"])
        if resource["number_lexemes"] != expected_lexemes:
            _fail(f"{path}: number-lexeme index drift")
        expected_digest = _resource_digest(path, dialect, schema_id, resource["document"])
        if resource["canonical_sha256"] != expected_digest:
            _fail(f"{path}: canonical resource digest drift")
    _validate_reference_closure(resources)


def check_baseline(root: Path, baseline_path: Path) -> None:
    _validate_safe_baseline_path(root, baseline_path)
    baseline = _load_baseline(baseline_path)
    _validate_baseline_shape(baseline)
    commit, tree = _validated_commit(root, baseline["source"]["commit"])
    _reject_generated_source_commit(root, commit)
    if tree != baseline["source"]["tree"]:
        _fail("baseline source tree provenance drift")
    for resource in baseline["resources"]:
        path = resource["path"]
        blob_oid, raw = _read_git_blob(root, commit, path)
        if blob_oid != resource["git_blob_oid"]:
            _fail(f"{path}: Git blob provenance drift")
        if _sha256(raw) != resource["source_sha256"]:
            _fail(f"{path}: source SHA-256 provenance drift")
        source_document = parse_lossless_json(raw, f"{commit}:{path}")
        if render_lossless_json(source_document, pretty=False) != render_lossless_json(
            resource["document"], pretty=False
        ):
            _fail(f"{path}: normalized document differs from pinned Git source")


def _resolved_within(root: Path, path: Path) -> Path:
    resolved_root = root.resolve()
    candidate = path if path.is_absolute() else root / path
    resolved = candidate.resolve(strict=False)
    try:
        resolved.relative_to(resolved_root)
    except ValueError as exc:
        raise BaselineError("baseline path leaves the repository root") from exc
    return resolved


def _validate_safe_baseline_path(root: Path, path: Path) -> Path:
    resolved = _resolved_within(root, path)
    public_paths = {_resolved_within(root, Path(item[0])) for item in PUBLIC_SCHEMA_IDENTITIES}
    if resolved in public_paths:
        _fail("baseline path may not be a public schema render/source path")
    return resolved


def _atomic_write(path: Path, payload: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary_name = tempfile.mkstemp(prefix=f".{path.name}.", suffix=".tmp", dir=path.parent)
    temporary = Path(temporary_name)
    try:
        with os.fdopen(descriptor, "wb") as stream:
            stream.write(payload)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
        if os.name != "nt":  # Windows does not provide directory fsync.
            directory_fd = os.open(
                path.parent,
                os.O_RDONLY | getattr(os, "O_DIRECTORY", 0),
            )
            try:
                os.fsync(directory_fd)
            finally:
                os.close(directory_fd)
    except BaseException:
        try:
            temporary.unlink(missing_ok=True)
        finally:
            raise


def _write_built_baseline(path: Path, baseline: dict[str, Any]) -> None:
    _validate_baseline_shape(baseline)
    _atomic_write(path, render_lossless_json(baseline, pretty=True))


def _require_write(args: argparse.Namespace) -> None:
    if not args.write:
        _fail("mutating baseline commands require --write")


def _command_bootstrap(root: Path, baseline_path: Path, args: argparse.Namespace) -> None:
    _require_write(args)
    if baseline_path.exists():
        _fail("baseline already exists; use refresh or an explicit new epoch")
    baseline = build_baseline(root, args.source_ref, args.epoch)
    _write_built_baseline(baseline_path, baseline)


def _command_refresh(root: Path, baseline_path: Path, args: argparse.Namespace) -> None:
    _require_write(args)
    current = _load_baseline(baseline_path)
    _validate_baseline_shape(current)
    if current["authority"] != "pre_cutover":
        _fail("baseline refresh is forbidden after cutover")
    if args.epoch is not None and args.epoch != current["baseline_id"]:
        _fail("refresh cannot change the baseline epoch")
    baseline = build_baseline(root, args.source_ref, current["baseline_id"])
    _write_built_baseline(baseline_path, baseline)


def _command_new_epoch(root: Path, baseline_path: Path, args: argparse.Namespace) -> None:
    _require_write(args)
    if not args.acknowledge_breaking_baseline_epoch:
        _fail("new-epoch requires --acknowledge-breaking-baseline-epoch")
    current = _load_baseline(baseline_path)
    _validate_baseline_shape(current)
    if args.epoch == current["baseline_id"]:
        _fail("new-epoch must select a different baseline ID")
    baseline = build_baseline(root, args.source_ref, args.epoch)
    _write_built_baseline(baseline_path, baseline)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--root",
        type=Path,
        default=Path(__file__).resolve().parent.parent,
        help="repository root (defaults to this script's repository)",
    )
    parser.add_argument(
        "--baseline",
        type=Path,
        default=DEFAULT_BASELINE_PATH,
        help="baseline path relative to the repository root",
    )
    commands = parser.add_subparsers(dest="command", required=True)

    bootstrap = commands.add_parser("bootstrap", help="create the first baseline epoch")
    bootstrap.add_argument("--source-ref", required=True)
    bootstrap.add_argument("--epoch", default=DEFAULT_BASELINE_ID)
    bootstrap.add_argument("--write", action="store_true")

    refresh = commands.add_parser("refresh", help="refresh the pre-cutover epoch")
    refresh.add_argument("--source-ref", required=True)
    refresh.add_argument("--epoch")
    refresh.add_argument("--write", action="store_true")

    new_epoch = commands.add_parser("new-epoch", help="start an explicitly acknowledged replacement epoch")
    new_epoch.add_argument("--source-ref", required=True)
    new_epoch.add_argument("--epoch", required=True)
    new_epoch.add_argument("--acknowledge-breaking-baseline-epoch", action="store_true")
    new_epoch.add_argument("--write", action="store_true")

    commands.add_parser("check", help="verify baseline integrity and Git provenance")
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    root = args.root.resolve()
    try:
        baseline_path = _validate_safe_baseline_path(root, args.baseline)
        if args.command == "bootstrap":
            _command_bootstrap(root, baseline_path, args)
        elif args.command == "refresh":
            _command_refresh(root, baseline_path, args)
        elif args.command == "new-epoch":
            _command_new_epoch(root, baseline_path, args)
        elif args.command == "check":
            check_baseline(root, baseline_path)
        else:  # pragma: no cover - argparse constrains this value
            parser.error(f"unsupported command {args.command!r}")
    except BaselineError as exc:
        print(f"telemetry_public_views: error: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
