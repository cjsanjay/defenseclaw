#!/usr/bin/env python3
# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
# SPDX-License-Identifier: Apache-2.0

"""Execute the legacy-public-schema-parity-v1 compatibility corpus.

The immutable pre-cutover baseline is the legacy authority. Candidate input is
read only from the exact live paths declared by the digest-pinned public-view
plan. The checker never scans the repository for additional candidates.
"""

from __future__ import annotations

import argparse
import copy
import hashlib
import importlib.util
import json
import re
import stat
import sys
from collections import Counter
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from types import ModuleType
from typing import Any, Final, NoReturn
from urllib.parse import urldefrag

import yaml
from jsonschema import validators
from referencing import Registry, Resource
from referencing.exceptions import NoSuchResource


def _load_baseline_reader() -> ModuleType:
    name = "telemetry_public_schema_baseline"
    try:
        path = Path(__file__).resolve().with_name(f"{name}.py").resolve(strict=True)
        if not stat.S_ISREG(path.stat().st_mode):
            raise OSError("baseline reader is not a regular file")
    except (OSError, RuntimeError) as exc:
        raise RuntimeError("cannot load telemetry public-schema baseline reader") from exc
    existing = sys.modules.get(name)
    if existing is not None:
        if not isinstance(existing, ModuleType):
            raise RuntimeError("preloaded telemetry public-schema baseline reader is unsafe")
        try:
            existing_path = Path(existing.__file__).resolve(strict=True)
            existing_spec = existing.__spec__
            if (
                existing.__name__ != name
                or existing_spec is None
                or existing_spec.name != name
                or existing_spec.loader is None
                or existing_spec.origin is None
            ):
                raise RuntimeError("preloaded reader has no canonical import identity")
            origin_path = Path(existing_spec.origin).resolve(strict=True)
            if not stat.S_ISREG(existing_path.stat().st_mode) or not stat.S_ISREG(origin_path.stat().st_mode):
                raise RuntimeError("preloaded reader is not a regular file")
        except (AttributeError, OSError, RuntimeError, TypeError) as exc:
            raise RuntimeError("preloaded telemetry public-schema baseline reader is unsafe") from exc
        if existing_path != path or origin_path != path:
            raise RuntimeError("preloaded telemetry public-schema baseline reader has foreign provenance")
        return existing
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise RuntimeError("cannot load telemetry public-schema baseline reader")
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    try:
        spec.loader.exec_module(module)
    except Exception:
        if sys.modules.get(name) is module:
            del sys.modules[name]
        raise
    return module


baseline_reader = _load_baseline_reader()

DEFAULT_MANIFEST: Final = Path("schemas/telemetry/v8/fixtures/legacy-public-schema-parity-v1/manifest.json")
PUBLIC_VIEWS_PATH: Final = Path("schemas/telemetry/v8/public-views.yaml")
BASELINE_PATH: Final = Path("schemas/telemetry/v8/baselines/public-schemas-v7.normalized.json")
MARKER_KEY: Final = "x-defenseclaw-generated"
BOUNDARY_STRATEGIES: Final = (
    "const",
    "enum",
    "maximum",
    "maxItems",
    "maxLength",
    "maxProperties",
    "minimum",
    "minLength",
    "pattern",
    "type",
)
EXPECTED_MANIFEST_KEYS: Final = {
    "authority",
    "baseline_id",
    "baseline_sha256",
    "boundary_strategies",
    "candidate_mode",
    "candidate_root",
    "coverage_strategy",
    "expected",
    "format_version",
    "id",
    "invalid_witness_strategy",
    "public_views_sha256",
    "valid_witness_strategy",
    "view_selection",
}
EXPECTED_COUNTS: Final = {
    "views": 21,
    "outputs": 26,
    "fields": 756,
    "dynamic_scopes": 94,
    "references": 39,
    "number_lexemes": 162,
}
SCHEMA_CHILD_MAPS: Final = ("$defs", "definitions", "properties", "patternProperties")
SCHEMA_CHILD_VALUES: Final = (
    "additionalProperties",
    "contains",
    "else",
    "if",
    "items",
    "not",
    "propertyNames",
    "then",
    "unevaluatedProperties",
)
SCHEMA_CHILD_ARRAYS: Final = ("allOf", "anyOf", "oneOf", "prefixItems")


class ParityError(RuntimeError):
    """A bounded compatibility diagnostic that never includes payload data."""


@dataclass(frozen=True, slots=True)
class ParityReport:
    views: int
    outputs: int
    fields: int
    dynamic_scopes: int
    references: int
    number_lexemes: int
    valid_witnesses: int
    invalid_witnesses: int
    required_omissions: int
    closed_extras: int
    boundary_cases: Mapping[str, int]


def _fail(message: str) -> NoReturn:
    raise ParityError(message)


def _sha256(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def _strict_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            _fail("fixture manifest contains a duplicate JSON object key")
        result[key] = value
    return result


def _load_manifest(raw: bytes) -> dict[str, Any]:
    try:
        value = json.loads(raw, object_pairs_hook=_strict_object)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ParityError("fixture manifest is not strict JSON") from exc
    if not isinstance(value, dict) or set(value) != EXPECTED_MANIFEST_KEYS:
        _fail("fixture manifest shape drift")
    canonical = (json.dumps(value, ensure_ascii=False, indent=2, sort_keys=True) + "\n").encode()
    if raw != canonical:
        _fail("fixture manifest is not canonical JSON")
    if (
        type(value["format_version"]) is not int
        or value["format_version"] != 1
        or value["id"] != "legacy-public-schema-parity-v1"
        or value["authority"] != "compatibility-witness-only"
        or value["baseline_id"] != "public-schemas-v7"
        or value["candidate_mode"] != "exact-live-paths-v1"
        or value["candidate_root"] != "."
        or value["view_selection"] != "exact-public-views-source-v1"
        or value["valid_witness_strategy"] != "derived-minimal-valid-v1"
        or value["invalid_witness_strategy"] != "derived-root-wrong-type-v1"
        or value["coverage_strategy"] != "derived-exhaustive-public-view-v1"
        or tuple(value["boundary_strategies"]) != BOUNDARY_STRATEGIES
        or value["expected"] != EXPECTED_COUNTS
    ):
        _fail("fixture manifest contract drift")
    for name in ("baseline_sha256", "public_views_sha256"):
        digest = value[name]
        if not isinstance(digest, str) or re.fullmatch(r"[0-9a-f]{64}", digest) is None:
            _fail(f"fixture manifest {name} is invalid")
    return value


def _load_yaml_mapping(raw: bytes, context: str) -> dict[str, Any]:
    try:
        value = yaml.safe_load(raw)
    except yaml.YAMLError as exc:
        raise ParityError(f"{context} is not valid YAML") from exc
    if not isinstance(value, dict):
        _fail(f"{context} root must be a mapping")
    return value


def _validated_live_candidate_path(root: Path, relative_path: str) -> Path:
    pure = PurePosixPath(relative_path)
    if (
        not relative_path
        or pure.is_absolute()
        or pure.as_posix() != relative_path
        or any(part in {"", ".", ".."} for part in pure.parts)
    ):
        _fail("live public-view path is not a normalized repository-relative path")
    current = root
    for index, part in enumerate(pure.parts):
        current /= part
        try:
            mode = current.lstat().st_mode
        except OSError as exc:
            raise ParityError("declared live public-view path is missing") from exc
        if stat.S_ISLNK(mode):
            _fail("declared live public-view path contains a symlink")
        if index == len(pure.parts) - 1:
            if not stat.S_ISREG(mode):
                _fail("declared live public-view path is not a regular file")
        elif not stat.S_ISDIR(mode):
            _fail("declared live public-view parent is not a directory")
    return current


def _escape(value: str) -> str:
    return value.replace("~", "~0").replace("/", "~1")


def _unescape(value: str) -> str:
    if re.search(r"~(?![01])", value):
        _fail("invalid JSON Pointer escape")
    return value.replace("~1", "/").replace("~0", "~")


def _pointer_get(document: Any, pointer: str) -> Any:
    if pointer == "":
        return document
    if not pointer.startswith("/"):
        _fail("invalid JSON Pointer")
    current = document
    for raw_token in pointer[1:].split("/"):
        token = _unescape(raw_token)
        if isinstance(current, Mapping):
            if token not in current:
                _fail(f"unresolved schema pointer {pointer}")
            current = current[token]
        elif isinstance(current, Sequence) and not isinstance(current, (str, bytes, bytearray)):
            if not token.isascii() or not token.isdigit():
                _fail(f"unresolved schema pointer {pointer}")
            index = int(token)
            if index >= len(current):
                _fail(f"unresolved schema pointer {pointer}")
            current = current[index]
        else:
            _fail(f"unresolved schema pointer {pointer}")
    return current


def _native_json(value: Any) -> Any:
    return json.loads(baseline_reader.render_lossless_json(value, pretty=False))


def _walk_values(value: Any, pointer: str = "") -> Iterable[tuple[str, Any]]:
    yield pointer, value
    if isinstance(value, Mapping):
        for key, child in value.items():
            yield from _walk_values(child, f"{pointer}/{_escape(key)}")
    elif isinstance(value, Sequence) and not isinstance(value, (str, bytes, bytearray)):
        for index, child in enumerate(value):
            yield from _walk_values(child, f"{pointer}/{index}")


def _reference_inventory(document: Mapping[str, Any]) -> tuple[tuple[str, str], ...]:
    return tuple(
        (pointer, value["$ref"])
        for pointer, value in _walk_values(document)
        if isinstance(value, Mapping) and isinstance(value.get("$ref"), str)
    )


def _walk_schema_nodes(schema: Mapping[str, Any], pointer: str = "") -> Iterable[tuple[str, Mapping[str, Any]]]:
    yield pointer, schema
    for keyword in SCHEMA_CHILD_MAPS:
        children = schema.get(keyword)
        if isinstance(children, Mapping):
            for name, child in children.items():
                if isinstance(child, Mapping):
                    yield from _walk_schema_nodes(child, f"{pointer}/{_escape(keyword)}/{_escape(name)}")
    for keyword in SCHEMA_CHILD_VALUES:
        child = schema.get(keyword)
        if isinstance(child, Mapping):
            yield from _walk_schema_nodes(child, f"{pointer}/{_escape(keyword)}")
    for keyword in SCHEMA_CHILD_ARRAYS:
        children = schema.get(keyword)
        if isinstance(children, list):
            for index, child in enumerate(children):
                if isinstance(child, Mapping):
                    yield from _walk_schema_nodes(child, f"{pointer}/{_escape(keyword)}/{index}")


def _offline_retrieve(uri: str) -> Resource[Any]:
    raise NoSuchResource(ref=uri)


class _SchemaWorld:
    def __init__(self, documents: Mapping[str, Mapping[str, Any]]) -> None:
        self.documents = dict(documents)
        registry: Registry[Any] = Registry(retrieve=_offline_retrieve)
        registry = registry.with_resources(
            (schema_id, Resource.from_contents(document)) for schema_id, document in self.documents.items()
        )
        self.registry = registry
        self._validators: dict[tuple[str, str], Any] = {}
        for schema_id, document in self.documents.items():
            validator_type = validators.validator_for(document)
            validator_type.check_schema(document)
            self._validators[(schema_id, "")] = validator_type(
                document,
                registry=self.registry,
                format_checker=None,
            )

    def validator(self, schema_id: str, pointer: str = "") -> Any:
        key = (schema_id, pointer)
        cached = self._validators.get(key)
        if cached is not None:
            return cached
        document = self.documents[schema_id]
        reference = schema_id + (f"#{pointer}" if pointer else "")
        wrapper = {"$schema": document["$schema"], "$ref": reference}
        validator_type = validators.validator_for(wrapper)
        validator = validator_type(wrapper, registry=self.registry, format_checker=None)
        self._validators[key] = validator
        return validator

    def is_valid(self, schema_id: str, pointer: str, value: Any) -> bool:
        try:
            return next(self.validator(schema_id, pointer).iter_errors(value), None) is None
        except Exception as exc:
            raise ParityError("offline schema resolution failed") from exc


def _resolve_schema(
    schema: Mapping[str, Any],
    schema_id: str,
    documents: Mapping[str, Mapping[str, Any]],
) -> tuple[Mapping[str, Any], str]:
    reference = schema.get("$ref")
    if not isinstance(reference, str):
        return schema, schema_id
    base, fragment = urldefrag(reference)
    target_id = base or schema_id
    target = documents.get(target_id)
    if target is None:
        _fail("synthesis reference leaves offline resource set")
    pointer = f"/{fragment[1:]}" if fragment.startswith("/") else ("" if fragment == "" else fragment)
    resolved = _pointer_get(target, pointer)
    if not isinstance(resolved, Mapping):
        _fail("synthesis reference does not resolve to a schema object")
    siblings = {key: value for key, value in schema.items() if key != "$ref"}
    if siblings:
        resolved = _merge_schema(resolved, siblings)
    return resolved, target_id


def _merge_schema(left: Mapping[str, Any], right: Mapping[str, Any]) -> dict[str, Any]:
    result = copy.deepcopy(dict(left))
    for key, value in right.items():
        if key == "properties" and isinstance(value, Mapping):
            properties = dict(result.get("properties", {}))
            properties.update(copy.deepcopy(dict(value)))
            result[key] = properties
        elif key == "required" and isinstance(value, list):
            result[key] = list(dict.fromkeys([*result.get("required", []), *value]))
        else:
            result[key] = copy.deepcopy(value)
    return result


def _string_witness(schema: Mapping[str, Any], *, exact_length: int | None = None) -> str:
    minimum = schema.get("minLength", 0)
    maximum = schema.get("maxLength")
    if type(minimum) is not int:
        minimum = 0
    candidates = [
        "x",
        "a",
        "0",
        "chat x",
        "execute_tool x",
        "exec.approval/x",
        "invoke_agent",
        "codex.notify.x",
        "execution-" + "0" * 16,
        "lifecycle-" + "0" * 16,
        "sha256:" + "0" * 64,
        "0" * 16,
        "0" * 32,
        "00000000-0000-4000-8000-000000000000",
        "2026-01-01T00:00:00Z",
        "",
    ]
    if exact_length is not None:
        candidates.insert(0, "x" * exact_length)
    pattern = schema.get("pattern")
    for candidate in candidates:
        if exact_length is not None and len(candidate) != exact_length:
            continue
        if len(candidate) < minimum or (type(maximum) is int and len(candidate) > maximum):
            continue
        if isinstance(pattern, str) and re.search(pattern, candidate) is None:
            continue
        return candidate
    length = exact_length if exact_length is not None else max(minimum, 1)
    candidate = "x" * length
    if type(maximum) is int and len(candidate) > maximum:
        _fail("cannot derive bounded string witness")
    if isinstance(pattern, str) and re.search(pattern, candidate) is None:
        _fail("cannot derive pattern witness")
    return candidate


def _schema_type(schema: Mapping[str, Any]) -> str | None:
    raw = schema.get("type")
    values = [raw] if isinstance(raw, str) else raw if isinstance(raw, list) else []
    for value in values:
        if value != "null":
            return value
    return (
        "null"
        if values
        else "object"
        if any(keyword in schema for keyword in ("properties", "required", "additionalProperties"))
        else None
    )


def _synthesize_schema(
    schema: Mapping[str, Any],
    schema_id: str,
    world: _SchemaWorld,
    *,
    depth: int = 0,
) -> Any:
    if depth > 32:
        _fail("schema witness derivation exceeded recursion bound")
    schema, schema_id = _resolve_schema(schema, schema_id, world.documents)
    if "const" in schema:
        return copy.deepcopy(schema["const"])
    enum = schema.get("enum")
    if isinstance(enum, list) and enum:
        return copy.deepcopy(enum[0])
    for keyword in ("oneOf", "anyOf"):
        branches = schema.get(keyword)
        if isinstance(branches, list):
            base = {key: value for key, value in schema.items() if key != keyword}
            for branch in branches:
                if not isinstance(branch, Mapping):
                    continue
                resolved_branch, branch_id = _resolve_schema(branch, schema_id, world.documents)
                merged = _merge_schema(base, resolved_branch)
                try:
                    return _synthesize_schema(merged, branch_id, world, depth=depth + 1)
                except ParityError:
                    continue
            _fail(f"cannot derive {keyword} witness")
    kind = _schema_type(schema)
    if kind == "object":
        properties = schema.get("properties", {})
        required = schema.get("required", [])
        if not isinstance(properties, Mapping) or not isinstance(required, list):
            _fail("object schema has invalid properties or required shape")
        result: dict[str, Any] = {}
        for name in sorted(required):
            child = properties.get(name)
            if not isinstance(child, Mapping):
                additional = schema.get("additionalProperties", True)
                if additional is False:
                    _fail("required property lacks a schema")
                child = additional if isinstance(additional, Mapping) else {}
            result[name] = _synthesize_schema(child, schema_id, world, depth=depth + 1)
        minimum = schema.get("minProperties", 0)
        if type(minimum) is int and len(result) < minimum:
            for name in sorted(properties):
                if name not in result and isinstance(properties[name], Mapping):
                    result[name] = _synthesize_schema(properties[name], schema_id, world, depth=depth + 1)
                    if len(result) >= minimum:
                        break
        return result
    if kind == "array":
        minimum = schema.get("minItems", 0)
        count = minimum if type(minimum) is int else 0
        items = schema.get("items", {})
        if items is False:
            return []
        if not isinstance(items, Mapping):
            items = {}
        return [_synthesize_schema(items, schema_id, world, depth=depth + 1) for _ in range(count)]
    if kind == "string":
        return _string_witness(schema)
    if kind in {"integer", "number"}:
        minimum = schema.get("minimum", 0)
        value = minimum if isinstance(minimum, (int, float)) and not isinstance(minimum, bool) else 0
        return int(value) if kind == "integer" else value
    if kind == "boolean":
        return False
    if kind == "null":
        return None
    return None


def _synthesize_pointer(world: _SchemaWorld, schema_id: str, pointer: str) -> Any:
    schema = _pointer_get(world.documents[schema_id], pointer)
    if not isinstance(schema, Mapping):
        _fail("witness pointer does not identify a schema object")
    value = _synthesize_schema(schema, schema_id, world)
    if not world.is_valid(schema_id, pointer, value):
        _fail(f"derived valid witness is invalid at {pointer or '/'}")
    return value


def _wrong_type(schema: Mapping[str, Any]) -> Any:
    raw = schema.get("type")
    allowed = {raw} if isinstance(raw, str) else set(raw) if isinstance(raw, list) else set()
    candidates: list[Any] = [None, False, 0, "x", [], {}]
    kinds = {
        type(None): "null",
        bool: "boolean",
        int: "integer",
        str: "string",
        list: "array",
        dict: "object",
    }
    for candidate in candidates:
        kind = kinds[type(candidate)]
        if kind not in allowed and not (kind == "integer" and "number" in allowed):
            return candidate
    _fail("cannot derive wrong-type witness")


def _invalid_domain_value(value: Any, disallowed: Sequence[Any]) -> Any:
    candidates: list[Any] = ["__defenseclaw_invalid__", -1, True, None, {}, []]
    for candidate in candidates:
        if candidate != value and candidate not in disallowed:
            return candidate
    _fail("cannot derive invalid domain witness")


def _assert_pair(
    baseline: _SchemaWorld,
    candidate: _SchemaWorld,
    schema_id: str,
    pointer: str,
    value: Any,
    *,
    expected: bool,
    context: str,
) -> None:
    baseline_valid = baseline.is_valid(schema_id, pointer, value)
    candidate_valid = candidate.is_valid(schema_id, pointer, value)
    if baseline_valid != candidate_valid:
        _fail(f"baseline/candidate differential validation drift: {context}")
    if baseline_valid != expected:
        _fail(f"derived witness expectation failed: {context}")


def _boundary_values(
    schema: Mapping[str, Any],
    keyword: str,
    schema_id: str,
    world: _SchemaWorld,
) -> tuple[Any, Any]:
    if keyword == "type":
        return _synthesize_schema(schema, schema_id, world), _wrong_type(schema)
    if keyword == "const":
        value = copy.deepcopy(schema["const"])
        return value, _invalid_domain_value(value, [value])
    if keyword == "enum":
        values = schema["enum"]
        return copy.deepcopy(values[0]), _invalid_domain_value(values[0], values)
    if keyword in {"minimum", "maximum"}:
        boundary = schema[keyword]
        delta = 1 if _schema_type(schema) == "integer" else 0.5
        invalid = boundary - delta if keyword == "minimum" else boundary + delta
        return boundary, invalid
    if keyword in {"minLength", "maxLength"}:
        boundary = schema[keyword]
        valid = _string_witness(schema, exact_length=boundary)
        invalid_length = boundary - 1 if keyword == "minLength" else boundary + 1
        return valid, "x" * invalid_length
    if keyword == "pattern":
        valid = _string_witness(schema)
        pattern = schema["pattern"]
        for invalid in ("/", "!", "not matching", ""):
            if re.search(pattern, invalid) is None:
                return valid, invalid
        _fail("cannot derive invalid pattern witness")
    if keyword == "maxItems":
        maximum = schema[keyword]
        items = schema.get("items", {})
        if not isinstance(items, Mapping):
            items = {}
        item = _synthesize_schema(items, schema_id, world)
        if schema.get("uniqueItems") is True:
            if isinstance(item, str):
                values = [f"{item}{index}" for index in range(maximum + 1)]
            elif isinstance(item, int) and not isinstance(item, bool):
                values = [item + index for index in range(maximum + 1)]
            else:
                values = [{"index": index} for index in range(maximum + 1)]
        else:
            values = [copy.deepcopy(item) for _ in range(maximum + 1)]
        return values[:maximum], values
    if keyword == "maxProperties":
        maximum = schema[keyword]
        additional = schema.get("additionalProperties", {})
        if not isinstance(additional, Mapping):
            additional = {}
        value = _synthesize_schema(additional, schema_id, world)
        valid = {f"k{index}": copy.deepcopy(value) for index in range(maximum)}
        invalid = dict(valid)
        invalid[f"k{maximum}"] = copy.deepcopy(value)
        return valid, invalid
    _fail(f"unsupported boundary strategy {keyword}")


def _parent_property_pointer(pointer: str) -> tuple[str, str]:
    marker = "/properties/"
    if marker not in pointer:
        _fail("field disposition is not rooted in properties")
    parent, raw_name = pointer.rsplit(marker, 1)
    if "/" in raw_name:
        _fail("field disposition property pointer has descendants")
    return parent, _unescape(raw_name)


def _check_coverage(
    public_views: Mapping[str, Any],
    baseline_world: _SchemaWorld,
    candidate_world: _SchemaWorld,
    baseline_lossless_by_path: Mapping[str, Any],
) -> tuple[int, int, int, int, Counter[str], int, int]:
    fields = dynamic_scopes = valid_witnesses = invalid_witnesses = 0
    required_omissions = closed_extras = 0
    boundary_counts: Counter[str] = Counter()
    views = public_views["views"]
    for view in views:
        schema_id = view["schema_id"]
        baseline_document = baseline_world.documents[schema_id]
        candidate_document = candidate_world.documents[schema_id]
        baseline_lossless_document = baseline_lossless_by_path[view["output_path"]]
        for field in view["field_dispositions"]:
            fields += 1
            if field.get("fixture_coverage") != ["legacy-public-schema-parity-v1"]:
                _fail("field fixture coverage drift")
            pointer = field["pointer"]
            baseline_schema = _pointer_get(baseline_document, pointer)
            candidate_schema = _pointer_get(candidate_document, pointer)
            if not isinstance(baseline_schema, Mapping) or not isinstance(candidate_schema, Mapping):
                _fail("field pointer does not resolve to schema objects")
            if baseline_schema != candidate_schema:
                _fail("field subschema drift")
            baseline_lossless_schema = _pointer_get(baseline_lossless_document, pointer)
            baseline_bytes = baseline_reader.render_lossless_json(baseline_lossless_schema, pretty=False)
            expected_digest = hashlib.sha256(b"DefenseClaw PublicView Subschema v1\x00" + baseline_bytes).hexdigest()
            if field["constraints"]["schema_sha256"] != expected_digest:
                _fail("field constraint digest drift")
            value = _synthesize_pointer(baseline_world, schema_id, pointer)
            _assert_pair(
                baseline_world,
                candidate_world,
                schema_id,
                pointer,
                value,
                expected=True,
                context="field valid witness",
            )
            valid_witnesses += 1
            if field["required"]:
                parent_pointer, property_name = _parent_property_pointer(pointer)
                parent = _synthesize_pointer(baseline_world, schema_id, parent_pointer)
                if not isinstance(parent, dict) or property_name not in parent:
                    _fail("required witness does not contain required property")
                omitted = dict(parent)
                del omitted[property_name]
                _assert_pair(
                    baseline_world,
                    candidate_world,
                    schema_id,
                    parent_pointer,
                    omitted,
                    expected=False,
                    context="required omission",
                )
                required_omissions += 1
                invalid_witnesses += 1

        for scope in view["dynamic_scopes"]:
            dynamic_scopes += 1
            if scope.get("fixture_coverage") != ["legacy-public-schema-parity-v1"]:
                _fail("dynamic-scope fixture coverage drift")
            pointer = scope["pointer"]
            if not pointer.endswith("/additionalProperties"):
                _fail("unsupported dynamic-scope pointer")
            parent_pointer = pointer[: -len("/additionalProperties")]
            parent_schema = _pointer_get(baseline_document, parent_pointer)
            if not isinstance(parent_schema, Mapping):
                _fail("dynamic-scope parent is not a schema object")
            parent = _synthesize_pointer(baseline_world, schema_id, parent_pointer)
            if not isinstance(parent, dict):
                _fail(f"dynamic-scope parent witness is not an object: {view['id']} {parent_pointer}")
            key = "defenseclaw_dynamic_witness"
            while key in parent:
                key += "_x"
            additional = parent_schema.get("additionalProperties", True)
            value = (
                _synthesize_schema(additional, schema_id, baseline_world)
                if isinstance(additional, Mapping)
                else "dynamic"
            )
            expanded = dict(parent)
            expanded[key] = value
            _assert_pair(
                baseline_world,
                candidate_world,
                schema_id,
                parent_pointer,
                expanded,
                expected=True,
                context="dynamic-scope witness",
            )
            valid_witnesses += 1
            if isinstance(additional, Mapping) and "type" in additional:
                invalid = dict(parent)
                invalid[key] = _wrong_type(additional)
                _assert_pair(
                    baseline_world,
                    candidate_world,
                    schema_id,
                    parent_pointer,
                    invalid,
                    expected=False,
                    context="dynamic-scope invalid witness",
                )
                invalid_witnesses += 1

        for pointer, schema in _walk_schema_nodes(baseline_document):
            candidate_schema = _pointer_get(candidate_document, pointer)
            if not isinstance(candidate_schema, Mapping):
                _fail("candidate schema-node pointer drift")
            if schema.get("additionalProperties") is False:
                parent = _synthesize_pointer(baseline_world, schema_id, pointer)
                if not isinstance(parent, dict):
                    _fail("closed-object witness is not an object")
                expanded = dict(parent)
                key = "defenseclaw_unknown_witness"
                while key in expanded:
                    key += "_x"
                expanded[key] = "unknown"
                _assert_pair(
                    baseline_world,
                    candidate_world,
                    schema_id,
                    pointer,
                    expanded,
                    expected=False,
                    context="closed additionalProperties witness",
                )
                closed_extras += 1
                invalid_witnesses += 1
            for keyword in BOUNDARY_STRATEGIES:
                if keyword not in schema:
                    continue
                valid, invalid = _boundary_values(schema, keyword, schema_id, baseline_world)
                _assert_pair(
                    baseline_world,
                    candidate_world,
                    schema_id,
                    pointer,
                    valid,
                    expected=True,
                    context=f"{view['id']} {pointer or '/'} {keyword} boundary",
                )
                _assert_pair(
                    baseline_world,
                    candidate_world,
                    schema_id,
                    pointer,
                    invalid,
                    expected=False,
                    context=f"{view['id']} {pointer or '/'} {keyword} invalid boundary",
                )
                boundary_counts[keyword] += 1
                valid_witnesses += 1
                invalid_witnesses += 1

    return (
        fields,
        dynamic_scopes,
        valid_witnesses,
        invalid_witnesses,
        boundary_counts,
        required_omissions,
        closed_extras,
    )


def check_repository(
    root: Path,
    *,
    manifest_bytes: bytes | None = None,
    public_views_bytes: bytes | None = None,
    candidate_overrides: Mapping[str, bytes] | None = None,
) -> ParityReport:
    root = root.resolve()
    manifest_raw = manifest_bytes or (root / DEFAULT_MANIFEST).read_bytes()
    manifest = _load_manifest(manifest_raw)
    baseline_raw = (root / BASELINE_PATH).read_bytes()
    if _sha256(baseline_raw) != manifest["baseline_sha256"]:
        _fail("fixture manifest baseline digest drift")
    baseline = baseline_reader.load_public_schema_baseline_bytes(baseline_raw, str(BASELINE_PATH))
    if baseline.baseline_id != manifest["baseline_id"]:
        _fail("fixture manifest baseline identity drift")
    baseline_lossless = baseline_reader.parse_lossless_json(baseline_raw, str(BASELINE_PATH))
    if not isinstance(baseline_lossless, dict) or not isinstance(baseline_lossless.get("resources"), list):
        _fail("baseline lossless resource inventory is invalid")
    baseline_lossless_by_path = {
        item["path"]: item["document"]
        for item in baseline_lossless["resources"]
        if isinstance(item, dict) and isinstance(item.get("path"), str)
    }

    public_raw = public_views_bytes or (root / PUBLIC_VIEWS_PATH).read_bytes()
    if _sha256(public_raw) != manifest["public_views_sha256"]:
        _fail("fixture manifest public-views digest drift")
    public_views = _load_yaml_mapping(public_raw, "public views")
    views = public_views.get("views")
    if not isinstance(views, list) or len(views) != EXPECTED_COUNTS["views"]:
        _fail("public view inventory drift")
    if [view.get("output_path") for view in views] != [resource.path for resource in baseline.resources]:
        _fail("public view path inventory differs from baseline")

    candidate_root = PurePosixPath(manifest["candidate_root"])
    expected_live: dict[str, str] = {}
    for view in views:
        output_path = view["output_path"]
        live_primary = (candidate_root / output_path).as_posix()
        expected_live[live_primary] = live_primary
        targets = view.get("targets")
        if not isinstance(targets, dict) or targets.get("wheels") != []:
            _fail("public view target inventory drift")
        mirrors = targets.get("mirrors")
        embeds = targets.get("embeds")
        if not isinstance(mirrors, list) or not isinstance(embeds, list):
            _fail("public view mirror/embed inventory drift")
        for target in {*mirrors, *embeds}:
            live_target = (candidate_root / target).as_posix()
            prior = expected_live.setdefault(live_target, live_primary)
            if prior != live_primary:
                _fail("multiple public views claim one live target")
    if len(expected_live) != EXPECTED_COUNTS["outputs"]:
        _fail("live public-view inventory count drift")

    live_files = {path: _validated_live_candidate_path(root, path) for path in expected_live}

    overrides = dict(candidate_overrides or {})
    unknown_overrides = set(overrides) - set(expected_live)
    if unknown_overrides:
        _fail("candidate override path inventory drift")
    candidate_raw: dict[str, bytes] = {
        path: overrides.get(path, live_files[path].read_bytes()) for path in expected_live
    }
    for target, primary in expected_live.items():
        if candidate_raw[target] != candidate_raw[primary]:
            _fail("live mirror/embed byte drift")

    baseline_documents: dict[str, Mapping[str, Any]] = {}
    candidate_documents: dict[str, Mapping[str, Any]] = {}
    candidate_lossless_resources: list[dict[str, Any]] = []
    reference_count = number_count = 0
    for view, resource in zip(views, baseline.resources, strict=True):
        primary_path = (candidate_root / resource.path).as_posix()
        raw = candidate_raw[primary_path]
        parsed = baseline_reader.parse_lossless_json(raw, primary_path)
        if not isinstance(parsed, dict):
            _fail("candidate public view root is not an object")
        native = json.loads(raw)
        marker = native.get(MARKER_KEY)
        marker_source = public_views.get("generated_marker")
        expected_marker = {
            "baseline_epoch": marker_source.get("baseline_epoch") if isinstance(marker_source, dict) else None,
            "generator": marker_source.get("generator") if isinstance(marker_source, dict) else None,
            "public_view_id": view["id"],
            "registry_version": marker_source.get("registry_version") if isinstance(marker_source, dict) else None,
        }
        if marker != expected_marker or set(marker or {}) != set(expected_marker):
            _fail("candidate public view marker drift")
        parsed.pop(MARKER_KEY, None)
        native.pop(MARKER_KEY, None)
        baseline_document = baseline_lossless_by_path[resource.path]
        lexemes = baseline_reader.number_lexemes(parsed)
        if lexemes != dict(resource.number_lexemes):
            _fail("candidate public view number-lexeme drift")
        number_count += len(lexemes)
        baseline_native = _native_json(baseline_document)
        baseline_refs = _reference_inventory(baseline_native)
        candidate_refs = _reference_inventory(native)
        if candidate_refs != baseline_refs:
            _fail("candidate public view reference inventory drift")
        reference_count += len(candidate_refs)
        baseline_bytes = baseline_reader.render_lossless_json(baseline_document, pretty=True)
        stripped_bytes = baseline_reader.render_lossless_json(parsed, pretty=True)
        if stripped_bytes != baseline_bytes:
            _fail("candidate public view canonical baseline drift")
        if (
            baseline_reader.resource_digest(
                resource.path,
                resource.dialect,
                resource.schema_id,
                parsed,
            )
            != resource.canonical_sha256
        ):
            _fail("candidate public view canonical digest drift")
        if (
            native.get("$schema") != resource.dialect
            or native.get("$id") != resource.schema_id
            or view.get("dialect") != resource.dialect
            or view.get("schema_id") != resource.schema_id
        ):
            _fail("candidate public view dialect or identity drift")
        baseline_documents[resource.schema_id] = baseline_native
        candidate_documents[resource.schema_id] = native
        candidate_lossless_resources.append({"path": resource.path, "document": parsed})

    if number_count != EXPECTED_COUNTS["number_lexemes"]:
        _fail("public view number-lexeme count drift")
    if reference_count != EXPECTED_COUNTS["references"]:
        _fail("public view reference count drift")
    try:
        baseline_reader.validate_reference_closure(candidate_lossless_resources)
    except baseline_reader.BaselineError as exc:
        raise ParityError("candidate public view offline reference closure failed") from exc

    baseline_world = _SchemaWorld(baseline_documents)
    candidate_world = _SchemaWorld(candidate_documents)
    valid_witnesses = invalid_witnesses = 0
    for resource in baseline.resources:
        valid = _synthesize_pointer(baseline_world, resource.schema_id, "")
        _assert_pair(
            baseline_world,
            candidate_world,
            resource.schema_id,
            "",
            valid,
            expected=True,
            context="per-view valid witness",
        )
        _assert_pair(
            baseline_world,
            candidate_world,
            resource.schema_id,
            "",
            [],
            expected=False,
            context="per-view invalid witness",
        )
        valid_witnesses += 1
        invalid_witnesses += 1

    (
        fields,
        dynamic_scopes,
        coverage_valid,
        coverage_invalid,
        boundary_counts,
        required_omissions,
        closed_extras,
    ) = _check_coverage(
        public_views,
        baseline_world,
        candidate_world,
        baseline_lossless_by_path,
    )
    valid_witnesses += coverage_valid
    invalid_witnesses += coverage_invalid
    if fields != EXPECTED_COUNTS["fields"] or dynamic_scopes != EXPECTED_COUNTS["dynamic_scopes"]:
        _fail("public view field or dynamic-scope coverage count drift")
    if set(boundary_counts) != set(BOUNDARY_STRATEGIES):
        _fail("boundary strategy coverage is incomplete")

    return ParityReport(
        views=len(views),
        outputs=len(expected_live),
        fields=fields,
        dynamic_scopes=dynamic_scopes,
        references=reference_count,
        number_lexemes=number_count,
        valid_witnesses=valid_witnesses,
        invalid_witnesses=invalid_witnesses,
        required_omissions=required_omissions,
        closed_extras=closed_extras,
        boundary_cases=dict(sorted(boundary_counts.items())),
    )


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=Path.cwd())
    parser.add_argument("--manifest", type=Path, default=DEFAULT_MANIFEST)
    arguments = parser.parse_args(argv)
    try:
        manifest_bytes = (arguments.root / arguments.manifest).read_bytes()
        report = check_repository(arguments.root, manifest_bytes=manifest_bytes)
    except (OSError, ParityError) as exc:
        print(f"telemetry_public_schema_parity: error: {exc}", file=sys.stderr)
        return 1
    boundaries = ",".join(f"{name}:{count}" for name, count in report.boundary_cases.items())
    print(
        "telemetry_public_schema_parity: OK "
        f"views={report.views} outputs={report.outputs} fields={report.fields} "
        f"dynamic_scopes={report.dynamic_scopes} references={report.references} "
        f"number_lexemes={report.number_lexemes} valid={report.valid_witnesses} "
        f"invalid={report.invalid_witnesses} required_omissions={report.required_omissions} "
        f"closed_extras={report.closed_extras} boundaries={boundaries}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
