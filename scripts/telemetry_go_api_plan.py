#!/usr/bin/env python3
# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# SPDX-License-Identifier: Apache-2.0
"""Deterministic compiler foundation for the telemetry-v8 generated Go API.

This module is deliberately independent of the registry generator and candidate
renderers.  It accepts a recursively immutable, ``CandidateRenderIndex``-like
object and returns syntax-complete immutable plans.  It performs no filesystem
I/O and never reads source YAML, a reviewed golden, or existing Go output.

The input object must expose ``materialized_view_sha256``, ``go_symbol_policy``,
``go_symbol_table``, ``enriched_fields``, ``enriched_families``,
``structured_types``, ``expanded_producer_mappings``, and
``go_declaration_values``.  The enrichment
records are an intentional trust boundary: missing family or structured
descriptor data is an error, never an invitation to reconstruct it from names.
"""

from __future__ import annotations

import dataclasses
import hashlib
import json
import math
import re
from collections.abc import Mapping, Sequence
from typing import Any, Final, TypeAlias


class GoAPIPlanError(RuntimeError):
    """A deterministic compiler-contract failure."""


@dataclasses.dataclass(frozen=True, slots=True)
class GoTypeRefIR:
    """Closed Go type AST; renderers only print this tree."""

    arm: str
    name: str | None = None
    element: GoTypeRefIR | None = None


@dataclasses.dataclass(frozen=True, slots=True)
class GoFieldPlanIR:
    owner: str
    selector: str
    type_ref: GoTypeRefIR
    order: int
    presence: str
    semantic_source_id: str
    enriched_descriptor_id: str
    value_source: str
    target_slot: str
    condition_binding: str | None
    mandatory_binding: str | None
    conversion_op: str


@dataclasses.dataclass(frozen=True, slots=True)
class GoInputPlanIR:
    declaration_kind: str
    declaration_source_id: str
    symbol: str
    output_file: str
    fields: tuple[GoFieldPlanIR, ...]
    private_kernel_target: str
    referenced_event_inputs: tuple[str, ...]
    referenced_link_inputs: tuple[str, ...]
    referenced_resource_descriptors: tuple[str, ...]


ParameterIR: TypeAlias = tuple[str, GoTypeRefIR]


@dataclasses.dataclass(frozen=True, slots=True)
class GoCallablePlanIR:
    declaration_kind: str
    declaration_source_id: str
    symbol: str
    output_file: str
    receiver_name: str | None
    receiver_type: GoTypeRefIR | None
    receiver_pointer: bool
    parameters: tuple[ParameterIR, ...]
    results: tuple[GoTypeRefIR, ...]
    error_contract: str
    private_target: str


@dataclasses.dataclass(frozen=True, slots=True)
class GoStructuredPlanIR:
    declaration_source_id: str
    symbol: str
    output_file: str
    shape: str
    scalar_descriptor_ids: tuple[str, ...]
    fields: tuple[GoFieldPlanIR, ...]
    item_type: GoTypeRefIR | None
    arm_declaration_keys: tuple[str, ...]
    arm_value_types: tuple[tuple[str, GoTypeRefIR], ...]
    arm_shapes: tuple[tuple[str, str, str], ...]
    dynamic_member_input_keys: tuple[str, ...]
    private_discriminator: str | None
    container_descriptor_ids: tuple[str, ...]
    limits: tuple[tuple[str, int], ...]
    conversion_plan: tuple[str, ...]


@dataclasses.dataclass(frozen=True, slots=True)
class GoFactValueIR:
    arm: str
    string_value: str | None = None
    integer_value: int | None = None
    double_value: float | None = None
    boolean_value: bool | None = None
    items: tuple[GoFactValueIR, ...] = ()
    fields: tuple[tuple[str, GoFactValueIR], ...] = ()


@dataclasses.dataclass(frozen=True, slots=True)
class GoKernelFieldDescriptorIR:
    descriptor_id: str
    key: str
    field_type: str
    requirement: str
    condition_id: str | None
    condition_fact: str | None
    false_requirement: str | None
    field_class: str
    constraints: GoFactValueIR
    value_source: str
    target_slot: str
    order: int


@dataclasses.dataclass(frozen=True, slots=True)
class GoKernelLimitsIR:
    max_encoded_bytes: int
    max_item_utf8_bytes: int
    max_items: int
    max_depth: int
    max_properties: int


@dataclasses.dataclass(frozen=True, slots=True)
class GoTraceContractPlanIR:
    attribute_limits: GoKernelLimitsIR
    resource_limits: GoKernelLimitsIR
    scope_limits: GoKernelLimitsIR
    event_limits: GoKernelLimitsIR
    link_limits: GoKernelLimitsIR
    max_events: int
    max_links: int
    scope_name: str
    scope_schema_url: str
    trace_schema_version: str
    semantic_profile: str


@dataclasses.dataclass(frozen=True, slots=True)
class GoDescriptorPlanIR:
    family_id: str
    signal: str
    domain: str
    identity_bucket: str
    identity_name: str
    family_schema_version: int
    outcome_requirement: str
    allowed_outcomes: tuple[str, ...]
    field_contracts: tuple[GoKernelFieldDescriptorIR, ...]
    enriched_field_descriptor_ids: tuple[str, ...]
    resource_field_descriptor_ids: tuple[str, ...]
    scope_field_descriptor_ids: tuple[str, ...]
    span_name_parts: tuple[tuple[str, str], ...]
    allowed_kinds: tuple[str, ...]
    event_contracts: tuple[tuple[str, str, tuple[str, ...]], ...]
    link_contracts: tuple[tuple[str, tuple[str, ...]], ...]
    metric_contract: tuple[tuple[str, str], ...]
    metric_description: str | None
    metric_boundaries: tuple[int | float, ...]
    metric_attribute_limits: GoKernelLimitsIR | None
    trace_contract: GoTraceContractPlanIR | None
    mandatory_rule_ids: tuple[str, ...]
    mandatory_constant_terms: tuple[bool, ...]
    mandatory_fact_terms: tuple[tuple[str, str], ...]
    private_kernel_target: str


DeclarationKeyIR: TypeAlias = tuple[str, str]
LiteralValueIR: TypeAlias = str | int


@dataclasses.dataclass(frozen=True, slots=True)
class GoDeclarationPlanIR:
    """One complete package declaration assignment.

    Constants carry an exact typed value; non-constants carry no literal but do
    retain their compiler-owned form, semantic owner, and output file.
    """

    kind: str
    source_id: str
    symbol: str
    declaration_form: str
    owner: str
    output_file: str
    go_type: GoTypeRefIR | None
    literal_kind: str | None
    literal_value: LiteralValueIR | None


@dataclasses.dataclass(frozen=True, slots=True)
class GoFilePlanIR:
    path: str
    declaration_keys: tuple[DeclarationKeyIR, ...]
    declarations: tuple[GoDeclarationPlanIR, ...]
    private_descriptor_ids: tuple[str, ...]
    private_projection_ids: tuple[str, ...]
    expected_digest_headers: tuple[str, ...]


@dataclasses.dataclass(frozen=True, slots=True)
class GoFixturePlanIR:
    example_id: str
    signal: str
    family_id: str | None
    valid: bool
    input_declaration_key: DeclarationKeyIR | None
    callable_declaration_key: DeclarationKeyIR | None
    field_bindings: tuple[tuple[str, str, str], ...]
    builder_context: GoFactValueIR
    expected_record: GoFactValueIR
    expected_record_json: str
    expected_error: str | None
    base_example: str | None


@dataclasses.dataclass(frozen=True, slots=True)
class GoAPIPlanIR:
    version: int
    materialized_view_sha256: str
    go_symbol_table_sha256: str
    inputs: tuple[GoInputPlanIR, ...]
    callables: tuple[GoCallablePlanIR, ...]
    structured: tuple[GoStructuredPlanIR, ...]
    descriptors: tuple[GoDescriptorPlanIR, ...]
    declarations: tuple[GoDeclarationPlanIR, ...]
    fixtures: tuple[GoFixturePlanIR, ...]
    files: tuple[GoFilePlanIR, ...]
    api_plan_sha256: str


_GO_API_PLAN_DIGEST_DOMAIN: Final = b"DefenseClaw GoAPIPlanIR v1\x00"
_GO_SYMBOL_TABLE_DIGEST_DOMAIN: Final = b"DefenseClaw GoSymbolTableIR v1\x00"
_CANONICAL_SYMBOL_TABLE_SHA256: Final = "d897fab03a91351740e122682f96cc821a66f522250ba881e3a47b65afcc5fd7"
_SHA256: Final = re.compile(r"^[0-9a-f]{64}$")
_GO_IDENTIFIER: Final = re.compile(r"^[A-Za-z][A-Za-z0-9]*$")

_GO_SYMBOL_KIND_ORDER: Final = (
    "attribute",
    "family",
    "log_event",
    "span_event",
    "link_relation",
    "metric_instrument",
    "condition",
    "condition_fact",
    "phase",
    "phase_code",
    "semantic_profile",
    "structured_type",
    "structured_member",
    "structured_arm",
    "structured_member_input",
    "structured_member_constructor",
    "family_input",
    "family_builder",
    "span_event_input",
    "span_event_constructor",
    "span_link_input",
    "span_link_constructor",
)
_DECLARATION_FORMS: Final = frozenset({"exported_const", "exported_type", "exported_function", "family_builder_method"})
_FORM_BY_KIND: Final = {
    **{
        kind: "exported_const"
        for kind in (
            "attribute",
            "family",
            "log_event",
            "span_event",
            "link_relation",
            "metric_instrument",
            "condition",
            "condition_fact",
            "phase",
            "phase_code",
            "semantic_profile",
            "structured_member",
        )
    },
    **{
        kind: "exported_type"
        for kind in (
            "structured_type",
            "structured_arm",
            "structured_member_input",
            "family_input",
            "span_event_input",
            "span_link_input",
        )
    },
    **{
        kind: "exported_function"
        for kind in (
            "structured_member_constructor",
            "span_event_constructor",
            "span_link_constructor",
        )
    },
    "family_builder": "family_builder_method",
}

_IDS_FILE: Final = "internal/observability/zz_generated_telemetry_ids.go"
_CATALOG_FILE: Final = "internal/observability/zz_generated_telemetry_catalog.go"
_PRODUCERS_FILE: Final = "internal/observability/zz_generated_telemetry_producers.go"
_DOMAIN_FILES: Final = {
    "genai": "internal/observability/zz_generated_telemetry_builders_genai.go",
    "security": "internal/observability/zz_generated_telemetry_builders_security.go",
    "operations": "internal/observability/zz_generated_telemetry_builders_operations.go",
}
_FIXTURES_FILE: Final = "internal/observability/zz_generated_telemetry_builder_fixtures_test.go"
GO_OUTPUT_FILES: Final = (
    _IDS_FILE,
    _CATALOG_FILE,
    _PRODUCERS_FILE,
    _DOMAIN_FILES["genai"],
    _DOMAIN_FILES["security"],
    _DOMAIN_FILES["operations"],
    _FIXTURES_FILE,
)
_EXPECTED_REVIEWED_PARTITION: Final = {
    _IDS_FILE: 893,
    _DOMAIN_FILES["genai"]: 282,
    _DOMAIN_FILES["security"]: 212,
    _DOMAIN_FILES["operations"]: 386,
}
_EXPECTED_CANONICAL_PUBLIC_VALUES: Final = {
    "log": 1420,
    "span": 700,
    "resource": 325,
    "metric": 346,
}

_GO_RESERVED_IDENTIFIERS: Final = frozenset(
    {
        "break",
        "case",
        "chan",
        "const",
        "continue",
        "default",
        "defer",
        "else",
        "fallthrough",
        "for",
        "func",
        "go",
        "goto",
        "if",
        "import",
        "interface",
        "map",
        "package",
        "range",
        "return",
        "select",
        "struct",
        "switch",
        "type",
        "var",
        "any",
        "append",
        "bool",
        "byte",
        "cap",
        "clear",
        "close",
        "comparable",
        "complex",
        "complex64",
        "complex128",
        "copy",
        "delete",
        "error",
        "false",
        "float32",
        "float64",
        "imag",
        "int",
        "int8",
        "int16",
        "int32",
        "int64",
        "iota",
        "len",
        "make",
        "max",
        "min",
        "new",
        "nil",
        "panic",
        "print",
        "println",
        "real",
        "recover",
        "rune",
        "string",
        "true",
        "uint",
        "uint8",
        "uint16",
        "uint32",
        "uint64",
        "uintptr",
    }
)
_PRESENCE: Final = frozenset({"required", "recommended", "optional", "conditional"})
_VALUE_SOURCES: Final = frozenset(
    {
        "input",
        "constant",
        "envelope.bucket",
        "family.id",
        "family.family_schema_version",
        "envelope.source",
        "provenance.config_generation",
        "envelope.outcome",
        "provenance.binary_version",
        "semantic_profile.trace_schema_version",
        "semantic_profile.id",
        "link.relation",
    }
)
_INPUT_OWNER_KINDS: Final = frozenset({"family", "event", "link", "structured", "none"})
_COMPONENTS: Final = frozenset({"family", "resource", "scope", "event", "link", "structured"})
_CONVERSIONS: Final = frozenset(
    {
        "required_scalar",
        "optional_scalar",
        "copied_string_slice",
        "structured_encoder",
        "metric_number",
        "condition_fact",
        "mandatory_fact",
        "trace_event",
        "trace_link",
    }
)
_STRUCTURED_SHAPES: Final = frozenset({"object", "array", "tagged_union", "canonical_json"})
_DIGEST_HEADERS: Final = (
    "materialized_view_sha256",
    "candidate_render_index_sha256",
    "go_symbol_table_sha256",
)


@dataclasses.dataclass(frozen=True, slots=True)
class _Symbol:
    kind: str
    source_id: str
    symbol: str
    declaration_form: str


@dataclasses.dataclass(frozen=True, slots=True)
class _Policy:
    separators: tuple[str, ...]
    brand_spellings: tuple[tuple[str, str], ...]
    initialisms: tuple[str, ...]


@dataclasses.dataclass(frozen=True, slots=True)
class _Field:
    id: str
    owner_id: str
    component: str
    semantic_source_id: str
    primitive_type: str
    structured_type: str | None
    requirement: str
    condition_id: str | None
    condition_fact: str | None
    false_requirement: str | None
    field_class: str
    constraints: GoFactValueIR
    value_source: str
    target_slot: str
    input_owner_kind: str
    order: int


def _read(value: Any, name: str, path: str) -> Any:
    if isinstance(value, Mapping):
        if name not in value:
            raise GoAPIPlanError(f"{path}.{name}: required compiler fact is missing")
        return value[name]
    try:
        return getattr(value, name)
    except AttributeError as exc:
        raise GoAPIPlanError(f"{path}.{name}: required compiler fact is missing") from exc


def _string(value: Any, path: str) -> str:
    if not isinstance(value, str) or not value:
        raise GoAPIPlanError(f"{path}: expected non-empty string")
    return value


def _integer(value: Any, path: str, *, minimum: int = 0) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < minimum:
        raise GoAPIPlanError(f"{path}: expected integer >= {minimum}")
    return value


def _sequence(value: Any, path: str) -> tuple[Any, ...]:
    if isinstance(value, (str, bytes, bytearray)) or not isinstance(value, Sequence):
        raise GoAPIPlanError(f"{path}: expected sequence")
    return tuple(value)


def _optional(value: Any, name: str, default: Any = None) -> Any:
    if isinstance(value, Mapping):
        return value.get(name, default)
    return getattr(value, name, default)


def _fact_value(value: Any, path: str) -> GoFactValueIR:
    if isinstance(value, Mapping):
        return GoFactValueIR(
            "object",
            fields=tuple(
                (_string(key, f"{path}.key"), _fact_value(value[key], f"{path}.{key}")) for key in sorted(value)
            ),
        )
    if isinstance(value, tuple):
        return GoFactValueIR("sequence", items=tuple(_fact_value(item, path) for item in value))
    if value is None:
        return GoFactValueIR("null")
    if isinstance(value, str):
        return GoFactValueIR("string", string_value=value)
    if isinstance(value, bool):
        return GoFactValueIR("boolean", boolean_value=value)
    if isinstance(value, int):
        return GoFactValueIR("integer", integer_value=value)
    if isinstance(value, float) and math.isfinite(value):
        return GoFactValueIR("double", double_value=value)
    raise GoAPIPlanError(f"{path}: unsupported or non-finite compiler fact")


def _named(name: str) -> GoTypeRefIR:
    _validate_identifier(name, "named Go type")
    return GoTypeRefIR("named", name=name)


def _builtin(name: str) -> GoTypeRefIR:
    if name not in {"string", "bool", "int", "int64", "uint32", "uint64", "float64", "error"}:
        raise GoAPIPlanError("unsupported builtin Go type")
    return GoTypeRefIR("builtin", name=name)


def _optional_type(element: GoTypeRefIR) -> GoTypeRefIR:
    return GoTypeRefIR("optional", element=element)


def _slice(element: GoTypeRefIR) -> GoTypeRefIR:
    return GoTypeRefIR("slice", element=element)


def _validate_identifier(value: str, path: str) -> None:
    if not value.isascii() or _GO_IDENTIFIER.fullmatch(value) is None or value in _GO_RESERVED_IDENTIFIERS:
        raise GoAPIPlanError(f"{path}: invalid or reserved Go identifier")


def _policy(index: Any) -> _Policy:
    raw = _read(index, "go_symbol_policy", "candidate")
    if _read(raw, "version", "go_symbol_policy") != 1 or _read(raw, "package", "go_symbol_policy") != "observability":
        raise GoAPIPlanError("go_symbol_policy: unsupported policy identity")
    if any(
        _read(raw, name, "go_symbol_policy") != "reject"
        for name in ("reserved_word_policy", "collision_policy", "auto_suffix_policy")
    ):
        raise GoAPIPlanError("go_symbol_policy: repair policies are forbidden")
    separators = tuple(
        _string(item, "go_symbol_policy.separators")
        for item in _sequence(_read(raw, "separators", "go_symbol_policy"), "go_symbol_policy.separators")
    )
    if not separators or len(separators) != len(set(separators)) or any(len(item) != 1 for item in separators):
        raise GoAPIPlanError("go_symbol_policy.separators: invalid separator inventory")
    raw_brands = _read(raw, "brand_spellings", "go_symbol_policy")
    if not isinstance(raw_brands, Mapping) or not raw_brands:
        raise GoAPIPlanError("go_symbol_policy.brand_spellings: expected mapping")
    brands = tuple(
        sorted((_string(key, "brand key"), _string(value, "brand value")) for key, value in raw_brands.items())
    )
    for key, value in brands:
        if key != key.lower():
            raise GoAPIPlanError("go_symbol_policy.brand_spellings: keys must be lowercase")
        _validate_identifier(value, "go_symbol_policy.brand_spellings")
    initialisms = tuple(
        _string(item, "go_symbol_policy.initialisms")
        for item in _sequence(_read(raw, "initialisms", "go_symbol_policy"), "go_symbol_policy.initialisms")
    )
    if (
        not initialisms
        or len(initialisms) != len(set(initialisms))
        or any(item != item.upper() for item in initialisms)
    ):
        raise GoAPIPlanError("go_symbol_policy.initialisms: invalid inventory")
    return _Policy(separators, brands, initialisms)


def _public_name(policy: _Policy, source: str, path: str) -> str:
    source = _string(source, path)
    separators = frozenset(policy.separators)
    tokens: list[str] = []
    current: list[str] = []
    for character in source:
        if character in separators:
            if not current:
                raise GoAPIPlanError(f"{path}: empty Go selector token")
            tokens.append("".join(current))
            current = []
            continue
        if not character.isascii() or not character.isalnum():
            raise GoAPIPlanError(f"{path}: selector tokens require ASCII letters and digits")
        current.append(character)
    if not current:
        raise GoAPIPlanError(f"{path}: empty Go selector token")
    tokens.append("".join(current))
    brands = dict(policy.brand_spellings)
    initialisms = frozenset(policy.initialisms)
    result = "".join(
        brands[token.lower()]
        if token.lower() in brands
        else token.upper()
        if token.upper() in initialisms
        else token[:1].upper() + token[1:].lower()
        for token in tokens
    )
    _validate_identifier(result, path)
    return result


def _symbol_table(index: Any) -> tuple[tuple[_Symbol, ...], str]:
    raw = _read(index, "go_symbol_table", "candidate")
    if _read(raw, "version", "go_symbol_table") != 1 or _read(raw, "package", "go_symbol_table") != "observability":
        raise GoAPIPlanError("go_symbol_table: unsupported table identity")
    rows = tuple(
        _Symbol(
            _string(_read(item, "kind", f"go_symbol_table.rows[{position}]"), "symbol kind"),
            _string(_read(item, "source_id", f"go_symbol_table.rows[{position}]"), "symbol source"),
            _string(_read(item, "symbol", f"go_symbol_table.rows[{position}]"), "symbol name"),
            _string(_read(item, "declaration_form", f"go_symbol_table.rows[{position}]"), "declaration form"),
        )
        for position, item in enumerate(_sequence(_read(raw, "rows", "go_symbol_table"), "go_symbol_table.rows"))
    )
    if not rows:
        raise GoAPIPlanError("go_symbol_table.rows: empty table")
    rank = {kind: position for position, kind in enumerate(_GO_SYMBOL_KIND_ORDER)}
    keys: set[tuple[str, str]] = set()
    symbols: set[str] = set()
    prior: tuple[int, bytes] | None = None
    kind_counts = {kind: 0 for kind in _GO_SYMBOL_KIND_ORDER}
    declaration_counts = {form: 0 for form in _DECLARATION_FORMS}
    for row in rows:
        if row.kind not in rank or row.declaration_form not in _DECLARATION_FORMS:
            raise GoAPIPlanError("go_symbol_table.rows: unknown kind or declaration form")
        if _FORM_BY_KIND[row.kind] != row.declaration_form:
            raise GoAPIPlanError("go_symbol_table.rows: declaration form disagrees with kind")
        if not row.source_id.isascii():
            raise GoAPIPlanError("go_symbol_table.rows: non-ASCII source identity")
        _validate_identifier(row.symbol, "go_symbol_table.rows.symbol")
        key = (row.kind, row.source_id)
        order_key = (rank[row.kind], row.source_id.encode("ascii"))
        if key in keys or row.symbol in symbols or (prior is not None and order_key <= prior):
            raise GoAPIPlanError("go_symbol_table.rows: duplicate, colliding, or unordered row")
        keys.add(key)
        symbols.add(row.symbol)
        prior = order_key
        kind_counts[row.kind] += 1
        declaration_counts[row.declaration_form] += 1
    materialized_kind_counts = dict(_read(raw, "kind_counts", "go_symbol_table"))
    materialized_declaration_counts = dict(_read(raw, "declaration_form_counts", "go_symbol_table"))
    if materialized_kind_counts != kind_counts or materialized_declaration_counts != declaration_counts:
        raise GoAPIPlanError("go_symbol_table: materialized counts disagree with rows")
    payload = json.dumps(
        [[row.kind, row.source_id, row.symbol, row.declaration_form] for row in rows],
        ensure_ascii=False,
        separators=(",", ":"),
    ).encode("utf-8")
    digest = hashlib.sha256(_GO_SYMBOL_TABLE_DIGEST_DOMAIN + payload).hexdigest()
    if _read(raw, "table_sha256", "go_symbol_table") != digest:
        raise GoAPIPlanError("go_symbol_table: digest disagrees with rows")
    return rows, digest


def _fields(index: Any) -> dict[str, _Field]:
    raw_fields = _read(index, "enriched_fields", "candidate")
    items = tuple(raw_fields.values()) if isinstance(raw_fields, Mapping) else _sequence(raw_fields, "enriched_fields")
    result: dict[str, _Field] = {}
    for position, raw in enumerate(items):
        path = f"enriched_fields[{position}]"
        context = _string(_read(raw, "context", path), f"{path}.context")
        component = {"log": "family", "span": "family", "metric": "family"}.get(context, context)
        placement = _string(_read(raw, "input_placement", path), f"{path}.input_placement")
        input_owner_kind = {
            "family_input": "family",
            "resource_input": "family",
            "event_input": "event",
            "link_input": "link",
            "structured_input": "structured",
            "private_derived": "none",
        }.get(placement)
        if input_owner_kind is None:
            raise GoAPIPlanError(f"{path}.input_placement: unknown public ownership")
        field_types = tuple(
            _string(item, f"{path}.field_types")
            for item in _sequence(_read(raw, "field_types", path), f"{path}.field_types")
        )
        structured_type = _optional(raw, "structured_type")
        if structured_type is not None:
            primitive_type = "structured"
        elif len(field_types) == 1:
            primitive_type = field_types[0]
        else:
            raise GoAPIPlanError(f"{path}.field_types: public Go fields require one closed type")
        field = _Field(
            id=_string(_read(raw, "id", path), f"{path}.id"),
            owner_id=_string(_read(raw, "owner_id", path), f"{path}.owner_id"),
            component=component,
            semantic_source_id=_string(_read(raw, "attribute_id", path), f"{path}.attribute_id"),
            primitive_type=primitive_type,
            structured_type=structured_type,
            requirement=_string(_read(raw, "requirement_level", path), f"{path}.requirement_level"),
            condition_id=_optional(raw, "condition_id"),
            condition_fact=_optional(raw, "condition_fact"),
            false_requirement=_optional(raw, "condition_false_requirement"),
            field_class=_string(_read(raw, "field_class", path), f"{path}.field_class"),
            constraints=_fact_value(_read(raw, "effective_constraints", path), f"{path}.effective_constraints"),
            value_source=_string(_read(raw, "value_source", path), f"{path}.value_source"),
            target_slot=_string(_read(raw, "target_slot", path), f"{path}.target_slot"),
            input_owner_kind=input_owner_kind,
            order=_integer(_read(raw, "order", path), f"{path}.order"),
        )
        if field.id in result:
            raise GoAPIPlanError("enriched_fields: duplicate descriptor ID")
        if field.component not in _COMPONENTS or field.requirement not in _PRESENCE:
            raise GoAPIPlanError(f"{path}: unknown component or requirement")
        if field.value_source not in _VALUE_SOURCES or field.input_owner_kind not in _INPUT_OWNER_KINDS:
            raise GoAPIPlanError(f"{path}: unknown value source or input owner")
        if field.requirement == "conditional":
            _string(field.condition_fact, f"{path}.condition_fact")
            _string(field.condition_id, f"{path}.condition_id")
            _string(field.false_requirement, f"{path}.condition_false_requirement")
        elif field.condition_fact is not None:
            raise GoAPIPlanError(f"{path}.condition_fact: only conditional fields bind facts")
        if field.value_source == "input" and field.input_owner_kind == "none":
            raise GoAPIPlanError(f"{path}: input value has no public owner")
        if field.value_source != "input" and field.input_owner_kind != "none":
            raise GoAPIPlanError(f"{path}: derived value cannot expose a public input")
        if field.structured_type is not None and not isinstance(field.structured_type, str):
            raise GoAPIPlanError(f"{path}.structured_type: invalid structured binding")
        result[field.id] = field
    if not result:
        raise GoAPIPlanError("enriched_fields: descriptor inventory is empty")
    return result


def _symbol_index(rows: tuple[_Symbol, ...]) -> dict[tuple[str, str], _Symbol]:
    return {(row.kind, row.source_id): row for row in rows}


def _required_symbol(symbols: Mapping[tuple[str, str], _Symbol], kind: str, source_id: str) -> _Symbol:
    try:
        return symbols[(kind, source_id)]
    except KeyError as exc:
        raise GoAPIPlanError(f"Go declaration {kind}/{source_id}: symbol-table row is missing") from exc


def _base_type(field: _Field, symbols: Mapping[tuple[str, str], _Symbol]) -> GoTypeRefIR:
    if field.structured_type is not None:
        if field.primitive_type != "structured":
            raise GoAPIPlanError(f"enriched field {field.id}: structured binding has incompatible primitive type")
        return _named(_required_symbol(symbols, "structured_type", field.structured_type).symbol)
    mapping = {
        "string": _builtin("string"),
        "boolean": _builtin("bool"),
        "int64": _builtin("int64"),
        "uint32": _builtin("uint32"),
        "uint64": _builtin("uint64"),
        "double": _builtin("float64"),
        "string[]": _slice(_builtin("string")),
    }
    try:
        return mapping[field.primitive_type]
    except KeyError as exc:
        raise GoAPIPlanError(f"enriched field {field.id}: unsupported Go field type") from exc


def _conversion(field: _Field) -> str:
    if field.structured_type is not None:
        return "structured_encoder"
    if field.primitive_type == "string[]":
        return "copied_string_slice"
    return "required_scalar" if field.requirement == "required" else "optional_scalar"


def _public_field(
    field: _Field,
    *,
    owner: str,
    order: int,
    policy: _Policy,
    symbols: Mapping[tuple[str, str], _Symbol],
    selector_prefix: str = "",
) -> GoFieldPlanIR:
    base = _base_type(field, symbols)
    type_ref = base if field.requirement == "required" else _optional_type(base)
    selector = selector_prefix + _public_name(policy, field.semantic_source_id, f"field selector {field.id}")
    return GoFieldPlanIR(
        owner=owner,
        selector=selector,
        type_ref=type_ref,
        order=order,
        presence=field.requirement,
        semantic_source_id=field.semantic_source_id,
        enriched_descriptor_id=field.id,
        value_source=field.value_source,
        target_slot=field.target_slot,
        condition_binding=field.condition_fact,
        mandatory_binding=None,
        conversion_op=_conversion(field),
    )


def _common_field(
    owner: str,
    selector: str,
    type_ref: GoTypeRefIR,
    order: int,
    *,
    presence: str = "required",
    conversion: str = "required_scalar",
) -> GoFieldPlanIR:
    return GoFieldPlanIR(
        owner,
        selector,
        type_ref,
        order,
        presence,
        f"structural.{selector}",
        f"common:{owner}:{selector}",
        "input",
        selector,
        None,
        None,
        conversion,
    )


def _condition_fields(
    owner: str,
    values: Sequence[GoFieldPlanIR],
    start: int,
    policy: _Policy,
) -> tuple[GoFieldPlanIR, ...]:
    seen: set[str] = set()
    result: list[GoFieldPlanIR] = []
    for value in values:
        fact = value.condition_binding
        if fact is None or fact in seen:
            continue
        seen.add(fact)
        selector = "Condition" + _public_name(policy, fact, f"condition selector {owner}")
        result.append(
            GoFieldPlanIR(
                owner,
                selector,
                _builtin("bool"),
                start + len(result),
                "required",
                fact,
                f"condition:{owner}:{fact}",
                "input",
                "conditions",
                fact,
                None,
                "condition_fact",
            )
        )
    return tuple(result)


def _mandatory_fields(owner: str, raw_program: Any, start: int, policy: _Policy) -> tuple[GoFieldPlanIR, ...]:
    facts = _sequence(_read(raw_program, "fact_terms", f"mandatory program {owner}"), "mandatory fact terms")
    result: list[GoFieldPlanIR] = []
    seen: set[str] = set()
    for raw_fact in facts:
        fact = _string(raw_fact, f"mandatory program {owner}.fact_terms")
        if fact in seen:
            raise GoAPIPlanError(f"mandatory program {owner}: duplicate fact term")
        seen.add(fact)
        selector = "Mandatory" + _public_name(policy, fact, f"mandatory selector {owner}")
        result.append(
            GoFieldPlanIR(
                owner,
                selector,
                _builtin("bool"),
                start + len(result),
                "required",
                fact,
                f"mandatory:{owner}:{fact}",
                "input",
                "mandatory",
                None,
                fact,
                "mandatory_fact",
            )
        )
    return tuple(result)


def _validate_owner_fields(fields: Sequence[GoFieldPlanIR]) -> None:
    selectors: set[str] = set()
    orders: set[int] = set()
    for field in fields:
        _validate_identifier(field.selector, f"{field.owner} field selector")
        if field.selector in selectors or field.order in orders or field.conversion_op not in _CONVERSIONS:
            raise GoAPIPlanError(f"{field.owner}: field selector/order collision")
        selectors.add(field.selector)
        orders.add(field.order)
    if tuple(sorted(orders)) != tuple(range(len(fields))):
        raise GoAPIPlanError("Go input field orders are not contiguous")


def _field_ids(raw: Any, name: str, path: str, fields: Mapping[str, _Field]) -> tuple[str, ...]:
    ids = tuple(_string(item, f"{path}.{name}") for item in _sequence(_read(raw, name, path), f"{path}.{name}"))
    if len(ids) != len(set(ids)) or any(item not in fields for item in ids):
        raise GoAPIPlanError(f"{path}.{name}: duplicate or unknown enriched descriptor")
    return ids


def _kernel_field(field: _Field) -> GoKernelFieldDescriptorIR:
    field_type = "structured" if field.structured_type is not None else field.primitive_type
    return GoKernelFieldDescriptorIR(
        field.id,
        field.semantic_source_id,
        field_type,
        field.requirement,
        field.condition_id,
        field.condition_fact,
        field.false_requirement,
        field.field_class,
        field.constraints,
        field.value_source,
        field.target_slot,
        field.order,
    )


def _kernel_limits(containers: Mapping[str, Any], descriptor_id: str) -> GoKernelLimitsIR:
    descriptor = containers.get(descriptor_id)
    if descriptor is None:
        raise GoAPIPlanError(f"enriched container {descriptor_id}: required limit contract is missing")
    raw_bounds = _read(descriptor, "bounds", f"enriched container {descriptor_id}")
    if not isinstance(raw_bounds, Mapping):
        raise GoAPIPlanError(f"enriched container {descriptor_id}: bounds are invalid")

    def bound(name: str) -> int:
        return _integer(raw_bounds.get(name), f"enriched container {descriptor_id}.{name}", minimum=1)

    return GoKernelLimitsIR(
        bound("max_utf8_bytes"),
        bound("max_item_utf8_bytes"),
        bound("max_items"),
        bound("max_depth"),
        bound("max_properties"),
    )


def _tag_fields(value: Any, path: str) -> Mapping[str, Any]:
    if not isinstance(value, Mapping):
        raise GoAPIPlanError(f"{path}: expected tagged compiler mapping")
    fields = value.get("fields") if "$type" in value else value
    if not isinstance(fields, Mapping):
        raise GoAPIPlanError(f"{path}: tagged fields are invalid")
    return fields


def _trace_contract_defaults(index: Any) -> GoTraceContractPlanIR:
    fields = _read(index, "fields", "candidate")
    if not isinstance(fields, Mapping):
        raise GoAPIPlanError("candidate.fields: expected mapping")
    profiles = _sequence(fields["semantic_profiles"], "candidate.fields.semantic_profiles")
    if len(profiles) != 1:
        raise GoAPIPlanError("candidate semantic profile inventory is not singular")
    profile = _tag_fields(profiles[0], "semantic profile")
    contract = _tag_fields(fields["structural_contract"], "structural contract")

    def structural_limits(object_name: str, field_name: str) -> GoKernelLimitsIR:
        structural = _tag_fields(contract[object_name], f"structural contract {object_name}")
        matching = [
            _tag_fields(item, f"structural contract {object_name}.fields")
            for item in _sequence(structural["fields"], f"structural contract {object_name}.fields")
            if _tag_fields(item, f"structural contract {object_name}.fields").get("name") == field_name
        ]
        if len(matching) != 1:
            raise GoAPIPlanError(f"structural contract {object_name}.{field_name}: field is missing")
        normalization = _tag_fields(matching[0]["normalization"], f"{object_name}.{field_name}.normalization")
        constraints = normalization["effective_constraints"]
        if not isinstance(constraints, Mapping):
            raise GoAPIPlanError(f"structural contract {object_name}.{field_name}: constraints are invalid")

        def value(name: str) -> int:
            return _integer(constraints.get(name), f"{object_name}.{field_name}.{name}", minimum=1)

        return GoKernelLimitsIR(
            value("max_utf8_bytes"),
            value("max_item_utf8_bytes"),
            value("max_items"),
            value("max_depth"),
            value("max_properties"),
        )

    events_limits = structural_limits("trace_body", "events")
    links_limits = structural_limits("trace_body", "links")
    scope = _tag_fields(contract["trace_scope"], "trace scope")
    scope_constants: dict[str, str] = {}
    for raw_field in _sequence(scope["fields"], "trace scope fields"):
        field = _tag_fields(raw_field, "trace scope field")
        constant = field.get("const")
        if isinstance(constant, str):
            scope_constants[_string(field["name"], "trace scope field name")] = constant
    try:
        scope_name = scope_constants["name"]
        scope_schema_url = scope_constants["schema_url"]
    except KeyError as exc:
        raise GoAPIPlanError("trace scope constants are incomplete") from exc
    return GoTraceContractPlanIR(
        structural_limits("trace_body", "attributes"),
        structural_limits("trace_resource", "attributes"),
        structural_limits("trace_scope", "attributes"),
        structural_limits("trace_event", "attributes"),
        structural_limits("trace_link", "attributes"),
        events_limits.max_items,
        links_limits.max_items,
        scope_name,
        scope_schema_url,
        _string(profile["trace_schema_version"], "semantic profile trace schema version"),
        _string(profile["id"], "semantic profile ID"),
    )


def _metric_limits_from_trace_contract(index: Any) -> GoKernelLimitsIR:
    fields = _read(index, "fields", "candidate")
    contract = _tag_fields(fields["structural_contract"], "structural contract")
    instrument = _tag_fields(contract["metric_instrument_data"], "metric instrument data")
    matching = [
        _tag_fields(item, "metric instrument field")
        for item in _sequence(instrument["fields"], "metric instrument fields")
        if _tag_fields(item, "metric instrument field").get("name") == "attributes"
    ]
    if len(matching) != 1:
        raise GoAPIPlanError("metric attribute structural contract is missing")
    normalization = _tag_fields(matching[0]["normalization"], "metric attribute normalization")
    constraints = normalization["effective_constraints"]
    if not isinstance(constraints, Mapping):
        raise GoAPIPlanError("metric attribute constraints are invalid")
    return GoKernelLimitsIR(
        _integer(constraints.get("max_utf8_bytes"), "metric max UTF8", minimum=1),
        _integer(constraints.get("max_item_utf8_bytes"), "metric max item UTF8", minimum=1),
        _integer(constraints.get("max_items"), "metric max items", minimum=1),
        _integer(constraints.get("max_depth"), "metric max depth", minimum=1),
        _integer(constraints.get("max_properties"), "metric max properties", minimum=1),
    )


def _ordered_public_fields(
    ids: Sequence[str],
    *,
    owner: str,
    component: str,
    input_owner_kind: str,
    start: int,
    policy: _Policy,
    symbols: Mapping[tuple[str, str], _Symbol],
    fields: Mapping[str, _Field],
    selector_prefix: str = "",
    descriptor_owner_id: str | None = None,
) -> tuple[GoFieldPlanIR, ...]:
    selected = [fields[item] for item in ids]
    expected_descriptor_owner = descriptor_owner_id or owner
    if any(
        field.owner_id != expected_descriptor_owner
        or field.component != component
        or (field.value_source == "input" and field.input_owner_kind != input_owner_kind)
        for field in selected
    ):
        raise GoAPIPlanError(f"{owner}: enriched field ownership disagrees with descriptor")
    public = sorted((field for field in selected if field.value_source == "input"), key=lambda field: field.order)
    if len({field.order for field in public}) != len(public):
        raise GoAPIPlanError(f"{owner}: duplicate enriched field order")
    return tuple(
        _public_field(
            field,
            owner=owner,
            order=start + position,
            policy=policy,
            symbols=symbols,
            selector_prefix=selector_prefix,
        )
        for position, field in enumerate(public)
    )


def _log_common(owner: str, outcome: str) -> tuple[GoFieldPlanIR, ...]:
    fields = [
        _common_field(owner, "Envelope", _named("FamilyEnvelopeInput"), 0),
        _common_field(
            owner, "Severity", _optional_type(_named("Severity")), 1, presence="optional", conversion="optional_scalar"
        ),
        _common_field(
            owner, "LogLevel", _optional_type(_named("LogLevel")), 2, presence="optional", conversion="optional_scalar"
        ),
    ]
    if outcome == "required":
        fields.append(_common_field(owner, "Outcome", _named("Outcome"), 3))
    elif outcome == "optional":
        fields.append(
            _common_field(
                owner,
                "Outcome",
                _optional_type(_named("Outcome")),
                3,
                presence="optional",
                conversion="optional_scalar",
            )
        )
    elif outcome != "forbidden":
        raise GoAPIPlanError(f"{owner}: invalid log outcome requirement")
    return tuple(fields)


def _span_common(owner: str) -> tuple[GoFieldPlanIR, ...]:
    specs = (
        ("Envelope", _named("FamilyEnvelopeInput"), "required", "required_scalar"),
        ("Outcome", _named("Outcome"), "required", "required_scalar"),
        ("Kind", _builtin("string"), "required", "required_scalar"),
        ("StartTimeUnixNano", _builtin("uint64"), "required", "required_scalar"),
        ("EndTimeUnixNano", _builtin("uint64"), "required", "required_scalar"),
        ("ParentSpanID", _optional_type(_builtin("string")), "optional", "optional_scalar"),
        ("Status", _named("TraceStatusInput"), "required", "required_scalar"),
        ("Resource", _named("TraceResourceInput"), "required", "required_scalar"),
        ("Scope", _named("TraceScopeInput"), "required", "required_scalar"),
        ("DroppedAttributesCount", _optional_type(_builtin("uint32")), "optional", "optional_scalar"),
        ("Events", _slice(_named("TraceEventInput")), "required", "trace_event"),
        ("DroppedEventsCount", _optional_type(_builtin("uint32")), "optional", "optional_scalar"),
        ("Links", _slice(_named("TraceLinkInput")), "required", "trace_link"),
        ("DroppedLinksCount", _optional_type(_builtin("uint32")), "optional", "optional_scalar"),
    )
    return tuple(
        _common_field(owner, selector, type_ref, order, presence=presence, conversion=conversion)
        for order, (selector, type_ref, presence, conversion) in enumerate(specs)
    )


def _event_common(owner: str) -> tuple[GoFieldPlanIR, ...]:
    return (
        _common_field(owner, "TimeUnixNano", _builtin("uint64"), 0),
        _common_field(
            owner,
            "DroppedAttributesCount",
            _optional_type(_builtin("uint32")),
            1,
            presence="optional",
            conversion="optional_scalar",
        ),
    )


def _link_common(owner: str) -> tuple[GoFieldPlanIR, ...]:
    return (
        _common_field(owner, "TraceID", _builtin("string"), 0),
        _common_field(owner, "SpanID", _builtin("string"), 1),
        _common_field(
            owner,
            "TraceState",
            _optional_type(_builtin("string")),
            2,
            presence="optional",
            conversion="optional_scalar",
        ),
        _common_field(
            owner,
            "DroppedAttributesCount",
            _optional_type(_builtin("uint32")),
            3,
            presence="optional",
            conversion="optional_scalar",
        ),
    )


def _structured_value_type(raw: Any, symbols: Mapping[tuple[str, str], _Symbol], path: str) -> GoTypeRefIR:
    scalar = _optional(raw, "scalar")
    reference = _optional(raw, "reference")
    if (scalar is None) == (reference is None):
        raise GoAPIPlanError(f"{path}: expected exactly one scalar or reference")
    if reference is not None:
        target = _string(_read(reference, "structured_ref", path), f"{path}.structured_ref")
        return _named(_required_symbol(symbols, "structured_type", target).symbol)
    field_type = _string(_read(scalar, "field_type", path), f"{path}.field_type")
    mapping = {
        "string": _builtin("string"),
        "boolean": _builtin("bool"),
        "int64": _builtin("int64"),
        "double": _builtin("float64"),
    }
    try:
        return mapping[field_type]
    except KeyError as exc:
        raise GoAPIPlanError(f"{path}: unsupported structured scalar type") from exc


def _compile_structured(
    index: Any,
    *,
    policy: _Policy,
    symbols: Mapping[tuple[str, str], _Symbol],
    fields: Mapping[str, _Field],
) -> tuple[
    tuple[GoStructuredPlanIR, ...], tuple[GoInputPlanIR, ...], tuple[GoCallablePlanIR, ...], set[DeclarationKeyIR]
]:
    raw_descriptors = _read(index, "structured_types", "candidate")
    containers = _read(index, "enriched_containers", "candidate")
    if not isinstance(containers, Mapping):
        raise GoAPIPlanError("enriched_containers: expected compiler-owned mapping")
    items = (
        tuple(raw_descriptors.values())
        if isinstance(raw_descriptors, Mapping)
        else _sequence(raw_descriptors, "structured_types")
    )
    by_id: dict[str, Any] = {}
    for position, raw in enumerate(items):
        identifier = _string(_read(raw, "id", f"structured_types[{position}]"), "structured descriptor id")
        if identifier in by_id:
            raise GoAPIPlanError("structured_types: duplicate type")
        by_id[identifier] = raw
    expected = {source_id for kind, source_id in symbols if kind == "structured_type"}
    if set(by_id) != expected:
        raise GoAPIPlanError("structured_types: complete structured descriptor inventory is required")
    plans: list[GoStructuredPlanIR] = []
    inputs: list[GoInputPlanIR] = []
    callables: list[GoCallablePlanIR] = []
    planned: set[DeclarationKeyIR] = set()
    for identifier in sorted(by_id, key=str.encode):
        raw = by_id[identifier]
        symbol = _required_symbol(symbols, "structured_type", identifier)
        shape = _string(_read(raw, "kind", f"structured {identifier}"), f"structured {identifier}.kind")
        if shape not in _STRUCTURED_SHAPES:
            raise GoAPIPlanError(f"structured {identifier}: unknown shape")
        container = containers.get(f"structured:{identifier}")
        if container is None:
            raise GoAPIPlanError(f"structured {identifier}: enriched container descriptor is missing")
        scalar_ids = tuple(
            _string(item, f"structured {identifier}.child_fields")
            for item in _sequence(
                _read(container, "child_fields", f"structured {identifier}"),
                f"structured {identifier}.child_fields",
            )
        )
        scalar_by_member = {fields[item].semantic_source_id: fields[item] for item in scalar_ids if item in fields}
        if len(scalar_by_member) != len(scalar_ids):
            raise GoAPIPlanError(f"structured {identifier}: scalar descriptor links are incomplete")
        used_scalar_ids: set[str] = set()
        value_fields: list[GoFieldPlanIR] = []
        for order, raw_field in enumerate(_optional(raw, "fields", ()) or ()):
            name = _string(_read(raw_field, "name", f"structured {identifier}.fields"), "structured field name")
            required = _read(raw_field, "required", f"structured {identifier}.{name}")
            if not isinstance(required, bool):
                raise GoAPIPlanError(f"structured {identifier}.{name}: required flag is not Boolean")
            scalar = _optional(raw_field, "scalar")
            if scalar is not None:
                descriptor = scalar_by_member.get(f"field:{name}")
                if descriptor is None:
                    raise GoAPIPlanError(f"structured {identifier}.{name}: scalar descriptor is missing")
                used_scalar_ids.add(descriptor.id)
                base_type = _base_type(descriptor, symbols)
                descriptor_id = descriptor.id
            else:
                base_type = _structured_value_type(raw_field, symbols, f"structured {identifier}.{name}")
                descriptor_id = f"structured-edge:{identifier}:field:{name}"
                if descriptor_id not in containers:
                    raise GoAPIPlanError(f"structured {identifier}.{name}: reference edge descriptor is missing")
            value_fields.append(
                GoFieldPlanIR(
                    identifier,
                    _public_name(policy, name, f"structured selector {identifier}.{name}"),
                    base_type if required else _optional_type(base_type),
                    order,
                    "required" if required else "optional",
                    name,
                    descriptor_id,
                    "input",
                    "structured.fixed",
                    None,
                    None,
                    "structured_encoder"
                    if base_type.arm == "named"
                    else ("required_scalar" if required else "optional_scalar"),
                )
            )
        item_type: GoTypeRefIR | None = None
        if shape == "array":
            item_type = _structured_value_type(
                {"scalar": _optional(raw, "items_scalar"), "reference": _optional(raw, "items_reference")},
                symbols,
                f"structured {identifier}.items",
            )
        arm_types: list[tuple[str, GoTypeRefIR]] = []
        arm_shapes: list[tuple[str, str, str]] = []
        for variant in _optional(raw, "variants", ()) or ():
            tag = _string(_read(variant, "tag", f"structured {identifier}.variants"), "structured variant tag")
            target = _string(
                _read(variant, "structured_ref", f"structured {identifier}.variants"), "structured variant target"
            )
            arm_types.append(
                (f"{identifier}#{tag}", _named(_required_symbol(symbols, "structured_type", target).symbol))
            )
            arm_shapes.append((f"{identifier}#{tag}", "registered", "Value"))
        dynamic_variant = _optional(raw, "dynamic_variant")
        if dynamic_variant is not None:
            arm_id = _string(_read(dynamic_variant, "arm_id", f"structured {identifier}"), "dynamic arm ID")
            target = _string(_read(dynamic_variant, "structured_ref", f"structured {identifier}"), "dynamic arm target")
            arm_types.append(
                (f"{identifier}#{arm_id}", _named(_required_symbol(symbols, "structured_type", target).symbol))
            )
            arm_shapes.append((f"{identifier}#{arm_id}", "dynamic", "Tag,Value"))
        canonical = _optional(raw, "canonical_json")
        if canonical is not None:
            canonical_types: dict[str, GoTypeRefIR] = {
                "array": _slice(_named(symbol.symbol)),
                "object": _slice(
                    _named(_required_symbol(symbols, "structured_member_input", f"{identifier}#entry").symbol)
                ),
            }
            for scalar_arm in ("boolean", "int64", "finite_double", "string"):
                descriptor = scalar_by_member.get(f"canonical_arm:{scalar_arm}")
                if descriptor is None:
                    raise GoAPIPlanError(f"structured {identifier}: canonical scalar descriptor is missing")
                canonical_types[scalar_arm] = _base_type(descriptor, symbols)
                used_scalar_ids.add(descriptor.id)
            for arm_id in _sequence(_read(canonical, "arms", f"structured {identifier}"), "canonical arms"):
                arm_id = _string(arm_id, "canonical arm")
                try:
                    arm_types.append((f"{identifier}#{arm_id}", canonical_types[arm_id]))
                    selector = "Items" if arm_id == "array" else "Entries" if arm_id == "object" else "Value"
                    arm_shapes.append((f"{identifier}#{arm_id}", "canonical", selector))
                except KeyError as exc:
                    raise GoAPIPlanError(f"structured {identifier}: unknown canonical arm") from exc
        for source_id, _ in arm_types:
            _required_symbol(symbols, "structured_arm", source_id)
            planned.add(("structured_arm", source_id))
        dynamic_member = _optional(raw, "dynamic_members")
        if canonical is not None:
            dynamic_member = {
                "member_id": _read(canonical, "object_member_id", f"structured {identifier}"),
                "value": _read(canonical, "object_value", f"structured {identifier}"),
            }
        dynamic_keys: list[str] = []
        if dynamic_member is not None:
            member_id = _string(_read(dynamic_member, "member_id", f"structured {identifier}"), "member ID")
            source_id = f"{identifier}#{member_id}"
            input_symbol = _required_symbol(symbols, "structured_member_input", source_id)
            constructor_symbol = _required_symbol(symbols, "structured_member_constructor", source_id)
            value = _read(dynamic_member, "value", f"structured {identifier}")
            value_type = _structured_value_type(
                {"scalar": _optional(value, "scalar"), "reference": value},
                symbols,
                f"structured member {source_id}",
            )
            name_descriptor = scalar_by_member.get(f"dynamic_name:{member_id}")
            if name_descriptor is None:
                raise GoAPIPlanError(f"structured {identifier}: dynamic-name descriptor is missing")
            used_scalar_ids.add(name_descriptor.id)
            member_fields = (
                GoFieldPlanIR(
                    source_id,
                    "Name",
                    _base_type(name_descriptor, symbols),
                    0,
                    "required",
                    name_descriptor.semantic_source_id,
                    name_descriptor.id,
                    "input",
                    name_descriptor.target_slot,
                    None,
                    None,
                    "required_scalar",
                ),
                _common_field(source_id, "Value", value_type, 1),
            )
            _validate_owner_fields(member_fields)
            inputs.append(
                GoInputPlanIR(
                    "structured_member_input",
                    source_id,
                    input_symbol.symbol,
                    _DOMAIN_FILES["genai"],
                    member_fields,
                    "validateGeneratedStructuredMember",
                    (),
                    (),
                    (),
                )
            )
            callables.append(
                GoCallablePlanIR(
                    "structured_member_constructor",
                    source_id,
                    constructor_symbol.symbol,
                    _DOMAIN_FILES["genai"],
                    None,
                    None,
                    False,
                    (("name", _builtin("string")), ("value", value_type)),
                    (_named(input_symbol.symbol), _builtin("error")),
                    "family_build_error",
                    "newGeneratedStructuredMember",
                )
            )
            dynamic_keys.append(source_id)
            planned.update({("structured_member_input", source_id), ("structured_member_constructor", source_id)})
        selectors = {field.selector for field in value_fields}
        reserved_here = {"Entries"} if dynamic_member is not None else set()
        if shape == "array":
            reserved_here.add("Items")
        if selectors & reserved_here:
            raise GoAPIPlanError(f"structured {identifier}: reserved selector collision")
        _validate_owner_fields(value_fields)
        if shape in {"tagged_union", "canonical_json"} and not arm_types:
            raise GoAPIPlanError(f"structured {identifier}: union has no arms")
        discriminator = _optional(raw, "discriminator")
        if discriminator is not None:
            discriminator_name = _string(
                _read(discriminator, "name", f"structured {identifier}"), "structured discriminator"
            )
            discriminator_descriptor = scalar_by_member.get(f"discriminator:{discriminator_name}")
            if discriminator_descriptor is None:
                raise GoAPIPlanError(f"structured {identifier}: discriminator descriptor is missing")
            used_scalar_ids.add(discriminator_descriptor.id)
        else:
            discriminator_name = None
        if used_scalar_ids != set(scalar_ids):
            raise GoAPIPlanError(f"structured {identifier}: scalar descriptor coverage is incomplete")
        child_container_ids = tuple(
            _string(item, f"structured {identifier}.child_containers")
            for item in _sequence(
                _read(container, "child_containers", f"structured {identifier}"),
                f"structured {identifier}.child_containers",
            )
        )
        if any(item not in containers for item in child_container_ids):
            raise GoAPIPlanError(f"structured {identifier}: child container link is unresolved")
        limit_values: dict[str, int] = {}
        raw_bounds = _read(container, "bounds", f"structured {identifier}")
        if not isinstance(raw_bounds, Mapping):
            raise GoAPIPlanError(f"structured {identifier}: bounds are invalid")
        for name, value in raw_bounds.items():
            if isinstance(value, int) and not isinstance(value, bool):
                limit_values[_string(name, f"structured {identifier}.bounds")] = value
        for name in ("min_items", "max_items"):
            value = _optional(raw, name)
            if isinstance(value, int) and not isinstance(value, bool):
                limit_values[name] = value
        if canonical is not None:
            canonical_limits = _read(canonical, "limits", f"structured {identifier}")
            if not isinstance(canonical_limits, Mapping):
                raise GoAPIPlanError(f"structured {identifier}: canonical limits are invalid")
            for name, value in canonical_limits.items():
                limit_values[_string(name, f"structured {identifier}.canonical_limits")] = _integer(
                    value, f"structured {identifier}.{name}", minimum=1
                )
        plans.append(
            GoStructuredPlanIR(
                identifier,
                symbol.symbol,
                _DOMAIN_FILES["genai"],
                shape,
                scalar_ids,
                tuple(value_fields),
                item_type,
                tuple(source_id for source_id, _ in arm_types),
                tuple(arm_types),
                tuple(arm_shapes),
                tuple(dynamic_keys),
                discriminator_name,
                (f"structured:{identifier}",) + child_container_ids,
                tuple(sorted(limit_values.items())),
                {
                    "object": ("validate_fixed_fields", "validate_dynamic_members", "encode_object"),
                    "array": ("validate_items", "encode_array"),
                    "tagged_union": ("validate_registered_arm", "encode_tagged_union"),
                    "canonical_json": (
                        "validate_canonical_arm",
                        "enforce_recursive_limits",
                        "encode_canonical_json",
                    ),
                }[shape],
            )
        )
        planned.add(("structured_type", identifier))
    return tuple(plans), tuple(inputs), tuple(callables), planned


def _compile_families(
    index: Any,
    *,
    policy: _Policy,
    symbols: Mapping[tuple[str, str], _Symbol],
    fields: Mapping[str, _Field],
) -> tuple[
    tuple[GoInputPlanIR, ...],
    tuple[GoCallablePlanIR, ...],
    tuple[GoDescriptorPlanIR, ...],
    set[DeclarationKeyIR],
    dict[str, str],
]:
    raw_families = _read(index, "enriched_families", "candidate")
    items = (
        tuple(raw_families.values())
        if isinstance(raw_families, Mapping)
        else _sequence(raw_families, "enriched_families")
    )
    by_id: dict[str, Any] = {}
    for position, raw in enumerate(items):
        identifier = _string(_read(raw, "id", f"enriched_families[{position}]"), "family descriptor ID")
        if identifier in by_id:
            raise GoAPIPlanError("enriched_families: duplicate family")
        by_id[identifier] = raw
    expected = {source_id for kind, source_id in symbols if kind == "family_input"}
    if set(by_id) != expected:
        raise GoAPIPlanError("enriched_families: complete family descriptor inventory is required")
    inputs: list[GoInputPlanIR] = []
    callables: list[GoCallablePlanIR] = []
    descriptors: list[GoDescriptorPlanIR] = []
    planned: set[DeclarationKeyIR] = set()
    family_domains: dict[str, str] = {}
    traces = _read(index, "enriched_traces", "candidate")
    metrics = _read(index, "enriched_metrics", "candidate")
    mandatory_programs = _read(index, "mandatory_programs", "candidate")
    if (
        not isinstance(traces, Mapping)
        or not isinstance(metrics, Mapping)
        or not isinstance(mandatory_programs, Mapping)
    ):
        raise GoAPIPlanError("candidate enriched family companions are incomplete")
    trace_defaults = _trace_contract_defaults(index)
    containers = _read(index, "enriched_containers", "candidate")
    if not isinstance(containers, Mapping):
        raise GoAPIPlanError("enriched_containers: expected mapping")
    metric_attribute_limits = _metric_limits_from_trace_contract(index)
    for identifier in sorted(by_id, key=str.encode):
        raw = by_id[identifier]
        path = f"family {identifier}"
        if _optional(raw, "removed_in") is not None:
            raise GoAPIPlanError(f"{path}: only active canonical families may own generated declarations")
        raw_signal = _string(_read(raw, "signal", path), f"{path}.signal")
        signal = {"logs": "log", "traces": "span", "metrics": "metric"}.get(raw_signal)
        if signal is None:
            raise GoAPIPlanError(f"{path}: unknown signal")
        domain = _string(_read(raw, "domain", path), f"{path}.domain")
        if domain not in _DOMAIN_FILES:
            raise GoAPIPlanError(f"{path}: unknown output domain")
        family_domains[identifier] = domain
        output_file = _DOMAIN_FILES[domain]
        input_symbol = _required_symbol(symbols, "family_input", identifier)
        builder_symbol = _required_symbol(symbols, "family_builder", identifier)
        raw_outcome = _optional(raw, "outcome_requirement")
        outcome_requirement = (
            "forbidden" if raw_outcome is None else _string(raw_outcome, f"{path}.outcome_requirement")
        )
        family_ids = _field_ids(raw, "field_descriptor_ids", path, fields)
        trace = traces.get(identifier)
        metric = metrics.get(identifier)
        resource_ids = (
            _field_ids(trace, "resource_field_descriptor_ids", f"trace {identifier}", fields)
            if trace is not None
            else ()
        )
        scope_ids = (
            _field_ids(trace, "scope_field_descriptor_ids", f"trace {identifier}", fields) if trace is not None else ()
        )
        if signal == "log":
            common = _log_common(identifier, outcome_requirement)
        elif signal == "span":
            if outcome_requirement != "required":
                raise GoAPIPlanError(f"{path}: span outcome must be required")
            common = _span_common(identifier)
        else:
            if outcome_requirement != "forbidden":
                raise GoAPIPlanError(f"{path}: metric outcome must be forbidden")
            if metric is None:
                raise GoAPIPlanError(f"{path}: enriched metric descriptor is missing")
            value_type = _string(_read(metric, "value_type", f"metric {identifier}"), f"{path}.metric_value_type")
            if value_type not in {"int64", "double"}:
                raise GoAPIPlanError(f"{path}: metric value type is unsupported")
            common = (
                _common_field(identifier, "Envelope", _named("FamilyEnvelopeInput"), 0),
                _common_field(
                    identifier,
                    "Value",
                    _builtin("int64" if value_type == "int64" else "float64"),
                    1,
                    conversion="metric_number",
                ),
            )
        values: list[GoFieldPlanIR] = []
        if signal == "span":
            values.extend(
                _ordered_public_fields(
                    resource_ids,
                    owner=identifier,
                    component="resource",
                    input_owner_kind="family",
                    start=len(common),
                    policy=policy,
                    symbols=symbols,
                    fields=fields,
                    selector_prefix="Resource",
                    descriptor_owner_id="resource.core",
                )
            )
        values.extend(
            _ordered_public_fields(
                family_ids,
                owner=identifier,
                component="family",
                input_owner_kind="family",
                start=len(common) + len(values),
                policy=policy,
                symbols=symbols,
                fields=fields,
            )
        )
        conditions = _condition_fields(identifier, values, len(common) + len(values), policy)
        program_id = _optional(raw, "mandatory_program_id")
        raw_program = mandatory_programs.get(program_id) if program_id is not None else None
        mandatory_program = {
            "rule_ids": _read(raw_program, "rule_ids", f"mandatory {identifier}") if raw_program is not None else (),
            "constant_terms": tuple(
                True
                for _ in (
                    _read(raw_program, "constant_rule_ids", f"mandatory {identifier}")
                    if raw_program is not None
                    else ()
                )
            ),
            "fact_terms": tuple(
                fact
                for _, fact in (
                    _read(raw_program, "fact_terms", f"mandatory {identifier}") if raw_program is not None else ()
                )
            ),
        }
        mandatory = _mandatory_fields(
            identifier, mandatory_program, len(common) + len(values) + len(conditions), policy
        )
        if signal != "log" and mandatory:
            raise GoAPIPlanError(f"{path}: only logs may expose mandatory facts")
        input_fields = common + tuple(values) + conditions + mandatory
        _validate_owner_fields(input_fields)
        if signal == "span" and trace is None:
            raise GoAPIPlanError(f"{path}: enriched trace descriptor is missing")
        raw_events = tuple(
            {
                "source_id": f"{identifier}#{event_name}",
                "event_name": event_name,
                "field_ids": _read(trace, "event_field_descriptor_ids", f"trace {identifier}")[event_name],
            }
            for event_name in (_read(trace, "event_refs", f"trace {identifier}") if trace is not None else ())
        )
        event_keys: list[str] = []
        event_contracts: list[tuple[str, str, tuple[str, ...]]] = []
        for raw_event in raw_events:
            source_id = _string(_read(raw_event, "source_id", f"{path}.events"), "event source ID")
            event_name = _string(_read(raw_event, "event_name", f"{path}.events"), "event name")
            event_ids = _field_ids(raw_event, "field_ids", f"event {source_id}", fields)
            event_symbol = _required_symbol(symbols, "span_event_input", source_id)
            constructor = _required_symbol(symbols, "span_event_constructor", source_id)
            event_values = _ordered_public_fields(
                event_ids,
                owner=source_id,
                component="event",
                input_owner_kind="event",
                start=2,
                policy=policy,
                symbols=symbols,
                fields=fields,
                descriptor_owner_id=event_name,
            )
            event_fields = (
                _event_common(source_id)
                + event_values
                + _condition_fields(source_id, event_values, 2 + len(event_values), policy)
            )
            _validate_owner_fields(event_fields)
            inputs.append(
                GoInputPlanIR(
                    "span_event_input",
                    source_id,
                    event_symbol.symbol,
                    output_file,
                    event_fields,
                    "validateGeneratedTraceEvent",
                    (),
                    (),
                    (),
                )
            )
            callables.append(
                GoCallablePlanIR(
                    "span_event_constructor",
                    source_id,
                    constructor.symbol,
                    output_file,
                    None,
                    None,
                    False,
                    (("input", _named(event_symbol.symbol)),),
                    (_named("TraceEventInput"), _builtin("error")),
                    "family_build_error",
                    "newGeneratedTraceEventInput",
                )
            )
            event_keys.append(source_id)
            event_contracts.append((source_id, event_name, event_ids))
            planned.update({("span_event_input", source_id), ("span_event_constructor", source_id)})
        raw_links = tuple(
            {
                "source_id": f"{identifier}#{relation}",
                "relation": relation,
                "field_ids": _read(trace, "link_field_descriptor_ids", f"trace {identifier}"),
            }
            for relation in (_read(trace, "link_relations", f"trace {identifier}") if trace is not None else ())
        )
        link_keys: list[str] = []
        link_contracts: list[tuple[str, tuple[str, ...]]] = []
        for raw_link in raw_links:
            source_id = _string(_read(raw_link, "source_id", f"{path}.links"), "link source ID")
            relation = _string(_read(raw_link, "relation", f"{path}.links"), "link relation")
            link_ids = _field_ids(raw_link, "field_ids", f"link {source_id}", fields)
            link_symbol = _required_symbol(symbols, "span_link_input", source_id)
            constructor = _required_symbol(symbols, "span_link_constructor", source_id)
            link_values = _ordered_public_fields(
                link_ids,
                owner=source_id,
                component="link",
                input_owner_kind="link",
                start=4,
                policy=policy,
                symbols=symbols,
                fields=fields,
                descriptor_owner_id="link.core",
            )
            link_fields = (
                _link_common(source_id)
                + link_values
                + _condition_fields(source_id, link_values, 4 + len(link_values), policy)
            )
            _validate_owner_fields(link_fields)
            inputs.append(
                GoInputPlanIR(
                    "span_link_input",
                    source_id,
                    link_symbol.symbol,
                    output_file,
                    link_fields,
                    "validateGeneratedTraceLink",
                    (),
                    (),
                    (),
                )
            )
            callables.append(
                GoCallablePlanIR(
                    "span_link_constructor",
                    source_id,
                    constructor.symbol,
                    output_file,
                    None,
                    None,
                    False,
                    (("input", _named(link_symbol.symbol)),),
                    (_named("TraceLinkInput"), _builtin("error")),
                    "family_build_error",
                    "newGeneratedTraceLinkInput",
                )
            )
            link_keys.append(source_id)
            link_contracts.append((relation, link_ids))
            planned.update({("span_link_input", source_id), ("span_link_constructor", source_id)})
        inputs.append(
            GoInputPlanIR(
                "family_input",
                identifier,
                input_symbol.symbol,
                output_file,
                input_fields,
                {
                    "log": "familyLogBuildInput",
                    "span": "familyTraceBuildInput",
                    "metric": "familyMetricBuildInput",
                }[signal],
                tuple(event_keys),
                tuple(link_keys),
                resource_ids,
            )
        )
        callables.append(
            GoCallablePlanIR(
                "family_builder",
                identifier,
                builder_symbol.symbol,
                output_file,
                "builder",
                _named("FamilyBuilder"),
                True,
                (("input", _named(input_symbol.symbol)),),
                (_named("Record"), _builtin("error")),
                "family_build_error",
                {
                    "log": "buildGeneratedResolvedLog",
                    "span": "buildGeneratedTrace",
                    "metric": "buildGeneratedMetric",
                }[signal],
            )
        )
        allowed_outcomes = tuple(
            _string(item, f"{path}.allowed_outcomes")
            for item in _sequence(_read(raw, "allowed_outcomes", path), f"{path}.allowed_outcomes")
        )
        raw_span_parts = (
            _sequence(_read(trace, "span_name_parts", f"trace {identifier}"), f"{path}.span_name_parts")
            if trace is not None
            else ()
        )
        span_parts = tuple(
            (
                _string(_read(part, "kind", f"{path}.span_name_parts"), "span-name part kind"),
                _string(
                    _read(part, "literal", f"{path}.span_name_parts")
                    if _read(part, "kind", f"{path}.span_name_parts") == "literal"
                    else _read(part, "field", f"{path}.span_name_parts"),
                    "span-name part value",
                ),
            )
            for part in raw_span_parts
        )
        metric_contract = (
            (
                ("instrument_name", _string(_read(metric, "instrument_name", f"metric {identifier}"), "instrument")),
                (
                    "instrument_type",
                    _string(_read(metric, "instrument_type", f"metric {identifier}"), "instrument type"),
                ),
                ("unit", _string(_read(metric, "unit", f"metric {identifier}"), "metric unit")),
                ("temporality", _string(_read(metric, "temporality", f"metric {identifier}"), "temporality")),
            )
            if metric is not None
            else ()
        )
        rule_ids = tuple(
            _string(item, f"{path}.mandatory_program.rule_ids")
            for item in _sequence(
                _read(mandatory_program, "rule_ids", f"{path}.mandatory_program"), "mandatory rule IDs"
            )
        )
        constant_terms = tuple(
            item
            for item in _sequence(
                _read(mandatory_program, "constant_terms", f"{path}.mandatory_program"), "mandatory constant terms"
            )
        )
        if any(not isinstance(item, bool) for item in constant_terms):
            raise GoAPIPlanError(f"{path}: mandatory constant term is not Boolean")
        mandatory_terms = tuple((field.mandatory_binding or "", field.selector) for field in mandatory)
        kernel_field_ids = tuple(
            dict.fromkeys(
                family_ids
                + resource_ids
                + scope_ids
                + tuple(field_id for _, _, event_ids in event_contracts for field_id in event_ids)
                + tuple(field_id for _, link_ids in link_contracts for field_id in link_ids)
            )
        )
        kernel_fields = tuple(_kernel_field(fields[field_id]) for field_id in kernel_field_ids)
        metric_description = (
            _string(_read(metric, "description", f"metric {identifier}"), "metric description")
            if metric is not None
            else None
        )
        metric_boundaries = tuple(_read(metric, "boundaries", f"metric {identifier}")) if metric is not None else ()
        if any(
            isinstance(value, bool)
            or not isinstance(value, (int, float))
            or isinstance(value, float)
            and not math.isfinite(value)
            for value in metric_boundaries
        ):
            raise GoAPIPlanError(f"{path}: metric boundaries are invalid")
        descriptors.append(
            GoDescriptorPlanIR(
                identifier,
                signal,
                domain,
                _string(_read(raw, "bucket", path), f"{path}.bucket"),
                _string(_read(raw, "event_name", path), f"{path}.event_name"),
                _integer(_read(raw, "family_schema_version", path), f"{path}.family_schema_version", minimum=1),
                outcome_requirement,
                allowed_outcomes,
                kernel_fields,
                family_ids,
                resource_ids,
                scope_ids,
                span_parts,
                tuple(
                    _string(item, f"{path}.allowed_kinds")
                    for item in (
                        _sequence(_read(trace, "span_kinds", f"trace {identifier}"), f"{path}.allowed_kinds")
                        if trace is not None
                        else ()
                    )
                ),
                tuple(event_contracts),
                tuple(link_contracts),
                metric_contract,
                metric_description,
                metric_boundaries,
                metric_attribute_limits if signal == "metric" else None,
                trace_defaults if signal == "span" else None,
                rule_ids,
                constant_terms,
                mandatory_terms,
                callables[-1].private_target,
            )
        )
        planned.update({("family_input", identifier), ("family_builder", identifier)})
    return tuple(inputs), tuple(callables), tuple(descriptors), planned, family_domains


def _family_source_for_row(row: _Symbol) -> str:
    return row.source_id.split("#", 1)[0]


def _file_assignments(
    rows: tuple[_Symbol, ...],
    family_domains: Mapping[str, str],
) -> dict[str, tuple[DeclarationKeyIR, ...]]:
    assigned: dict[str, list[DeclarationKeyIR]] = {path: [] for path in GO_OUTPUT_FILES}
    structured_kinds = {
        "structured_type",
        "structured_arm",
        "structured_member_input",
        "structured_member_constructor",
    }
    family_kinds = {
        "family_input",
        "family_builder",
        "span_event_input",
        "span_event_constructor",
        "span_link_input",
        "span_link_constructor",
    }
    for row in rows:
        if row.declaration_form == "exported_const":
            path = _IDS_FILE
        elif row.kind in structured_kinds:
            path = _DOMAIN_FILES["genai"]
        elif row.kind in family_kinds:
            family_id = _family_source_for_row(row)
            try:
                path = _DOMAIN_FILES[family_domains[family_id]]
            except KeyError as exc:
                raise GoAPIPlanError(f"Go declaration {row.kind}/{row.source_id}: family domain is missing") from exc
        else:
            raise GoAPIPlanError(f"Go declaration {row.kind}/{row.source_id}: no output-file assignment")
        assigned[path].append((row.kind, row.source_id))
    flattened = [key for path in GO_OUTPUT_FILES for key in assigned[path]]
    expected = [(row.kind, row.source_id) for row in rows]
    if len(flattened) != len(set(flattened)) or set(flattened) != set(expected):
        raise GoAPIPlanError("Go declaration file assignment is incomplete or duplicated")
    if len(rows) == 1773:
        counts = {path: len(assigned[path]) for path in _EXPECTED_REVIEWED_PARTITION}
        if counts != _EXPECTED_REVIEWED_PARTITION:
            raise GoAPIPlanError("reviewed Go declaration partition is not 893/282/212/386")
    return {path: tuple(assigned[path]) for path in GO_OUTPUT_FILES}


def _declaration_owner(row: _Symbol) -> str:
    structured_kinds = {
        "structured_type",
        "structured_member",
        "structured_arm",
        "structured_member_input",
        "structured_member_constructor",
    }
    family_kinds = {
        "family_input",
        "family_builder",
        "span_event_input",
        "span_event_constructor",
        "span_link_input",
        "span_link_constructor",
    }
    if row.kind in structured_kinds or row.kind in family_kinds:
        return row.source_id.split("#", 1)[0]
    return "package"


def _constant_value_facts(
    index: Any, rows: tuple[_Symbol, ...]
) -> dict[DeclarationKeyIR, tuple[GoTypeRefIR, str, LiteralValueIR]]:
    raw_facts = _read(index, "go_declaration_values", "candidate")
    items = (
        tuple(raw_facts.values()) if isinstance(raw_facts, Mapping) else _sequence(raw_facts, "go_declaration_values")
    )
    result: dict[DeclarationKeyIR, tuple[GoTypeRefIR, str, LiteralValueIR]] = {}
    rows_by_key = {(row.kind, row.source_id): row for row in rows}
    for position, raw in enumerate(items):
        path = f"go_declaration_values[{position}]"
        key = (
            _string(_read(raw, "kind", path), f"{path}.kind"),
            _string(_read(raw, "source_id", path), f"{path}.source_id"),
        )
        if key in result:
            raise GoAPIPlanError("go_declaration_values: duplicate declaration key")
        row = rows_by_key.get(key)
        if row is None or _read(raw, "symbol", path) != row.symbol:
            raise GoAPIPlanError(f"{path}.symbol: declaration identity disagrees with symbol table")
        go_type = _string(_read(raw, "go_type", path), f"{path}.go_type")
        type_ref = {"string": _builtin("string"), "int": _builtin("int")}.get(go_type)
        if type_ref is None:
            raise GoAPIPlanError(f"{path}.go_type: expected string or int")
        literal_kind = _string(_read(raw, "literal_kind", path), f"{path}.literal_kind")
        value = _read(raw, "value", path)
        if literal_kind == "string":
            if not isinstance(value, str):
                raise GoAPIPlanError(f"{path}.value: expected string literal value")
        elif literal_kind == "integer":
            if isinstance(value, bool) or not isinstance(value, int) or value < -(2**31) or value >= 2**31:
                raise GoAPIPlanError(f"{path}.value: expected integer literal value")
        else:
            raise GoAPIPlanError(f"{path}.literal_kind: unsupported constant literal")
        result[key] = (type_ref, literal_kind, value)
    expected = {(row.kind, row.source_id) for row in rows if row.declaration_form == "exported_const"}
    if set(result) != expected:
        raise GoAPIPlanError("go_declaration_values: exact exported-constant coverage is required")
    return result


def _declaration_plans(
    index: Any,
    rows: tuple[_Symbol, ...],
    assignments: Mapping[str, tuple[DeclarationKeyIR, ...]],
) -> tuple[GoDeclarationPlanIR, ...]:
    constants = _constant_value_facts(index, rows)
    file_by_key = {key: path for path, keys in assignments.items() for key in keys}
    plans: list[GoDeclarationPlanIR] = []
    for row in rows:
        key = (row.kind, row.source_id)
        constant = constants.get(key)
        plans.append(
            GoDeclarationPlanIR(
                row.kind,
                row.source_id,
                row.symbol,
                row.declaration_form,
                _declaration_owner(row),
                file_by_key[key],
                constant[0] if constant is not None else None,
                constant[1] if constant is not None else None,
                constant[2] if constant is not None else None,
            )
        )
    return tuple(plans)


def _canonical_node(value: Any) -> Any:
    if dataclasses.is_dataclass(value):
        return {
            "$type": type(value).__name__,
            "fields": {field.name: _canonical_node(getattr(value, field.name)) for field in dataclasses.fields(value)},
        }
    if isinstance(value, tuple):
        return [_canonical_node(item) for item in value]
    if value is None or isinstance(value, (str, int, bool)):
        return value
    if isinstance(value, float) and math.isfinite(value):
        return value
    raise GoAPIPlanError("Go API plan contains a non-canonical value")


def _plan_digest(plan: GoAPIPlanIR) -> str:
    without_digest = dataclasses.replace(plan, api_plan_sha256="")
    payload = json.dumps(
        _canonical_node(without_digest), ensure_ascii=False, sort_keys=True, separators=(",", ":")
    ).encode("utf-8")
    return hashlib.sha256(_GO_API_PLAN_DIGEST_DOMAIN + payload).hexdigest()


def _validate_canonical_counts(
    plan_inputs: Sequence[GoInputPlanIR],
    producer_ids: Sequence[str],
) -> None:
    observed = {key: 0 for key in _EXPECTED_CANONICAL_PUBLIC_VALUES}
    for input_plan in plan_inputs:
        if input_plan.declaration_kind != "family_input":
            continue
        semantic_fields = [
            field for field in input_plan.fields if not field.enriched_descriptor_id.startswith("common:")
        ]
        value_fields = [
            field for field in semantic_fields if field.conversion_op not in {"condition_fact", "mandatory_fact"}
        ]
        if input_plan.symbol.startswith("Log"):
            observed["log"] += len(value_fields)
        elif input_plan.symbol.startswith("Metric"):
            observed["metric"] += len(value_fields)
        elif input_plan.symbol.startswith("Span"):
            resource = [field for field in value_fields if field.selector.startswith("Resource")]
            observed["resource"] += len(resource)
            observed["span"] += len(value_fields) - len(resource)
    if observed != _EXPECTED_CANONICAL_PUBLIC_VALUES:
        raise GoAPIPlanError("canonical public value occurrence counts disagree")
    if len(producer_ids) != 8038:
        raise GoAPIPlanError("canonical expanded producer row count is not 8038")


def _plain_json(value: Any, path: str) -> Any:
    if isinstance(value, Mapping):
        return {_string(key, f"{path}.key"): _plain_json(value[key], f"{path}.{key}") for key in sorted(value)}
    if isinstance(value, tuple):
        return [_plain_json(item, path) for item in value]
    if value is None or type(value) in {str, int, bool}:
        return value
    if isinstance(value, float) and math.isfinite(value):
        return value
    raise GoAPIPlanError(f"{path}: non-JSON or non-finite fixture value")


def _fixture_plans(index: Any, inputs: Sequence[GoInputPlanIR]) -> tuple[GoFixturePlanIR, ...]:
    family_inputs = {item.declaration_source_id: item for item in inputs if item.declaration_kind == "family_input"}
    fixtures: list[GoFixturePlanIR] = []
    seen: set[str] = set()
    for position, raw in enumerate(_sequence(_read(index, "examples", "candidate"), "candidate.examples")):
        path = f"examples[{position}]"
        example_id = _string(_read(raw, "id", path), f"{path}.id")
        if example_id in seen:
            raise GoAPIPlanError("candidate examples contain a duplicate ID")
        seen.add(example_id)
        signal = _string(_read(raw, "signal", path), f"{path}.signal")
        family_id = _optional(raw, "family")
        if family_id is not None and not isinstance(family_id, str):
            raise GoAPIPlanError(f"{path}.family: invalid family ID")
        input_plan = family_inputs.get(family_id or "")
        if family_id is not None and input_plan is None:
            raise GoAPIPlanError(f"{path}: typed family input is missing")
        valid = _read(raw, "valid", path)
        if not isinstance(valid, bool):
            raise GoAPIPlanError(f"{path}.valid: expected Boolean")
        record = _read(raw, "record", path)
        record_plain = _plain_json(record, f"{path}.record")
        expected_error = _optional(raw, "expected_error")
        if expected_error is not None and not isinstance(expected_error, str):
            raise GoAPIPlanError(f"{path}.expected_error: invalid stable error")
        base_example = _optional(raw, "base_example")
        if base_example is not None and not isinstance(base_example, str):
            raise GoAPIPlanError(f"{path}.base_example: invalid fixture base")
        fixtures.append(
            GoFixturePlanIR(
                example_id,
                signal,
                family_id,
                valid,
                ("family_input", family_id) if input_plan is not None else None,
                ("family_builder", family_id) if input_plan is not None else None,
                tuple(
                    (field.selector, field.target_slot, field.semantic_source_id)
                    for field in (input_plan.fields if input_plan is not None else ())
                ),
                _fact_value(_read(raw, "builder_context", path), f"{path}.builder_context"),
                _fact_value(record, f"{path}.record"),
                json.dumps(record_plain, ensure_ascii=False, sort_keys=True, separators=(",", ":")),
                expected_error,
                base_example,
            )
        )
    return tuple(fixtures)


def compile_go_api_plan(index: Any) -> GoAPIPlanIR:
    """Compile one complete immutable Go API plan from enriched candidate facts."""

    materialized_digest = _string(_read(index, "materialized_view_sha256", "candidate"), "materialized view digest")
    if _SHA256.fullmatch(materialized_digest) is None:
        raise GoAPIPlanError("materialized_view_sha256: invalid digest")
    policy = _policy(index)
    rows, symbol_digest = _symbol_table(index)
    symbols = _symbol_index(rows)
    fields = _fields(index)
    structured, structured_inputs, structured_callables, structured_planned = _compile_structured(
        index, policy=policy, symbols=symbols, fields=fields
    )
    family_inputs, family_callables, descriptors, family_planned, family_domains = _compile_families(
        index, policy=policy, symbols=symbols, fields=fields
    )
    planned = structured_planned | family_planned
    expected_nonconstants = {(row.kind, row.source_id) for row in rows if row.declaration_form != "exported_const"}
    if planned != expected_nonconstants:
        raise GoAPIPlanError("Go API plans do not cover every non-constant declaration exactly once")
    assignments = _file_assignments(rows, family_domains)
    declarations = _declaration_plans(index, rows, assignments)
    declarations_by_file = {
        path: tuple(declaration for declaration in declarations if declaration.output_file == path)
        for path in GO_OUTPUT_FILES
    }
    producer_rows = _sequence(_read(index, "expanded_producer_mappings", "candidate"), "expanded_producer_mappings")
    producer_ids = tuple(
        _string(_read(row, "id", f"expanded_producer_mappings[{position}]"), "expanded producer row ID")
        for position, row in enumerate(producer_rows)
    )
    if len(producer_ids) != len(set(producer_ids)):
        raise GoAPIPlanError("expanded_producer_mappings: duplicate row ID")
    inputs = tuple(
        sorted(structured_inputs + family_inputs, key=lambda item: (item.declaration_kind, item.declaration_source_id))
    )
    callables = tuple(
        sorted(
            structured_callables + family_callables,
            key=lambda item: (item.declaration_kind, item.declaration_source_id),
        )
    )
    descriptors = tuple(sorted(descriptors, key=lambda item: item.family_id.encode("ascii")))
    fixtures = _fixture_plans(index, inputs)
    if symbol_digest == _CANONICAL_SYMBOL_TABLE_SHA256:
        _validate_canonical_counts(inputs, producer_ids)
    catalog_descriptor_ids = tuple(item.family_id for item in descriptors) + tuple(
        "structured:" + item.declaration_source_id for item in structured
    )
    files = tuple(
        GoFilePlanIR(
            path=path,
            declaration_keys=assignments[path],
            declarations=declarations_by_file[path],
            private_descriptor_ids=(catalog_descriptor_ids if path == _CATALOG_FILE else ()),
            private_projection_ids=(
                producer_ids
                if path == _PRODUCERS_FILE
                else tuple(fixture.example_id for fixture in fixtures)
                if path == _FIXTURES_FILE
                else ()
            ),
            expected_digest_headers=_DIGEST_HEADERS,
        )
        for path in GO_OUTPUT_FILES
    )
    owned_private_descriptors = [descriptor_id for file in files for descriptor_id in file.private_descriptor_ids]
    if len(owned_private_descriptors) != len(set(owned_private_descriptors)) or set(owned_private_descriptors) != set(
        catalog_descriptor_ids
    ):
        raise GoAPIPlanError("private descriptor definition ownership is duplicated or incomplete")
    plan = GoAPIPlanIR(
        1,
        materialized_digest,
        symbol_digest,
        inputs,
        callables,
        structured,
        descriptors,
        declarations,
        fixtures,
        files,
        "",
    )
    return dataclasses.replace(plan, api_plan_sha256=_plan_digest(plan))


__all__ = [
    "GO_OUTPUT_FILES",
    "GoAPIPlanError",
    "GoAPIPlanIR",
    "GoCallablePlanIR",
    "GoDeclarationPlanIR",
    "GoDescriptorPlanIR",
    "GoFactValueIR",
    "GoFieldPlanIR",
    "GoFilePlanIR",
    "GoFixturePlanIR",
    "GoInputPlanIR",
    "GoKernelFieldDescriptorIR",
    "GoKernelLimitsIR",
    "GoStructuredPlanIR",
    "GoTraceContractPlanIR",
    "GoTypeRefIR",
    "compile_go_api_plan",
]
