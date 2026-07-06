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
"""Compile closed inbound OTLP descriptors into a private generated-Go plan."""

from __future__ import annotations

import dataclasses
import hashlib
import json
import math
import re
from collections.abc import Mapping, Sequence
from typing import Any, Final


class GoInboundPlanError(RuntimeError):
    """The candidate inbound descriptor set cannot produce safe Go data."""


@dataclasses.dataclass(frozen=True, slots=True)
class GoInboundPredicateIR:
    location: str
    key: str
    operator: str
    values_json: str
    value_type: str


@dataclasses.dataclass(frozen=True, slots=True)
class GoInboundAliasIR:
    id: str
    target: str
    value_type: str
    normalization: str
    sources: tuple[str, ...]
    conflict_policy: str
    absence_policy: str
    field_class: str
    sensitivity: str


@dataclasses.dataclass(frozen=True, slots=True)
class GoInboundTargetOverrideIR:
    source: str
    target: str
    normalization: str


@dataclasses.dataclass(frozen=True, slots=True)
class GoInboundUnitScaleIR:
    source_unit: str
    scale: float


@dataclasses.dataclass(frozen=True, slots=True)
class GoInboundUnitRuleIR:
    kind: str
    target_unit: str
    accepted: tuple[GoInboundUnitScaleIR, ...]


@dataclasses.dataclass(frozen=True, slots=True)
class GoInboundMatchIR:
    id: str
    class_id: str
    signal: str
    sources: tuple[str, ...]
    shape: str
    discriminator_kind: str
    predicates: tuple[GoInboundPredicateIR, ...]
    mapping_strategy: str
    alias_ids: tuple[str, ...]
    target_override: GoInboundTargetOverrideIR | None
    source_unit_rule: GoInboundUnitRuleIR
    target_ids: tuple[str, ...]
    time_rule_json: str
    outcome_rule_json: str
    native_round_trip: bool


@dataclasses.dataclass(frozen=True, slots=True)
class GoInboundTargetIR:
    id: str
    match_id: str
    class_id: str
    signal: str
    role: str
    target_kind: str
    family: str
    bucket: str
    event_name: str
    family_schema_version: int
    instrument_name: str
    instrument_type: str
    instrument_unit: str
    field_refs: tuple[str, ...]
    field_descriptor_ids: tuple[str, ...]
    descriptor_symbol: str
    mapping_strategy: str
    derivation_strategy: str
    time_rule_json: str
    outcome_rule_json: str
    import_context_id: str
    source_unit_rule: GoInboundUnitRuleIR


@dataclasses.dataclass(frozen=True, slots=True)
class GoInboundEchoRecognizerIR:
    id: str
    signal: str
    family: str
    bucket: str
    event_name: str
    instrument_name: str
    forward_placement: str
    compare_self_with: str


@dataclasses.dataclass(frozen=True, slots=True)
class GoInboundNativeMarkerIR:
    id: str
    signal: str
    location: str
    key: str
    marker_kind: str
    values_json: str
    value_type: str


@dataclasses.dataclass(frozen=True, slots=True)
class GoInboundImportContextIR:
    id: str
    family_descriptor_id: str
    bucket: str
    event_name: str
    construction_mode: str
    capabilities: tuple[str, ...]
    descriptor_symbol: str


@dataclasses.dataclass(frozen=True, slots=True)
class GoInboundPlanIR:
    version: int
    materialized_view_sha256: str
    candidate_render_index_sha256: str
    scope_name: str
    scope_schema_url: str
    resource_schema_url: str
    semantic_resource_instance_key: str
    forward_instance_key: str
    forward_destination_key: str
    forward_hop_count_key: str
    record_id_key: str
    max_forward_hops: int
    unknown_fields: str
    native_marker_rule: str
    structural_marker_rule: str
    native_malformed_disposition: str
    native_malformed_external_fallback: str
    aliases: tuple[GoInboundAliasIR, ...]
    matches: tuple[GoInboundMatchIR, ...]
    targets: tuple[GoInboundTargetIR, ...]
    native_markers: tuple[GoInboundNativeMarkerIR, ...]
    echo_recognizers: tuple[GoInboundEchoRecognizerIR, ...]
    import_contexts: tuple[GoInboundImportContextIR, ...]
    projection_ids: tuple[str, ...]
    inbound_plan_sha256: str


_DIGEST_DOMAIN: Final = b"DefenseClaw GoInboundPlanIR v1\x00"
_SHA256: Final = re.compile(r"^[0-9a-f]{64}$")


def _read(value: Any, name: str, path: str) -> Any:
    if not hasattr(value, name):
        raise GoInboundPlanError(f"{path}.{name}: required")
    return getattr(value, name)


def _mapping(value: Any, path: str) -> Mapping[str, Any]:
    if not isinstance(value, Mapping):
        raise GoInboundPlanError(f"{path}: expected mapping")
    return value


def _sequence(value: Any, path: str) -> Sequence[Any]:
    if not isinstance(value, tuple):
        raise GoInboundPlanError(f"{path}: expected immutable sequence")
    return value


def _string(value: Any, path: str, *, empty: bool = False) -> str:
    if not isinstance(value, str) or (not empty and not value):
        raise GoInboundPlanError(f"{path}: expected {'possibly empty ' if empty else 'nonempty '}string")
    return value


def _json(value: Any) -> str:
    def plain(item: Any) -> Any:
        if isinstance(item, Mapping):
            return {key: plain(item[key]) for key in sorted(item)}
        if isinstance(item, tuple):
            return [plain(child) for child in item]
        if item is None or type(item) in {bool, int, float, str}:
            return item
        raise GoInboundPlanError("inbound plan contains unsupported JSON data")

    return json.dumps(plain(value), ensure_ascii=False, sort_keys=True, separators=(",", ":"))


def _unit_rule(value: Any, path: str) -> GoInboundUnitRuleIR:
    item = _mapping(value, path)
    if set(item) != {"kind", "target_unit", "accepted"}:
        raise GoInboundPlanError(f"{path}: invalid source-unit rule shape")
    accepted: list[GoInboundUnitScaleIR] = []
    for position, raw in enumerate(_sequence(item["accepted"], f"{path}.accepted")):
        entry = _mapping(raw, f"{path}.accepted[{position}]")
        if set(entry) != {"source_unit", "scale"}:
            raise GoInboundPlanError(f"{path}.accepted[{position}]: invalid source-unit scale shape")
        source_unit = _string(entry["source_unit"], "source unit", empty=True)
        scale = entry["scale"]
        if type(scale) not in {int, float} or isinstance(scale, bool) or not math.isfinite(float(scale)) or scale <= 0:
            raise GoInboundPlanError(f"{path}.accepted[{position}].scale: invalid source-unit scale")
        accepted.append(GoInboundUnitScaleIR(source_unit, float(scale)))
    return GoInboundUnitRuleIR(
        _string(item["kind"], f"{path}.kind"),
        _string(item["target_unit"], f"{path}.target_unit", empty=True),
        tuple(accepted),
    )


def _digest_payload(value: Any) -> Any:
    if dataclasses.is_dataclass(value) and not isinstance(value, type):
        return {field.name: _digest_payload(getattr(value, field.name)) for field in dataclasses.fields(value)}
    if isinstance(value, Mapping):
        return {key: _digest_payload(value[key]) for key in sorted(value)}
    if isinstance(value, tuple):
        return [_digest_payload(item) for item in value]
    if value is None or type(value) in {bool, int, float, str}:
        return value
    raise GoInboundPlanError("inbound plan digest contains unsupported data")


def compile_go_inbound_plan(index: Any) -> GoInboundPlanIR:
    """Return immutable private Go descriptors from one digest-valid candidate."""

    if type(index).__name__ not in {"CandidateRenderIndex", "_ProvisionalCandidateEnrichment"}:
        raise GoInboundPlanError("inbound plan requires compiler-owned candidate facts")
    materialized = _string(_read(index, "materialized_view_sha256", "CandidateRenderIndex"), "materialized digest")
    if _SHA256.fullmatch(materialized) is None:
        raise GoInboundPlanError("materialized digest is invalid")
    candidate = getattr(index, "candidate_render_index_sha256", None)
    if candidate is None:
        candidate = "0" * 64
    candidate = _string(candidate, "candidate digest")
    if _SHA256.fullmatch(candidate) is None:
        raise GoInboundPlanError("candidate digest is invalid")
    inbound = _read(index, "inbound_otlp", "CandidateRenderIndex")
    api_plan = _read(index, "go_api_plan", "CandidateRenderIndex")
    descriptors_by_family: dict[str, Any] = {}
    for descriptor in _sequence(_read(api_plan, "descriptors", "GoAPIPlanIR"), "GoAPIPlanIR.descriptors"):
        family_id = _string(_read(descriptor, "family_id", "GoDescriptorPlanIR"), "descriptor family ID")
        if family_id in descriptors_by_family:
            raise GoInboundPlanError("generated family descriptor is duplicated")
        descriptors_by_family[family_id] = descriptor

    aliases: list[GoInboundAliasIR] = []
    for position, raw in enumerate(_sequence(_read(inbound, "alias_sets", "inbound"), "inbound.alias_sets")):
        item = _mapping(raw, f"inbound.alias_sets[{position}]")
        contract = _mapping(item["target_field_contract"], "inbound alias field contract")
        aliases.append(
            GoInboundAliasIR(
                _string(item["id"], "alias id"),
                _string(item["target"], "alias target"),
                _string(item["value_type"], "alias value type"),
                _string(item["normalization"], "alias normalization"),
                tuple(_string(source, "alias source") for source in _sequence(item["sources"], "alias sources")),
                _string(item["conflict_policy"], "alias conflict policy"),
                _string(item["absence_policy"], "alias absence policy"),
                _string(contract["field_class"], "alias field class"),
                _string(contract["sensitivity"], "alias sensitivity"),
            )
        )

    matches: list[GoInboundMatchIR] = []
    for position, raw in enumerate(_sequence(_read(inbound, "match_descriptors", "inbound"), "inbound.matches")):
        item = _mapping(raw, f"inbound.matches[{position}]")
        discriminator = _mapping(item["discriminator"], "match discriminator")
        predicates = tuple(
            GoInboundPredicateIR(
                _string(predicate["location"], "predicate location"),
                _string(predicate["key"], "predicate key"),
                _string(predicate["operator"], "predicate operator"),
                _json(predicate["values"]),
                _string(predicate["value_type"], "predicate value type"),
            )
            for predicate in (
                _mapping(value, "predicate") for value in _sequence(discriminator["predicates"], "predicates")
            )
        )
        mapping = _mapping(item["mapping"], "match mapping")
        raw_override = mapping["target_override"]
        target_override = None
        if raw_override is not None:
            override = _mapping(raw_override, "match target override")
            target_override = GoInboundTargetOverrideIR(
                _string(override["source"], "target override source"),
                _string(override["target"], "target override target"),
                _string(override["normalization"], "target override normalization"),
            )
        aliases_for_match = tuple(
            _string(_mapping(alias, "match alias")["id"], "match alias id")
            for alias in _sequence(mapping["alias_sets"], "match aliases")
        )
        matches.append(
            GoInboundMatchIR(
                _string(item["id"], "match id"),
                _string(item["class_id"], "match class id"),
                _string(item["signal"], "match signal"),
                tuple(_string(source, "match source") for source in _sequence(item["sources"], "match sources")),
                _string(item["shape"], "match shape"),
                _string(discriminator["kind"], "discriminator kind"),
                predicates,
                _string(mapping["strategy"], "mapping strategy"),
                aliases_for_match,
                target_override,
                _unit_rule(mapping["source_unit_rule"], "match source-unit rule"),
                tuple(_string(value, "target id") for value in _sequence(item["target_ids"], "target ids")),
                _json(item["time_rule"]),
                _json(item["outcome_rule"]),
                item["native_round_trip"] is True,
            )
        )

    targets: list[GoInboundTargetIR] = []
    for position, raw in enumerate(_sequence(_read(inbound, "target_descriptors", "inbound"), "inbound.targets")):
        item = _mapping(raw, f"inbound.targets[{position}]")
        field_refs = tuple(_string(value, "field ref") for value in _sequence(item["field_refs"], "field refs"))
        field_descriptor_ids = tuple(
            _string(value, "field descriptor ID")
            for value in _sequence(item["field_descriptor_ids"], "field descriptor IDs")
        )
        if len(field_refs) != len(field_descriptor_ids):
            raise GoInboundPlanError("target field refs and descriptor IDs disagree")
        version = item["family_schema_version"]
        if type(version) is not int or version < 1:
            raise GoInboundPlanError("target family schema version is invalid")
        family_id = _string(item["family"], "target family")
        descriptor = descriptors_by_family.get(family_id)
        if descriptor is None:
            raise GoInboundPlanError("target generated family descriptor is missing")
        signal = {"logs": "log", "traces": "span", "metrics": "metric"}.get(item["signal"])
        catalog = _read(descriptor, "catalog_contract", "GoDescriptorPlanIR")
        descriptor_symbol = _string(
            _read(catalog, "descriptor_type_symbol", "GoCatalogContractPlanIR"),
            "generated descriptor symbol",
        )
        metric_catalog = _read(catalog, "metric", "GoCatalogContractPlanIR")
        expected_unit = _read(metric_catalog, "unit", "GoMetricFamilyContractPlanIR") if signal == "metric" else ""
        if (
            signal is None
            or _read(descriptor, "signal", "GoDescriptorPlanIR") != signal
            or _read(descriptor, "identity_bucket", "GoDescriptorPlanIR") != item["bucket"]
            or _read(descriptor, "identity_name", "GoDescriptorPlanIR") != item["event_name"]
            or (signal == "metric" and item["instrument_name"] != item["event_name"])
            or (signal != "metric" and item["instrument_name"] is not None)
            or (item["instrument_unit"] or "") != expected_unit
            or _read(descriptor, "family_schema_version", "GoDescriptorPlanIR") != version
            or tuple(_read(descriptor, "enriched_field_descriptor_ids", "GoDescriptorPlanIR")) != field_descriptor_ids
        ):
            raise GoInboundPlanError("target disagrees with generated family descriptor")
        targets.append(
            GoInboundTargetIR(
                _string(item["id"], "target id"),
                _string(item["match_id"], "target match id"),
                _string(item["class_id"], "target class id"),
                _string(item["signal"], "target signal"),
                _string(item["role"], "target role"),
                _string(item["target_kind"], "target kind"),
                family_id,
                _string(item["bucket"], "target bucket"),
                _string(item["event_name"], "target event name"),
                version,
                _string(item["instrument_name"] or "", "target instrument", empty=True),
                _string(item["instrument_type"] or "", "target instrument type", empty=True),
                _string(item["instrument_unit"] or "", "target instrument unit", empty=True),
                field_refs,
                field_descriptor_ids,
                descriptor_symbol,
                _string(item["mapping_strategy"], "target mapping strategy"),
                _string(item["derivation_strategy"] or "", "derivation strategy", empty=True),
                _json(item["time_rule"]),
                _json(item["outcome_rule"]),
                _string(item["import_context_id"] or "", "import context id", empty=True),
                _unit_rule(item["source_unit_rule"], "target source-unit rule"),
            )
        )

    native_markers = tuple(
        GoInboundNativeMarkerIR(
            _string(item["id"], "native marker id"),
            _string(item["signal"], "native marker signal"),
            _string(item["location"], "native marker location"),
            _string(item["key"], "native marker key"),
            _string(item["marker_kind"], "native marker kind"),
            _json(item["values"]),
            _string(item["value_type"], "native marker value type"),
        )
        for item in (
            _mapping(value, "native marker")
            for value in _sequence(_read(inbound, "native_markers", "inbound"), "inbound native markers")
        )
    )
    echoes = tuple(
        GoInboundEchoRecognizerIR(
            _string(item["id"], "echo id"),
            _string(item["signal"], "echo signal"),
            _string(item["family"], "echo family"),
            _string(item["bucket"], "echo bucket"),
            _string(item["event_name"], "echo event name"),
            _string(item["instrument_name"] or "", "echo instrument", empty=True),
            _string(item["forward_placement"], "echo forward placement"),
            _string(item["compare_self_with"], "echo self key"),
        )
        for item in (
            _mapping(value, "echo recognizer")
            for value in _sequence(_read(inbound, "echo_recognizers", "inbound"), "inbound echoes")
        )
    )
    context_rows: list[GoInboundImportContextIR] = []
    for value in _sequence(_read(inbound, "import_contexts", "inbound"), "inbound contexts"):
        item = _mapping(value, "import context")
        family_id = _string(item["family_descriptor_id"], "context family")
        descriptor = descriptors_by_family.get(family_id)
        if (
            descriptor is None
            or _read(descriptor, "signal", "GoDescriptorPlanIR") != "log"
            or _read(descriptor, "identity_bucket", "GoDescriptorPlanIR") != item["bucket"]
            or _read(descriptor, "identity_name", "GoDescriptorPlanIR") != item["event_name"]
        ):
            raise GoInboundPlanError("import context disagrees with generated log descriptor")
        catalog = _read(descriptor, "catalog_contract", "GoDescriptorPlanIR")
        context_rows.append(
            GoInboundImportContextIR(
                _string(item["id"], "context id"),
                family_id,
                _string(item["bucket"], "context bucket"),
                _string(item["event_name"], "context event"),
                _string(item["construction_mode"], "context mode"),
                tuple(
                    _string(capability, "context capability")
                    for capability in _sequence(item["capabilities"], "capabilities")
                ),
                _string(
                    _read(catalog, "descriptor_type_symbol", "GoCatalogContractPlanIR"),
                    "context descriptor symbol",
                ),
            )
        )
    contexts = tuple(context_rows)
    projection_ids = tuple(
        [f"inbound:alias:{item.id}" for item in aliases]
        + [f"inbound:match:{item.id}" for item in matches]
        + [f"inbound:target:{item.id}" for item in targets]
        + [f"inbound:marker:{item.id}" for item in native_markers]
        + [f"inbound:echo:{item.id}" for item in echoes]
        + [f"inbound:context:{item.id}" for item in contexts]
    )
    if len(projection_ids) != len(set(projection_ids)):
        raise GoInboundPlanError("inbound projection IDs are duplicated")
    shape_policy = _mapping(_read(inbound, "shape_policy", "inbound"), "inbound shape policy")
    plan_without_digest = GoInboundPlanIR(
        1,
        materialized,
        candidate,
        _string(_read(inbound, "scope_name", "inbound"), "scope name"),
        _string(_read(inbound, "scope_schema_url", "inbound"), "scope schema URL"),
        _string(_read(inbound, "resource_schema_url", "inbound"), "resource schema URL"),
        _string(_read(inbound, "semantic_resource_instance_key", "inbound"), "semantic instance key"),
        _string(_read(inbound, "forward_instance_key", "inbound"), "forward instance key"),
        _string(_read(inbound, "forward_destination_key", "inbound"), "forward destination key"),
        _string(_read(inbound, "forward_hop_count_key", "inbound"), "forward hop key"),
        _string(_read(inbound, "record_id_key", "inbound"), "record id key"),
        _read(inbound, "max_forward_hops", "inbound"),
        _string(_read(inbound, "unknown_fields", "inbound"), "unknown field policy"),
        _string(shape_policy["native_marker_rule"], "native marker rule"),
        _string(shape_policy["structural_marker_rule"], "structural marker rule"),
        _string(shape_policy["native_malformed_disposition"], "native malformed disposition"),
        _string(shape_policy["native_malformed_external_fallback"], "native fallback policy"),
        tuple(aliases),
        tuple(matches),
        tuple(targets),
        native_markers,
        echoes,
        contexts,
        projection_ids,
        "",
    )
    payload = _digest_payload(plan_without_digest)
    payload["inbound_plan_sha256"] = ""
    digest = hashlib.sha256(
        _DIGEST_DOMAIN + json.dumps(payload, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")
    ).hexdigest()
    return dataclasses.replace(plan_without_digest, inbound_plan_sha256=digest)


__all__ = ["GoInboundPlanError", "GoInboundPlanIR", "compile_go_inbound_plan"]
