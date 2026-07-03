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

from __future__ import annotations

import copy
from dataclasses import FrozenInstanceError
from typing import Any

import pytest
from defenseclaw.observability.v8_compatibility import (
    V7CompatibilityError,
    V7CompatibilitySelection,
    load_v7_compatibility_selection,
)


def _selector(**values: list[str]) -> dict[str, list[str]]:
    return values


def _artifact() -> dict[str, Any]:
    empty_signals = {"logs": [], "traces": [], "metrics": []}
    return {
        "schema_version": 1,
        "source_config_version": 7,
        "registry_schema_version": 3,
        "projection_profile": "legacy-v7",
        "collection": {
            "always": {
                "logs": ["platform.health", "compliance.activity"],
                "traces": [],
                "metrics": [],
            },
            "otel.logs": {
                **empty_signals,
                "logs": ["security.finding", "model.io"],
            },
            "otel.traces": {
                **empty_signals,
                "traces": ["tool.activity", "model.io"],
            },
            "otel.metrics": {
                **empty_signals,
                "metrics": ["platform.health", "model.io"],
            },
        },
        "exporters": {
            "gateway_jsonl": {
                "logs": [_selector(event_names=["platform.health", "config.changed"])],
            },
            "gateway_console": {
                "logs": [_selector(buckets=["platform.health", "compliance.activity"])],
            },
            "audit_sink": {
                "logs": [_selector(sources=["audit"], actions=["scan", "config-update"])],
            },
            "generic_otlp": {
                "logs": [_selector(buckets=["model.io", "security.finding"])],
                "traces": [_selector(event_names=["span.tool.execute", "span.model.chat"])],
                "metrics": [_selector(buckets=["platform.health", "model.io"])],
            },
            "local_observability": {
                "logs": [_selector(buckets=["agent.lifecycle", "platform.health"])],
                "traces": [_selector(event_names=["span.workflow.run", "span.agent.run"])],
                "metrics": [_selector(buckets=["agent.lifecycle", "platform.health"])],
            },
        },
        "features": {
            "otel_individual_findings": [
                _selector(event_names=["finding.observed"], sources=["telemetry.scan"])
            ],
        },
        "span_filter_operations": {
            "execute_tool": {
                "required_attributes": ["gen_ai.tool.name", "gen_ai.operation.name"],
                "selectors": [_selector(event_names=["span.tool.execute"])],
            },
            "chat": {
                "required_attributes": ["gen_ai.request.model", "gen_ai.operation.name"],
                "selectors": [_selector(event_names=["span.model.chat"])],
            },
        },
        "local_observability": {
            "profile_id": "local-observability-v1",
            "complete": True,
        },
    }


def test_valid_narrow_artifact_exposes_exact_immutable_queries() -> None:
    selection = load_v7_compatibility_selection(_artifact())

    assert selection.schema_version == 1
    assert selection.source_config_version == 7
    assert selection.registry_schema_version == 3
    assert selection.projection_profile == "legacy-v7"
    assert selection.collection_buckets("always", "logs") == (
        "compliance.activity",
        "platform.health",
    )
    assert selection.effective_collection(["traces"]) == {
        "logs": ("compliance.activity", "platform.health"),
        "traces": ("model.io", "tool.activity"),
        "metrics": (),
    }
    assert selection.exporter_selectors("audit_sink", "logs")[0].actions == (
        "config-update",
        "scan",
    )
    assert selection.feature_selectors("otel_individual_findings")[0].event_names == (
        "finding.observed",
    )
    assert selection.span_filter_selectors(
        "chat", ["gen_ai.operation.name", "gen_ai.request.model"]
    )[0].event_names == ("span.model.chat",)
    assert selection.local_observability.profile_id == "local-observability-v1"
    assert selection.local_observability.complete is True


def test_artifact_is_detached_deeply_immutable_and_hashable() -> None:
    source = _artifact()
    selection = V7CompatibilitySelection.from_mapping(source)
    source["collection"]["always"]["logs"].append("diagnostic")
    source["exporters"]["audit_sink"]["logs"][0]["actions"].append("block")

    assert "diagnostic" not in selection.collection_buckets("always", "logs")
    assert "block" not in selection.exporter_selectors("audit_sink", "logs")[0].actions
    assert hash(selection)
    with pytest.raises(FrozenInstanceError):
        selection.registry_schema_version = 4  # type: ignore[misc]
    with pytest.raises(TypeError):
        selection.collection["always"] = {}  # type: ignore[index]
    with pytest.raises(TypeError):
        selection.collection["always"]["logs"] = ()  # type: ignore[index]
    with pytest.raises(TypeError):
        selection.exporter_selectors("audit_sink", "logs")[0].actions[0] = "block"  # type: ignore[index]


@pytest.mark.parametrize(
    "mutation",
    [
        lambda value: value.pop("collection"),
        lambda value: value.update({"future_extension": {}}),
        lambda value: value["exporters"].pop("audit_sink"),
        lambda value: value["exporters"]["gateway_jsonl"].update({"traces": []}),
        lambda value: value["exporters"]["audit_sink"]["logs"][0].update(
            {"connectors": ["codex"]}
        ),
        lambda value: value["features"].clear(),
    ],
)
def test_missing_or_unknown_fields_and_exporters_fail_closed(mutation: Any) -> None:
    source = _artifact()
    mutation(source)

    with pytest.raises(V7CompatibilityError):
        load_v7_compatibility_selection(source)


@pytest.mark.parametrize(
    ("path", "value", "code"),
    [
        (("schema_version",), 2, "unsupported_version"),
        (("source_config_version",), 8, "unsupported_version"),
        (("registry_schema_version",), 0, "invalid_registry_version"),
        (("projection_profile",), "none", "invalid_projection_profile"),
        (
            ("local_observability", "profile_id"),
            "future-local-profile",
            "invalid_local_profile",
        ),
        (("local_observability", "complete"), False, "incomplete_local_profile"),
        (
            ("collection", "otel.logs", "traces"),
            ["model.io"],
            "invalid_collection_condition",
        ),
        (
            ("exporters", "generic_otlp", "logs", 0, "event_names"),
            ["*"],
            "invalid_token",
        ),
    ],
)
def test_malformed_metadata_conditions_and_tokens_are_rejected(
    path: tuple[Any, ...], value: Any, code: str
) -> None:
    source = _artifact()
    target: Any = source
    for part in path[:-1]:
        target = target[part]
    target[path[-1]] = value

    with pytest.raises(V7CompatibilityError) as captured:
        load_v7_compatibility_selection(source)
    assert captured.value.code == code


@pytest.mark.parametrize(
    ("path", "value", "code"),
    [
        (
            ("collection", "always", "logs"),
            ["compliance.activity", "compliance.activity"],
            "duplicate_bucket",
        ),
        (
            ("exporters", "audit_sink", "logs", 0, "actions"),
            ["scan", "scan"],
            "duplicate_token",
        ),
        (
            ("span_filter_operations", "chat", "required_attributes"),
            ["gen_ai.operation.name", "gen_ai.operation.name"],
            "duplicate_token",
        ),
    ],
)
def test_duplicate_values_are_rejected(path: tuple[Any, ...], value: Any, code: str) -> None:
    source = _artifact()
    target: Any = source
    for part in path[:-1]:
        target = target[part]
    target[path[-1]] = value

    with pytest.raises(V7CompatibilityError) as captured:
        load_v7_compatibility_selection(source)
    assert captured.value.code == code


def test_semantically_duplicate_selectors_are_rejected_after_canonicalization() -> None:
    source = _artifact()
    source["exporters"]["gateway_jsonl"]["logs"] = [
        _selector(event_names=["config.changed", "platform.health"]),
        _selector(event_names=["platform.health", "config.changed"]),
    ]

    with pytest.raises(V7CompatibilityError) as captured:
        load_v7_compatibility_selection(source)
    assert captured.value.code == "duplicate_selector"


def test_oversize_tokens_and_sequences_are_rejected() -> None:
    oversized_token = "x" * 129
    source = _artifact()
    source["span_filter_operations"]["chat"]["required_attributes"] = [oversized_token]
    with pytest.raises(V7CompatibilityError) as captured:
        load_v7_compatibility_selection(source)
    assert captured.value.code == "invalid_token"

    source = _artifact()
    source["exporters"]["generic_otlp"]["logs"] = [
        _selector(event_names=[f"event.{index}"]) for index in range(513)
    ]
    with pytest.raises(V7CompatibilityError) as captured:
        load_v7_compatibility_selection(source)
    assert captured.value.code == "invalid_selector_count"


def test_errors_and_representations_never_echo_untrusted_values() -> None:
    canary = "do-not-render-secret-canary"
    source = _artifact()
    source[canary] = {"Authorization": canary}
    with pytest.raises(V7CompatibilityError) as captured:
        load_v7_compatibility_selection(source)
    assert canary not in str(captured.value)
    assert canary not in repr(captured.value)

    source = _artifact()
    source["exporters"]["audit_sink"]["logs"][0]["sources"] = [canary]
    selection = load_v7_compatibility_selection(source)
    assert canary not in repr(selection)
    assert canary not in repr(selection.exporter_selectors("audit_sink", "logs")[0])


def test_mapping_and_sequence_order_canonicalize_deterministically() -> None:
    source = _artifact()
    reordered = copy.deepcopy(source)
    reordered["collection"] = dict(reversed(tuple(reordered["collection"].items())))
    reordered["exporters"] = dict(reversed(tuple(reordered["exporters"].items())))
    reordered["span_filter_operations"] = dict(
        reversed(tuple(reordered["span_filter_operations"].items()))
    )
    reordered["collection"]["always"]["logs"].reverse()
    reordered["exporters"]["audit_sink"]["logs"][0]["actions"].reverse()
    reordered["span_filter_operations"]["chat"]["required_attributes"].reverse()

    first = load_v7_compatibility_selection(source)
    second = load_v7_compatibility_selection(reordered)
    assert first == second
    assert hash(first) == hash(second)
    assert repr(first) == repr(second)


def test_queries_fail_closed_for_unknown_or_inexact_generated_predicates() -> None:
    selection = load_v7_compatibility_selection(_artifact())

    with pytest.raises(V7CompatibilityError) as captured:
        selection.exporter_selectors("future_exporter", "logs")
    assert captured.value.code == "unknown_query_key"
    with pytest.raises(V7CompatibilityError) as captured:
        selection.span_filter_selectors("future_operation", [])
    assert captured.value.code == "unmapped_span_filter_operation"
    with pytest.raises(V7CompatibilityError) as captured:
        selection.span_filter_selectors("chat", ["gen_ai.operation.name"])
    assert captured.value.code == "unmapped_span_filter_predicate"
    with pytest.raises(V7CompatibilityError) as captured:
        selection.effective_collection(["logs", "logs"])
    assert captured.value.code == "duplicate_query_value"
