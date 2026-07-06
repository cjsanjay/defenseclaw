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

"""Operator-safe observability-v8 status derived from the canonical plan.

The Go compiler owns defaults, destination capabilities, generated routes,
bucket membership, and effective redaction.  This module deliberately only
normalizes its masked effective-plan wire response into a small immutable view
shared by CLI/doctor/TUI renderers.  It never reads destination credentials and
never attempts to compile policy independently.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from defenseclaw.config_inspect import inspect_v8_config
from defenseclaw.observability.v8_config import V8ConfigError, load_validate_v8

_SIGNALS = ("logs", "traces", "metrics")


@dataclass(frozen=True)
class V8DestinationStatus:
    """One destination's effective, secret-free routing policy."""

    name: str
    kind: str
    enabled: bool
    generated: bool
    capabilities: tuple[str, ...]
    selected_signals: tuple[str, ...]
    policy_form: str
    endpoint: str
    route_count: int
    buckets: tuple[str, ...]
    redaction_profiles: tuple[str, ...]

    @property
    def redaction_label(self) -> str:
        if not self.redaction_profiles:
            return "not-applicable"
        if self.redaction_profiles == ("none",):
            return "unredacted (none)"
        if "none" in self.redaction_profiles:
            return "mixed: " + ", ".join(self.redaction_profiles)
        return "redacted: " + ", ".join(self.redaction_profiles)


@dataclass(frozen=True)
class V8BucketStatus:
    """One catalog bucket's effective collection and local profile."""

    name: str
    collected_signals: tuple[str, ...]
    redaction_profile: str


@dataclass(frozen=True)
class V8OperatorStatus:
    """Complete operator-facing policy snapshot for one plan digest."""

    source: str
    data_dir: str
    plan_digest: str
    bucket_catalog_version: int
    retention_days: int
    local_path: str
    judge_bodies_path: str
    destinations: tuple[V8DestinationStatus, ...]
    buckets: tuple[V8BucketStatus, ...]
    warnings: tuple[tuple[str, str, str], ...]

    @property
    def unbounded_retention(self) -> bool:
        return self.retention_days == 0


def source_is_v8(config_path: str | Path) -> bool:
    """Return whether ``config_path`` is a valid exact-v8 source.

    Invalid v8 documents are not misclassified as v7: only the canonical
    ``exact-version`` diagnostic means "not v8".  Every other strict parse or
    schema error is re-raised for the caller to report.
    """

    path = Path(config_path)
    try:
        source = path.read_bytes()
    except OSError:
        return False
    try:
        load_validate_v8(source, source_name=str(path))
    except V8ConfigError as exc:
        if exc.path == "$.config_version" and exc.keyword == "exact-version":
            return False
        raise
    return True


def inspect_v8_operator_status(config_path: str | Path) -> V8OperatorStatus:
    """Load one masked canonical effective plan and normalize its status."""

    result = inspect_v8_config("effective", config_path=str(config_path))
    if result.effective is None:  # defensive; the wire decoder already checks
        raise ValueError("canonical v8 effective plan is missing")
    return operator_status_from_effective(
        result.effective,
        source=result.source,
        data_dir=result.data_dir,
        plan_digest=result.plan_digest,
    )


def operator_status_from_effective(
    effective: Mapping[str, Any],
    *,
    source: str,
    data_dir: str,
    plan_digest: str,
) -> V8OperatorStatus:
    """Normalize a decoded canonical effective plan without adding policy."""

    raw_buckets = _mapping_sequence(effective.get("buckets"), "buckets")
    bucket_names = tuple(_required_string(item, "bucket") for item in raw_buckets)
    buckets = tuple(_bucket_status(item) for item in raw_buckets)
    destinations = tuple(
        _destination_status(item, bucket_names)
        for item in _mapping_sequence(effective.get("destinations"), "destinations")
    )
    local = _mapping(effective.get("local"), "local")
    retention_days = _required_integer(local, "retention_days", minimum=0)
    catalog_version = _required_integer(effective, "bucket_catalog_version", minimum=1)
    warnings = tuple(
        (
            _required_string(item, "code"),
            _required_string(item, "path"),
            _required_string(item, "summary"),
        )
        for item in _mapping_sequence(effective.get("warnings") or [], "warnings")
    )
    return V8OperatorStatus(
        source=source,
        data_dir=data_dir,
        plan_digest=plan_digest,
        bucket_catalog_version=catalog_version,
        retention_days=retention_days,
        local_path=_optional_string(local.get("path")),
        judge_bodies_path=_optional_string(local.get("judge_bodies_path")),
        destinations=destinations,
        buckets=buckets,
        warnings=warnings,
    )


def _bucket_status(item: Mapping[str, Any]) -> V8BucketStatus:
    collect = _mapping(item.get("collect"), "bucket.collect")
    selected = tuple(signal for signal in _SIGNALS if collect.get(signal) is True)
    for signal in _SIGNALS:
        if type(collect.get(signal)) is not bool:
            raise ValueError(f"canonical effective bucket has invalid collect.{signal}")
    return V8BucketStatus(
        name=_required_string(item, "bucket"),
        collected_signals=selected,
        redaction_profile=_required_string(item, "redaction_profile"),
    )


def _destination_status(
    item: Mapping[str, Any],
    all_buckets: tuple[str, ...],
) -> V8DestinationStatus:
    capabilities = _mapping(item.get("capabilities"), "destination.capabilities")
    capability_signals = _string_sequence(capabilities.get("signals"), "destination.capabilities.signals")
    selected_signals = _string_sequence(item.get("selected_signals"), "destination.selected_signals")
    routes = _mapping_sequence(item.get("routes"), "destination.routes")

    selected_buckets: set[str] = set()
    profiles: set[str] = set()
    for route in routes:
        if _required_string(route, "action") != "send":
            continue
        selector = _mapping(route.get("selector"), "destination.route.selector")
        if selector.get("bucket_wildcard") is True:
            selected_buckets.update(all_buckets)
        else:
            selected_buckets.update(_string_sequence(selector.get("buckets"), "destination.route.selector.buckets"))
        by_bucket = route.get("redaction_profile_by_bucket")
        if by_bucket is None:
            continue
        profile_map = _mapping(by_bucket, "destination.route.redaction_profile_by_bucket")
        for profile in profile_map.values():
            profiles.add(_required_scalar_string(profile, "destination route redaction profile"))

    transport = _mapping(item.get("transport", {}), "destination.transport")
    endpoint = _optional_string(transport.get("endpoint")) or _optional_string(transport.get("path"))
    return V8DestinationStatus(
        name=_required_string(item, "name"),
        kind=_required_string(item, "kind"),
        enabled=_required_boolean(item, "enabled"),
        generated=_required_boolean(item, "generated"),
        capabilities=capability_signals,
        selected_signals=selected_signals,
        policy_form=_required_string(item, "policy_form"),
        endpoint=endpoint,
        route_count=len(routes),
        buckets=tuple(name for name in all_buckets if name in selected_buckets),
        redaction_profiles=tuple(sorted(profiles)),
    )


def _mapping(value: Any, label: str) -> Mapping[str, Any]:
    if not isinstance(value, Mapping):
        raise ValueError(f"canonical effective {label} is invalid")
    return value


def _mapping_sequence(value: Any, label: str) -> tuple[Mapping[str, Any], ...]:
    if not isinstance(value, Sequence) or isinstance(value, (str, bytes, bytearray)):
        raise ValueError(f"canonical effective {label} is invalid")
    result: list[Mapping[str, Any]] = []
    for item in value:
        result.append(_mapping(item, label))
    return tuple(result)


def _string_sequence(value: Any, label: str) -> tuple[str, ...]:
    if value is None:
        return ()
    if not isinstance(value, Sequence) or isinstance(value, (str, bytes, bytearray)):
        raise ValueError(f"canonical effective {label} is invalid")
    result: list[str] = []
    for item in value:
        result.append(_required_scalar_string(item, label))
    return tuple(result)


def _required_string(value: Mapping[str, Any], field: str) -> str:
    return _required_scalar_string(value.get(field), field)


def _required_scalar_string(value: Any, label: str) -> str:
    if not isinstance(value, str) or not value:
        raise ValueError(f"canonical effective {label} is invalid")
    return value


def _optional_string(value: Any) -> str:
    if value is None:
        return ""
    if not isinstance(value, str):
        raise ValueError("canonical effective optional string is invalid")
    return value


def _required_boolean(value: Mapping[str, Any], field: str) -> bool:
    result = value.get(field)
    if type(result) is not bool:
        raise ValueError(f"canonical effective {field} is invalid")
    return result


def _required_integer(value: Mapping[str, Any], field: str, *, minimum: int) -> int:
    result = value.get(field)
    if type(result) is not int or result < minimum:
        raise ValueError(f"canonical effective {field} is invalid")
    return result


__all__ = [
    "V8BucketStatus",
    "V8DestinationStatus",
    "V8OperatorStatus",
    "inspect_v8_operator_status",
    "operator_status_from_effective",
    "source_is_v8",
]
