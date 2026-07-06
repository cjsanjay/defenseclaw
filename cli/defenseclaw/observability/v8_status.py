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

import re
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Any

from defenseclaw.config_inspect import inspect_v8_config
from defenseclaw.observability.display import redact_endpoint_for_display
from defenseclaw.observability.v8_config import V8ConfigError, load_validate_v8

_SIGNALS = ("logs", "traces", "metrics")
_DESTINATION_HEALTH_STATES = frozenset(
    ("disabled", "initializing", "healthy", "degraded", "failing", "draining", "stopped")
)
_SAFE_HEALTH_TOKEN = re.compile(r"^[a-z0-9][a-z0-9_.:-]{0,127}$")


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
class V8DestinationHealth:
    """One content-free live destination-health snapshot.

    The gateway health contract is allowed to evolve additively, so the
    presentation layer accepts both the current transition-shaped payload and
    the planned per-destination list.  It deliberately ignores arbitrary
    ``last_error`` text, headers, response bodies, and endpoint fields: only
    closed state/reason/error tokens, non-negative counters, and valid
    timestamps may cross this boundary.
    """

    name: str
    state: str = ""
    reason: str = ""
    queue_items: int | None = None
    queue_bytes: int | None = None
    queue_max_items: int | None = None
    queue_max_bytes: int | None = None
    dropped: int | None = None
    last_success: str = ""
    last_failure: str = ""
    last_error_class: str = ""

    @property
    def queue_label(self) -> str:
        parts: list[str] = []
        if self.queue_items is not None:
            value = str(self.queue_items)
            if self.queue_max_items is not None:
                value += f"/{self.queue_max_items} items"
            else:
                value += " items"
            parts.append(value)
        if self.queue_bytes is not None:
            value = _format_bytes(self.queue_bytes)
            if self.queue_max_bytes is not None:
                value += f"/{_format_bytes(self.queue_max_bytes)}"
            parts.append(value)
        if self.dropped is not None:
            parts.append(f"{self.dropped} dropped")
        return ", ".join(parts) or "unavailable"

    @property
    def activity_label(self) -> str:
        parts: list[str] = []
        if self.last_success:
            parts.append(f"ok {self.last_success}")
        if self.last_failure:
            failure = f"error {self.last_failure}"
            if self.last_error_class:
                failure += f" ({self.last_error_class})"
            parts.append(failure)
        elif self.last_error_class:
            parts.append(f"error {self.last_error_class}")
        return "; ".join(parts) or "unavailable"


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
    judge_bodies_enabled: bool = True

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

    path = Path(config_path)
    validated = load_validate_v8(path.read_bytes(), source_name=str(path)).source
    guardrail = validated.get("guardrail")
    retain_judge_bodies = True
    if isinstance(guardrail, Mapping) and "retain_judge_bodies" in guardrail:
        retain_judge_bodies = guardrail["retain_judge_bodies"] is True
    result = inspect_v8_config("effective", config_path=str(path))
    if result.effective is None:  # defensive; the wire decoder already checks
        raise ValueError("canonical v8 effective plan is missing")
    return operator_status_from_effective(
        result.effective,
        source=result.source,
        data_dir=result.data_dir,
        plan_digest=result.plan_digest,
        judge_bodies_enabled=retain_judge_bodies,
    )


def operator_status_from_effective(
    effective: Mapping[str, Any],
    *,
    source: str,
    data_dir: str,
    plan_digest: str,
    judge_bodies_enabled: bool = True,
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
        judge_bodies_enabled=judge_bodies_enabled,
    )


def destination_health_from_gateway(health: Mapping[str, Any] | None) -> dict[str, V8DestinationHealth]:
    """Extract secret-safe v8 destination health from a gateway snapshot.

    A missing field remains missing.  In particular, an aggregate telemetry
    state is never promoted into a destination state and delivery counters are
    never reinterpreted as queue depth or timestamps.
    """

    if not isinstance(health, Mapping):
        return {}
    telemetry: Any = health.get("telemetry", health)
    if isinstance(telemetry, Mapping) and "details" in telemetry:
        details = telemetry.get("details")
    else:
        details = telemetry
    if not isinstance(details, Mapping):
        return {}

    candidates: list[Mapping[str, Any]] = []
    raw_destinations = details.get("destinations")
    if isinstance(raw_destinations, Sequence) and not isinstance(raw_destinations, (str, bytes, bytearray)):
        candidates.extend(item for item in raw_destinations if isinstance(item, Mapping))
    if details.get("destination"):
        candidates.append(details)

    result: dict[str, V8DestinationHealth] = {}
    for item in candidates:
        name = item.get("name") or item.get("destination")
        if not isinstance(name, str) or not name or len(name) > 64:
            continue
        queue = item.get("queue") if isinstance(item.get("queue"), Mapping) else {}
        counters = item.get("counters") if isinstance(item.get("counters"), Mapping) else {}
        delivery = item.get("delivery") if isinstance(item.get("delivery"), Mapping) else {}
        state = _safe_health_state(item.get("health_state", item.get("state")))
        reason = _safe_health_token(item.get("reason"))
        last_error_class = ""
        for key in ("last_error_class", "last_error_code", "error_code", "failure", "warning"):
            last_error_class = _safe_health_token(item.get(key))
            if last_error_class:
                break
        raw_delivery_error = delivery.get("last_error")
        delivery_failed = isinstance(raw_delivery_error, str) and bool(
            raw_delivery_error.strip()
        )
        if not last_error_class and delivery_failed:
            last_error_class = "details_redacted"
        last_success = _safe_timestamp(
            item.get("last_success", item.get("last_success_at"))
        ) or _safe_timestamp(delivery.get("last_success_at"))
        last_failure = _safe_timestamp(
            item.get("last_failure", item.get("last_failure_at"))
        )
        if not last_failure and delivery_failed:
            # The legacy provider clears last_error on success. A non-empty
            # last_error therefore proves that its last_attempt_at was the
            # failed attempt; the raw error itself remains discarded.
            last_failure = _safe_timestamp(delivery.get("last_attempt_at"))
        result[name] = V8DestinationHealth(
            name=name,
            state=state,
            reason=reason,
            queue_items=_nonnegative_int(queue.get("items", item.get("queue_items"))),
            queue_bytes=_nonnegative_int(queue.get("bytes", item.get("queue_bytes"))),
            queue_max_items=_nonnegative_int(
                queue.get("max_items", item.get("queue_max_items", item.get("max_queue_items")))
            ),
            queue_max_bytes=_nonnegative_int(
                queue.get("max_bytes", item.get("queue_max_bytes", item.get("max_queue_bytes")))
            ),
            dropped=_nonnegative_int(queue.get("dropped", item.get("queue_dropped", counters.get("dropped")))),
            last_success=last_success,
            last_failure=last_failure,
            last_error_class=last_error_class,
        )
    return result


def retention_health_from_gateway(health: Mapping[str, Any] | None) -> tuple[str, str]:
    """Return the bounded retention controller state/failure, if published."""

    if not isinstance(health, Mapping):
        return "", ""
    telemetry: Any = health.get("telemetry", health)
    details = telemetry.get("details") if isinstance(telemetry, Mapping) else None
    if not isinstance(details, Mapping):
        return "", ""
    state = _safe_health_token(details.get("retention_state"))
    if state not in {
        "waiting_for_readiness",
        "healthy",
        "degraded",
        "disabled",
        "stopped",
    }:
        state = ""
    if not state:
        return "", ""
    failure = _safe_health_token(details.get("retention_failure", details.get("failure")))
    return state, failure


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
    remote_endpoint = _optional_string(transport.get("endpoint"))
    endpoint = (
        redact_endpoint_for_display(remote_endpoint) if remote_endpoint else _optional_string(transport.get("path"))
    )
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


def _safe_health_state(value: Any) -> str:
    if not isinstance(value, str):
        return ""
    normalized = value.strip().lower()
    return normalized if normalized in _DESTINATION_HEALTH_STATES else ""


def _safe_health_token(value: Any) -> str:
    if not isinstance(value, str):
        return ""
    normalized = value.strip().lower()
    return normalized if _SAFE_HEALTH_TOKEN.fullmatch(normalized) else ""


def _nonnegative_int(value: Any) -> int | None:
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        return None
    return value


def _safe_timestamp(value: Any) -> str:
    if not isinstance(value, str) or not value or len(value) > 64:
        return ""
    normalized = value.strip()
    try:
        parsed = datetime.fromisoformat(normalized.replace("Z", "+00:00"))
    except ValueError:
        return ""
    if parsed.tzinfo is None or parsed.year <= 1:
        return ""
    return normalized


def _format_bytes(value: int) -> str:
    if value < 1_024:
        return f"{value} B"
    if value < 1_024 * 1_024:
        return f"{value / 1_024:.1f} KiB"
    return f"{value / (1_024 * 1_024):.1f} MiB"


__all__ = [
    "V8BucketStatus",
    "V8DestinationHealth",
    "V8DestinationStatus",
    "V8OperatorStatus",
    "destination_health_from_gateway",
    "inspect_v8_operator_status",
    "operator_status_from_effective",
    "retention_health_from_gateway",
    "source_is_v8",
]
