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

"""Read-only renderers for routes already compiled by the Go v8 planner."""

from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Any

import click

from defenseclaw import config as config_module
from defenseclaw.config_inspect import ConfigInspectError, inspect_v8_config

_BUCKETS = (
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
)
_SIGNALS = ("logs", "traces", "metrics")
_SEVERITY_RANK = {"INFO": 1, "LOW": 2, "MEDIUM": 3, "HIGH": 4, "CRITICAL": 5}


@dataclass(frozen=True)
class _PlanFilters:
    connector: str = ""
    source: str = ""
    action: str = ""
    event_name: str = ""
    severity: str = ""


@click.group("observability")
def observability_cmd() -> None:
    """Inspect canonical observability collection and routing policy."""


@observability_cmd.command("plan")
@click.option("--bucket", "buckets", multiple=True, type=click.Choice(_BUCKETS), help="Limit bucket rows.")
@click.option("--signal", "signals", multiple=True, type=click.Choice(_SIGNALS), help="Limit signal rows.")
@click.option("--connector", default="", help="Evaluate connector-constrained routes.")
@click.option("--source", default="", help="Evaluate source-constrained routes.")
@click.option("--action", default="", help="Evaluate action-constrained routes.")
@click.option("--event-name", default="", help="Evaluate event-name-constrained routes.")
@click.option(
    "--severity",
    type=click.Choice(tuple(_SEVERITY_RANK), case_sensitive=False),
    default=None,
    help="Evaluate minimum-severity route constraints.",
)
@click.option("--format", "fmt", type=click.Choice(["table", "json"]), default="table", show_default=True)
def observability_plan(
    buckets: tuple[str, ...],
    signals: tuple[str, ...],
    connector: str,
    source: str,
    action: str,
    event_name: str,
    severity: str | None,
    fmt: str,
) -> None:
    """Render collection and first-route outcomes from the compiled Go plan."""

    try:
        inspected = inspect_v8_config(
            "effective",
            config_path=str(config_module.config_path()),
        )
    except ConfigInspectError as exc:
        raise click.ClickException(str(exc)) from exc
    effective = inspected.effective or {}
    filters = _PlanFilters(
        connector=connector.strip(),
        source=source.strip(),
        action=action.strip(),
        event_name=event_name.strip(),
        severity=severity.upper() if severity else "",
    )
    rows = _plan_rows(
        effective,
        selected_buckets=set(buckets),
        selected_signals=set(signals),
        filters=filters,
    )
    delivery = _delivery_settings(effective)
    if fmt == "json":
        click.echo(
            json.dumps(
                {
                    "basis": "canonical_go_compiled_routes",
                    "config_version": inspected.config_version,
                    "plan_digest": inspected.plan_digest,
                    "network_validation": inspected.network_validation,
                    "delivery": delivery,
                    "rows": rows,
                },
                indent=2,
                sort_keys=True,
            )
        )
    else:
        _render_plan_table(rows, inspected.plan_digest, delivery)
    for warning in effective.get("warnings") or []:
        if isinstance(warning, dict):
            code = str(warning.get("code") or "warning")
            summary = str(warning.get("summary") or "configuration warning")
            click.echo(f"warning: {code}: {summary}", err=True)


def _plan_rows(
    effective: dict[str, Any],
    *,
    selected_buckets: set[str],
    selected_signals: set[str],
    filters: _PlanFilters,
) -> list[dict[str, Any]]:
    destinations = [item for item in effective.get("destinations") or [] if isinstance(item, dict)]
    rows: list[dict[str, Any]] = []
    for bucket_policy in effective.get("buckets") or []:
        if not isinstance(bucket_policy, dict):
            continue
        bucket = str(bucket_policy.get("bucket") or "")
        if selected_buckets and bucket not in selected_buckets:
            continue
        collect = bucket_policy.get("collect") if isinstance(bucket_policy.get("collect"), dict) else {}
        for signal in _SIGNALS:
            if selected_signals and signal not in selected_signals:
                continue
            collected = bool(collect.get(signal, False))
            for destination in destinations:
                rows.append(_destination_row(bucket, signal, collected, destination, filters))
    return rows


def _destination_row(
    bucket: str,
    signal: str,
    collected: bool,
    destination: dict[str, Any],
    filters: _PlanFilters,
) -> dict[str, Any]:
    name = str(destination.get("name") or "")
    result: dict[str, Any] = {
        "bucket": bucket,
        "signal": signal,
        "collected": collected,
        "destination": name,
        "decision": "unmatched",
        "route": None,
        "redaction_profile": None,
    }
    if not destination.get("enabled", False):
        result["decision"] = "destination_disabled"
        return result
    if signal not in (destination.get("selected_signals") or []):
        result["decision"] = "signal_not_selected"
        return result
    if not collected:
        floor_route = _destination_floor_route(destination) if name == "local-sqlite" else None
        if signal == "logs" and floor_route is not None:
            # The effective plan deliberately identifies the floor route but
            # does not duplicate the event-level floor catalog.  Do not claim
            # an exact event match that the Python renderer cannot prove.
            result["decision"] = "conditional"
            result["potential_action"] = "floor_only"
            result["condition"] = "mandatory_floor_event_qualification"
            result["route"] = floor_route
        else:
            result["decision"] = "not_collected"
        return result

    for route in destination.get("routes") or []:
        if not isinstance(route, dict):
            continue
        match = _route_match(route, bucket, signal, filters)
        if match == "no":
            continue
        result["route"] = route.get("name") or None
        if match == "conditional":
            result["decision"] = "conditional"
            result["potential_action"] = route.get("action") or "send"
            return result
        action = str(route.get("action") or "send")
        result["decision"] = action
        if action == "send" and signal in {"logs", "traces"}:
            profiles = route.get("redaction_profile_by_bucket")
            if isinstance(profiles, dict):
                result["redaction_profile"] = profiles.get(bucket)
        return result
    return result


def _route_match(route: dict[str, Any], bucket: str, signal: str, filters: _PlanFilters) -> str:
    if signal not in (route.get("signals") or []):
        return "no"
    selector = route.get("selector") if isinstance(route.get("selector"), dict) else {}
    route_buckets = selector.get("buckets") or []
    if route_buckets and bucket not in route_buckets:
        return "no"

    conditional = False
    dimensions = (
        ("sources", filters.source),
        ("connectors", filters.connector),
        ("actions", filters.action),
        ("event_names", filters.event_name),
    )
    for field, provided in dimensions:
        expected = selector.get(field) or []
        if not expected or "*" in expected:
            continue
        if not provided:
            conditional = True
        elif provided not in expected:
            return "no"

    minimum = str(selector.get("min_severity") or "").upper()
    if minimum:
        if not filters.severity:
            conditional = True
        elif _SEVERITY_RANK.get(filters.severity, 0) < _SEVERITY_RANK.get(minimum, 0):
            return "no"
    return "conditional" if conditional else "match"


def _destination_floor_route(destination: dict[str, Any]) -> str | None:
    for route in destination.get("routes") or []:
        if isinstance(route, dict) and route.get("includes_mandatory_floor") is True:
            return str(route.get("name") or "") or None
    return None


def _delivery_settings(effective: dict[str, Any]) -> list[dict[str, Any]]:
    """Project compiled queue/batch values without deriving defaults in Python."""

    result: list[dict[str, Any]] = []
    for destination in effective.get("destinations") or []:
        if not isinstance(destination, dict):
            continue
        transport = destination.get("transport")
        if not isinstance(transport, dict):
            continue
        batch = transport.get("batch")
        if not isinstance(batch, dict):
            continue
        result.append(
            {
                "destination": str(destination.get("name") or ""),
                "kind": str(destination.get("kind") or ""),
                "max_queue_size": batch.get("max_queue_size"),
                "max_queue_bytes": batch.get("max_queue_bytes"),
                "max_export_batch_size": batch.get("max_export_batch_size"),
                "max_export_batch_bytes": batch.get("max_export_batch_bytes"),
                "scheduled_delay_ms": batch.get("scheduled_delay_ms"),
            }
        )
    return result


def _render_plan_table(rows: list[dict[str, Any]], digest: str, delivery: list[dict[str, Any]]) -> None:
    click.echo(f"Compiled Go plan digest: {digest}")
    headings = ("BUCKET", "SIGNAL", "COLLECT", "DESTINATION", "DECISION", "ROUTE", "REDACTION")
    values = [
        (
            row["bucket"],
            row["signal"],
            "yes"
            if row["collected"]
            else (
                "floor?" if row["decision"] == "conditional" and row.get("potential_action") == "floor_only" else "no"
            ),
            row["destination"],
            row["decision"],
            row["route"] or "-",
            row["redaction_profile"] or "-",
        )
        for row in rows
    ]
    widths = [len(value) for value in headings]
    for row in values:
        for index, value in enumerate(row):
            widths[index] = max(widths[index], len(str(value)))
    click.echo("  ".join(value.ljust(widths[index]) for index, value in enumerate(headings)))
    for row in values:
        click.echo("  ".join(str(value).ljust(widths[index]) for index, value in enumerate(row)))
    if any(row["decision"] == "conditional" for row in rows):
        click.echo("conditional = an earlier route constrains metadata not supplied by the current filters")
    if delivery:
        click.echo("Delivery limits (compiled defaults and source overrides):")
        delivery_headings = (
            "DESTINATION",
            "KIND",
            "QUEUE_RECORDS",
            "QUEUE_BYTES",
            "BATCH_RECORDS",
            "BATCH_BYTES",
            "DELAY_MS",
        )
        delivery_values = [
            (
                item["destination"],
                item["kind"],
                item["max_queue_size"],
                item["max_queue_bytes"],
                item["max_export_batch_size"] or "-",
                item["max_export_batch_bytes"] or "-",
                item["scheduled_delay_ms"] or "-",
            )
            for item in delivery
        ]
        delivery_widths = [len(value) for value in delivery_headings]
        for row in delivery_values:
            for index, value in enumerate(row):
                delivery_widths[index] = max(delivery_widths[index], len(str(value)))
        click.echo("  ".join(value.ljust(delivery_widths[index]) for index, value in enumerate(delivery_headings)))
        for row in delivery_values:
            click.echo("  ".join(str(value).ljust(delivery_widths[index]) for index, value in enumerate(row)))
    click.echo("Rows render canonical Go-compiled routes; Python does not compile routing policy.")
