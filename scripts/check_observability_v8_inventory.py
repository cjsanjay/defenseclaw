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

"""Check the observability-v8 current-state inventory for source drift.

This is an inventory gate, not the v8 classifier or migrator. In particular,
audit actions and gateway event types intentionally remain marked for P1
classification rather than receiving guessed bucket mappings here.
"""

from __future__ import annotations

import argparse
import json
import re
import subprocess
import sys
from pathlib import Path
from typing import Any

import yaml

ROOT = Path(__file__).resolve().parents[1]
DEFAULT_INVENTORY = (
    ROOT / "docs" / "design" / "observability-v8" / "current-state-inventory.yaml"
)
CORE_DATASOURCE_TYPES = {"prometheus", "loki", "tempo"}

GO_ACTION_PATTERN = re.compile(
    r'^\s*(Action[A-Za-z0-9_]+)\s+Action\s*=\s*"([^"]+)"',
    re.MULTILINE,
)
GO_EVENT_TYPE_PATTERN = re.compile(
    r'^\s*(Event[A-Za-z0-9_]+)\s+EventType\s*=\s*"([^"]+)"',
    re.MULTILINE,
)
COMMIT_PATTERN = re.compile(r"[0-9a-f]{40}")


class InventoryError(RuntimeError):
    """The inventory or a source surface is malformed."""


def load_inventory(path: Path) -> dict[str, Any]:
    try:
        data = yaml.safe_load(path.read_text(encoding="utf-8"))
    except (OSError, yaml.YAMLError) as exc:
        raise InventoryError(f"cannot load inventory {path}: {exc}") from exc
    if not isinstance(data, dict):
        raise InventoryError("inventory root must be a mapping")
    if data.get("inventory_version") != 1:
        raise InventoryError("inventory_version must be 1")
    classes = data.get("classes")
    if not isinstance(classes, dict):
        raise InventoryError("classes must be a mapping")
    categories = data.get("migration_disposition_categories")
    if not isinstance(categories, list) or not categories or not all(
        isinstance(value, str) and value for value in categories
    ):
        raise InventoryError("migration_disposition_categories must be a non-empty string list")
    if len(categories) != len(set(categories)):
        raise InventoryError("migration_disposition_categories contains duplicates")
    allowed = set(categories)
    for name, inventory_class in classes.items():
        if not isinstance(inventory_class, dict):
            raise InventoryError(f"classes.{name} must be a mapping")
        disposition = inventory_class.get("migration_disposition")
        if disposition not in allowed:
            raise InventoryError(
                f"classes.{name}.migration_disposition {disposition!r} is not declared",
            )
        if "items" not in inventory_class:
            raise InventoryError(f"classes.{name}.items is required")
        if disposition == "per_item":
            items = inventory_class["items"]
            if not isinstance(items, list):
                raise InventoryError(f"classes.{name}.items must be a list for per_item")
            for index, item in enumerate(items):
                if not isinstance(item, dict):
                    raise InventoryError(f"classes.{name}.items[{index}] must be a mapping")
                item_disposition = item.get("migration_disposition")
                if item_disposition not in allowed - {"per_item"}:
                    raise InventoryError(
                        f"classes.{name}.items[{index}] has invalid migration_disposition "
                        f"{item_disposition!r}",
                    )
    return data


def _class(inventory: dict[str, Any], name: str) -> dict[str, Any]:
    try:
        value = inventory["classes"][name]
    except KeyError as exc:
        raise InventoryError(f"missing inventory class {name!r}") from exc
    if not isinstance(value, dict):
        raise InventoryError(f"inventory class {name!r} must be a mapping")
    return value


def _root_path(root: Path, value: object, *, field: str) -> Path:
    if not isinstance(value, str) or not value:
        raise InventoryError(f"{field} must be a non-empty path string")
    path = root / value
    if not path.is_file():
        raise InventoryError(f"{field} does not exist: {value}")
    return path


def _mapping_items(inventory_class: dict[str, Any], *, name: str) -> dict[str, Any]:
    items = inventory_class.get("items")
    if not isinstance(items, dict) or not items:
        raise InventoryError(f"classes.{name}.items must be a non-empty mapping")
    if not all(isinstance(key, str) and key for key in items):
        raise InventoryError(f"classes.{name}.items keys must be non-empty strings")
    return items


def discover_go_constants(path: Path, pattern: re.Pattern[str], *, label: str) -> dict[str, str]:
    pairs = pattern.findall(path.read_text(encoding="utf-8"))
    if not pairs:
        raise InventoryError(f"parsed zero {label} from {path}")
    result: dict[str, str] = {}
    for symbol, wire_value in pairs:
        if symbol in result:
            raise InventoryError(f"duplicate {label} symbol {symbol!r} in {path}")
        result[symbol] = wire_value
    return result


def discover_metrics(path: Path) -> dict[str, dict[str, str]]:
    try:
        document = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise InventoryError(f"cannot parse metric schema {path}: {exc}") from exc
    emitted = document.get("x-emitted-metrics")
    if not isinstance(emitted, list) or not emitted:
        raise InventoryError(f"{path}: x-emitted-metrics must be a non-empty list")
    result: dict[str, dict[str, str]] = {}
    for index, item in enumerate(emitted):
        if not isinstance(item, dict):
            raise InventoryError(f"{path}: x-emitted-metrics[{index}] must be an object")
        name = item.get("name")
        metric_type = item.get("type")
        unit = item.get("unit")
        if not all(isinstance(value, str) and value for value in (name, metric_type, unit)):
            raise InventoryError(
                f"{path}: x-emitted-metrics[{index}] requires string name/type/unit",
            )
        if name in result:
            raise InventoryError(f"{path}: duplicate emitted metric {name!r}")
        result[name] = {"type": metric_type, "unit": unit}
    return result


def discover_schema_files(root: Path, inventory_class: dict[str, Any]) -> set[str]:
    directory_value = inventory_class.get("source_directory")
    if not isinstance(directory_value, str) or not directory_value:
        raise InventoryError("classes.schema_files.source_directory must be a path")
    directory = root / directory_value
    if not directory.is_dir():
        raise InventoryError(f"schema source directory does not exist: {directory_value}")
    return {
        path.relative_to(root).as_posix()
        for path in directory.rglob("*.json")
        if path.is_file()
    }


def discover_dashboards(root: Path, inventory_class: dict[str, Any]) -> dict[str, str]:
    directory_value = inventory_class.get("source_directory")
    if not isinstance(directory_value, str) or not directory_value:
        raise InventoryError("classes.grafana_dashboard_uids.source_directory must be a path")
    directory = root / directory_value
    if not directory.is_dir():
        raise InventoryError(f"dashboard source directory does not exist: {directory_value}")
    result: dict[str, str] = {}
    seen_uids: set[str] = set()
    for path in sorted(directory.glob("*.json")):
        try:
            document = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            raise InventoryError(f"cannot parse dashboard {path}: {exc}") from exc
        uid = document.get("uid")
        if not isinstance(uid, str) or not uid:
            raise InventoryError(f"dashboard {path} has no UID")
        if uid in seen_uids:
            raise InventoryError(f"duplicate dashboard UID {uid!r}")
        seen_uids.add(uid)
        result[path.relative_to(root).as_posix()] = uid
    if not result:
        raise InventoryError(f"no dashboards found under {directory_value}")
    return result


def discover_core_datasources(path: Path) -> dict[str, str]:
    try:
        document = yaml.safe_load(path.read_text(encoding="utf-8"))
    except (OSError, yaml.YAMLError) as exc:
        raise InventoryError(f"cannot parse datasource config {path}: {exc}") from exc
    datasources = document.get("datasources") if isinstance(document, dict) else None
    if not isinstance(datasources, list):
        raise InventoryError(f"{path}: datasources must be a list")
    result: dict[str, str] = {}
    for index, item in enumerate(datasources):
        if not isinstance(item, dict):
            raise InventoryError(f"{path}: datasources[{index}] must be a mapping")
        datasource_type = item.get("type")
        if datasource_type not in CORE_DATASOURCE_TYPES:
            continue
        uid = item.get("uid")
        if not isinstance(uid, str) or not uid:
            raise InventoryError(f"{path}: core datasource {datasource_type!r} has no UID")
        if datasource_type in result:
            raise InventoryError(f"{path}: duplicate core datasource type {datasource_type!r}")
        result[datasource_type] = uid
    if set(result) != CORE_DATASOURCE_TYPES:
        raise InventoryError(
            f"{path}: core datasource types are {sorted(result)}, "
            f"expected {sorted(CORE_DATASOURCE_TYPES)}",
        )
    return result


def check_legacy_anchors(
    root: Path,
    inventory_class: dict[str, Any],
) -> tuple[int, list[str]]:
    items = inventory_class.get("items")
    if not isinstance(items, list) or not items:
        raise InventoryError("classes.legacy_config_anchors.items must be a non-empty list")
    errors: list[str] = []
    seen_ids: set[str] = set()
    env_names_by_source: dict[Path, set[str]] = {}
    for index, item in enumerate(items):
        if not isinstance(item, dict):
            raise InventoryError(
                f"classes.legacy_config_anchors.items[{index}] must be a mapping",
            )
        anchor_id = item.get("id")
        if not isinstance(anchor_id, str) or not anchor_id:
            raise InventoryError(f"legacy_config_anchors.items[{index}].id is required")
        if anchor_id in seen_ids:
            raise InventoryError(f"duplicate legacy config anchor id {anchor_id!r}")
        seen_ids.add(anchor_id)
        source = _root_path(root, item.get("source"), field=f"legacy anchor {anchor_id}.source")
        matcher = item.get("matcher")
        value = item.get("value")
        if not isinstance(value, str) or not value:
            raise InventoryError(f"legacy anchor {anchor_id}.value must be a non-empty string")
        if matcher == "literal":
            if value not in source.read_text(encoding="utf-8"):
                errors.append(f"legacy_config_anchors[{anchor_id}]: literal not found: {value!r}")
        elif matcher == "env_registry":
            if source not in env_names_by_source:
                try:
                    document = json.loads(source.read_text(encoding="utf-8"))
                except (OSError, json.JSONDecodeError) as exc:
                    raise InventoryError(f"cannot parse environment registry {source}: {exc}") from exc
                entries = document.get("entries") if isinstance(document, dict) else None
                if not isinstance(entries, list):
                    raise InventoryError(f"{source}: entries must be a list")
                env_names_by_source[source] = {
                    entry.get("name")
                    for entry in entries
                    if isinstance(entry, dict) and isinstance(entry.get("name"), str)
                }
            if value not in env_names_by_source[source]:
                errors.append(f"legacy_config_anchors[{anchor_id}]: env var not registered: {value}")
        else:
            raise InventoryError(
                f"legacy anchor {anchor_id}.matcher must be literal or env_registry",
            )
    return len(items), errors


def check_baseline_commits(
    root: Path,
    inventory_class: dict[str, Any],
    *,
    verify_git_ancestry: bool,
) -> tuple[int, list[str]]:
    items = inventory_class.get("items")
    if not isinstance(items, list) or not items:
        raise InventoryError("classes.compatibility_baseline_commits.items must be a non-empty list")
    errors: list[str] = []
    seen_prs: set[int] = set()
    for index, item in enumerate(items):
        if not isinstance(item, dict):
            raise InventoryError(f"compatibility_baseline_commits.items[{index}] must be a mapping")
        pr = item.get("pull_request")
        commit = item.get("merge_commit")
        if not isinstance(pr, int) or pr <= 0 or pr in seen_prs:
            raise InventoryError(f"invalid or duplicate pull request at baseline index {index}")
        seen_prs.add(pr)
        if not isinstance(commit, str) or COMMIT_PATTERN.fullmatch(commit) is None:
            raise InventoryError(f"PR #{pr} merge_commit must be a 40-character lowercase SHA")
        source = _root_path(root, item.get("source"), field=f"PR #{pr}.source")
        if commit not in source.read_text(encoding="utf-8"):
            errors.append(f"compatibility_baseline_commits[PR #{pr}]: SHA absent from {source}")
        if not verify_git_ancestry:
            continue
        exists = subprocess.run(
            ["git", "cat-file", "-e", f"{commit}^{{commit}}"],
            cwd=root,
            check=False,
            capture_output=True,
            text=True,
        )
        if exists.returncode != 0:
            errors.append(f"compatibility_baseline_commits[PR #{pr}]: commit not present: {commit}")
            continue
        ancestor = subprocess.run(
            ["git", "merge-base", "--is-ancestor", commit, "HEAD"],
            cwd=root,
            check=False,
            capture_output=True,
            text=True,
        )
        if ancestor.returncode != 0:
            errors.append(f"compatibility_baseline_commits[PR #{pr}]: commit is not an ancestor of HEAD")
    return len(items), errors


def compare_mapping(label: str, expected: dict[str, Any], actual: dict[str, Any]) -> list[str]:
    errors: list[str] = []
    expected_keys = set(expected)
    actual_keys = set(actual)
    for key in sorted(expected_keys - actual_keys):
        errors.append(f"{label}: missing source item {key!r}")
    for key in sorted(actual_keys - expected_keys):
        errors.append(f"{label}: untracked source item {key!r}")
    for key in sorted(expected_keys & actual_keys):
        if expected[key] != actual[key]:
            errors.append(
                f"{label}: {key!r} changed: inventory={expected[key]!r}, source={actual[key]!r}",
            )
    return errors


def run_checks(
    root: Path,
    inventory: dict[str, Any],
    *,
    verify_git_ancestry: bool = False,
) -> tuple[dict[str, int], list[str]]:
    counts: dict[str, int] = {}
    errors: list[str] = []

    anchors = _class(inventory, "legacy_config_anchors")
    counts["legacy_config_anchors"], anchor_errors = check_legacy_anchors(root, anchors)
    errors.extend(anchor_errors)

    event_types = _class(inventory, "gateway_event_types")
    event_source = _root_path(
        root,
        event_types.get("source"),
        field="classes.gateway_event_types.source",
    )
    expected_events = _mapping_items(event_types, name="gateway_event_types")
    actual_events = discover_go_constants(
        event_source,
        GO_EVENT_TYPE_PATTERN,
        label="gateway EventType constants",
    )
    counts["gateway_event_types"] = len(actual_events)
    errors.extend(compare_mapping("gateway_event_types", expected_events, actual_events))

    actions = _class(inventory, "audit_actions")
    action_source = _root_path(root, actions.get("source"), field="classes.audit_actions.source")
    expected_actions = _mapping_items(actions, name="audit_actions")
    actual_actions = discover_go_constants(
        action_source,
        GO_ACTION_PATTERN,
        label="audit Action constants",
    )
    counts["audit_actions"] = len(actual_actions)
    errors.extend(compare_mapping("audit_actions", expected_actions, actual_actions))

    metrics = _class(inventory, "emitted_metrics")
    metric_source = _root_path(root, metrics.get("source"), field="classes.emitted_metrics.source")
    expected_metrics = _mapping_items(metrics, name="emitted_metrics")
    actual_metrics = discover_metrics(metric_source)
    counts["emitted_metrics"] = len(actual_metrics)
    errors.extend(compare_mapping("emitted_metrics", expected_metrics, actual_metrics))

    schemas = _class(inventory, "schema_files")
    schema_items = schemas.get("items")
    if not isinstance(schema_items, list) or not schema_items:
        raise InventoryError("classes.schema_files.items must be a non-empty list")
    expected_schemas = {
        item.get("path")
        for item in schema_items
        if isinstance(item, dict) and isinstance(item.get("path"), str)
    }
    if len(expected_schemas) != len(schema_items):
        raise InventoryError("schema_files items require unique path strings")
    actual_schemas = discover_schema_files(root, schemas)
    counts["schema_files"] = len(actual_schemas)
    errors.extend(
        compare_mapping(
            "schema_files",
            {path: True for path in expected_schemas},
            {path: True for path in actual_schemas},
        ),
    )

    dashboards = _class(inventory, "grafana_dashboard_uids")
    expected_dashboards = _mapping_items(dashboards, name="grafana_dashboard_uids")
    actual_dashboards = discover_dashboards(root, dashboards)
    counts["grafana_dashboard_uids"] = len(actual_dashboards)
    errors.extend(compare_mapping("grafana_dashboard_uids", expected_dashboards, actual_dashboards))

    datasources = _class(inventory, "grafana_datasource_uids")
    datasource_source = _root_path(
        root,
        datasources.get("source"),
        field="classes.grafana_datasource_uids.source",
    )
    expected_datasources = _mapping_items(datasources, name="grafana_datasource_uids")
    actual_datasources = discover_core_datasources(datasource_source)
    counts["grafana_datasource_uids"] = len(actual_datasources)
    errors.extend(compare_mapping("grafana_datasource_uids", expected_datasources, actual_datasources))

    baselines = _class(inventory, "compatibility_baseline_commits")
    counts["compatibility_baseline_commits"], baseline_errors = check_baseline_commits(
        root,
        baselines,
        verify_git_ancestry=verify_git_ancestry,
    )
    errors.extend(baseline_errors)
    return counts, errors


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=ROOT, help="repository root")
    parser.add_argument(
        "--inventory",
        type=Path,
        default=DEFAULT_INVENTORY,
        help="current-state inventory YAML",
    )
    parser.add_argument(
        "--verify-git-ancestry",
        action="store_true",
        help=(
            "require pinned compatibility commits to exist and be ancestors of HEAD; "
            "use only in an intentional full-history checkout"
        ),
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    root = args.root.resolve()
    inventory_path = args.inventory.resolve()
    try:
        inventory = load_inventory(inventory_path)
        counts, errors = run_checks(
            root,
            inventory,
            verify_git_ancestry=args.verify_git_ancestry,
        )
    except InventoryError as exc:
        print(f"check_observability_v8_inventory: invalid inventory/source: {exc}", file=sys.stderr)
        return 2
    except OSError as exc:
        print(f"check_observability_v8_inventory: source read failed: {exc}", file=sys.stderr)
        return 2

    if errors:
        print("check_observability_v8_inventory: current-state drift detected", file=sys.stderr)
        for error in errors:
            print(f"  - {error}", file=sys.stderr)
        return 1

    summary = ", ".join(f"{name}={count}" for name, count in counts.items())
    print(f"check_observability_v8_inventory: ok ({summary})")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
