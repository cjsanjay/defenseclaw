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

"""Refresh user-seeded bundle copies from the wheel/repo source.

Both the local Splunk bridge (``~/.defenseclaw/splunk-bridge/``) and the
local observability stack (``~/.defenseclaw/observability-stack/``) are
seeded by ``defenseclaw init`` and *never* refreshed by it on a re-run
(``init`` preserves the seeded copy so operator edits survive). That
historically meant new bundle code shipped in the wheel — the v0.130
``s3_exporter/`` sidecar, a fix to ``compose/docker-compose.local.yml``,
a new dashboard — sat unused on disk forever.

This module is the explicit, opt-out path for picking those up:

* :func:`refresh_splunk_bridge` does an rsync-style overwrite of the
  whole bridge, preserving only operator-secret files (``env/.env``)
  and regenerated artefacts (``splunk/build/``). The Splunk bundle is
  overwhelmingly maintainer-owned (compose, bin, app source,
  ``s3_exporter/``); the only operator-overrideable Splunk runtime
  state lives inside the persistent ``splunk_etc`` Docker volume,
  which we never touch.

* :func:`refresh_local_observability_stack` refreshes maintainer-owned
  files (``bin/``, ``run.sh``, ``docker-compose.yml``) by default and
  preserves operator-editable surfaces (Grafana dashboards, Prometheus
  rules, Loki/Tempo/OTel-Collector configs). Pass
  ``refresh_config=True`` for a wholesale refresh — that's destructive
  to operator dashboard edits and so is opt-in.

* :func:`is_compose_project_running` uses ``docker ps`` labels to spot
  a running stack so callers can stop → refresh → restart in one
  motion.

All refresh writes go through a tmp dir + ``os.replace`` so a crash
midway through a copy can't leave the seeded copy half-overwritten.
"""

from __future__ import annotations

import hashlib
import json
import os
import shutil
import socket
import stat
import subprocess
import tempfile
import time
import urllib.error
import urllib.request
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path

import yaml

from defenseclaw.paths import (
    bundled_local_observability_dir,
    bundled_splunk_bridge_dir,
)

# ---------------------------------------------------------------------------
# Public dataclass
# ---------------------------------------------------------------------------


@dataclass
class RefreshResult:
    """Outcome of a single refresh + (optional) restart cycle.

    All paths are stored as the relative-to-bundle-root strings the
    caller passed in (e.g. ``"compose/docker-compose.local.yml"``) so
    they render cleanly in CLI status output.
    """

    bundle_kind: str
    seeded_dest: str
    bundle_source: str
    refreshed: bool = False
    refreshed_paths: list[str] = field(default_factory=list)
    preserved_paths: list[str] = field(default_factory=list)
    skipped_reason: str | None = None
    was_running: bool = False
    stopped: bool = False
    restarted: bool = False
    errors: list[str] = field(default_factory=list)


@dataclass(frozen=True)
class LocalObservabilityUpgradeResult:
    """Serializable result of the fail-closed upgrade refresh transaction."""

    installed: bool
    refreshed: bool = False
    was_running: bool = False
    stopped: bool = False
    restart_required: bool = False
    restarted: bool = False
    managed_paths: tuple[str, ...] = ()
    changed_paths: tuple[str, ...] = ()
    conflict_paths: tuple[str, ...] = ()
    preserved_custom_paths: tuple[str, ...] = ()
    named_volumes: tuple[str, ...] = ()
    manifest_sha256: str | None = None
    degraded_errors: tuple[str, ...] = ()

    def to_dict(self) -> dict[str, object]:
        return {
            "installed": self.installed,
            "refreshed": self.refreshed,
            "was_running": self.was_running,
            "stopped": self.stopped,
            "restart_required": self.restart_required,
            "restarted": self.restarted,
            "managed_paths": list(self.managed_paths),
            "changed_paths": list(self.changed_paths),
            "conflict_paths": list(self.conflict_paths),
            "preserved_custom_paths": list(self.preserved_custom_paths),
            "named_volumes": list(self.named_volumes),
            "manifest_sha256": self.manifest_sha256,
            "degraded_errors": list(self.degraded_errors),
        }


class LocalObservabilityUpgradeError(RuntimeError):
    """Value-safe failure raised before the upgraded services may restart."""

    def __init__(self, code: str, phase: str) -> None:
        self.code = code
        self.phase = phase
        super().__init__(f"local observability bundle upgrade failed ({code}, {phase})")


# ---------------------------------------------------------------------------
# Splunk bridge refresh
# ---------------------------------------------------------------------------


# Files inside ``~/.defenseclaw/splunk-bridge/`` that the refresh must
# never overwrite. ``env/.env`` carries the operator's SPLUNK_PASSWORD
# (and any AWS creds for the s3_exporter sidecar), and ``splunk/build/``
# is the generated tarball that ``package_local_mode_app.sh`` rebuilds
# every ``up`` so there is no point in ferrying it across.
_SPLUNK_BRIDGE_PRESERVE: tuple[str, ...] = (
    "env/.env",
    "splunk/build",
)

_SPLUNK_BRIDGE_DEST_REL: str = "splunk-bridge"


def refresh_splunk_bridge(data_dir: str) -> RefreshResult:
    """Refresh ``~/.defenseclaw/splunk-bridge/`` from the bundled source.

    Returns a :class:`RefreshResult` describing what changed. Never
    raises for missing source / missing dest — the result captures
    those as a ``skipped_reason`` so the CLI can render a soft
    warning instead of crashing the setup flow.
    """
    bundle = bundled_splunk_bridge_dir()
    dest = os.path.join(data_dir, _SPLUNK_BRIDGE_DEST_REL)
    result = RefreshResult(
        bundle_kind="splunk-bridge",
        seeded_dest=dest,
        bundle_source=str(bundle),
    )

    if not bundle.is_dir():
        result.skipped_reason = f"bundled source missing ({bundle})"
        return result

    if not os.path.isdir(dest):
        # No prior seed — fall back to a plain copytree. Keeps the
        # refresh path safe to call before ``init`` has run.
        try:
            shutil.copytree(str(bundle), dest)
        except OSError as exc:
            result.errors.append(f"initial seed: {exc}")
            return result
        bridge_bin = os.path.join(dest, "bin", "splunk-claw-bridge")
        if os.path.isfile(bridge_bin):
            try:
                os.chmod(bridge_bin, 0o755)
            except OSError as exc:
                result.errors.append(f"chmod splunk-claw-bridge: {exc}")
        result.refreshed = True
        result.refreshed_paths.append("(initial seed)")
        return result

    refreshed, preserved, errors = _rsync_overwrite(
        src=Path(bundle),
        dest=Path(dest),
        preserve=_SPLUNK_BRIDGE_PRESERVE,
    )
    result.refreshed_paths = refreshed
    result.preserved_paths = preserved
    result.errors = errors
    result.refreshed = bool(refreshed)

    bridge_bin = os.path.join(dest, "bin", "splunk-claw-bridge")
    if os.path.isfile(bridge_bin):
        try:
            os.chmod(bridge_bin, 0o755)
        except OSError as exc:
            result.errors.append(f"chmod splunk-claw-bridge: {exc}")

    return result


# ---------------------------------------------------------------------------
# Local observability stack refresh
# ---------------------------------------------------------------------------


# Operator-editable surfaces — preserved unless the caller passes
# ``refresh_config=True``. Each entry is a relative path inside
# ``~/.defenseclaw/observability-stack/`` and may be a file or a
# directory; ``_rsync_overwrite`` treats both correctly.
_LOCAL_OBSERVABILITY_OPERATOR_PATHS: tuple[str, ...] = (
    "grafana",
    "prometheus",
    "loki",
    "tempo",
    "otel-collector",
)

# Maintainer-owned files removed from newer bundles.  The rsync-style refresh
# intentionally preserves arbitrary destination-only files so operator-created
# dashboards survive upgrades; explicit tombstones let us remove only retired
# DefenseClaw assets without turning refresh into a destructive directory
# mirror.
_LOCAL_OBSERVABILITY_RETIRED_PATHS: tuple[str, ...] = ("grafana/dashboards/defenseclaw-reliability.json",)
_LOCAL_OBSERVABILITY_RETIRED_SHA256: dict[str, frozenset[str]] = {
    "grafana/dashboards/defenseclaw-reliability.json": frozenset(
        {
            "4993c6ca65313823a410df84778531c377eec217b2947f2e78d083b18437aae5",
            "ba845c3ced38a69b6a6d175a88227c4887556731ba7c77fa4f3efa880cbe5443",
            "c39b8d1e45726c2016e6622bdc4234ff3d5bbfbc683f0283106f026eab245d26",
        }
    ),
}

_LOCAL_OBSERVABILITY_DEST_REL: str = "observability-stack"
_LOCAL_OBSERVABILITY_MANIFEST = ".defenseclaw-bundle-manifest.json"
_LOCAL_OBSERVABILITY_MANIFEST_SCHEMA = 1
_LOCAL_OBSERVABILITY_REQUIRED_FILES: tuple[str, ...] = (
    "bin/openclaw-observability-bridge",
    "docker-compose.yml",
    "grafana/provisioning/dashboards/dashboards.yml",
    "grafana/provisioning/datasources/datasources.yml",
    "loki/loki.yaml",
    "otel-collector/config.yaml",
    "prometheus/prometheus.yml",
    "prometheus/rules/alerts.yml",
    "prometheus/rules/recording.yml",
    "run.sh",
    "tempo/tempo.yaml",
)
_LOCAL_OBSERVABILITY_SERVICES: tuple[str, ...] = (
    "otel-collector",
    "prometheus",
    "loki",
    "tempo",
    "grafana",
)
_LOCAL_OBSERVABILITY_NAMED_VOLUMES: tuple[str, ...] = (
    "grafana-data",
    "loki-data",
    "prometheus-data",
    "tempo-data",
)
_LOCAL_OBSERVABILITY_DASHBOARD_UIDS: tuple[str, ...] = (
    "defenseclaw-activity",
    "defenseclaw-agent-360",
    "defenseclaw-agent-identity",
    "defenseclaw-ai-discovery",
    "defenseclaw-connector-detail",
    "defenseclaw-connectors",
    "defenseclaw-findings",
    "defenseclaw-hitl",
    "defenseclaw-overview",
    "defenseclaw-policy-decisions",
    "defenseclaw-runtime",
    "defenseclaw-scanners",
    "defenseclaw-security",
    "defenseclaw-traffic",
)


@dataclass(frozen=True)
class _BundleFile:
    path: str
    sha256: str
    size: int
    mode: int


@dataclass(frozen=True)
class _BundleManifest:
    bundle_version: str
    files: tuple[_BundleFile, ...]
    dashboard_uids: tuple[str, ...]
    named_volumes: tuple[str, ...]
    raw: bytes
    sha256: str


def refresh_local_observability_stack(
    data_dir: str,
    *,
    refresh_config: bool = False,
) -> RefreshResult:
    """Refresh ``~/.defenseclaw/observability-stack/`` from the bundle.

    By default we refresh maintainer-owned files (``bin/``, ``run.sh``,
    ``docker-compose.yml``) and preserve every operator-editable
    surface listed in :data:`_LOCAL_OBSERVABILITY_OPERATOR_PATHS`. Set
    ``refresh_config=True`` to also overwrite those — destructive to
    Grafana dashboard / Prometheus rule edits, hence opt-in.
    """
    bundle = bundled_local_observability_dir()
    dest = os.path.join(data_dir, _LOCAL_OBSERVABILITY_DEST_REL)
    result = RefreshResult(
        bundle_kind="observability-stack",
        seeded_dest=dest,
        bundle_source=str(bundle),
    )

    if not bundle.is_dir():
        result.skipped_reason = f"bundled source missing ({bundle})"
        return result

    if not os.path.isdir(dest):
        try:
            shutil.copytree(str(bundle), dest)
        except OSError as exc:
            result.errors.append(f"initial seed: {exc}")
            return result
        _ensure_observability_executables(dest)
        result.refreshed = True
        result.refreshed_paths.append("(initial seed)")
        return result

    preserve: tuple[str, ...] = ()
    if not refresh_config:
        preserve = _LOCAL_OBSERVABILITY_OPERATOR_PATHS

    refreshed, preserved, errors = _rsync_overwrite(
        src=Path(bundle),
        dest=Path(dest),
        preserve=preserve,
    )
    result.refreshed_paths = refreshed
    result.preserved_paths = preserved
    result.errors = errors
    result.refreshed = bool(refreshed)

    if refresh_config:
        removed, removal_errors = _remove_retired_paths(
            Path(dest),
            _LOCAL_OBSERVABILITY_RETIRED_PATHS,
        )
        result.refreshed_paths.extend(f"{path} (removed)" for path in removed)
        result.errors.extend(removal_errors)
        result.refreshed = bool(result.refreshed_paths)

    _ensure_observability_executables(dest)
    return result


def upgrade_local_observability_stack(
    data_dir: str,
    backup_dir: str,
    *,
    bundle_version: str,
    fault_injector: Callable[[str, str | None], None] | None = None,
) -> LocalObservabilityUpgradeResult:
    """Safely refresh an installed local-observability stack during upgrade.

    Unlike the interactive setup refresher, this path is an all-or-rollback
    transaction over the complete DefenseClaw-owned file set. Destination-only
    files are never removed, and Docker named volumes are never copied, reset,
    or passed to ``compose down -v``.
    """

    data_root = Path(data_dir).expanduser().absolute()
    destination = data_root / _LOCAL_OBSERVABILITY_DEST_REL
    if not destination.exists() and not destination.is_symlink():
        return LocalObservabilityUpgradeResult(installed=False)
    if destination.is_symlink() or not destination.is_dir():
        raise LocalObservabilityUpgradeError("unsafe_install_root", "preflight")

    source = bundled_local_observability_dir().absolute()
    target = _build_local_observability_manifest(source, bundle_version)
    prior = _read_installed_bundle_manifest(destination)
    managed_retired = _managed_retired_paths(destination)
    _preflight_upgrade_destination(destination, target, managed_retired)

    was_running = _strict_compose_project_running(LOCAL_OBSERVABILITY_COMPOSE_PROJECT)
    stopped = False
    if was_running:
        bridge = destination / "bin" / "openclaw-observability-bridge"
        _require_regular_file(destination, bridge, "bridge")
        try:
            completed = subprocess.run(
                [str(bridge), "down"],
                capture_output=True,
                text=True,
                timeout=120,
                check=False,
            )
        except (OSError, subprocess.TimeoutExpired) as exc:
            raise LocalObservabilityUpgradeError("stack_stop_failed", "stop") from exc
        if completed.returncode != 0:
            raise LocalObservabilityUpgradeError("stack_stop_failed", "stop")
        if _strict_compose_project_running(LOCAL_OBSERVABILITY_COMPOSE_PROJECT):
            raise LocalObservabilityUpgradeError("stack_still_running", "stop")
        stopped = True

    return _activate_local_observability_manifest(
        source,
        destination,
        Path(backup_dir).expanduser().absolute(),
        target,
        prior,
        managed_retired,
        was_running=was_running,
        stopped=stopped,
        fault_injector=fault_injector,
    )


def restart_upgraded_local_observability_stack(
    data_dir: str,
    *,
    timeout: int = 180,
) -> LocalObservabilityUpgradeResult:
    """Restart and smoke-check a stack stopped by the upgrade transaction.

    Restart/readiness failures are returned as degraded status because the
    bundle bytes have already been safely activated. They never trigger a
    config/gateway rollback and never reset named volumes.
    """

    destination = Path(data_dir).expanduser().absolute() / _LOCAL_OBSERVABILITY_DEST_REL
    if not destination.is_dir() or destination.is_symlink():
        return LocalObservabilityUpgradeResult(
            installed=False,
            degraded_errors=("installed_bundle_missing",),
        )
    bridge = destination / "bin" / "openclaw-observability-bridge"
    try:
        _require_regular_file(destination, bridge, "bridge")
        completed = subprocess.run(
            [str(bridge), "up", "--output", "json", "--timeout", str(timeout)],
            capture_output=True,
            text=True,
            timeout=max(timeout + 30, 60),
            check=False,
        )
    except (LocalObservabilityUpgradeError, OSError, subprocess.TimeoutExpired):
        return LocalObservabilityUpgradeResult(
            installed=True,
            restart_required=True,
            degraded_errors=("stack_restart_failed",),
        )
    if completed.returncode != 0 or not _bridge_contract_valid(completed.stdout):
        return LocalObservabilityUpgradeResult(
            installed=True,
            restart_required=True,
            degraded_errors=("stack_restart_failed",),
        )

    errors = _live_local_observability_smoke(timeout=min(max(timeout, 1), 30))
    return LocalObservabilityUpgradeResult(
        installed=True,
        restart_required=True,
        restarted=not errors,
        named_volumes=_LOCAL_OBSERVABILITY_NAMED_VOLUMES,
        degraded_errors=tuple(errors),
    )


def _build_local_observability_manifest(source: Path, bundle_version: str) -> _BundleManifest:
    if source.is_symlink() or not source.is_dir():
        raise LocalObservabilityUpgradeError("target_bundle_missing", "manifest")
    entries: list[_BundleFile] = []
    for root, dirs, files in os.walk(source, followlinks=False):
        root_path = Path(root)
        for name in dirs:
            if (root_path / name).is_symlink():
                raise LocalObservabilityUpgradeError("target_bundle_unsafe", "manifest")
        for name in files:
            path = root_path / name
            _require_regular_file(source, path, "target")
            relative = _safe_relative_path(path.relative_to(source).as_posix())
            metadata = path.stat()
            entries.append(
                _BundleFile(
                    path=relative,
                    sha256=_sha256_file(path),
                    size=metadata.st_size,
                    mode=stat.S_IMODE(metadata.st_mode),
                )
            )
    entries.sort(key=lambda item: item.path.encode("utf-8"))
    paths = {entry.path for entry in entries}
    if not set(_LOCAL_OBSERVABILITY_REQUIRED_FILES).issubset(paths):
        raise LocalObservabilityUpgradeError("target_bundle_incomplete", "manifest")

    dashboards = _validate_dashboard_inventory(source, paths)
    named_volumes = _validate_compose_inventory(source / "docker-compose.yml")
    document = {
        "schema_version": _LOCAL_OBSERVABILITY_MANIFEST_SCHEMA,
        "bundle_version": bundle_version,
        "dashboard_uids": list(dashboards),
        "named_volumes": list(named_volumes),
        "files": [
            {
                "path": entry.path,
                "sha256": entry.sha256,
                "size": entry.size,
                "mode": entry.mode,
            }
            for entry in entries
        ],
    }
    raw = (json.dumps(document, sort_keys=True, separators=(",", ":")) + "\n").encode()
    return _BundleManifest(
        bundle_version=bundle_version,
        files=tuple(entries),
        dashboard_uids=dashboards,
        named_volumes=named_volumes,
        raw=raw,
        sha256=hashlib.sha256(raw).hexdigest(),
    )


def _validate_dashboard_inventory(source: Path, paths: set[str]) -> tuple[str, ...]:
    prefix = "grafana/dashboards/"
    dashboard_paths = sorted(path for path in paths if path.startswith(prefix) and path.endswith(".json"))
    uids: list[str] = []
    for relative in dashboard_paths:
        try:
            document = json.loads((source / relative).read_text(encoding="utf-8"))
        except (OSError, UnicodeError, ValueError) as exc:
            raise LocalObservabilityUpgradeError("target_dashboard_invalid", "manifest") from exc
        uid = document.get("uid") if isinstance(document, dict) else None
        if not isinstance(uid, str) or not uid:
            raise LocalObservabilityUpgradeError("target_dashboard_invalid", "manifest")
        uids.append(uid)
    observed = tuple(sorted(uids))
    if observed != _LOCAL_OBSERVABILITY_DASHBOARD_UIDS:
        raise LocalObservabilityUpgradeError("target_dashboard_inventory_mismatch", "manifest")
    return observed


def _validate_compose_inventory(compose_path: Path) -> tuple[str, ...]:
    try:
        document = yaml.safe_load(compose_path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, yaml.YAMLError) as exc:
        raise LocalObservabilityUpgradeError("target_compose_invalid", "manifest") from exc
    if not isinstance(document, dict) or document.get("name") != LOCAL_OBSERVABILITY_COMPOSE_PROJECT:
        raise LocalObservabilityUpgradeError("target_compose_invalid", "manifest")
    services = document.get("services")
    volumes = document.get("volumes")
    if not isinstance(services, dict) or not set(_LOCAL_OBSERVABILITY_SERVICES).issubset(services):
        raise LocalObservabilityUpgradeError("target_service_inventory_mismatch", "manifest")
    if not isinstance(volumes, dict):
        raise LocalObservabilityUpgradeError("target_volume_inventory_mismatch", "manifest")
    observed = tuple(sorted(str(name) for name in volumes))
    if observed != _LOCAL_OBSERVABILITY_NAMED_VOLUMES:
        raise LocalObservabilityUpgradeError("target_volume_inventory_mismatch", "manifest")
    return observed


def _read_installed_bundle_manifest(destination: Path) -> _BundleManifest | None:
    path = destination / _LOCAL_OBSERVABILITY_MANIFEST
    if not path.exists() and not path.is_symlink():
        return None
    _require_regular_file(destination, path, "installed_manifest")
    try:
        if path.stat().st_size > 4 * 1024 * 1024:
            raise ValueError("manifest is too large")
        raw = path.read_bytes()
        document = json.loads(raw)
        if not isinstance(document, dict):
            raise ValueError("manifest is not an object")
        if document.get("schema_version") != _LOCAL_OBSERVABILITY_MANIFEST_SCHEMA:
            raise ValueError("unsupported schema")
        bundle_version = document["bundle_version"]
        files_raw = document["files"]
        dashboards_raw = document["dashboard_uids"]
        volumes_raw = document["named_volumes"]
        if not isinstance(bundle_version, str) or not isinstance(files_raw, list) or len(files_raw) > 4096:
            raise ValueError("invalid manifest fields")
        files: list[_BundleFile] = []
        seen: set[str] = set()
        for item in files_raw:
            if not isinstance(item, dict) or set(item) != {"path", "sha256", "size", "mode"}:
                raise ValueError("invalid file row")
            relative = _safe_relative_path(item["path"])
            digest = item["sha256"]
            size = item["size"]
            mode = item["mode"]
            if (
                relative in seen
                or not isinstance(digest, str)
                or len(digest) != 64
                or any(char not in "0123456789abcdef" for char in digest)
                or not isinstance(size, int)
                or isinstance(size, bool)
                or size < 0
                or not isinstance(mode, int)
                or isinstance(mode, bool)
                or mode < 0
                or mode > 0o7777
            ):
                raise ValueError("invalid file row")
            seen.add(relative)
            files.append(_BundleFile(relative, digest, size, mode))
        if (
            not isinstance(dashboards_raw, list)
            or len(dashboards_raw) > 256
            or not all(isinstance(v, str) for v in dashboards_raw)
        ):
            raise ValueError("invalid dashboard inventory")
        if (
            not isinstance(volumes_raw, list)
            or len(volumes_raw) > 256
            or not all(isinstance(v, str) for v in volumes_raw)
        ):
            raise ValueError("invalid volume inventory")
        return _BundleManifest(
            bundle_version=bundle_version,
            files=tuple(files),
            dashboard_uids=tuple(dashboards_raw),
            named_volumes=tuple(volumes_raw),
            raw=raw,
            sha256=hashlib.sha256(raw).hexdigest(),
        )
    except (KeyError, OSError, UnicodeError, ValueError, json.JSONDecodeError) as exc:
        raise LocalObservabilityUpgradeError("installed_manifest_invalid", "preflight") from exc


def _managed_retired_paths(destination: Path) -> set[str]:
    """Return only retired files whose bytes match a reviewed shipped asset.

    A destination-only file at a retired DefenseClaw filename is still an
    operator file unless its digest is one of the historical bundle digests.
    This prevents a tombstone from deleting an unrelated custom dashboard.
    """

    managed: set[str] = set()
    for relative, historical_digests in _LOCAL_OBSERVABILITY_RETIRED_SHA256.items():
        path = destination / relative
        if not path.exists() or path.is_symlink():
            continue
        try:
            if stat.S_ISREG(path.lstat().st_mode) and _sha256_file(path) in historical_digests:
                managed.add(relative)
        except OSError as exc:
            raise LocalObservabilityUpgradeError("retired_path_unreadable", "preflight") from exc
    return managed


def _preflight_upgrade_destination(
    destination: Path,
    target: _BundleManifest,
    managed_retired: set[str],
) -> None:
    managed = {entry.path for entry in target.files}
    managed.update(managed_retired)
    managed.add(_LOCAL_OBSERVABILITY_MANIFEST)
    for relative in sorted(managed):
        path = destination / relative
        _validate_destination_ancestors(destination, path)
        if path.exists() or path.is_symlink():
            _require_regular_file(destination, path, "destination")


def _activate_local_observability_manifest(
    source: Path,
    destination: Path,
    backup_dir: Path,
    target: _BundleManifest,
    prior: _BundleManifest | None,
    managed_retired: set[str],
    *,
    was_running: bool,
    stopped: bool,
    fault_injector: Callable[[str, str | None], None] | None,
) -> LocalObservabilityUpgradeResult:
    target_by_path = {entry.path: entry for entry in target.files}
    prior_by_path = {entry.path: entry for entry in prior.files} if prior else {}
    # Never treat an installed manifest's arbitrary extra rows as deletion
    # authority. Only current target entries and reviewed tombstones are
    # DefenseClaw-managed; destination-only paths remain operator-owned.
    managed_paths = set(target_by_path) | managed_retired
    old_manifest_path = destination / _LOCAL_OBSERVABILITY_MANIFEST
    backup_root = backup_dir / "local-observability-stack"
    backup_managed = backup_root / "managed"
    if backup_dir.is_symlink() or (backup_dir.exists() and not backup_dir.is_dir()):
        raise LocalObservabilityUpgradeError("unsafe_backup_root", "backup")
    if not backup_dir.exists():
        _mkdir_private(backup_dir)
    if backup_root.exists() or backup_root.is_symlink():
        raise LocalObservabilityUpgradeError("backup_collision", "backup")

    changed: list[str] = []
    conflicts: list[str] = []
    existing: list[str] = []
    custom = _destination_only_files(destination, managed_paths | {_LOCAL_OBSERVABILITY_MANIFEST})
    old_digests: dict[str, str] = {}
    old_modes: dict[str, int] = {}
    try:
        _mkdir_private(backup_root)
        _mkdir_private(backup_managed)
        for relative in sorted(managed_paths | {_LOCAL_OBSERVABILITY_MANIFEST}):
            path = destination / relative
            if not path.exists():
                continue
            existing.append(relative)
            digest = _sha256_file(path)
            old_digests[relative] = digest
            old_modes[relative] = stat.S_IMODE(path.stat().st_mode)
            backup_path = backup_managed / relative
            _mkdir_private(backup_path.parent)
            shutil.copy2(path, backup_path, follow_symlinks=False)
            os.chmod(backup_path, 0o600)

            target_entry = target_by_path.get(relative)
            prior_entry = prior_by_path.get(relative)
            current_mode = old_modes[relative]
            if target_entry is None:
                # This path entered ``managed_paths`` only because its bytes
                # matched a reviewed historical bundle digest.
                continue
            if digest == target_entry.sha256 and current_mode == target_entry.mode:
                continue
            if prior_entry is None or (digest != prior_entry.sha256 or current_mode != prior_entry.mode):
                conflicts.append(relative)

        backup_metadata = {
            "schema_version": 1,
            "target_manifest_sha256": target.sha256,
            "prior_manifest_sha256": prior.sha256 if prior else None,
            "existing_paths": existing,
            "old_sha256": old_digests,
            "old_modes": old_modes,
            "conflict_paths": sorted(conflicts),
            "preserved_custom_paths": list(custom),
            "named_volumes": list(target.named_volumes),
        }
        _atomic_write_bytes(
            backup_root / "refresh-backup.json",
            (json.dumps(backup_metadata, sort_keys=True, separators=(",", ":")) + "\n").encode(),
            mode=0o600,
        )
        if fault_injector:
            fault_injector("after_backup", None)
    except (OSError, LocalObservabilityUpgradeError) as exc:
        if isinstance(exc, LocalObservabilityUpgradeError):
            raise
        raise LocalObservabilityUpgradeError("backup_failed", "backup") from exc

    stage = Path(tempfile.mkdtemp(prefix=".local-observability-stage-", dir=destination.parent))
    os.chmod(stage, 0o700)
    mutation_started = False
    try:
        for entry in target.files:
            stage_path = stage / entry.path
            stage_path.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(source / entry.path, stage_path, follow_symlinks=False)
            if _sha256_file(stage_path) != entry.sha256:
                raise LocalObservabilityUpgradeError("staged_digest_mismatch", "stage")
        if fault_injector:
            fault_injector("after_stage", None)

        for entry in target.files:
            destination_path = destination / entry.path
            current_digest = _sha256_file(destination_path) if destination_path.exists() else None
            current_mode = stat.S_IMODE(destination_path.stat().st_mode) if destination_path.exists() else None
            if current_digest == entry.sha256 and current_mode == entry.mode:
                continue
            mutation_started = True
            if fault_injector:
                fault_injector("before_activate", entry.path)
            destination_path.parent.mkdir(parents=True, exist_ok=True)
            _atomic_copy_file(str(stage / entry.path), str(destination_path))
            changed.append(entry.path)
            if fault_injector:
                fault_injector("after_activate", entry.path)

        retired = sorted(managed_retired - set(target_by_path))
        for relative in retired:
            path = destination / relative
            if not path.exists():
                continue
            mutation_started = True
            if fault_injector:
                fault_injector("before_remove", relative)
            path.unlink()
            changed.append(relative)

        if not old_manifest_path.exists() or old_manifest_path.read_bytes() != target.raw:
            mutation_started = True
            _atomic_write_bytes(old_manifest_path, target.raw, mode=0o600)
            changed.append(_LOCAL_OBSERVABILITY_MANIFEST)
        _verify_activated_bundle(destination, target)
        if fault_injector:
            fault_injector("after_verify", None)
    except Exception as exc:
        try:
            if mutation_started:
                _restore_local_observability_backup(
                    destination,
                    backup_managed,
                    managed_paths | {_LOCAL_OBSERVABILITY_MANIFEST},
                    set(existing),
                    old_digests,
                    old_modes,
                )
        except Exception as rollback_exc:
            raise LocalObservabilityUpgradeError("rollback_failed", "rollback") from rollback_exc
        if isinstance(exc, LocalObservabilityUpgradeError):
            raise
        raise LocalObservabilityUpgradeError("activation_failed", "activate") from exc
    finally:
        shutil.rmtree(stage, ignore_errors=True)

    return LocalObservabilityUpgradeResult(
        installed=True,
        refreshed=bool(changed),
        was_running=was_running,
        stopped=stopped,
        restart_required=was_running,
        managed_paths=tuple(sorted(target_by_path)),
        changed_paths=tuple(changed),
        conflict_paths=tuple(sorted(conflicts)),
        preserved_custom_paths=custom,
        named_volumes=target.named_volumes,
        manifest_sha256=target.sha256,
    )


def _restore_local_observability_backup(
    destination: Path,
    backup_managed: Path,
    managed_paths: set[str],
    existing_paths: set[str],
    old_digests: dict[str, str],
    old_modes: dict[str, int],
) -> None:
    for relative in sorted(managed_paths):
        destination_path = destination / relative
        if relative in existing_paths:
            backup_path = backup_managed / relative
            if not backup_path.is_file() or backup_path.is_symlink():
                raise OSError("backup member missing")
            destination_path.parent.mkdir(parents=True, exist_ok=True)
            _atomic_copy_file(str(backup_path), str(destination_path))
            os.chmod(destination_path, old_modes[relative])
            if _sha256_file(destination_path) != old_digests[relative]:
                raise OSError("restored member digest mismatch")
        elif destination_path.exists() or destination_path.is_symlink():
            if destination_path.is_dir() and not destination_path.is_symlink():
                raise OSError("unexpected directory at managed file path")
            destination_path.unlink()


def _verify_activated_bundle(destination: Path, target: _BundleManifest) -> None:
    for entry in target.files:
        path = destination / entry.path
        _require_regular_file(destination, path, "activated")
        metadata = path.stat()
        if (
            metadata.st_size != entry.size
            or _sha256_file(path) != entry.sha256
            or stat.S_IMODE(metadata.st_mode) != entry.mode
        ):
            raise LocalObservabilityUpgradeError("activated_digest_mismatch", "verify")
    manifest_path = destination / _LOCAL_OBSERVABILITY_MANIFEST
    _require_regular_file(destination, manifest_path, "activated_manifest")
    if manifest_path.read_bytes() != target.raw:
        raise LocalObservabilityUpgradeError("activated_manifest_mismatch", "verify")


def _destination_only_files(destination: Path, managed_paths: set[str]) -> tuple[str, ...]:
    custom: list[str] = []
    for root, dirs, files in os.walk(destination, followlinks=False):
        root_path = Path(root)
        dirs[:] = [name for name in dirs if not (root_path / name).is_symlink()]
        for name in files:
            path = root_path / name
            relative = path.relative_to(destination).as_posix()
            if relative not in managed_paths:
                custom.append(relative)
    return tuple(sorted(custom))


def _strict_compose_project_running(project_name: str, *, timeout: float = 10.0) -> bool:
    docker = shutil.which("docker")
    if not docker:
        if _local_observability_ports_active():
            raise LocalObservabilityUpgradeError("docker_state_unknown", "stack_state")
        return False
    try:
        completed = subprocess.run(
            [
                docker,
                "ps",
                "--filter",
                f"label=com.docker.compose.project={project_name}",
                "--filter",
                "status=running",
                "--format",
                "{{.ID}}",
            ],
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        if _local_observability_ports_active():
            raise LocalObservabilityUpgradeError("docker_state_unknown", "stack_state") from exc
        return False
    if completed.returncode != 0:
        if _local_observability_ports_active():
            raise LocalObservabilityUpgradeError("docker_state_unknown", "stack_state")
        return False
    return bool((completed.stdout or "").strip())


def _local_observability_ports_active() -> bool:
    for port in (3000, 3100, 3200, 4317, 4318, 9090):
        try:
            with socket.create_connection(("127.0.0.1", port), timeout=0.05):
                return True
        except OSError:
            continue
    return False


def _bridge_contract_valid(stdout: str | None) -> bool:
    for line in (stdout or "").splitlines():
        if not line.lstrip().startswith("{"):
            continue
        try:
            document = json.loads(line)
        except json.JSONDecodeError:
            continue
        if (
            isinstance(document, dict)
            and document.get("otlp_endpoint")
            and document.get("grafana_url")
            and document.get("prometheus_url")
            and document.get("tempo_url")
            and document.get("loki_url")
        ):
            return True
    return False


def _live_local_observability_smoke(timeout: int) -> list[str]:
    deadline = time.monotonic() + max(timeout, 1)
    readiness = (
        ("collector", "http://127.0.0.1:13133/"),
        ("prometheus", "http://127.0.0.1:9090/-/ready"),
        ("loki", "http://127.0.0.1:3100/ready"),
        ("tempo", "http://127.0.0.1:3200/ready"),
        ("grafana", "http://127.0.0.1:3000/api/health"),
    )
    pending = dict(readiness)
    while pending and time.monotonic() < deadline:
        for name, url in tuple(pending.items()):
            if _http_ready(url):
                pending.pop(name, None)
        if pending:
            time.sleep(min(0.25, max(deadline - time.monotonic(), 0)))
    errors = [f"{name}_not_ready" for name in pending]
    if errors:
        return errors
    inventory_error = "grafana_inventory_unavailable"
    while time.monotonic() < deadline:
        try:
            search = _http_get_json("http://127.0.0.1:3000/api/search?type=dash-db")
        except (OSError, ValueError, urllib.error.URLError):
            inventory_error = "grafana_inventory_unavailable"
        else:
            if not isinstance(search, list):
                inventory_error = "grafana_inventory_invalid"
            else:
                observed = {
                    item.get("uid") for item in search if isinstance(item, dict) and isinstance(item.get("uid"), str)
                }
                if not set(_LOCAL_OBSERVABILITY_DASHBOARD_UIDS) - observed:
                    return []
                inventory_error = "grafana_dashboard_inventory_incomplete"
        time.sleep(min(0.25, max(deadline - time.monotonic(), 0)))
    return [inventory_error]


def _http_ready(url: str) -> bool:
    try:
        with urllib.request.urlopen(url, timeout=2) as response:  # noqa: S310 - fixed loopback URL
            return 200 <= response.status < 400
    except (OSError, urllib.error.URLError):
        return False


def _http_get_json(url: str) -> object:
    with urllib.request.urlopen(url, timeout=3) as response:  # noqa: S310 - fixed loopback URL
        if not 200 <= response.status < 300:
            raise OSError("unexpected HTTP status")
        raw = response.read(2 * 1024 * 1024 + 1)
        if len(raw) > 2 * 1024 * 1024:
            raise ValueError("response too large")
        return json.loads(raw)


def _validate_destination_ancestors(root: Path, path: Path) -> None:
    try:
        relative = path.relative_to(root)
    except ValueError as exc:
        raise LocalObservabilityUpgradeError("managed_path_escape", "preflight") from exc
    current = root
    for part in relative.parts[:-1]:
        current = current / part
        if current.is_symlink():
            raise LocalObservabilityUpgradeError("managed_parent_symlink", "preflight")
        if current.exists() and not current.is_dir():
            raise LocalObservabilityUpgradeError("managed_parent_not_directory", "preflight")


def _require_regular_file(root: Path, path: Path, phase: str) -> None:
    _validate_destination_ancestors(root, path)
    try:
        metadata = path.lstat()
    except OSError as exc:
        raise LocalObservabilityUpgradeError("managed_file_unreadable", phase) from exc
    if not stat.S_ISREG(metadata.st_mode):
        raise LocalObservabilityUpgradeError("managed_file_not_regular", phase)


def _safe_relative_path(value: object) -> str:
    if (
        not isinstance(value, str)
        or not value
        or "\\" in value
        or any(ord(char) < 32 or ord(char) == 127 for char in value)
    ):
        raise ValueError("invalid relative path")
    path = Path(value)
    if path.is_absolute() or ".." in path.parts or path.as_posix() != value:
        raise ValueError("invalid relative path")
    return value


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _mkdir_private(path: Path) -> None:
    path.mkdir(parents=True, exist_ok=True, mode=0o700)
    os.chmod(path, 0o700)


def _atomic_write_bytes(path: Path, raw: bytes, *, mode: int) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, temporary = tempfile.mkstemp(prefix=".bundle-", dir=path.parent)
    try:
        with os.fdopen(fd, "wb") as handle:
            handle.write(raw)
            handle.flush()
            os.fsync(handle.fileno())
        os.chmod(temporary, mode)
        os.replace(temporary, path)
        _fsync_directory(path.parent)
    except Exception:
        try:
            os.close(fd)
        except OSError:
            pass
        try:
            os.unlink(temporary)
        except OSError:
            pass
        raise


def _remove_retired_paths(
    dest: Path,
    retired_paths: tuple[str, ...],
) -> tuple[list[str], list[str]]:
    """Remove explicit bundle tombstones while preserving custom files."""
    removed: list[str] = []
    errors: list[str] = []
    root = dest.resolve()
    for rel in retired_paths:
        rel_path = Path(rel)
        if rel_path.is_absolute() or not rel_path.parts or ".." in rel_path.parts:
            errors.append(f"refused invalid retired path: {rel}")
            continue
        candidate = dest.joinpath(*rel_path.parts)
        try:
            candidate.resolve().relative_to(root)
        except ValueError:
            errors.append(f"refused retired path outside bundle root: {rel}")
            continue
        if not candidate.exists() and not candidate.is_symlink():
            continue
        reviewed_digests = _LOCAL_OBSERVABILITY_RETIRED_SHA256.get(rel)
        if not reviewed_digests:
            errors.append(f"refused unreviewed retired path: {rel}")
            continue
        if candidate.is_symlink() or not candidate.is_file():
            errors.append(f"refused non-regular retired path: {rel}")
            continue
        try:
            if _sha256_file(candidate) not in reviewed_digests:
                # A local file reusing a retired DefenseClaw filename is
                # operator-owned unless its bytes match a shipped asset.
                continue
        except OSError as exc:
            errors.append(f"inspect retired {rel}: {exc}")
            continue
        try:
            candidate.unlink()
        except OSError as exc:
            errors.append(f"remove retired {rel}: {exc}")
            continue
        removed.append(rel)
    return removed, errors


def _ensure_observability_executables(dest: str) -> None:
    """Make the bridge entry points executable after a refresh.

    Keeps parity with ``cmd_init._ensure_observability_stack_executables``
    — re-implemented here so the refresh module has zero dependencies on
    the (much larger) ``cmd_init`` import chain at import time.
    """
    for rel in (
        os.path.join("bin", "openclaw-observability-bridge"),
        "run.sh",
    ):
        path = os.path.join(dest, rel)
        if os.path.isfile(path):
            try:
                os.chmod(path, 0o755)
            except OSError:
                # Non-fatal — the bridge will fail loudly on first
                # invocation if it really lacks the +x bit, and we
                # don't want refresh() to abort over a chmod hiccup.
                pass


# ---------------------------------------------------------------------------
# Compose-project running detection
# ---------------------------------------------------------------------------


# Compose project label values used by each bundle — kept in lockstep
# with bundles/splunk_local_bridge/compose/docker-compose.local.yml
# (``name:`` field) and bundles/local_observability_stack/docker-compose.yml.
SPLUNK_COMPOSE_PROJECT: str = "defenseclaw-splunk-local"
LOCAL_OBSERVABILITY_COMPOSE_PROJECT: str = "defenseclaw-observability"


def is_compose_project_running(project_name: str, *, timeout: float = 5.0) -> bool:
    """Return True if a docker-compose project has at least one running container.

    Best-effort: returns False if Docker is missing/unreachable rather
    than raising. Callers use this to decide whether to stop the stack
    before refreshing the bundle on disk; a False here is correctly
    interpreted as "nothing to stop".
    """
    if not shutil.which("docker"):
        return False
    try:
        result = subprocess.run(
            [
                "docker",
                "ps",
                "--filter",
                f"label=com.docker.compose.project={project_name}",
                "--filter",
                "status=running",
                "--format",
                "{{.ID}}",
            ],
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired):
        return False
    if result.returncode != 0:
        return False
    return bool((result.stdout or "").strip())


# ---------------------------------------------------------------------------
# rsync-style overwrite primitive
# ---------------------------------------------------------------------------


def _rsync_overwrite(
    *,
    src: Path,
    dest: Path,
    preserve: tuple[str, ...],
) -> tuple[list[str], list[str], list[str]]:
    """Copy every file from ``src`` over ``dest``, except ``preserve`` paths.

    Returns ``(refreshed_paths, preserved_paths, errors)`` where each
    list contains the source-relative paths actually touched / kept /
    failed. ``preserve`` entries may be either files or directories;
    a directory in ``preserve`` shields its entire subtree.

    The copy goes through ``shutil.copy2 → tmp → os.replace`` per file
    so a crash during the loop leaves each file either fully old or
    fully new (never half-written). We do NOT prune dest-only files —
    the seeded copy can have generated artefacts (e.g.
    ``splunk/build/defenseclaw_local_mode.tgz``) that should outlive
    the refresh.
    """
    refreshed: list[str] = []
    preserved: list[str] = []
    errors: list[str] = []

    preserve_norm = tuple(p.strip("/") for p in preserve if p)

    for root, dirs, files in os.walk(src):
        rel_root = os.path.relpath(root, src)
        if rel_root == ".":
            rel_root = ""

        # Prune directories that match a preserve entry so we don't
        # descend into them at all. Track each as preserved so the
        # caller can show what survived.
        kept_dirs: list[str] = []
        for d in dirs:
            rel_dir = os.path.join(rel_root, d) if rel_root else d
            if _path_is_preserved(rel_dir, preserve_norm):
                preserved.append(rel_dir)
                continue
            kept_dirs.append(d)
        dirs[:] = kept_dirs

        for fname in files:
            rel_file = os.path.join(rel_root, fname) if rel_root else fname
            if _path_is_preserved(rel_file, preserve_norm):
                preserved.append(rel_file)
                continue

            src_path = os.path.join(root, fname)
            dest_path = os.path.join(str(dest), rel_file)
            try:
                os.makedirs(os.path.dirname(dest_path) or ".", exist_ok=True)
                _atomic_copy_file(src_path, dest_path)
            except OSError as exc:
                errors.append(f"{rel_file}: {exc}")
                continue
            refreshed.append(rel_file)

    return refreshed, preserved, errors


def _path_is_preserved(rel: str, preserve: tuple[str, ...]) -> bool:
    """Return True if ``rel`` exactly matches or is nested under any preserve entry."""
    rel_norm = rel.strip("/")
    for p in preserve:
        if rel_norm == p:
            return True
        if rel_norm.startswith(p + "/"):
            return True
    return False


def _atomic_copy_file(src_path: str, dest_path: str) -> None:
    """``shutil.copy2`` to a same-directory tmp file, then ``os.replace``.

    Preserves mode bits via ``copy2``. Same-directory tmp file is
    required because ``os.replace`` is only atomic on the same
    filesystem — a tmp in ``/tmp`` could land on a different mount
    on Linux when ``data_dir`` is on an external volume.
    """
    dest_dir = os.path.dirname(dest_path) or "."
    fd, tmp_path = tempfile.mkstemp(
        prefix=".refresh-",
        dir=dest_dir,
    )
    os.close(fd)
    try:
        shutil.copy2(src_path, tmp_path)
        with open(tmp_path, "rb") as temporary:
            os.fsync(temporary.fileno())
        os.replace(tmp_path, dest_path)
        _fsync_directory(Path(dest_dir))
    except OSError:
        # Best-effort cleanup of the orphan tmp; re-raise so the
        # caller logs the original failure.
        try:
            os.unlink(tmp_path)
        except OSError:
            pass
        raise


def _fsync_directory(path: Path) -> None:
    """Durably publish a same-directory rename where the platform supports it."""

    directory_flag = getattr(os, "O_DIRECTORY", None)
    if directory_flag is None:
        return
    fd = os.open(path, os.O_RDONLY | directory_flag)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


__all__ = [
    "LOCAL_OBSERVABILITY_COMPOSE_PROJECT",
    "LocalObservabilityUpgradeError",
    "LocalObservabilityUpgradeResult",
    "RefreshResult",
    "SPLUNK_COMPOSE_PROJECT",
    "is_compose_project_running",
    "refresh_local_observability_stack",
    "refresh_splunk_bridge",
    "restart_upgraded_local_observability_stack",
    "upgrade_local_observability_stack",
]
