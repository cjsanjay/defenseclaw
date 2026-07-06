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

"""Exact P7-WP03 tests for the local-observability bundle transaction."""

from __future__ import annotations

import hashlib
import json
import os
import shutil
import stat
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest
from defenseclaw.bundle_refresh import (
    _LOCAL_OBSERVABILITY_DASHBOARD_UIDS,
    LocalObservabilityUpgradeError,
    _live_local_observability_smoke,
    restart_upgraded_local_observability_stack,
    upgrade_local_observability_stack,
)

ROOT = Path(__file__).resolve().parents[2]
REAL_BUNDLE = ROOT / "bundles" / "local_observability_stack"


@pytest.fixture()
def installed_bundle(tmp_path: Path) -> tuple[Path, Path, Path]:
    source = tmp_path / "target-bundle"
    data_dir = tmp_path / "data"
    destination = data_dir / "observability-stack"
    shutil.copytree(REAL_BUNDLE, source)
    shutil.copytree(source, destination)
    return source, data_dir, destination


def _upgrade(
    source: Path,
    data_dir: Path,
    backup: Path,
    *,
    version: str = "8.0.0",
    fault=None,
):
    with (
        patch("defenseclaw.bundle_refresh.bundled_local_observability_dir", return_value=source),
        patch("defenseclaw.bundle_refresh._strict_compose_project_running", return_value=False),
    ):
        return upgrade_local_observability_stack(
            str(data_dir),
            str(backup),
            bundle_version=version,
            fault_injector=fault,
        )


def _managed_snapshot(destination: Path) -> dict[str, tuple[bytes, int]]:
    result: dict[str, tuple[bytes, int]] = {}
    for path in sorted(destination.rglob("*")):
        if path.is_file() and not path.is_symlink():
            result[path.relative_to(destination).as_posix()] = (
                path.read_bytes(),
                stat.S_IMODE(path.stat().st_mode),
            )
    return result


def test_untouched_baseline_refreshes_without_false_conflict(
    installed_bundle: tuple[Path, Path, Path],
    tmp_path: Path,
) -> None:
    source, data_dir, destination = installed_bundle
    first = _upgrade(source, data_dir, tmp_path / "backup-1", version="7.9.0")
    assert first.conflict_paths == ()

    old = destination.joinpath("README.md").read_bytes()
    source.joinpath("README.md").write_bytes(old + b"\nnew target release\n")
    second = _upgrade(source, data_dir, tmp_path / "backup-2", version="8.0.0")

    assert second.refreshed is True
    assert "README.md" in second.changed_paths
    assert second.conflict_paths == ()
    assert destination.joinpath("README.md").read_bytes().endswith(b"new target release\n")
    assert (tmp_path / "backup-2/local-observability-stack/managed/README.md").read_bytes() == old


def test_custom_file_survives_and_managed_conflict_is_backed_up(
    installed_bundle: tuple[Path, Path, Path],
    tmp_path: Path,
) -> None:
    source, data_dir, destination = installed_bundle
    _upgrade(source, data_dir, tmp_path / "backup-1", version="7.9.0")
    custom = destination / "grafana/dashboards/team-custom.json"
    custom.write_text('{"uid":"team-custom"}\n', encoding="utf-8")
    managed = destination / "prometheus/prometheus.yml"
    operator_bytes = b"# operator modified managed config\n"
    managed.write_bytes(operator_bytes)

    result = _upgrade(source, data_dir, tmp_path / "backup-2", version="8.0.0")

    assert custom.read_text(encoding="utf-8") == '{"uid":"team-custom"}\n'
    assert "grafana/dashboards/team-custom.json" in result.preserved_custom_paths
    assert result.conflict_paths == ("prometheus/prometheus.yml",)
    conflict_backup = tmp_path / ("backup-2/local-observability-stack/managed/prometheus/prometheus.yml")
    assert conflict_backup.read_bytes() == operator_bytes
    if os.name != "nt":
        assert stat.S_IMODE((tmp_path / "backup-2/local-observability-stack").stat().st_mode) == 0o700
        assert stat.S_IMODE(conflict_backup.stat().st_mode) == 0o600
    assert managed.read_bytes() == source.joinpath("prometheus/prometheus.yml").read_bytes()


def test_installed_manifest_cannot_claim_and_delete_an_operator_file(
    installed_bundle: tuple[Path, Path, Path],
    tmp_path: Path,
) -> None:
    source, data_dir, destination = installed_bundle
    _upgrade(source, data_dir, tmp_path / "backup-1", version="7.9.0")
    custom = destination / "operator/private-notes.txt"
    custom.parent.mkdir()
    custom.write_bytes(b"must survive\n")
    manifest_path = destination / ".defenseclaw-bundle-manifest.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    manifest["files"].append(
        {
            "path": "operator/private-notes.txt",
            "sha256": hashlib.sha256(custom.read_bytes()).hexdigest(),
            "size": custom.stat().st_size,
            "mode": stat.S_IMODE(custom.stat().st_mode),
        }
    )
    manifest_path.write_text(json.dumps(manifest), encoding="utf-8")

    result = _upgrade(source, data_dir, tmp_path / "backup-2", version="8.0.0")

    assert custom.read_bytes() == b"must survive\n"
    assert "operator/private-notes.txt" in result.preserved_custom_paths


def test_retired_path_collision_is_preserved_when_bytes_are_not_a_shipped_asset(
    installed_bundle: tuple[Path, Path, Path],
    tmp_path: Path,
) -> None:
    source, data_dir, destination = installed_bundle
    retired = destination / "grafana/dashboards/defenseclaw-reliability.json"
    retired.write_bytes(b'{"uid":"operator-reliability"}\n')

    result = _upgrade(source, data_dir, tmp_path / "backup")

    assert retired.read_bytes() == b'{"uid":"operator-reliability"}\n'
    assert result.conflict_paths == ()
    assert "grafana/dashboards/defenseclaw-reliability.json" in result.preserved_custom_paths


def test_reviewed_retired_bundle_asset_is_backed_up_then_removed(
    installed_bundle: tuple[Path, Path, Path],
    tmp_path: Path,
) -> None:
    source, data_dir, destination = installed_bundle
    retired = destination / "grafana/dashboards/defenseclaw-reliability.json"
    retired_bytes = b'{"uid":"old-shipped-reliability"}\n'
    retired.write_bytes(retired_bytes)
    digest = hashlib.sha256(retired_bytes).hexdigest()

    with patch.dict(
        "defenseclaw.bundle_refresh._LOCAL_OBSERVABILITY_RETIRED_SHA256",
        {"grafana/dashboards/defenseclaw-reliability.json": frozenset({digest})},
        clear=True,
    ):
        result = _upgrade(source, data_dir, tmp_path / "backup")

    assert not retired.exists()
    assert result.conflict_paths == ()
    backup = tmp_path / ("backup/local-observability-stack/managed/grafana/dashboards/defenseclaw-reliability.json")
    assert backup.read_bytes() == retired_bytes


def test_named_volumes_are_declared_and_running_stack_uses_down_without_v(
    installed_bundle: tuple[Path, Path, Path],
    tmp_path: Path,
) -> None:
    source, data_dir, _destination = installed_bundle
    completed = MagicMock(returncode=0, stdout="", stderr="")
    with (
        patch("defenseclaw.bundle_refresh.bundled_local_observability_dir", return_value=source),
        patch(
            "defenseclaw.bundle_refresh._strict_compose_project_running",
            side_effect=[True, False],
        ),
        patch("defenseclaw.bundle_refresh.subprocess.run", return_value=completed) as run,
    ):
        result = upgrade_local_observability_stack(
            str(data_dir),
            str(tmp_path / "backup"),
            bundle_version="8.0.0",
        )

    assert result.was_running is True
    assert result.stopped is True
    assert result.restart_required is True
    assert result.named_volumes == (
        "grafana-data",
        "loki-data",
        "prometheus-data",
        "tempo-data",
    )
    command = run.call_args.args[0]
    assert command[-1] == "down"
    assert "-v" not in command
    assert "reset" not in command


def test_partial_activation_restores_exact_managed_tree_and_manifest(
    installed_bundle: tuple[Path, Path, Path],
    tmp_path: Path,
) -> None:
    source, data_dir, destination = installed_bundle
    _upgrade(source, data_dir, tmp_path / "backup-1", version="7.9.0")
    custom = destination / "grafana/dashboards/team-custom.json"
    custom.write_text('{"uid":"team-custom"}\n', encoding="utf-8")
    source.joinpath("README.md").write_text("replacement\n", encoding="utf-8")
    before = _managed_snapshot(destination)

    def fail_after_first_write(event: str, path: str | None) -> None:
        if event == "after_activate" and path == "README.md":
            raise OSError("injected write failure")

    with pytest.raises(LocalObservabilityUpgradeError, match="activation_failed"):
        _upgrade(
            source,
            data_dir,
            tmp_path / "backup-2",
            version="8.0.0",
            fault=fail_after_first_write,
        )

    assert _managed_snapshot(destination) == before
    assert custom.read_text(encoding="utf-8") == '{"uid":"team-custom"}\n'


def test_stop_failure_prevents_refresh_and_leaves_bytes_untouched(
    installed_bundle: tuple[Path, Path, Path],
    tmp_path: Path,
) -> None:
    source, data_dir, destination = installed_bundle
    before = _managed_snapshot(destination)
    with (
        patch("defenseclaw.bundle_refresh.bundled_local_observability_dir", return_value=source),
        patch("defenseclaw.bundle_refresh._strict_compose_project_running", return_value=True),
        patch(
            "defenseclaw.bundle_refresh.subprocess.run",
            return_value=MagicMock(returncode=1, stdout="", stderr="failure"),
        ),
        pytest.raises(LocalObservabilityUpgradeError, match="stack_stop_failed"),
    ):
        upgrade_local_observability_stack(
            str(data_dir),
            str(tmp_path / "backup"),
            bundle_version="8.0.0",
        )
    assert _managed_snapshot(destination) == before
    assert not (tmp_path / "backup/local-observability-stack").exists()


def test_same_target_retry_is_idempotent(
    installed_bundle: tuple[Path, Path, Path],
    tmp_path: Path,
) -> None:
    source, data_dir, destination = installed_bundle
    custom = destination / "grafana/dashboards/team-custom.json"
    custom.write_text('{"uid":"team-custom"}\n', encoding="utf-8")
    first = _upgrade(source, data_dir, tmp_path / "backup-1")
    first_manifest = destination.joinpath(".defenseclaw-bundle-manifest.json").read_bytes()
    second = _upgrade(source, data_dir, tmp_path / "backup-2")

    assert first.refreshed is True
    assert second.refreshed is False
    assert second.changed_paths == ()
    assert second.conflict_paths == ()
    assert destination.joinpath(".defenseclaw-bundle-manifest.json").read_bytes() == first_manifest
    assert custom.exists()


def test_non_local_bundle_install_is_a_noop_before_docker_or_source_lookup(
    tmp_path: Path,
) -> None:
    data_dir = tmp_path / "data"
    data_dir.mkdir()
    with (
        patch("defenseclaw.bundle_refresh.bundled_local_observability_dir") as source,
        patch("defenseclaw.bundle_refresh._strict_compose_project_running") as running,
    ):
        result = upgrade_local_observability_stack(
            str(data_dir),
            str(tmp_path / "backup"),
            bundle_version="8.0.0",
        )
    assert result.installed is False
    source.assert_not_called()
    running.assert_not_called()


def test_seeded_but_unused_bundle_refreshes_without_docker(
    installed_bundle: tuple[Path, Path, Path],
    tmp_path: Path,
) -> None:
    source, data_dir, _destination = installed_bundle
    with (
        patch("defenseclaw.bundle_refresh.bundled_local_observability_dir", return_value=source),
        patch("defenseclaw.bundle_refresh.shutil.which", return_value=None),
        patch("defenseclaw.bundle_refresh._local_observability_ports_active", return_value=False),
    ):
        result = upgrade_local_observability_stack(
            str(data_dir),
            str(tmp_path / "backup"),
            bundle_version="8.0.0",
        )
    assert result.installed is True
    assert result.was_running is False
    assert result.restart_required is False


def test_uninspectable_active_stack_fails_before_backup(
    installed_bundle: tuple[Path, Path, Path],
    tmp_path: Path,
) -> None:
    source, data_dir, _destination = installed_bundle
    with (
        patch("defenseclaw.bundle_refresh.bundled_local_observability_dir", return_value=source),
        patch("defenseclaw.bundle_refresh.shutil.which", return_value=None),
        patch("defenseclaw.bundle_refresh._local_observability_ports_active", return_value=True),
        pytest.raises(LocalObservabilityUpgradeError, match="docker_state_unknown"),
    ):
        upgrade_local_observability_stack(
            str(data_dir),
            str(tmp_path / "backup"),
            bundle_version="8.0.0",
        )
    assert not (tmp_path / "backup/local-observability-stack").exists()


def test_restart_smoke_never_uses_reset_and_reports_success(
    installed_bundle: tuple[Path, Path, Path],
) -> None:
    _source, data_dir, _destination = installed_bundle
    contract = (
        '{"otlp_endpoint":"127.0.0.1:4317",'
        '"grafana_url":"http://localhost:3000",'
        '"prometheus_url":"http://localhost:9090",'
        '"tempo_url":"http://localhost:3200",'
        '"loki_url":"http://localhost:3100"}\n'
    )
    with (
        patch(
            "defenseclaw.bundle_refresh.subprocess.run",
            return_value=MagicMock(returncode=0, stdout=contract, stderr=""),
        ) as run,
        patch("defenseclaw.bundle_refresh._live_local_observability_smoke", return_value=[]),
    ):
        result = restart_upgraded_local_observability_stack(str(data_dir), timeout=5)

    assert result.restarted is True
    command = run.call_args.args[0]
    assert command[1] == "up"
    assert "reset" not in command
    assert "-v" not in command


def test_live_smoke_requires_every_readiness_probe_and_dashboard_uid() -> None:
    complete = [{"uid": uid} for uid in _LOCAL_OBSERVABILITY_DASHBOARD_UIDS]
    with (
        patch("defenseclaw.bundle_refresh._http_ready", return_value=True) as ready,
        patch("defenseclaw.bundle_refresh._http_get_json", return_value=complete),
    ):
        assert _live_local_observability_smoke(1) == []
    assert ready.call_count == 5

    with (
        patch("defenseclaw.bundle_refresh._http_ready", return_value=True),
        patch("defenseclaw.bundle_refresh._http_get_json", return_value=complete[:-1]),
    ):
        assert _live_local_observability_smoke(1) == ["grafana_dashboard_inventory_incomplete"]


@pytest.mark.skipif(os.name == "nt", reason="symlink semantics require POSIX")
def test_managed_parent_symlink_fails_before_stack_state_or_backup(
    installed_bundle: tuple[Path, Path, Path],
    tmp_path: Path,
) -> None:
    source, data_dir, destination = installed_bundle
    shutil.rmtree(destination / "prometheus")
    outside = tmp_path / "outside"
    outside.mkdir()
    (destination / "prometheus").symlink_to(outside, target_is_directory=True)
    with (
        patch("defenseclaw.bundle_refresh.bundled_local_observability_dir", return_value=source),
        patch("defenseclaw.bundle_refresh._strict_compose_project_running") as running,
        pytest.raises(LocalObservabilityUpgradeError, match="managed_parent_symlink"),
    ):
        upgrade_local_observability_stack(
            str(data_dir),
            str(tmp_path / "backup"),
            bundle_version="8.0.0",
        )
    running.assert_not_called()
    assert not (tmp_path / "backup/local-observability-stack").exists()


@pytest.mark.skipif(os.name == "nt", reason="symlink semantics require POSIX")
def test_backup_root_symlink_is_rejected_before_copy(
    installed_bundle: tuple[Path, Path, Path],
    tmp_path: Path,
) -> None:
    source, data_dir, _destination = installed_bundle
    outside = tmp_path / "outside"
    outside.mkdir()
    backup = tmp_path / "backup"
    backup.symlink_to(outside, target_is_directory=True)
    with (
        patch("defenseclaw.bundle_refresh.bundled_local_observability_dir", return_value=source),
        patch("defenseclaw.bundle_refresh._strict_compose_project_running", return_value=False),
        pytest.raises(LocalObservabilityUpgradeError, match="unsafe_backup_root"),
    ):
        upgrade_local_observability_stack(
            str(data_dir),
            str(backup),
            bundle_version="8.0.0",
        )
    assert list(outside.iterdir()) == []


@pytest.mark.skipif(os.name == "nt", reason="symlink semantics require POSIX")
def test_dangling_install_root_symlink_is_not_treated_as_absent(tmp_path: Path) -> None:
    data_dir = tmp_path / "data"
    data_dir.mkdir()
    (data_dir / "observability-stack").symlink_to(tmp_path / "missing")

    with pytest.raises(LocalObservabilityUpgradeError, match="unsafe_install_root"):
        upgrade_local_observability_stack(
            str(data_dir),
            str(tmp_path / "backup"),
            bundle_version="8.0.0",
        )
