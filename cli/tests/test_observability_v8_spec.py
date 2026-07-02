"""Regression tests for the tracked observability-v8 specification gate."""

from __future__ import annotations

import shutil
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
CHECKER = ROOT / "scripts" / "check_observability_v8_spec.py"
PACKAGE = ROOT / "docs" / "design" / "observability-v8"


def _run(package: Path = PACKAGE) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, str(CHECKER), "--package", str(package)],
        cwd=ROOT,
        check=False,
        capture_output=True,
        text=True,
        timeout=60,
    )


def _copy_package(tmp_path: Path) -> Path:
    target = tmp_path / "observability-v8"
    shutil.copytree(PACKAGE, target)
    return target


def test_observability_v8_spec_is_complete_and_traceable() -> None:
    result = _run()

    assert result.returncode == 0, result.stdout + result.stderr
    assert "D=22 S=12 P=47 total=81" in result.stdout


def test_observability_v8_spec_detects_missing_traceability(tmp_path: Path) -> None:
    package = _copy_package(tmp_path)
    path = package / "13-decision-traceability.md"
    text = path.read_text(encoding="utf-8")
    path.write_text(
        text.replace("| P-047 |", "| P-999 |", 1),
        encoding="utf-8",
    )

    result = _run(package)

    assert result.returncode == 1
    assert "decisions missing traceability rows: ['P-047']" in result.stderr
    assert "traceability rows without decisions: ['P-999']" in result.stderr


def test_observability_v8_spec_detects_broken_package_link(tmp_path: Path) -> None:
    package = _copy_package(tmp_path)
    path = package / "README.md"
    path.write_text(
        path.read_text(encoding="utf-8") + "\n[missing](not-present.md)\n",
        encoding="utf-8",
    )

    result = _run(package)

    assert result.returncode == 1
    assert "README.md: missing linked path 'not-present.md'" in result.stderr
