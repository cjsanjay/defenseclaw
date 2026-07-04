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
    repository = tmp_path / "repository"
    target = repository / "docs" / "design" / "observability-v8"
    repository.mkdir()
    shutil.copy2(ROOT / "spec.md", repository / "spec.md")
    target.parent.mkdir(parents=True)
    shutil.copytree(PACKAGE, target)
    return target


def test_observability_v8_spec_is_complete_and_traceable() -> None:
    result = _run()

    assert result.returncode == 0, result.stdout + result.stderr
    assert "D=22 S=12 P=67 total=101" in result.stdout


def test_observability_v8_redaction_contract_locks_machine_boundaries() -> None:
    redaction = (PACKAGE / "04-redaction-contract.md").read_text(encoding="utf-8")
    verification = (PACKAGE / "07-verification-and-acceptance.md").read_text(encoding="utf-8")
    traceability = (PACKAGE / "13-decision-traceability.md").read_text(encoding="utf-8")

    assert "| `credential` | `preserve` | `remove` | `remove` | `remove` |" in redaction
    assert "schemas/telemetry/v8/redaction/detector-catalog-v1.yaml" in redaction
    assert "raw|inspected|transformed|failed_closed" in redaction
    assert "at most 4,198,400 bytes" in redaction
    assert "unicode-age-13.0.json" in redaction
    assert "projection_context_mismatch" in redaction
    assert "one shared success/error fixture" in redaction
    assert "`P-001` through `P-067`" in verification
    assert "| P-038 | 04 §7.6 | 07 §6.3 |" in traceability


def test_observability_v8_delivery_contract_locks_machine_boundaries() -> None:
    configuration = (PACKAGE / "03-configuration-contract.md").read_text(
        encoding="utf-8",
    )
    storage = (PACKAGE / "05-storage-retention-and-delivery.md").read_text(
        encoding="utf-8",
    )
    traceability = (PACKAGE / "13-decision-traceability.md").read_text(
        encoding="utf-8",
    )

    assert "`batch.max_queue_bytes`" in configuration
    assert "`batch.max_export_batch_bytes`" in configuration
    assert "newest attempted enqueue is dropped" in storage
    assert "immutable projection selected and redacted for that" in storage
    assert "Splunk destination" in storage
    assert "| P-062 | 01 §10; 03 §§1.1,2.1,4.4; 05 §§6-7 |" in traceability
    assert "| P-063 | 03 §4.4; 05 §7.1 |" in traceability


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


def test_observability_v8_spec_ignores_rows_and_links_in_fences(tmp_path: Path) -> None:
    package = _copy_package(tmp_path)
    path = package / "README.md"
    path.write_text(
        path.read_text(encoding="utf-8")
        + "\n```markdown\n"
        + "| D-001 | illustrative duplicate |\n"
        + "| P-999 | illustrative contract | illustrative test |\n"
        + "[illustrative missing link](not-present.md)\n"
        + "```\n",
        encoding="utf-8",
    )

    result = _run(package)

    assert result.returncode == 0, result.stdout + result.stderr


def test_observability_v8_spec_detects_unclosed_tilde_fence(tmp_path: Path) -> None:
    package = _copy_package(tmp_path)
    path = package / "README.md"
    path.write_text(
        path.read_text(encoding="utf-8") + "\n~~~yaml\nunclosed: true\n",
        encoding="utf-8",
    )

    result = _run(package)

    assert result.returncode == 1
    assert "README.md: unbalanced fenced code blocks" in result.stderr
