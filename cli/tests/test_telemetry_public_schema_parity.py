# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

import copy
import hashlib
import importlib.util
import json
import os
import sys
from collections.abc import Mapping
from pathlib import Path
from types import ModuleType
from typing import Any

import pytest
import yaml

ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / "scripts" / "check_telemetry_public_schema_parity.py"
MANIFEST = ROOT / "schemas/telemetry/v8/fixtures/legacy-public-schema-parity-v1/manifest.json"
PUBLIC_VIEWS = ROOT / "schemas/telemetry/v8/public-views.yaml"


def _load_module() -> ModuleType:
    spec = importlib.util.spec_from_file_location("check_telemetry_public_schema_parity", SCRIPT)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


parity = _load_module()


@pytest.mark.parametrize("preload", ["foreign-module", "same-path-object-spoof"])
def test_checker_rejects_noncanonical_preloaded_generated_transaction(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    preload: str,
) -> None:
    name = "telemetry_generated_transaction"
    if preload == "foreign-module":
        foreign = tmp_path / f"{name}.py"
        foreign.write_text("# foreign transaction helper\n", encoding="utf-8")
        spec = importlib.util.spec_from_file_location(name, foreign)
        assert spec is not None and spec.loader is not None
        existing = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(existing)
        diagnostic = "foreign provenance"
    else:
        existing = object()
        diagnostic = "unsafe"
    monkeypatch.setitem(sys.modules, name, existing)

    with pytest.raises(RuntimeError, match=diagnostic):
        parity._load_generated_transaction()


def test_generated_transaction_loader_uses_package_identity(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(parity, "_PARITY_PACKAGE_MODE", True)
    monkeypatch.delitem(sys.modules, "telemetry_generated_transaction", raising=False)
    monkeypatch.delitem(sys.modules, "scripts.telemetry_generated_transaction", raising=False)

    loaded = parity._load_generated_transaction()

    assert loaded.__name__ == "scripts.telemetry_generated_transaction"
    assert parity._load_generated_transaction() is loaded


def test_generated_transaction_loader_rejects_opposite_identity(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setitem(
        sys.modules,
        "scripts.telemetry_generated_transaction",
        parity.generated_transaction,
    )

    with pytest.raises(RuntimeError, match="conflicting identity"):
        parity._load_generated_transaction()


@pytest.mark.parametrize("preload", ["foreign-module", "same-path-object-spoof"])
def test_checker_rejects_noncanonical_preloaded_baseline_reader(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    preload: str,
) -> None:
    name = "telemetry_public_schema_baseline"
    if preload == "foreign-module":
        foreign = tmp_path / f"{name}.py"
        foreign.write_text("# foreign reader\n", encoding="utf-8")
        spec = importlib.util.spec_from_file_location(name, foreign)
        assert spec is not None and spec.loader is not None
        existing = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(existing)
        diagnostic = "foreign provenance"
    else:
        existing = object()
        diagnostic = "unsafe"
    monkeypatch.setitem(sys.modules, name, existing)

    with pytest.raises(RuntimeError, match=diagnostic):
        parity._load_baseline_reader()


def test_checker_baseline_reader_exec_failure_cleans_canonical_identity(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    name = "telemetry_public_schema_baseline"
    monkeypatch.delitem(sys.modules, name, raising=False)
    real_spec_from_file_location = parity.importlib.util.spec_from_file_location

    class FailingLoader:
        def create_module(self, _spec: Any) -> None:
            return None

        def exec_module(self, _module: ModuleType) -> None:
            raise RuntimeError("injected baseline-reader import failure")

    def failing_spec(module_name: str, path: Path) -> Any:
        if module_name == name:
            return importlib.util.spec_from_loader(module_name, FailingLoader(), origin=str(path))
        return real_spec_from_file_location(module_name, path)

    monkeypatch.setattr(parity.importlib.util, "spec_from_file_location", failing_spec)

    with pytest.raises(RuntimeError, match="injected baseline-reader import failure"):
        parity._load_baseline_reader()

    assert name not in sys.modules


def _canonical_json(value: Any) -> bytes:
    return (json.dumps(value, ensure_ascii=False, indent=2, sort_keys=True) + "\n").encode()


def _manifest(**updates: Any) -> bytes:
    value = json.loads(MANIFEST.read_bytes())
    value.update(updates)
    return _canonical_json(value)


def _public_views() -> dict[str, Any]:
    value = yaml.safe_load(PUBLIC_VIEWS.read_bytes())
    assert isinstance(value, dict)
    return value


def _public_views_and_manifest(value: Mapping[str, Any]) -> tuple[bytes, bytes]:
    raw = yaml.safe_dump(dict(value), sort_keys=False).encode()
    return raw, _manifest(public_views_sha256=hashlib.sha256(raw).hexdigest())


def _live_candidates() -> dict[str, bytes]:
    public_views = _public_views()
    candidates: dict[str, bytes] = {}
    for view in public_views["views"]:
        paths = {
            view["output_path"],
            *view["targets"]["mirrors"],
            *view["targets"]["embeds"],
        }
        for path in paths:
            candidates[path] = (ROOT / path).read_bytes()
    assert len(candidates) == 26
    return candidates


def _mutated_live_candidates(output_path: str, raw: bytes) -> dict[str, bytes]:
    public_views = _public_views()
    view = next(item for item in public_views["views"] if item["output_path"] == output_path)
    candidates = _live_candidates()
    for path in {output_path, *view["targets"]["mirrors"], *view["targets"]["embeds"]}:
        candidates[path] = raw
    return candidates


def _candidate_document(output_path: str) -> dict[str, Any]:
    value = json.loads(_live_candidates()[output_path])
    assert isinstance(value, dict)
    return value


def _first_ref(value: Any) -> tuple[dict[str, Any], str]:
    if isinstance(value, dict):
        reference = value.get("$ref")
        if isinstance(reference, str):
            return value, reference
        for child in value.values():
            try:
                return _first_ref(child)
            except LookupError:
                pass
    elif isinstance(value, list):
        for child in value:
            try:
                return _first_ref(child)
            except LookupError:
                pass
    raise LookupError("document has no reference")


def test_corpus_proves_exact_inventory_and_derived_coverage() -> None:
    report = parity.check_repository(ROOT)

    assert (report.views, report.outputs) == (21, 26)
    assert (report.fields, report.dynamic_scopes) == (756, 94)
    assert (report.references, report.number_lexemes) == (39, 162)
    assert report.valid_witnesses >= report.views
    assert report.invalid_witnesses >= report.views
    assert report.required_omissions > 0
    assert report.closed_extras > 0
    assert set(report.boundary_cases) == set(parity.BOUNDARY_STRATEGIES)
    assert all(count > 0 for count in report.boundary_cases.values())


def test_marker_mutation_is_rejected() -> None:
    output_path = "schemas/audit-event.json"
    candidate = _candidate_document(output_path)
    candidate[parity.MARKER_KEY]["baseline_epoch"] = "mutated"

    with pytest.raises(parity.ParityError, match="marker drift"):
        parity.check_repository(
            ROOT,
            candidate_overrides=_mutated_live_candidates(output_path, _canonical_json(candidate)),
        )


def test_public_view_path_mutation_is_rejected() -> None:
    public_views = _public_views()
    public_views["views"][0]["output_path"] = "schemas/mutated-activity-event.json"
    public_raw, manifest_raw = _public_views_and_manifest(public_views)

    with pytest.raises(parity.ParityError, match="path inventory differs from baseline"):
        parity.check_repository(
            ROOT,
            manifest_bytes=manifest_raw,
            public_views_bytes=public_raw,
        )


def test_reference_mutation_is_rejected_by_reference_inventory() -> None:
    output_path = "schemas/gateway-event-envelope.json"
    candidate = _candidate_document(output_path)
    owner, reference = _first_ref(candidate)
    owner["$ref"] = f"{reference}-mutated"

    with pytest.raises(parity.ParityError, match="reference inventory drift"):
        parity.check_repository(
            ROOT,
            candidate_overrides=_mutated_live_candidates(output_path, _canonical_json(candidate)),
        )


def test_number_token_mutation_is_rejected_losslessly() -> None:
    output_path = "schemas/audit-event.json"
    candidate = _candidate_document(output_path)
    candidate["properties"]["generation"]["minimum"] = 0.0

    with pytest.raises(parity.ParityError, match="number-lexeme drift"):
        parity.check_repository(
            ROOT,
            candidate_overrides=_mutated_live_candidates(output_path, _canonical_json(candidate)),
        )


def test_witness_strategy_mutation_is_rejected() -> None:
    with pytest.raises(parity.ParityError, match="manifest contract drift"):
        parity.check_repository(
            ROOT,
            manifest_bytes=_manifest(valid_witness_strategy="mutated"),
        )


def test_field_coverage_mutation_is_rejected() -> None:
    public_views = copy.deepcopy(_public_views())
    public_views["views"][0]["field_dispositions"][0]["fixture_coverage"] = []
    public_raw, manifest_raw = _public_views_and_manifest(public_views)

    with pytest.raises(parity.ParityError, match="field fixture coverage drift"):
        parity.check_repository(
            ROOT,
            manifest_bytes=manifest_raw,
            public_views_bytes=public_raw,
        )


def test_live_mirror_mutation_is_rejected() -> None:
    candidates = _live_candidates()
    public_views = _public_views()
    view = next(item for item in public_views["views"] if item["targets"]["mirrors"])
    candidates[view["targets"]["mirrors"][0]] = b"{}\n"

    with pytest.raises(parity.ParityError, match="live mirror/embed byte drift"):
        parity.check_repository(ROOT, candidate_overrides=candidates)


def test_live_candidate_reader_reads_safe_direct_file(tmp_path: Path) -> None:
    candidate = tmp_path / "schemas" / "candidate.json"
    candidate.parent.mkdir()
    candidate.write_bytes(b"{}\n")

    assert parity._read_live_candidate(tmp_path, "schemas/candidate.json") == b"{}\n"


def test_live_candidate_reader_rejects_symlink(tmp_path: Path) -> None:
    target = tmp_path / "target.json"
    target.write_text("{}\n", encoding="utf-8")
    candidate = tmp_path / "schemas" / "candidate.json"
    candidate.parent.mkdir()
    try:
        candidate.symlink_to(target)
    except OSError:
        pytest.skip("platform does not permit test symlinks")

    with pytest.raises(parity.ParityError, match="unsafe or unreadable"):
        parity._read_live_candidate(tmp_path, "schemas/candidate.json")


def test_live_candidate_reader_rejects_hard_link(tmp_path: Path) -> None:
    target = tmp_path / "target.json"
    target.write_bytes(b"{}\n")
    candidate = tmp_path / "schemas" / "candidate.json"
    candidate.parent.mkdir()
    try:
        os.link(target, candidate)
    except OSError:
        pytest.skip("platform does not permit test hard links")

    with pytest.raises(parity.ParityError, match="unsafe or unreadable"):
        parity._read_live_candidate(tmp_path, "schemas/candidate.json")


def test_live_candidate_reader_rejects_path_swapped_to_symlink_before_open(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    candidate = tmp_path / "schemas" / "candidate.json"
    candidate.parent.mkdir()
    candidate.write_bytes(b"{}\n")
    outside = tmp_path / "outside.json"
    outside.write_bytes(b'{"unsafe": true}\n')
    original_read = parity.generated_transaction.read_repository_file_bounded

    def swap_then_read(root: Path, relative: str, *, maximum: int) -> bytes:
        (root / relative).replace(root / "original.json")
        (root / relative).symlink_to(outside)
        return original_read(root, relative, maximum=maximum)

    monkeypatch.setattr(
        parity.generated_transaction,
        "read_repository_file_bounded",
        swap_then_read,
    )

    with pytest.raises(parity.ParityError, match="unsafe or unreadable"):
        parity._read_live_candidate(tmp_path, "schemas/candidate.json")


def test_live_candidate_reader_rejects_directory_entry_swapped_during_read(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    candidate = tmp_path / "schemas" / "candidate.json"
    candidate.parent.mkdir()
    candidate.write_bytes(b"{}\n")
    original_read = parity.generated_transaction.os.read
    swapped = False

    def swap_after_read(descriptor: int, maximum: int) -> bytes:
        nonlocal swapped
        chunk = original_read(descriptor, maximum)
        if not swapped:
            swapped = True
            candidate.replace(tmp_path / "original.json")
            candidate.write_bytes(b'{"replacement": true}\n')
        return chunk

    monkeypatch.setattr(parity.generated_transaction.os, "read", swap_after_read)

    with pytest.raises(parity.ParityError, match="unsafe or unreadable"):
        parity._read_live_candidate(tmp_path, "schemas/candidate.json")
    assert swapped


def test_live_candidate_reader_rejects_oversized_file(tmp_path: Path) -> None:
    candidate = tmp_path / "schemas" / "candidate.json"
    candidate.parent.mkdir()
    candidate.write_bytes(b"x" * (parity.MAX_LIVE_PUBLIC_VIEW_BYTES + 1))

    with pytest.raises(parity.ParityError, match="unsafe or unreadable"):
        parity._read_live_candidate(tmp_path, "schemas/candidate.json")


def test_live_candidate_reader_rejects_missing_file(tmp_path: Path) -> None:
    (tmp_path / "schemas").mkdir()

    with pytest.raises(parity.ParityError, match="unsafe or unreadable"):
        parity._read_live_candidate(tmp_path, "schemas/candidate.json")


def test_candidate_overrides_still_read_every_declared_live_path(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    candidates = _live_candidates()
    observed: list[str] = []
    original_read = parity._read_live_candidate

    def observing_read(root: Path, relative: str) -> bytes:
        observed.append(relative)
        return original_read(root, relative)

    monkeypatch.setattr(parity, "_read_live_candidate", observing_read)

    parity.check_repository(ROOT, candidate_overrides=candidates)

    assert len(observed) == 26
    assert set(observed) == set(candidates)
