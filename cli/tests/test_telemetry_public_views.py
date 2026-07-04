# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

import importlib.util
import json
import subprocess
import sys
from collections.abc import Callable
from pathlib import Path
from types import ModuleType

import pytest

ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / "scripts" / "update_telemetry_public_views.py"


def _load_module() -> ModuleType:
    spec = importlib.util.spec_from_file_location("update_telemetry_public_views", SCRIPT)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


public_views = _load_module()


def _git(repo: Path, *arguments: str) -> str:
    result = subprocess.run(
        ["git", "-C", str(repo), *arguments],
        check=True,
        capture_output=True,
        text=True,
    )
    return result.stdout.strip()


def _commit(repo: Path, message: str) -> str:
    _git(repo, "add", "schemas")
    _git(repo, "commit", "-m", message)
    commit = _git(repo, "rev-parse", "HEAD")
    assert len(commit) == 40
    return commit


def _base_document(path: str, *, reverse: bool = False) -> bytes:
    dialect, schema_id = public_views.IDENTITY_BY_PATH[path]
    entries = [
        ("$schema", dialect),
        ("$id", schema_id),
        ("title", path),
        ("type", "object"),
        (
            "properties",
            {
                "z": {"type": "string"},
                "a": {"type": "string"},
            },
        ),
    ]
    if reverse:
        entries.reverse()
    document = dict(entries)
    if path == "schemas/gateway-event-envelope.json":
        document["properties"].update(
            {
                "activity": {"$ref": ("https://defenseclaw.io/schemas/activity-event.json#/properties/a")},
                "scan": {"$ref": ("https://defenseclaw.io/schemas/scan-event.json#/properties/a")},
                "scan_finding": {"$ref": ("https://defenseclaw.io/schemas/scan-finding-event.json#/properties/a")},
            }
        )
    return (json.dumps(document, ensure_ascii=False, indent=2) + "\n").encode()


@pytest.fixture
def repo_factory(tmp_path: Path) -> Callable[..., tuple[Path, str]]:
    counter = 0

    def create(
        *,
        overrides: dict[str, bytes | None] | None = None,
        reverse: bool = False,
        manifest: dict | bytes | None = None,
    ) -> tuple[Path, str]:
        nonlocal counter
        counter += 1
        repo = tmp_path / f"repo-{counter}"
        repo.mkdir()
        _git(repo, "init")
        _git(repo, "config", "user.email", "telemetry-test@example.invalid")
        _git(repo, "config", "user.name", "Telemetry Test")
        overrides = overrides or {}
        for path, _dialect, _schema_id in public_views.PUBLIC_SCHEMA_IDENTITIES:
            raw = overrides.get(path, _base_document(path, reverse=reverse))
            if raw is None:
                continue
            target = repo / path
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(raw)
        if manifest is not None:
            target = repo / public_views.GENERATED_OUTPUT_MANIFEST_PATH
            target.parent.mkdir(parents=True, exist_ok=True)
            manifest_raw = manifest if isinstance(manifest, bytes) else (json.dumps(manifest, indent=2) + "\n").encode()
            target.write_bytes(manifest_raw)
        return repo, _commit(repo, "seed public schemas")

    return create


def _run(
    repo: Path,
    baseline: Path,
    command: str,
    *arguments: str,
) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [
            sys.executable,
            str(SCRIPT),
            "--root",
            str(repo),
            "--baseline",
            str(baseline),
            command,
            *arguments,
        ],
        check=False,
        capture_output=True,
        text=True,
    )


def _bootstrap(repo: Path, commit: str, baseline: Path) -> None:
    result = _run(repo, baseline, "bootstrap", "--source-ref", commit, "--write")
    assert result.returncode == 0, result.stderr


def _read_baseline(path: Path) -> dict:
    value = public_views.parse_lossless_json(path.read_bytes(), str(path))
    assert isinstance(value, dict)
    return value


def _write_baseline(path: Path, value: dict) -> None:
    path.write_bytes(public_views.render_lossless_json(value, pretty=True))


def test_bootstrap_records_exact_inventory_git_provenance_and_checks(
    repo_factory: Callable[..., tuple[Path, str]],
) -> None:
    repo, commit = repo_factory()
    baseline = repo / "baseline.json"
    _bootstrap(repo, commit, baseline)

    document = _read_baseline(baseline)
    resources = document["resources"]
    assert len(resources) == 21
    assert [resource["path"] for resource in resources] == [item[0] for item in public_views.PUBLIC_SCHEMA_IDENTITIES]
    assert document["source"] == {
        "commit": commit,
        "tree": _git(repo, "rev-parse", f"{commit}^{{tree}}"),
    }
    for resource in resources:
        assert resource["git_blob_oid"] == _git(repo, "rev-parse", f"{commit}:{resource['path']}")
        assert len(resource["source_sha256"]) == 64
        assert len(resource["canonical_sha256"]) == 64

    checked = _run(repo, baseline, "check")
    assert checked.returncode == 0, checked.stderr


def test_exact_number_lexemes_and_unicode_strings_survive_round_trip(
    repo_factory: Callable[..., tuple[Path, str]],
) -> None:
    path = "schemas/activity-event.json"
    dialect, schema_id = public_views.IDENTITY_BY_PATH[path]
    raw = (
        "{\n"
        f'  "$schema": {json.dumps(dialect)},\n'
        f'  "$id": {json.dumps(schema_id)},\n'
        '  "title": "é é",\n'
        '  "type": "object",\n'
        '  "properties": {"a": {"type": "string"}},\n'
        '  "x-numbers": [0.0, 1.0, 900719925474099312345, 1e-7, 1E+9, -0]\n'
        "}\n"
    ).encode()
    repo, commit = repo_factory(overrides={path: raw})
    baseline = repo / "baseline.json"
    _bootstrap(repo, commit, baseline)

    document = _read_baseline(baseline)
    resource = next(item for item in document["resources"] if item["path"] == path)
    assert resource["number_lexemes"] == {
        "/x-numbers/0": "0.0",
        "/x-numbers/1": "1.0",
        "/x-numbers/2": "900719925474099312345",
        "/x-numbers/3": "1e-7",
        "/x-numbers/4": "1E+9",
        "/x-numbers/5": "-0",
    }
    rendered = public_views.render_lossless_json(resource["document"], pretty=False)
    assert b"[0.0,1.0,900719925474099312345,1e-7,1E+9,-0]" in rendered
    assert "é é" in rendered.decode("utf-8")
    assert _run(repo, baseline, "check").returncode == 0


@pytest.mark.parametrize(
    ("replacement", "diagnostic"),
    [
        (b'{"$schema":"x","$schema":"x"}', "duplicate JSON object keys"),
        (b'{"value":"\\ud800"}', "lone Unicode surrogates"),
        (b'{"value":NaN}', "non-finite JSON number"),
        (b'{"value":Infinity}', "non-finite JSON number"),
        (b'{"value":"\xff"}', "invalid UTF-8"),
    ],
)
def test_strict_json_failures_are_rejected_before_any_write(
    repo_factory: Callable[..., tuple[Path, str]],
    replacement: bytes,
    diagnostic: str,
) -> None:
    path = "schemas/activity-event.json"
    repo, commit = repo_factory(overrides={path: replacement})
    baseline = repo / "baseline.json"
    result = _run(repo, baseline, "bootstrap", "--source-ref", commit, "--write")
    assert result.returncode == 1
    assert diagnostic in result.stderr
    assert not baseline.exists()


@pytest.mark.parametrize(
    "reference",
    [
        "https://example.invalid/schema.json#/properties/a",
        "file:///tmp/schema.json#/properties/a",
        "../schema.json#/properties/a",
        "#/properties/missing",
        "#named-anchor",
        "#/properties/~2invalid",
        "#/properties/a%20b",
    ],
)
def test_reference_closure_rejects_external_relative_and_unresolved_targets(
    repo_factory: Callable[..., tuple[Path, str]],
    reference: str,
) -> None:
    path = "schemas/gateway-event-envelope.json"
    document = json.loads(_base_document(path))
    document["properties"]["activity"]["$ref"] = reference
    repo, commit = repo_factory(overrides={path: (json.dumps(document) + "\n").encode()})
    baseline = repo / "baseline.json"
    result = _run(repo, baseline, "bootstrap", "--source-ref", commit, "--write")
    assert result.returncode == 1
    assert not baseline.exists()


def test_cross_resource_empty_fragment_is_valid_offline(
    repo_factory: Callable[..., tuple[Path, str]],
) -> None:
    path = "schemas/gateway-event-envelope.json"
    document = json.loads(_base_document(path))
    document["properties"]["activity"]["$ref"] = "https://defenseclaw.io/schemas/activity-event.json#"
    repo, commit = repo_factory(overrides={path: (json.dumps(document) + "\n").encode()})
    baseline = repo / "baseline.json"
    _bootstrap(repo, commit, baseline)
    assert _run(repo, baseline, "check").returncode == 0


def test_unicode_digit_array_pointer_fails_structurally_without_value_error(
    repo_factory: Callable[..., tuple[Path, str]],
) -> None:
    path = "schemas/gateway-event-envelope.json"
    document = json.loads(_base_document(path))
    document["x-array"] = ["value"]
    document["properties"]["activity"]["$ref"] = "#/x-array/²"
    repo, commit = repo_factory(overrides={path: (json.dumps(document, ensure_ascii=False) + "\n").encode()})
    baseline = repo / "baseline.json"
    result = _run(repo, baseline, "bootstrap", "--source-ref", commit, "--write")
    assert result.returncode == 1
    assert "unresolved JSON Pointer" in result.stderr
    assert "ValueError" not in result.stderr


@pytest.mark.parametrize(
    ("keyword", "value"),
    [
        ("$id", "nested"),
        ("$schema", public_views.DRAFT_2020_12),
        ("$anchor", "anchor"),
        ("$dynamicRef", "#anchor"),
        ("$recursiveRef", "#"),
        ("$dynamicAnchor", "anchor"),
        ("$recursiveAnchor", True),
    ],
)
def test_nested_base_anchor_dynamic_and_recursive_features_are_rejected(
    repo_factory: Callable[..., tuple[Path, str]],
    keyword: str,
    value: object,
) -> None:
    path = "schemas/activity-event.json"
    document = json.loads(_base_document(path))
    document["properties"]["a"][keyword] = value
    repo, commit = repo_factory(overrides={path: (json.dumps(document) + "\n").encode()})
    baseline = repo / "baseline.json"
    result = _run(repo, baseline, "bootstrap", "--source-ref", commit, "--write")
    assert result.returncode == 1
    assert not baseline.exists()


def test_deep_source_is_rejected_with_a_bounded_structural_error(
    repo_factory: Callable[..., tuple[Path, str]],
) -> None:
    path = "schemas/activity-event.json"
    dialect, schema_id = public_views.IDENTITY_BY_PATH[path]
    raw = (
        "{"
        f'"$schema":{json.dumps(dialect)},'
        f'"$id":{json.dumps(schema_id)},'
        '"properties":{"a":{}},"x-deep":'
        + "[" * (public_views.MAX_JSON_DEPTH + 20)
        + "0"
        + "]" * (public_views.MAX_JSON_DEPTH + 20)
        + "}\n"
    ).encode()
    repo, commit = repo_factory(overrides={path: raw})
    baseline = repo / "baseline.json"
    result = _run(repo, baseline, "bootstrap", "--source-ref", commit, "--write")
    assert result.returncode == 1
    assert "depth limit" in result.stderr
    assert not baseline.exists()


def test_missing_inventory_member_is_rejected(
    repo_factory: Callable[..., tuple[Path, str]],
) -> None:
    missing = "schemas/scan-result.json"
    repo, commit = repo_factory(overrides={missing: None})
    baseline = repo / "baseline.json"
    result = _run(repo, baseline, "bootstrap", "--source-ref", commit, "--write")
    assert result.returncode == 1
    assert "Git object lookup failed" in result.stderr
    assert not baseline.exists()


@pytest.mark.parametrize("marker_value", [{}, None, "unexpected-shape"])
def test_generated_schema_marker_presence_blocks_recursive_baseline_seed(
    repo_factory: Callable[..., tuple[Path, str]],
    marker_value: object,
) -> None:
    path = "schemas/activity-event.json"
    assert public_views.GENERATED_SCHEMA_MARKER_KEY == "x-defenseclaw-generated"
    document = json.loads(_base_document(path))
    document[public_views.GENERATED_SCHEMA_MARKER_KEY] = marker_value
    repo, commit = repo_factory(overrides={path: (json.dumps(document) + "\n").encode()})
    baseline = repo / "baseline.json"
    result = _run(repo, baseline, "bootstrap", "--source-ref", commit, "--write")
    assert result.returncode == 1
    assert "generated public-view sources" in result.stderr
    assert not baseline.exists()


@pytest.mark.parametrize(
    "manifest",
    [
        {"outputs": ["schemas/activity-event.json"]},
        {"generated_authority_paths": ["schemas/activity-event.json"]},
        {
            "public_views": [
                {
                    "authority": "generated",
                    "output_path": "schemas/activity-event.json",
                }
            ]
        },
    ],
)
def test_generated_output_manifest_blocks_recursive_authority(
    repo_factory: Callable[..., tuple[Path, str]],
    manifest: dict,
) -> None:
    repo, commit = repo_factory(manifest=manifest)
    baseline = repo / "baseline.json"
    result = _run(repo, baseline, "bootstrap", "--source-ref", commit, "--write")
    assert result.returncode == 1
    assert "generated authority" in result.stderr
    assert not baseline.exists()


def test_non_public_generated_manifest_output_does_not_block_bootstrap(
    repo_factory: Callable[..., tuple[Path, str]],
) -> None:
    repo, commit = repo_factory(manifest={"outputs": [public_views.GENERATED_OUTPUT_MANIFEST_PATH]})
    baseline = repo / "baseline.json"
    _bootstrap(repo, commit, baseline)


@pytest.mark.parametrize("identity_field", ["$schema", "$id"])
def test_exact_dialect_and_schema_identity_are_required(
    repo_factory: Callable[..., tuple[Path, str]],
    identity_field: str,
) -> None:
    path = "schemas/network-egress-event.json"
    document = json.loads(_base_document(path))
    document[identity_field] = "https://example.invalid/wrong"
    repo, commit = repo_factory(overrides={path: (json.dumps(document) + "\n").encode()})
    baseline = repo / "baseline.json"
    result = _run(repo, baseline, "bootstrap", "--source-ref", commit, "--write")
    assert result.returncode == 1
    assert not baseline.exists()


@pytest.mark.parametrize("source_ref", ["HEAD", "main", "0" * 39, "0" * 40 + ";x"])
def test_source_ref_must_be_a_full_commit_without_shell_interpretation(
    repo_factory: Callable[..., tuple[Path, str]],
    source_ref: str,
) -> None:
    repo, _commit_id = repo_factory()
    baseline = repo / "baseline.json"
    result = _run(
        repo,
        baseline,
        "bootstrap",
        "--source-ref",
        source_ref,
        "--write",
    )
    assert result.returncode == 1
    assert "full 40-hex commit ID" in result.stderr
    assert not baseline.exists()


def test_reordered_source_has_stable_canonical_digests_and_deterministic_refresh(
    repo_factory: Callable[..., tuple[Path, str]],
) -> None:
    repo, first_commit = repo_factory()
    baseline = repo / "baseline.json"
    _bootstrap(repo, first_commit, baseline)
    before = _read_baseline(baseline)
    before_digests = {resource["path"]: resource["canonical_sha256"] for resource in before["resources"]}

    for path, _dialect, _schema_id in public_views.PUBLIC_SCHEMA_IDENTITIES:
        (repo / path).write_bytes(_base_document(path, reverse=True))
    second_commit = _commit(repo, "reorder schema object keys")
    refreshed = _run(
        repo,
        baseline,
        "refresh",
        "--source-ref",
        second_commit,
        "--write",
    )
    assert refreshed.returncode == 0, refreshed.stderr
    after = _read_baseline(baseline)
    assert {resource["path"]: resource["canonical_sha256"] for resource in after["resources"]} == before_digests
    first_refresh_bytes = baseline.read_bytes()

    repeated = _run(
        repo,
        baseline,
        "refresh",
        "--source-ref",
        second_commit,
        "--write",
    )
    assert repeated.returncode == 0, repeated.stderr
    assert baseline.read_bytes() == first_refresh_bytes


@pytest.mark.parametrize("field", ["source_sha256", "canonical_sha256"])
def test_check_detects_digest_tampering(
    repo_factory: Callable[..., tuple[Path, str]],
    field: str,
) -> None:
    repo, commit = repo_factory()
    baseline = repo / "baseline.json"
    _bootstrap(repo, commit, baseline)
    document = _read_baseline(baseline)
    document["resources"][0][field] = "0" * 64
    _write_baseline(baseline, document)

    checked = _run(repo, baseline, "check")
    assert checked.returncode == 1
    assert "drift" in checked.stderr


def test_check_detects_document_and_number_index_tampering(
    repo_factory: Callable[..., tuple[Path, str]],
) -> None:
    repo, commit = repo_factory()
    baseline = repo / "baseline.json"
    _bootstrap(repo, commit, baseline)
    document = _read_baseline(baseline)
    document["resources"][0]["document"]["title"] = "tampered"
    _write_baseline(baseline, document)
    assert _run(repo, baseline, "check").returncode == 1

    _bootstrap_after_remove(repo, commit, baseline)
    document = _read_baseline(baseline)
    document["resources"][0]["number_lexemes"]["/invented"] = "1"
    _write_baseline(baseline, document)
    checked = _run(repo, baseline, "check")
    assert checked.returncode == 1
    assert "number-lexeme index drift" in checked.stderr


@pytest.mark.parametrize(
    "branch",
    ["root", "source", "resources", "resource", "document", "canonicalization"],
)
def test_scalar_baseline_shape_branches_fail_closed(
    repo_factory: Callable[..., tuple[Path, str]],
    branch: str,
) -> None:
    repo, commit = repo_factory()
    baseline = repo / "baseline.json"
    _bootstrap(repo, commit, baseline)
    if branch == "root":
        baseline.write_bytes(b'"scalar"\n')
    else:
        document = _read_baseline(baseline)
        if branch == "source":
            document["source"] = "scalar"
        elif branch == "resources":
            document["resources"] = "scalar"
        elif branch == "resource":
            document["resources"][0] = "scalar"
        elif branch == "document":
            document["resources"][0]["document"] = "scalar"
        elif branch == "canonicalization":
            document["canonicalization"] = "scalar"
        _write_baseline(baseline, document)
    assert _run(repo, baseline, "check").returncode == 1


@pytest.mark.parametrize("mutation", ["reorder", "duplicate", "extra"])
def test_baseline_inventory_order_duplicates_and_extras_are_rejected(
    repo_factory: Callable[..., tuple[Path, str]],
    mutation: str,
) -> None:
    repo, commit = repo_factory()
    baseline = repo / "baseline.json"
    _bootstrap(repo, commit, baseline)
    document = _read_baseline(baseline)
    resources = document["resources"]
    if mutation == "reorder":
        resources[0], resources[1] = resources[1], resources[0]
    elif mutation == "duplicate":
        resources[-1] = resources[0]
    else:
        resources.append(dict(resources[0], path="schemas/extra.json"))
    _write_baseline(baseline, document)
    checked = _run(repo, baseline, "check")
    assert checked.returncode == 1
    assert "exact ordered 21-schema inventory" in checked.stderr


@pytest.mark.parametrize("mismatch", ["tree", "blob", "normalized_document"])
def test_git_provenance_mismatches_survive_shape_validation_then_fail_check(
    repo_factory: Callable[..., tuple[Path, str]],
    mismatch: str,
) -> None:
    repo, commit = repo_factory()
    baseline = repo / "baseline.json"
    _bootstrap(repo, commit, baseline)
    document = _read_baseline(baseline)
    if mismatch == "tree":
        schema_path = repo / "schemas/activity-event.json"
        changed = json.loads(schema_path.read_bytes())
        changed["title"] = "second tree"
        schema_path.write_text(json.dumps(changed) + "\n")
        second_commit = _commit(repo, "second source tree")
        document["source"]["tree"] = _git(repo, "rev-parse", f"{second_commit}^{{tree}}")
    elif mismatch == "blob":
        document["resources"][0]["git_blob_oid"] = document["resources"][1]["git_blob_oid"]
    else:
        resource = document["resources"][0]
        resource["document"]["title"] = "internally consistent but not source"
        resource["number_lexemes"] = public_views._number_lexemes(resource["document"])
        resource["canonical_sha256"] = public_views._resource_digest(
            resource["path"],
            resource["dialect"],
            resource["schema_id"],
            resource["document"],
        )
    public_views._validate_baseline_shape(document)
    _write_baseline(baseline, document)

    checked = _run(repo, baseline, "check")
    assert checked.returncode == 1
    assert "provenance drift" in checked.stderr or "pinned Git source" in checked.stderr


def test_check_rejects_noncanonical_baseline_bytes(
    repo_factory: Callable[..., tuple[Path, str]],
) -> None:
    repo, commit = repo_factory()
    baseline = repo / "baseline.json"
    _bootstrap(repo, commit, baseline)
    baseline.write_bytes(b" \n" + baseline.read_bytes())

    checked = _run(repo, baseline, "check")
    assert checked.returncode == 1
    assert "not in canonical lossless JSON form" in checked.stderr


def _bootstrap_after_remove(repo: Path, commit: str, baseline: Path) -> None:
    baseline.unlink()
    _bootstrap(repo, commit, baseline)


def test_worktree_schema_changes_are_never_used_by_check(
    repo_factory: Callable[..., tuple[Path, str]],
) -> None:
    repo, commit = repo_factory()
    baseline = repo / "baseline.json"
    _bootstrap(repo, commit, baseline)
    (repo / "schemas/activity-event.json").write_bytes(b"not json\n")

    checked = _run(repo, baseline, "check")
    assert checked.returncode == 0, checked.stderr


@pytest.mark.parametrize(
    "unsafe_path",
    [Path("schemas/activity-event.json"), Path("../outside-baseline.json")],
)
def test_baseline_path_cannot_alias_a_source_or_leave_repository(
    repo_factory: Callable[..., tuple[Path, str]],
    unsafe_path: Path,
) -> None:
    repo, commit = repo_factory()
    original = (repo / "schemas/activity-event.json").read_bytes()
    result = _run(
        repo,
        unsafe_path,
        "bootstrap",
        "--source-ref",
        commit,
        "--write",
    )
    assert result.returncode == 1
    assert (repo / "schemas/activity-event.json").read_bytes() == original


def test_missing_baseline_is_a_bounded_error(
    repo_factory: Callable[..., tuple[Path, str]],
) -> None:
    repo, _commit_id = repo_factory()
    result = _run(repo, repo / "missing.json", "check")
    assert result.returncode == 1
    assert "cannot read baseline" in result.stderr
    assert "Traceback" not in result.stderr


def test_non_git_root_fails_without_raw_git_stderr(tmp_path: Path) -> None:
    root = tmp_path / "not-git"
    root.mkdir()
    baseline = root / "baseline.json"
    result = _run(
        root,
        baseline,
        "bootstrap",
        "--source-ref",
        "0" * 40,
        "--write",
    )
    assert result.returncode == 1
    assert "Git object lookup failed" in result.stderr
    assert "fatal:" not in result.stderr


def test_symlinked_baseline_cannot_escape_repository(
    repo_factory: Callable[..., tuple[Path, str]],
    tmp_path: Path,
) -> None:
    repo, _commit_id = repo_factory()
    outside = tmp_path / "outside.json"
    outside.write_text("outside\n")
    link = repo / "baseline.json"
    try:
        link.symlink_to(outside)
    except OSError as exc:  # pragma: no cover - platform capability
        pytest.skip(f"symlinks unavailable: {exc}")
    result = _run(repo, Path("baseline.json"), "check")
    assert result.returncode == 1
    assert "leaves the repository root" in result.stderr
    assert outside.read_text() == "outside\n"


def test_refresh_validation_failure_rolls_back_existing_baseline(
    repo_factory: Callable[..., tuple[Path, str]],
) -> None:
    repo, first_commit = repo_factory()
    baseline = repo / "baseline.json"
    _bootstrap(repo, first_commit, baseline)
    original = baseline.read_bytes()

    (repo / "schemas/activity-event.json").write_bytes(b'{"value":NaN}\n')
    bad_commit = _commit(repo, "invalid schema source")
    refreshed = _run(
        repo,
        baseline,
        "refresh",
        "--source-ref",
        bad_commit,
        "--write",
    )
    assert refreshed.returncode == 1
    assert baseline.read_bytes() == original


def test_atomic_replace_failure_preserves_existing_file(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    target = tmp_path / "baseline.json"
    target.write_bytes(b"original\n")

    def fail_replace(_source: Path, _target: Path) -> None:
        raise OSError("simulated replace failure")

    monkeypatch.setattr(public_views.os, "replace", fail_replace)
    with pytest.raises(OSError, match="simulated replace failure"):
        public_views._atomic_write(target, b"replacement\n")
    assert target.read_bytes() == b"original\n"
    assert list(tmp_path.glob(".baseline.json.*.tmp")) == []


def test_atomic_write_fsyncs_file_and_parent_directory(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    if public_views.os.name == "nt":
        pytest.skip("directory fsync is unavailable on Windows")
    calls: list[int] = []
    original_fsync = public_views.os.fsync

    def record_fsync(descriptor: int) -> None:
        calls.append(descriptor)
        original_fsync(descriptor)

    monkeypatch.setattr(public_views.os, "fsync", record_fsync)
    target = tmp_path / "baseline.json"
    public_views._atomic_write(target, b"payload\n")
    assert target.read_bytes() == b"payload\n"
    assert len(calls) == 2


def test_git_timeout_is_bounded_and_reports_no_command_tokens(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    observed: dict[str, object] = {}
    monkeypatch.setenv("SECRET_AMBIENT", "must-not-be-forwarded")

    def time_out(*_args: object, **kwargs: object) -> None:
        observed.update(kwargs)
        raise subprocess.TimeoutExpired(cmd=["git", "secret-token"], timeout=1)

    monkeypatch.setattr(public_views.subprocess, "run", time_out)
    with pytest.raises(public_views.BaselineError) as raised:
        public_views._git(tmp_path, ["cat-file", "-t", "secret-token"])
    assert str(raised.value) == "Git object lookup timed out"
    assert observed["timeout"] == public_views.GIT_TIMEOUT_SECONDS
    environment = observed["env"]
    assert isinstance(environment, dict)
    assert environment["GIT_TERMINAL_PROMPT"] == "0"
    assert environment["GIT_OPTIONAL_LOCKS"] == "0"
    assert environment["GIT_CONFIG_NOSYSTEM"] == "1"
    assert "HOME" not in environment
    assert "SECRET_AMBIENT" not in environment


def test_git_failure_scrubs_stderr_and_source_tokens(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    secret = "raw-secret-git-stderr"

    def fail(*_args: object, **_kwargs: object) -> subprocess.CompletedProcess[str]:
        return subprocess.CompletedProcess([], 128, stdout="", stderr=secret)

    monkeypatch.setattr(public_views.subprocess, "run", fail)
    with pytest.raises(public_views.BaselineError) as raised:
        public_views._git(tmp_path, ["rev-parse", secret])
    assert str(raised.value) == "Git object lookup failed"
    assert secret not in str(raised.value)


def test_optional_manifest_lookup_does_not_treat_repository_failure_as_absent(
    tmp_path: Path,
) -> None:
    root = tmp_path / "not-a-repository"
    root.mkdir()
    with pytest.raises(public_views.BaselineError, match="Git object lookup failed"):
        public_views._read_optional_git_blob(
            root,
            "0" * 40,
            public_views.GENERATED_OUTPUT_MANIFEST_PATH,
        )


def test_mutating_commands_require_write(
    repo_factory: Callable[..., tuple[Path, str]],
) -> None:
    repo, commit = repo_factory()
    baseline = repo / "baseline.json"
    result = _run(repo, baseline, "bootstrap", "--source-ref", commit)
    assert result.returncode == 1
    assert "require --write" in result.stderr
    assert not baseline.exists()


def test_refresh_stays_in_epoch_and_new_epoch_requires_explicit_acknowledgement(
    repo_factory: Callable[..., tuple[Path, str]],
) -> None:
    repo, commit = repo_factory()
    baseline = repo / "baseline.json"
    _bootstrap(repo, commit, baseline)
    original = baseline.read_bytes()

    wrong_refresh = _run(
        repo,
        baseline,
        "refresh",
        "--source-ref",
        commit,
        "--epoch",
        "public-schemas-v8",
        "--write",
    )
    assert wrong_refresh.returncode == 1
    assert baseline.read_bytes() == original

    unacknowledged = _run(
        repo,
        baseline,
        "new-epoch",
        "--source-ref",
        commit,
        "--epoch",
        "public-schemas-v8",
        "--write",
    )
    assert unacknowledged.returncode == 1
    assert baseline.read_bytes() == original

    same_epoch = _run(
        repo,
        baseline,
        "new-epoch",
        "--source-ref",
        commit,
        "--epoch",
        "public-schemas-v7",
        "--acknowledge-breaking-baseline-epoch",
        "--write",
    )
    assert same_epoch.returncode == 1
    assert baseline.read_bytes() == original

    changed = _run(
        repo,
        baseline,
        "new-epoch",
        "--source-ref",
        commit,
        "--epoch",
        "public-schemas-v8",
        "--acknowledge-breaking-baseline-epoch",
        "--write",
    )
    assert changed.returncode == 0, changed.stderr
    assert _read_baseline(baseline)["baseline_id"] == "public-schemas-v8"


def test_bootstrap_refuses_to_overwrite_existing_baseline(
    repo_factory: Callable[..., tuple[Path, str]],
) -> None:
    repo, commit = repo_factory()
    baseline = repo / "baseline.json"
    _bootstrap(repo, commit, baseline)
    original = baseline.read_bytes()
    second = _run(
        repo,
        baseline,
        "bootstrap",
        "--source-ref",
        commit,
        "--write",
    )
    assert second.returncode == 1
    assert baseline.read_bytes() == original
