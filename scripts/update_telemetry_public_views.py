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

"""Create and verify the immutable public-schema migration baseline.

This utility is deliberately separate from the telemetry registry compiler.
It reads each migration source from one fully-qualified Git commit, never from
the worktree.  The resulting file is an inert migration input until a later
change explicitly imports it into the registry.

The JSON reader is lossless for number tokens.  In particular, values such as
``0.0``, ``-0``, large integers, and exponent spellings are not routed through
an IEEE-754 value before they are hashed or rendered.
"""

from __future__ import annotations

import argparse
import importlib.util
import os
import stat
import subprocess
import sys
import tempfile
from collections.abc import Sequence
from pathlib import Path
from types import ModuleType
from typing import Any


def _load_baseline_reader() -> ModuleType:
    name = "telemetry_public_schema_baseline"
    try:
        path = Path(__file__).resolve().with_name(f"{name}.py").resolve(strict=True)
        if not stat.S_ISREG(path.stat().st_mode):
            raise OSError("baseline reader is not a regular file")
    except (OSError, RuntimeError) as exc:
        raise RuntimeError("cannot load telemetry public-schema baseline reader") from exc
    existing = sys.modules.get(name)
    if existing is not None:
        if not isinstance(existing, ModuleType):
            raise RuntimeError("preloaded telemetry public-schema baseline reader is unsafe")
        try:
            existing_path = Path(existing.__file__).resolve(strict=True)
            existing_spec = existing.__spec__
            if (
                existing.__name__ != name
                or existing_spec is None
                or existing_spec.name != name
                or existing_spec.loader is None
                or existing_spec.origin is None
            ):
                raise RuntimeError("preloaded reader has no canonical import identity")
            origin_path = Path(existing_spec.origin).resolve(strict=True)
            if not stat.S_ISREG(existing_path.stat().st_mode) or not stat.S_ISREG(origin_path.stat().st_mode):
                raise RuntimeError("preloaded reader is not a regular file")
        except (AttributeError, OSError, RuntimeError, TypeError) as exc:
            raise RuntimeError("preloaded telemetry public-schema baseline reader is unsafe") from exc
        if existing_path != path or origin_path != path:
            raise RuntimeError("preloaded telemetry public-schema baseline reader has foreign provenance")
        return existing
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise RuntimeError("cannot load telemetry public-schema baseline reader")
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    try:
        spec.loader.exec_module(module)
    except Exception:
        if sys.modules.get(name) is module:
            del sys.modules[name]
        raise
    return module


baseline_reader = _load_baseline_reader()

# Preserve the updater's established import surface while keeping one parser,
# canonicalizer, and baseline/resource validator implementation.
BASELINE_FORMAT_VERSION = baseline_reader.BASELINE_FORMAT_VERSION
CANONICALIZATION_ID = baseline_reader.CANONICALIZATION_ID
RESOURCE_DIGEST_DOMAIN = baseline_reader.RESOURCE_DIGEST_DOMAIN
GENERATED_SCHEMA_MARKER_KEY = baseline_reader.GENERATED_SCHEMA_MARKER_KEY
MAX_JSON_DEPTH = baseline_reader.MAX_JSON_DEPTH
MAX_JSON_NODES = baseline_reader.MAX_JSON_NODES
FULL_COMMIT_RE = baseline_reader.FULL_COMMIT_RE
EPOCH_RE = baseline_reader.EPOCH_RE
HEX_OID_RE = baseline_reader.HEX_OID_RE
DRAFT_2020_12 = baseline_reader.DRAFT_2020_12
DRAFT_07 = baseline_reader.DRAFT_07
PUBLIC_SCHEMA_IDENTITIES = baseline_reader.PUBLIC_SCHEMA_IDENTITIES
IDENTITY_BY_PATH = baseline_reader.IDENTITY_BY_PATH
PATH_BY_SCHEMA_ID = baseline_reader.PATH_BY_SCHEMA_ID
CANONICALIZATION_DESCRIPTOR = baseline_reader.CANONICALIZATION_DESCRIPTOR
BaselineError = baseline_reader.BaselineError
RawNumber = baseline_reader.RawNumber
parse_lossless_json = baseline_reader.parse_lossless_json
render_lossless_json = baseline_reader.render_lossless_json
_fail = baseline_reader._fail
_number_lexemes = baseline_reader.number_lexemes
_sha256 = baseline_reader._sha256
_resource_digest = baseline_reader.resource_digest
_validate_identity = baseline_reader.validate_identity
_validate_schema_subset = baseline_reader.validate_schema_subset
_validate_reference_closure = baseline_reader.validate_reference_closure
_load_baseline = baseline_reader.load_baseline_document
_validate_baseline_shape = baseline_reader.validate_baseline_shape

DEFAULT_BASELINE_ID = "public-schemas-v7"
DEFAULT_BASELINE_PATH = Path("schemas/telemetry/v8/baselines/public-schemas-v7.normalized.json")
GENERATED_OUTPUT_MANIFEST_PATH = "schemas/telemetry/generated/output-manifest.json"
GIT_TIMEOUT_SECONDS = 15.0


def _git(
    root: Path,
    arguments: Sequence[str],
    *,
    binary: bool = False,
) -> bytes | str:
    command = [
        "git",
        "-c",
        "credential.interactive=never",
        "-C",
        str(root),
        *arguments,
    ]
    environment = {
        "PATH": os.environ.get("PATH", os.defpath),
        "GIT_CONFIG_GLOBAL": os.devnull,
        "GIT_CONFIG_NOSYSTEM": "1",
        "GIT_OPTIONAL_LOCKS": "0",
        "GIT_TERMINAL_PROMPT": "0",
        "GCM_INTERACTIVE": "Never",
        "LANG": "C",
        "LC_ALL": "C",
    }
    for name in ("COMSPEC", "PATHEXT", "SYSTEMROOT", "TEMP", "TMP", "TMPDIR", "WINDIR"):
        value = os.environ.get(name)
        if value:
            environment[name] = value
    try:
        result = subprocess.run(
            command,
            check=False,
            capture_output=True,
            text=not binary,
            timeout=GIT_TIMEOUT_SECONDS,
            env=environment,
        )
    except subprocess.TimeoutExpired as exc:
        raise BaselineError("Git object lookup timed out") from exc
    except OSError as exc:
        raise BaselineError("cannot execute Git") from exc
    if result.returncode != 0:
        raise BaselineError("Git object lookup failed")
    return result.stdout


def _required_git_text(root: Path, arguments: Sequence[str]) -> str:
    result = _git(root, arguments)
    if not isinstance(result, str):  # defensive type narrowing
        _fail("Git returned an unexpected result type")
    return result


def _validated_commit(root: Path, source_ref: str) -> tuple[str, str]:
    if not FULL_COMMIT_RE.fullmatch(source_ref):
        _fail("source-ref must be a full 40-hex commit ID")
    commit = source_ref.lower()
    object_type = _required_git_text(root, ["cat-file", "-t", commit]).strip()
    if object_type != "commit":
        _fail(f"source-ref names a {object_type!r} object, not a commit")
    tree = _required_git_text(root, ["rev-parse", f"{commit}^{{tree}}"]).strip()
    if not HEX_OID_RE.fullmatch(tree):
        _fail("Git returned an invalid tree object ID")
    return commit, tree


def _read_git_blob(root: Path, commit: str, path: str) -> tuple[str, bytes]:
    object_spec = f"{commit}:{path}"
    blob_oid = _required_git_text(root, ["rev-parse", object_spec]).strip()
    if not HEX_OID_RE.fullmatch(blob_oid):
        _fail(f"{path}: Git returned an invalid blob object ID")
    object_type = _required_git_text(root, ["cat-file", "-t", blob_oid]).strip()
    if object_type != "blob":
        _fail(f"{path}: source object is not a blob")
    raw = _git(root, ["cat-file", "blob", blob_oid], binary=True)
    if not isinstance(raw, bytes):  # defensive type narrowing
        _fail(f"{path}: Git returned a non-binary blob")
    return blob_oid, raw


def _read_optional_git_blob(root: Path, commit: str, path: str) -> bytes | None:
    listing = _git(
        root,
        ["ls-tree", "-z", "--full-tree", commit, "--", path],
        binary=True,
    )
    if not isinstance(listing, bytes):
        _fail("Git returned an unexpected tree-listing type")
    if listing == b"":
        return None
    entries = [entry for entry in listing.split(b"\x00") if entry]
    if len(entries) != 1 or b"\t" not in entries[0]:
        _fail("Git returned an invalid optional tree entry")
    header, listed_path = entries[0].split(b"\t", 1)
    fields = header.split(b" ")
    if len(fields) != 3:
        _fail("Git returned an invalid optional tree entry")
    _mode, object_type, raw_blob_oid = fields
    try:
        listed_path_text = listed_path.decode("utf-8", errors="strict")
        blob_oid = raw_blob_oid.decode("ascii", errors="strict")
        object_type_text = object_type.decode("ascii", errors="strict")
    except UnicodeDecodeError as exc:
        raise BaselineError("Git returned an invalid optional tree entry") from exc
    if listed_path_text != path or object_type_text != "blob":
        _fail("Git optional tree entry does not identify the expected blob")
    if not HEX_OID_RE.fullmatch(blob_oid):
        _fail("Git returned an invalid optional blob object ID")
    raw = _git(root, ["cat-file", "blob", blob_oid], binary=True)
    if not isinstance(raw, bytes):
        _fail("Git returned an unexpected optional blob type")
    return raw


def _generated_authority_paths(manifest: Any) -> set[str]:
    if not isinstance(manifest, dict):
        _fail("generated output manifest root must be an object")
    declared: set[str] = set()

    authority_paths = manifest.get("generated_authority_paths", [])
    if authority_paths is not None:
        if not isinstance(authority_paths, list):
            _fail("generated output manifest authority paths must be an array")
        if not all(isinstance(path, str) for path in authority_paths):
            _fail("generated output manifest authority path must be a string")
        declared.update(authority_paths)

    outputs = manifest.get("outputs", [])
    if outputs is not None:
        if not isinstance(outputs, list):
            _fail("generated output manifest outputs must be an array")
        for output in outputs:
            if isinstance(output, str):
                declared.add(output)
            elif isinstance(output, dict):
                path = output.get("path", output.get("output_path"))
                authority = output.get("authority", "generated")
                if path is not None and not isinstance(path, str):
                    _fail("generated output manifest output path must be a string")
                if authority == "generated" and path is not None:
                    declared.add(path)
            else:
                _fail("generated output manifest output entry has an invalid shape")

    public_views = manifest.get("public_views", [])
    if public_views is not None:
        if not isinstance(public_views, list):
            _fail("generated output manifest public views must be an array")
        for view in public_views:
            if not isinstance(view, dict):
                _fail("generated output manifest public view must be an object")
            path = view.get("output_path")
            authority = view.get("authority")
            if path is not None and not isinstance(path, str):
                _fail("generated output manifest public-view path must be a string")
            if authority == "generated" and path is not None:
                declared.add(path)
    return declared


def _reject_generated_source_commit(root: Path, commit: str) -> None:
    raw = _read_optional_git_blob(root, commit, GENERATED_OUTPUT_MANIFEST_PATH)
    if raw is None:
        return
    manifest = parse_lossless_json(raw, f"{commit}:{GENERATED_OUTPUT_MANIFEST_PATH}")
    generated = _generated_authority_paths(manifest)
    public_paths = set(IDENTITY_BY_PATH)
    if generated & public_paths:
        _fail("source commit declares a public schema as generated authority")


def _make_resource(root: Path, commit: str, path: str) -> dict[str, Any]:
    blob_oid, raw = _read_git_blob(root, commit, path)
    document = parse_lossless_json(raw, f"{commit}:{path}")
    dialect, schema_id = _validate_identity(document, path)
    _validate_schema_subset(document, path)
    return {
        "canonical_sha256": _resource_digest(path, dialect, schema_id, document),
        "dialect": dialect,
        "document": document,
        "git_blob_oid": blob_oid,
        "number_lexemes": _number_lexemes(document),
        "path": path,
        "schema_id": schema_id,
        "source_sha256": _sha256(raw),
    }


def build_baseline(root: Path, source_ref: str, baseline_id: str) -> dict[str, Any]:
    if not EPOCH_RE.fullmatch(baseline_id):
        _fail("baseline ID must be a lowercase, filesystem-safe epoch token")
    commit, tree = _validated_commit(root, source_ref)
    _reject_generated_source_commit(root, commit)
    resources = [_make_resource(root, commit, path) for path, _dialect, _schema_id in PUBLIC_SCHEMA_IDENTITIES]
    _validate_reference_closure(resources)
    return {
        "authority": "pre_cutover",
        "baseline_id": baseline_id,
        "canonicalization": dict(CANONICALIZATION_DESCRIPTOR),
        "format_version": BASELINE_FORMAT_VERSION,
        "resources": resources,
        "source": {"commit": commit, "tree": tree},
    }


def check_baseline(root: Path, baseline_path: Path) -> None:
    _validate_safe_baseline_path(root, baseline_path)
    baseline = _load_baseline(baseline_path)
    _validate_baseline_shape(baseline)
    commit, tree = _validated_commit(root, baseline["source"]["commit"])
    _reject_generated_source_commit(root, commit)
    if tree != baseline["source"]["tree"]:
        _fail("baseline source tree provenance drift")
    for resource in baseline["resources"]:
        path = resource["path"]
        blob_oid, raw = _read_git_blob(root, commit, path)
        if blob_oid != resource["git_blob_oid"]:
            _fail(f"{path}: Git blob provenance drift")
        if _sha256(raw) != resource["source_sha256"]:
            _fail(f"{path}: source SHA-256 provenance drift")
        source_document = parse_lossless_json(raw, f"{commit}:{path}")
        if render_lossless_json(source_document, pretty=False) != render_lossless_json(
            resource["document"], pretty=False
        ):
            _fail(f"{path}: normalized document differs from pinned Git source")


def _resolved_within(root: Path, path: Path) -> Path:
    resolved_root = root.resolve()
    candidate = path if path.is_absolute() else root / path
    resolved = candidate.resolve(strict=False)
    try:
        resolved.relative_to(resolved_root)
    except ValueError as exc:
        raise BaselineError("baseline path leaves the repository root") from exc
    return resolved


def _validate_safe_baseline_path(root: Path, path: Path) -> Path:
    resolved = _resolved_within(root, path)
    public_paths = {_resolved_within(root, Path(item[0])) for item in PUBLIC_SCHEMA_IDENTITIES}
    if resolved in public_paths:
        _fail("baseline path may not be a public schema render/source path")
    return resolved


def _atomic_write(path: Path, payload: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary_name = tempfile.mkstemp(prefix=f".{path.name}.", suffix=".tmp", dir=path.parent)
    temporary = Path(temporary_name)
    try:
        with os.fdopen(descriptor, "wb") as stream:
            stream.write(payload)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
        if os.name != "nt":  # Windows does not provide directory fsync.
            directory_fd = os.open(
                path.parent,
                os.O_RDONLY | getattr(os, "O_DIRECTORY", 0),
            )
            try:
                os.fsync(directory_fd)
            finally:
                os.close(directory_fd)
    except BaseException:
        try:
            temporary.unlink(missing_ok=True)
        finally:
            raise


def _write_built_baseline(path: Path, baseline: dict[str, Any]) -> None:
    _validate_baseline_shape(baseline)
    _atomic_write(path, render_lossless_json(baseline, pretty=True))


def _require_write(args: argparse.Namespace) -> None:
    if not args.write:
        _fail("mutating baseline commands require --write")


def _command_bootstrap(root: Path, baseline_path: Path, args: argparse.Namespace) -> None:
    _require_write(args)
    if baseline_path.exists():
        _fail("baseline already exists; use refresh or an explicit new epoch")
    baseline = build_baseline(root, args.source_ref, args.epoch)
    _write_built_baseline(baseline_path, baseline)


def _command_refresh(root: Path, baseline_path: Path, args: argparse.Namespace) -> None:
    _require_write(args)
    current = _load_baseline(baseline_path)
    _validate_baseline_shape(current)
    if current["authority"] != "pre_cutover":
        _fail("baseline refresh is forbidden after cutover")
    if args.epoch is not None and args.epoch != current["baseline_id"]:
        _fail("refresh cannot change the baseline epoch")
    baseline = build_baseline(root, args.source_ref, current["baseline_id"])
    _write_built_baseline(baseline_path, baseline)


def _command_new_epoch(root: Path, baseline_path: Path, args: argparse.Namespace) -> None:
    _require_write(args)
    if not args.acknowledge_breaking_baseline_epoch:
        _fail("new-epoch requires --acknowledge-breaking-baseline-epoch")
    current = _load_baseline(baseline_path)
    _validate_baseline_shape(current)
    if args.epoch == current["baseline_id"]:
        _fail("new-epoch must select a different baseline ID")
    baseline = build_baseline(root, args.source_ref, args.epoch)
    _write_built_baseline(baseline_path, baseline)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--root",
        type=Path,
        default=Path(__file__).resolve().parent.parent,
        help="repository root (defaults to this script's repository)",
    )
    parser.add_argument(
        "--baseline",
        type=Path,
        default=DEFAULT_BASELINE_PATH,
        help="baseline path relative to the repository root",
    )
    commands = parser.add_subparsers(dest="command", required=True)

    bootstrap = commands.add_parser("bootstrap", help="create the first baseline epoch")
    bootstrap.add_argument("--source-ref", required=True)
    bootstrap.add_argument("--epoch", default=DEFAULT_BASELINE_ID)
    bootstrap.add_argument("--write", action="store_true")

    refresh = commands.add_parser("refresh", help="refresh the pre-cutover epoch")
    refresh.add_argument("--source-ref", required=True)
    refresh.add_argument("--epoch")
    refresh.add_argument("--write", action="store_true")

    new_epoch = commands.add_parser("new-epoch", help="start an explicitly acknowledged replacement epoch")
    new_epoch.add_argument("--source-ref", required=True)
    new_epoch.add_argument("--epoch", required=True)
    new_epoch.add_argument("--acknowledge-breaking-baseline-epoch", action="store_true")
    new_epoch.add_argument("--write", action="store_true")

    commands.add_parser("check", help="verify baseline integrity and Git provenance")
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    root = args.root.resolve()
    try:
        baseline_path = _validate_safe_baseline_path(root, args.baseline)
        if args.command == "bootstrap":
            _command_bootstrap(root, baseline_path, args)
        elif args.command == "refresh":
            _command_refresh(root, baseline_path, args)
        elif args.command == "new-epoch":
            _command_new_epoch(root, baseline_path, args)
        elif args.command == "check":
            check_baseline(root, baseline_path)
        else:  # pragma: no cover - argparse constrains this value
            parser.error(f"unsupported command {args.command!r}")
    except BaselineError as exc:
        print(f"telemetry_public_views: error: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
