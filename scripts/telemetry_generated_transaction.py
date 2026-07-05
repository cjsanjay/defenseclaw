#!/usr/bin/env python3
# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# SPDX-License-Identifier: Apache-2.0
"""Safe multi-root transactions for checked-in telemetry-generated outputs.

This module deliberately does not render telemetry artifacts or parse the
telemetry output manifest.  Its caller supplies complete in-memory bytes and the
ownership records authenticated by the previous manifest.

There is no filesystem primitive that atomically renames files in both
``schemas/telemetry/generated`` and ``internal/observability``.  Writes are
therefore *logically* atomic: every prior file is backed up, a durable journal is
written, non-manifest files are replaced independently, and the output manifest
is replaced last as the commit marker.  A caught failure rolls back immediately;
the next writer recovers a process-interrupted journal while holding the same
exclusive repository-local lock.  That advisory lock serializes writers only;
the Go toolchain, language servers, and other direct filesystem readers do not
acquire it.  The transaction therefore does not provide a physical multi-file
reader snapshot.  Callers of ``write_outputs`` must quiesce all worktree readers
and mutations for the duration of the write.  After an interruption, readers
must not consume generated paths until a later writer recovers the journal.
Cooperating validators treat a journal or a manifest/content digest mismatch as
an incomplete transaction.  "All or none" describes the validated candidate and
the final committed checked-in state, not transient filesystem visibility.

Transaction state uses either a real ``<root>/.git`` directory or the exact
per-worktree gitdir named by a strictly validated Git indirection file.  It never
follows a symlink or consults a common-dir pointer.  Rollback removes only exact
manifest-owned files; newly created empty worktree directories may remain rather
than risking deletion of concurrently created, unowned directories.
"""

from __future__ import annotations

import base64
import contextlib
import ctypes
import dataclasses
import errno
import hashlib
import inspect
import json
import os
import re
import shutil
import stat
import sys
import uuid
from collections.abc import Callable, Mapping
from pathlib import Path, PurePosixPath
from typing import Final, TypeAlias

try:  # pragma: no cover - exercised on supported POSIX build hosts.
    import fcntl
except ImportError:  # pragma: no cover - fail closed on unsupported hosts.
    fcntl = None  # type: ignore[assignment]


MANIFEST_PATH: Final = "schemas/telemetry/generated/output-manifest.json"
GENERATED_ROOT: Final = PurePosixPath("schemas/telemetry/generated")
EXACT_INTERNAL_OUTPUTS: Final = frozenset(
    {
        "internal/observability/zz_generated_telemetry_ids.go",
        "internal/observability/zz_generated_telemetry_catalog.go",
        "internal/observability/zz_generated_telemetry_producers.go",
        "internal/observability/zz_generated_telemetry_builders_genai.go",
        "internal/observability/zz_generated_telemetry_builders_security.go",
        "internal/observability/zz_generated_telemetry_builders_operations.go",
        "internal/observability/zz_generated_telemetry_builder_fixtures_test.go",
    }
)
ALLOWED_OUTPUT_MODES: Final = frozenset({0o644})
STATE_DIRECTORY: Final = PurePosixPath(".git/defenseclaw-telemetry-generated")
STATE_SUBDIRECTORY: Final = "defenseclaw-telemetry-generated"
LOCK_NAME: Final = "transaction.lock"
JOURNAL_NAME: Final = "journal.json"
JOURNAL_FORMAT_VERSION: Final = 1
MAX_MARKER_BYTES: Final = 512
MARKER_SCAN_BYTES: Final = 4096
MAX_OUTPUTS: Final = 4096
MAX_JOURNAL_BYTES: Final = 8 * 1024 * 1024
MAX_GITFILE_BYTES: Final = 4096
_SHA256: Final = re.compile(r"^[0-9a-f]{64}$")


class TransactionError(RuntimeError):
    """A content-free generated-output transaction failure."""


class TransactionBusyError(TransactionError):
    """Another generated-output writer owns the repository lock."""


class GeneratedOutputDriftError(TransactionError):
    """Checked-in output bytes, modes, types, or ownership have drifted."""

    def __init__(self, problems: tuple[str, ...]):
        self.problems = problems
        super().__init__("generated output drift: " + "; ".join(problems))


class RecoveryRequiredError(TransactionError):
    """Check mode observed a durable interrupted-transaction journal."""


class RollbackError(TransactionError):
    """Rollback could not safely restore every prior path."""


class _JournalPublicationError(TransactionError):
    """A journal rename succeeded but its parent-directory sync failed."""

    def __init__(self, journal: _Journal):
        self.journal = journal
        super().__init__("generated-output transaction journal publication requires recovery")


FaultInjector: TypeAlias = Callable[[str, str | None], None]


@dataclasses.dataclass(frozen=True, slots=True)
class RenderedOutput:
    """One complete deterministic output held in memory.

    ``marker`` is a caller-selected, bounded byte sequence that identifies this
    file as generator-owned.  It must occur near the beginning of ``payload``.
    The transaction helper does not invent a format-specific JSON/Go/Markdown
    marker and therefore cannot become a second schema authority.
    """

    payload: bytes
    marker: bytes
    mode: int = 0o644


@dataclasses.dataclass(frozen=True, slots=True)
class PriorOwnedOutput:
    """Ownership evidence read and validated from the prior manifest."""

    sha256: str
    marker: bytes
    mode: int = 0o644

    @classmethod
    def from_rendered(cls, output: RenderedOutput) -> PriorOwnedOutput:
        return cls(sha256=_sha256(output.payload), marker=output.marker, mode=output.mode)


@dataclasses.dataclass(frozen=True, slots=True)
class RecoveryResult:
    recovered: bool
    action: str


@dataclasses.dataclass(frozen=True, slots=True)
class _PathState:
    path: str
    existed: bool
    sha256: str | None
    mode: int | None
    marker: bytes | None
    backup: str | None
    apply_detached: str
    rollback_detached: str
    retired: str
    discard_apply: str
    discard_rollback: str


@dataclasses.dataclass(frozen=True, slots=True)
class _DesiredState:
    path: str
    sha256: str
    mode: int
    marker: bytes


@dataclasses.dataclass(frozen=True, slots=True)
class _Journal:
    token: str
    phase: str
    prior: tuple[_PathState, ...]
    desired: tuple[_DesiredState, ...]
    created_directories: tuple[str, ...]
    entry_identity: _PathIdentity | None = None


@dataclasses.dataclass(frozen=True, slots=True)
class _PathIdentity:
    device: int
    inode: int
    mode: int
    links: int
    size: int
    modified_ns: int
    changed_ns: int


def _same_directory_entry(left: _PathIdentity, right: _PathIdentity) -> bool:
    """Return whether two observations name the same filesystem object.

    A successful rename can update ctime, so cleanup code cannot compare the
    complete mutation identity after it has atomically quarantined an entry.
    Device, inode, file type, and link count are sufficient for regular files.
    Directory link counts are filesystem-specific and may change when entries
    are added, so directory retirement uses ``_same_filesystem_object``.
    """

    return (
        left.device == right.device
        and left.inode == right.inode
        and stat.S_IFMT(left.mode) == stat.S_IFMT(right.mode)
        and left.links == right.links
    )


def _same_filesystem_object(left: _PathIdentity, right: _PathIdentity) -> bool:
    return (
        left.device == right.device and left.inode == right.inode and stat.S_IFMT(left.mode) == stat.S_IFMT(right.mode)
    )


def _sha256(payload: bytes) -> str:
    return hashlib.sha256(payload).hexdigest()


def _fault(injector: FaultInjector | None, stage: str, path: str | None = None) -> None:
    if injector is not None:
        injector(stage, path)


def _normalized_output_path(raw: str | Path) -> str:
    if isinstance(raw, Path):
        raw = raw.as_posix()
    if not isinstance(raw, str) or not raw or "\\" in raw or "\x00" in raw:
        raise TransactionError("generated output path is not normalized repository-relative POSIX syntax")
    if raw.startswith("/") or raw.endswith("/") or "//" in raw:
        raise TransactionError("generated output path is not normalized repository-relative POSIX syntax")
    path = PurePosixPath(raw)
    if path.is_absolute() or any(part in {"", ".", ".."} for part in path.parts):
        raise TransactionError("generated output path leaves its repository-relative identity")
    normalized = path.as_posix()
    if normalized != raw:
        raise TransactionError("generated output path is not canonical")
    under_generated = len(path.parts) > len(GENERATED_ROOT.parts) and path.is_relative_to(GENERATED_ROOT)
    if not under_generated and normalized not in EXACT_INTERNAL_OUTPUTS:
        raise TransactionError(f"generated output path is outside the allowlist: {normalized}")
    return normalized


def _validate_mode(mode: int) -> None:
    if type(mode) is not int or mode not in ALLOWED_OUTPUT_MODES:
        raise TransactionError("generated output mode is not allowlisted")


def _validate_marker(marker: bytes, payload: bytes | None = None) -> None:
    if (
        not isinstance(marker, bytes)
        or not 1 <= len(marker) <= MAX_MARKER_BYTES
        or any(value < 0x20 or value > 0x7E for value in marker)
    ):
        raise TransactionError("generated ownership marker is invalid")
    if payload is not None and marker not in payload[:MARKER_SCAN_BYTES]:
        raise TransactionError("generated output does not carry its ownership marker near the beginning")


def _validate_complete_internal_output_set(paths: set[str], *, inventory: str) -> None:
    """Reject a torn inventory of the exact generated Go output set."""

    selected = paths & EXACT_INTERNAL_OUTPUTS
    if selected and selected != EXACT_INTERNAL_OUTPUTS:
        raise TransactionError(f"{inventory} must contain either none or all exact internal generated outputs")


def _normalize_inputs(
    outputs: Mapping[str | Path, RenderedOutput],
    prior: Mapping[str | Path, PriorOwnedOutput],
) -> tuple[dict[str, RenderedOutput], dict[str, PriorOwnedOutput]]:
    if len(outputs) > MAX_OUTPUTS or len(prior) > MAX_OUTPUTS or len(set(outputs) | set(prior)) > MAX_OUTPUTS:
        raise TransactionError("generated output transaction exceeds the bounded file inventory")
    normalized_outputs: dict[str, RenderedOutput] = {}
    for raw_path, output in outputs.items():
        path = _normalized_output_path(raw_path)
        if path in normalized_outputs:
            raise TransactionError(f"duplicate generated output path: {path}")
        if not isinstance(output, RenderedOutput) or not isinstance(output.payload, bytes):
            raise TransactionError(f"generated output {path} is not complete in-memory bytes")
        _validate_mode(output.mode)
        _validate_marker(output.marker, output.payload)
        normalized_outputs[path] = output
    if MANIFEST_PATH not in normalized_outputs:
        raise TransactionError("generated output transaction requires the output manifest commit marker")
    _validate_complete_internal_output_set(set(normalized_outputs), inventory="generated output inventory")

    normalized_prior: dict[str, PriorOwnedOutput] = {}
    for raw_path, ownership in prior.items():
        path = _normalized_output_path(raw_path)
        if path in normalized_prior:
            raise TransactionError(f"duplicate prior generated ownership path: {path}")
        if not isinstance(ownership, PriorOwnedOutput) or _SHA256.fullmatch(ownership.sha256) is None:
            raise TransactionError(f"prior generated ownership for {path} is invalid")
        _validate_mode(ownership.mode)
        _validate_marker(ownership.marker)
        normalized_prior[path] = ownership
    _validate_complete_internal_output_set(set(normalized_prior), inventory="prior ownership inventory")
    return normalized_outputs, normalized_prior


def _safe_root(root: Path) -> Path:
    root = root.absolute()
    try:
        metadata = root.lstat()
    except OSError as exc:
        raise TransactionError("repository root is unavailable") from exc
    if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISDIR(metadata.st_mode):
        raise TransactionError("repository root must be a real directory")
    try:
        resolved = root.resolve(strict=True)
        observed = root.lstat()
        resolved_metadata = resolved.lstat()
    except OSError as exc:
        raise TransactionError("repository root changed while canonicalizing") from exc
    if (
        stat.S_ISLNK(observed.st_mode)
        or not stat.S_ISDIR(observed.st_mode)
        or not stat.S_ISDIR(resolved_metadata.st_mode)
        or observed.st_dev != metadata.st_dev
        or observed.st_ino != metadata.st_ino
        or resolved_metadata.st_dev != metadata.st_dev
        or resolved_metadata.st_ino != metadata.st_ino
    ):
        raise TransactionError("repository root changed while canonicalizing")
    return resolved


def _generated_root_exists(root: Path) -> bool:
    """Inspect the exact generated root without following any ancestor links."""

    parent = root / GENERATED_ROOT.parent.as_posix()
    with _directory_descriptor(parent) as parent_descriptor:
        try:
            metadata = os.stat(GENERATED_ROOT.name, dir_fd=parent_descriptor, follow_symlinks=False)
        except FileNotFoundError:
            return False
        except OSError as exc:
            raise TransactionError("cannot inspect the telemetry generated-output root") from exc
    if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISDIR(metadata.st_mode):
        raise TransactionError(f"generated output root is not a real directory: {GENERATED_ROOT.as_posix()}")
    return True


def generated_root_exists(root: Path) -> bool:
    """Return whether the exact safe telemetry generated-output root exists.

    This read-only bootstrap probe validates the repository root and every
    existing parent by descriptor.  A missing ``generated`` leaf is valid; a
    missing or linked ancestor is not.
    """

    return _generated_root_exists(_safe_root(root))


def _validate_required_roots(root: Path, *, allow_missing_generated: bool = False) -> bool:
    internal = root / "internal/observability"
    try:
        with _directory_descriptor(internal):
            pass
    except TransactionError as exc:
        raise TransactionError("generated output root is not a real directory: internal/observability") from exc
    generated_exists = _generated_root_exists(root)
    if not generated_exists and not allow_missing_generated:
        raise TransactionError(f"generated output root is not a real directory: {GENERATED_ROOT.as_posix()}")
    return generated_exists


def _lstat(path: Path) -> os.stat_result | None:
    try:
        return path.lstat()
    except FileNotFoundError:
        return None
    except OSError as exc:
        raise TransactionError(f"cannot inspect generated path {path.name!r}") from exc


@contextlib.contextmanager
def _directory_descriptor(path: Path):  # type: ignore[no-untyped-def]
    absolute = path.absolute()
    flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0)
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    descriptor = os.open(absolute.anchor, flags)
    try:
        for part in absolute.parts[1:]:
            next_descriptor = os.open(part, flags, dir_fd=descriptor)
            os.close(descriptor)
            descriptor = next_descriptor
        yield descriptor
    except OSError as exc:
        raise TransactionError("generated-output directory chain changed or is unsafe") from exc
    finally:
        os.close(descriptor)


def _validate_existing_parents(root: Path, relative: str) -> tuple[str, ...]:
    current = root
    missing: list[str] = []
    for part in PurePosixPath(relative).parts[:-1]:
        current /= part
        metadata = _lstat(current)
        if metadata is None:
            missing.append(current.relative_to(root).as_posix())
            continue
        if missing:
            raise TransactionError(f"generated output parent unexpectedly exists below a missing ancestor: {relative}")
        if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISDIR(metadata.st_mode):
            raise TransactionError(f"generated output parent is not a real directory: {relative}")
    return tuple(missing)


def _validate_regular_file(path: Path, *, expected_mode: int | None = None) -> os.stat_result:
    metadata = _lstat(path)
    if metadata is None:
        raise GeneratedOutputDriftError((f"missing={path.name}",))
    if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISREG(metadata.st_mode):
        raise TransactionError(f"generated output is not a regular file: {path.name}")
    if metadata.st_nlink != 1:
        raise TransactionError(f"generated output has multiple hard links: {path.name}")
    if expected_mode is not None and stat.S_IMODE(metadata.st_mode) != expected_mode:
        raise GeneratedOutputDriftError((f"mode={path.name}",))
    return metadata


def _path_identity(metadata: os.stat_result) -> _PathIdentity:
    return _PathIdentity(
        metadata.st_dev,
        metadata.st_ino,
        metadata.st_mode,
        metadata.st_nlink,
        metadata.st_size,
        metadata.st_mtime_ns,
        metadata.st_ctime_ns,
    )


def _identity_at_mutation(path: Path) -> _PathIdentity | None:
    metadata = _lstat(path)
    return None if metadata is None else _path_identity(metadata)


def _read_regular_file(path: Path) -> bytes:
    result = _read_regular_file_bounded(path, maximum=None, missing_ok=False)
    assert result is not None
    return result[0]


def _read_regular_file_bounded(
    path: Path,
    *,
    maximum: int | None,
    missing_ok: bool,
) -> tuple[bytes, os.stat_result] | None:
    flags = os.O_RDONLY
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    with _directory_descriptor(path.parent) as parent_descriptor:
        try:
            descriptor = os.open(path.name, flags, dir_fd=parent_descriptor)
        except FileNotFoundError:
            if missing_ok:
                return None
            raise GeneratedOutputDriftError((f"missing={path.name}",))
        except OSError as exc:
            raise TransactionError(f"cannot safely open generated output {path.name!r}") from exc
        try:
            before = os.fstat(descriptor)
            if not stat.S_ISREG(before.st_mode) or before.st_nlink != 1:
                raise TransactionError(f"generated output is not a safe regular file: {path.name}")
            if maximum is not None and before.st_size > maximum:
                raise RecoveryRequiredError("generated-output transaction journal exceeds its size limit")
            chunks: list[bytes] = []
            remaining = before.st_size
            while remaining:
                chunk = os.read(descriptor, min(remaining, 1024 * 1024))
                if not chunk:
                    break
                chunks.append(chunk)
                remaining -= len(chunk)
            payload = b"".join(chunks)
            after = os.fstat(descriptor)
            try:
                entry = os.stat(path.name, dir_fd=parent_descriptor, follow_symlinks=False)
            except OSError as exc:
                raise TransactionError(f"generated output directory entry changed while reading: {path.name}") from exc
            if (
                len(payload) != before.st_size
                or _path_identity(before) != _path_identity(after)
                or _path_identity(after) != _path_identity(entry)
            ):
                raise TransactionError(f"generated output changed while reading: {path.name}")
            return payload, before
        finally:
            os.close(descriptor)


def _normalized_repository_source_path(raw: str | Path) -> str:
    if isinstance(raw, Path):
        raw = raw.as_posix()
    if not isinstance(raw, str) or not raw or "\\" in raw or "\x00" in raw:
        raise TransactionError("repository source path is not normalized relative POSIX syntax")
    if raw.startswith("/") or raw.endswith("/") or "//" in raw:
        raise TransactionError("repository source path is not normalized relative POSIX syntax")
    path = PurePosixPath(raw)
    if path.is_absolute() or any(part in {"", ".", ".."} for part in path.parts) or path.as_posix() != raw:
        raise TransactionError("repository source path leaves its repository-relative identity")
    return raw


def read_repository_file_bounded(root: Path, relative: str | Path, *, maximum: int) -> bytes:
    """Read one repository source through pinned, no-follow descriptors.

    The source path is repository-relative and all ancestors must already be
    real directories.  The helper never creates parents and rejects linked,
    hard-linked, changing, missing, or over-limit files.
    """

    if type(maximum) is not int or maximum <= 0:
        raise TransactionError("repository source size limit is invalid")
    safe_root = _safe_root(root)
    normalized = _normalized_repository_source_path(relative)
    try:
        opened = _read_regular_file_bounded(
            safe_root / normalized,
            maximum=maximum,
            missing_ok=False,
        )
    except RecoveryRequiredError as exc:
        raise TransactionError("repository source file exceeds its size limit") from exc
    assert opened is not None
    return opened[0]


def _validate_current_ownership(
    root: Path,
    outputs: Mapping[str, RenderedOutput],
    prior: Mapping[str, PriorOwnedOutput],
) -> tuple[str, ...]:
    missing_directories: set[str] = set()
    for path in sorted(set(outputs) | set(prior)):
        missing_directories.update(_validate_existing_parents(root, path))
        target = root / path
        metadata = _lstat(target)
        owner = prior.get(path)
        if owner is None:
            if metadata is not None:
                raise TransactionError(f"refusing unowned generated-output collision: {path}")
            continue
        if metadata is None:
            raise GeneratedOutputDriftError((f"missing-prior={path}",))
        _validate_regular_file(target, expected_mode=owner.mode)
        payload = _read_regular_file(target)
        if _sha256(payload) != owner.sha256:
            raise TransactionError(f"prior generated output digest no longer matches its manifest: {path}")
        _validate_marker(owner.marker, payload)
    return tuple(sorted(missing_directories, key=lambda item: (item.count("/"), item)))


def _read_gitfile(path: Path, expected: os.stat_result) -> bytes:
    try:
        opened = _read_regular_file_bounded(path, maximum=MAX_GITFILE_BYTES, missing_ok=False)
        assert opened is not None
        payload, observed = opened
        if _path_identity(observed) != _path_identity(expected):
            raise TransactionError("repository .git indirection file is unsafe")
        return payload
    except TransactionError as exc:
        raise TransactionError("cannot safely read repository .git indirection file") from exc


def _validated_real_directory_chain(path: Path) -> Path:
    if not path.is_absolute():
        raise TransactionError("repository gitdir target is not absolute")
    try:
        metadata = path.lstat()
        resolved = path.resolve(strict=True)
        observed = path.lstat()
        resolved_metadata = resolved.lstat()
    except OSError as exc:
        raise TransactionError("repository gitdir target does not exist") from exc
    if (
        stat.S_ISLNK(metadata.st_mode)
        or not stat.S_ISDIR(metadata.st_mode)
        or stat.S_ISLNK(observed.st_mode)
        or not stat.S_ISDIR(observed.st_mode)
        or not stat.S_ISDIR(resolved_metadata.st_mode)
        or observed.st_dev != metadata.st_dev
        or observed.st_ino != metadata.st_ino
        or resolved_metadata.st_dev != metadata.st_dev
        or resolved_metadata.st_ino != metadata.st_ino
    ):
        raise TransactionError("repository gitdir target path is not a real directory chain")
    return resolved


def _git_metadata_directory(root: Path) -> Path:
    git = root / ".git"
    metadata = _lstat(git)
    if metadata is None or stat.S_ISLNK(metadata.st_mode):
        raise TransactionError("repository .git metadata is missing or unsafe")
    if stat.S_ISDIR(metadata.st_mode):
        return git
    if not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1 or metadata.st_size > MAX_GITFILE_BYTES:
        raise TransactionError("repository .git indirection file is unsafe")
    raw = _read_gitfile(git, metadata)
    if b"\x00" in raw or not raw.endswith(b"\n") or raw.count(b"\n") != 1 or b"\r" in raw:
        raise TransactionError("repository .git indirection file has invalid grammar")
    try:
        text = raw.decode("utf-8", errors="strict")
    except UnicodeDecodeError as exc:
        raise TransactionError("repository .git indirection file is not UTF-8") from exc
    if not text.startswith("gitdir: "):
        raise TransactionError("repository .git indirection file has invalid grammar")
    target_text = text[len("gitdir: ") : -1]
    if (
        not target_text
        or "\\" in target_text
        or "//" in target_text
        or target_text.endswith("/")
        or target_text != PurePosixPath(target_text).as_posix()
    ):
        raise TransactionError("repository gitdir target path is not canonical")
    target_path = PurePosixPath(target_text)
    if any(part in {"", ".", ".."} for part in target_path.parts):
        raise TransactionError("repository gitdir target path traversal is forbidden")
    target = Path(target_text) if target_path.is_absolute() else root / target_text
    return _validated_real_directory_chain(Path(os.path.abspath(target)))


def _state_root(root: Path, *, create: bool) -> Path:
    git_directory = _git_metadata_directory(root)
    state_root = git_directory / STATE_SUBDIRECTORY
    with _directory_descriptor(git_directory) as git_descriptor:
        try:
            state_metadata = os.stat(STATE_SUBDIRECTORY, dir_fd=git_descriptor, follow_symlinks=False)
        except FileNotFoundError:
            state_metadata = None
        if create and state_metadata is None:
            os.mkdir(STATE_SUBDIRECTORY, mode=0o700, dir_fd=git_descriptor)
            state_descriptor = os.open(
                STATE_SUBDIRECTORY,
                os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0),
                dir_fd=git_descriptor,
            )
            try:
                os.fchmod(state_descriptor, 0o700)
                os.fsync(state_descriptor)
                state_metadata = os.fstat(state_descriptor)
            finally:
                os.close(state_descriptor)
            os.fsync(git_descriptor)
    if state_metadata is None:
        return state_root
    if stat.S_ISLNK(state_metadata.st_mode) or not stat.S_ISDIR(state_metadata.st_mode):
        raise TransactionError("generated-output transaction state path is unsafe")
    if stat.S_IMODE(state_metadata.st_mode) != 0o700:
        raise TransactionError("generated-output transaction state permissions are unsafe")
    if hasattr(os, "getuid") and state_metadata.st_uid != os.getuid():
        raise TransactionError("generated-output transaction state owner is unsafe")
    if state_metadata.st_dev != root.lstat().st_dev:
        raise TransactionError("generated-output staging and worktree must share one filesystem")
    return state_root


def _fsync_directory(path: Path) -> None:
    if os.name == "nt":  # pragma: no cover - Windows has no directory fsync.
        return
    with _directory_descriptor(path) as descriptor:
        os.fsync(descriptor)


def _fsync_directory_tree(root: Path) -> None:
    if os.name == "nt":  # pragma: no cover - Windows has no directory fsync.
        return
    flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0)
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW

    def sync_tree(descriptor: int) -> None:
        try:
            names = tuple(os.listdir(descriptor))
        except OSError as exc:
            raise TransactionError("cannot inspect generated-output directory tree for sync") from exc
        for name in names:
            try:
                expected = os.stat(name, dir_fd=descriptor, follow_symlinks=False)
            except OSError as exc:
                raise TransactionError("generated-output directory tree changed before sync") from exc
            if stat.S_ISLNK(expected.st_mode):
                raise TransactionError("generated-output directory tree contains an unsafe symlink")
            if not stat.S_ISDIR(expected.st_mode):
                continue
            try:
                child = os.open(name, flags, dir_fd=descriptor)
            except OSError as exc:
                raise TransactionError("cannot safely open generated-output directory tree") from exc
            try:
                opened = os.fstat(child)
                if not _same_filesystem_object(_path_identity(expected), _path_identity(opened)):
                    raise TransactionError("generated-output directory tree changed while opening for sync")
                sync_tree(child)
                try:
                    observed = os.stat(name, dir_fd=descriptor, follow_symlinks=False)
                except OSError as exc:
                    raise TransactionError("generated-output directory tree changed during sync") from exc
                if not _same_filesystem_object(_path_identity(observed), _path_identity(os.fstat(child))):
                    raise TransactionError("generated-output directory tree changed during sync")
            finally:
                os.close(child)
        os.fsync(descriptor)

    with _directory_descriptor(root) as root_descriptor:
        sync_tree(root_descriptor)


def _rmtree_at_compat(parent_descriptor: int, name: str) -> None:
    """Recursively remove one directory using only descriptor-relative APIs.

    Python 3.10-3.13 installations do not consistently expose the public
    ``shutil.rmtree(..., dir_fd=...)`` API.  This fallback pins every traversed
    directory, atomically quarantines each child before removing it, and never
    constructs a path from a descriptor.
    """

    flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0)
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        expected = os.stat(name, dir_fd=parent_descriptor, follow_symlinks=False)
        descriptor = os.open(name, flags, dir_fd=parent_descriptor)
    except OSError as exc:
        raise TransactionError("cannot safely open generated-output transaction tree") from exc
    try:
        opened = os.fstat(descriptor)
        if (
            stat.S_ISLNK(expected.st_mode)
            or not stat.S_ISDIR(expected.st_mode)
            or not _same_filesystem_object(_path_identity(expected), _path_identity(opened))
        ):
            raise RecoveryRequiredError("generated-output transaction tree changed during removal")
        children = tuple(os.listdir(descriptor))
        for child in children:
            try:
                child_metadata = os.stat(child, dir_fd=descriptor, follow_symlinks=False)
            except OSError as exc:
                raise RecoveryRequiredError("generated-output transaction tree changed during removal") from exc
            quarantine = f".tree-cleanup-{uuid.uuid4().hex}"
            result = _rename_no_replace_at(descriptor, child, descriptor, quarantine)
            if result != 0:
                raise TransactionError("cannot atomically quarantine generated-output transaction entry")
            quarantined = os.stat(quarantine, dir_fd=descriptor, follow_symlinks=False)
            quarantined_identity = _path_identity(quarantined)
            child_identity = _path_identity(child_metadata)
            same_child = (
                _same_filesystem_object(quarantined_identity, child_identity)
                if stat.S_ISDIR(quarantined.st_mode)
                else _same_directory_entry(quarantined_identity, child_identity)
            )
            if not same_child:
                _rename_no_replace_at(descriptor, quarantine, descriptor, child)
                os.fsync(descriptor)
                raise RecoveryRequiredError("generated-output transaction entry changed before removal")
            if stat.S_ISDIR(quarantined.st_mode):
                _rmtree_at_compat(descriptor, quarantine)
            else:
                os.unlink(quarantine, dir_fd=descriptor)
            os.fsync(descriptor)
        if os.listdir(descriptor):
            raise RecoveryRequiredError("generated-output transaction tree changed during removal")
        entry = os.stat(name, dir_fd=parent_descriptor, follow_symlinks=False)
        if not _same_filesystem_object(_path_identity(entry), _path_identity(os.fstat(descriptor))):
            raise RecoveryRequiredError("generated-output transaction tree changed during removal")
    finally:
        os.close(descriptor)
    os.rmdir(name, dir_fd=parent_descriptor)


def _rmtree_at(parent_descriptor: int, name: str) -> None:
    try:
        supports_dir_fd = "dir_fd" in inspect.signature(shutil.rmtree).parameters
    except (TypeError, ValueError):
        supports_dir_fd = False
    if supports_dir_fd and getattr(shutil.rmtree, "avoids_symlink_attacks", False):
        shutil.rmtree(name, dir_fd=parent_descriptor)
        return
    _rmtree_at_compat(parent_descriptor, name)


def _secure_rmtree(parent: Path, name: str, expected_identity: _PathIdentity | None = None) -> None:
    with _directory_descriptor(parent) as parent_descriptor:
        try:
            metadata = os.stat(name, dir_fd=parent_descriptor, follow_symlinks=False)
        except FileNotFoundError:
            return
        if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISDIR(metadata.st_mode):
            raise RecoveryRequiredError("generated-output transaction tree is unsafe")
        expected = expected_identity or _path_identity(metadata)
        quarantine = f".cleanup-{uuid.uuid4().hex}"
        result = _rename_no_replace_at(parent_descriptor, name, parent_descriptor, quarantine)
        if result != 0:
            raise TransactionError("cannot atomically quarantine generated-output transaction tree")
        quarantined = os.stat(quarantine, dir_fd=parent_descriptor, follow_symlinks=False)
        if not _same_filesystem_object(_path_identity(quarantined), expected):
            _rename_no_replace_at(parent_descriptor, quarantine, parent_descriptor, name)
            os.fsync(parent_descriptor)
            raise RecoveryRequiredError("generated-output transaction tree changed before removal")
        _rmtree_at(parent_descriptor, quarantine)
        os.fsync(parent_descriptor)


def _secure_remove_regular(parent: Path, name: str, expected_identity: _PathIdentity) -> None:
    with _directory_descriptor(parent) as parent_descriptor:
        try:
            metadata = os.stat(name, dir_fd=parent_descriptor, follow_symlinks=False)
        except FileNotFoundError:
            return
        if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1:
            raise RecoveryRequiredError("generated-output transaction temporary is unsafe")
        quarantine = f".journal-cleanup-{uuid.uuid4().hex}.tmp"
        result = _rename_no_replace_at(parent_descriptor, name, parent_descriptor, quarantine)
        if result != 0:
            raise TransactionError("cannot atomically quarantine generated-output transaction temporary")
        quarantined = os.stat(quarantine, dir_fd=parent_descriptor, follow_symlinks=False)
        if not _same_directory_entry(_path_identity(quarantined), expected_identity):
            _rename_no_replace_at(parent_descriptor, quarantine, parent_descriptor, name)
            os.fsync(parent_descriptor)
            raise RecoveryRequiredError("generated-output transaction temporary changed before removal")
        os.unlink(quarantine, dir_fd=parent_descriptor)
        os.fsync(parent_descriptor)


def _write_file_durable(path: Path, payload: bytes, mode: int) -> None:
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    with _directory_descriptor(path.parent) as parent_descriptor:
        descriptor = os.open(path.name, flags, mode, dir_fd=parent_descriptor)
        try:
            with os.fdopen(descriptor, "wb", closefd=True) as stream:
                stream.write(payload)
                stream.flush()
                os.fchmod(stream.fileno(), mode)
                os.fsync(stream.fileno())
        except BaseException:
            with contextlib.suppress(TransactionError):
                opened = _read_regular_file_bounded(path, maximum=None, missing_ok=True)
                if opened is not None:
                    _, metadata = opened
                    _secure_remove_regular(path.parent, path.name, _path_identity(metadata))
            raise


def _rename_no_replace(source: Path, target: Path) -> None:
    """Atomically move ``source`` to an absent ``target`` without clobbering."""

    with (
        _directory_descriptor(source.parent) as source_descriptor,
        _directory_descriptor(target.parent) as target_descriptor,
    ):
        result = _rename_no_replace_at(
            source_descriptor,
            source.name,
            target_descriptor,
            target.name,
        )
        if result == 0:
            os.fsync(source_descriptor)
            if target_descriptor != source_descriptor:
                os.fsync(target_descriptor)
            return
    error = ctypes.get_errno()
    if error in {errno.EEXIST, errno.ENOTEMPTY}:
        raise TransactionError(f"generated-output no-clobber target already exists: {target.name}")
    raise TransactionError(f"generated-output atomic rename failed: {source.name}") from OSError(
        error, os.strerror(error)
    )


def _rename_no_replace_at(
    source_descriptor: int,
    source_name: str,
    target_descriptor: int,
    target_name: str,
) -> int:
    libc = ctypes.CDLL(None, use_errno=True)
    source_bytes = os.fsencode(source_name)
    target_bytes = os.fsencode(target_name)
    if sys.platform == "darwin":
        rename = getattr(libc, "renameatx_np", None)
        if rename is None:
            raise TransactionError("atomic descriptor-relative no-clobber rename is unavailable")
        rename.argtypes = (
            ctypes.c_int,
            ctypes.c_char_p,
            ctypes.c_int,
            ctypes.c_char_p,
            ctypes.c_uint,
        )
        rename.restype = ctypes.c_int
        return rename(source_descriptor, source_bytes, target_descriptor, target_bytes, 0x00000004)
    if sys.platform.startswith("linux"):
        rename = getattr(libc, "renameat2", None)
        if rename is None:
            raise TransactionError("atomic descriptor-relative no-clobber rename is unavailable")
        rename.argtypes = (
            ctypes.c_int,
            ctypes.c_char_p,
            ctypes.c_int,
            ctypes.c_char_p,
            ctypes.c_uint,
        )
        rename.restype = ctypes.c_int
        return rename(source_descriptor, source_bytes, target_descriptor, target_bytes, 0x00000001)
    raise TransactionError("atomic descriptor-relative no-clobber rename is unavailable")


def _restore_detached_no_clobber(detached: Path, target: Path) -> None:
    try:
        _rename_no_replace(detached, target)
    finally:
        _fsync_directory(target.parent)


def _retire_detached(
    detached: Path,
    private: Path,
    expected_kind: str,
    prior_state: _PathState,
    desired: _DesiredState | None,
) -> None:
    _rename_no_replace(detached, private)
    _fsync_directory(detached.parent)
    _fsync_directory(private.parent)
    if _classify_transaction_file(private, prior_state, desired) == expected_kind:
        return
    if _lstat(detached) is None:
        with contextlib.suppress(TransactionError):
            _rename_no_replace(private, detached)
            _fsync_directory(detached.parent)
            _fsync_directory(private.parent)
    raise TransactionError(f"detached generated output changed before retirement: {prior_state.path}")


def _replace_file_durable(
    staged: Path,
    target: Path,
    prior_state: _PathState,
    ownership: PriorOwnedOutput | None,
    transaction_root: Path,
) -> None:
    if ownership is None:
        _rename_no_replace(staged, target)
        _fsync_directory(target.parent)
        return

    detached = target.parents[0] / Path(prior_state.apply_detached).name
    _rename_no_replace(target, detached)
    _fsync_directory(target.parent)
    try:
        payload = _read_regular_file(detached)
        if not _target_matches(payload, ownership.sha256, ownership.marker):
            raise TransactionError(f"prior generated output changed during atomic detach: {prior_state.path}")
        _rename_no_replace(staged, target)
        _fsync_directory(target.parent)
    except Exception:
        if _lstat(detached) is not None and _lstat(target) is None:
            with contextlib.suppress(TransactionError):
                _restore_detached_no_clobber(detached, target)
        raise
    _retire_detached(
        detached,
        transaction_root / prior_state.retired,
        "prior",
        prior_state,
        None,
    )


def _delete_file_durable(
    target: Path,
    prior_state: _PathState,
    ownership: PriorOwnedOutput,
    transaction_root: Path,
) -> None:
    detached = target.parent / Path(prior_state.apply_detached).name
    _rename_no_replace(target, detached)
    _fsync_directory(target.parent)
    try:
        payload = _read_regular_file(detached)
        if not _target_matches(payload, ownership.sha256, ownership.marker):
            raise TransactionError(f"prior generated output changed during atomic delete: {prior_state.path}")
    except Exception:
        if _lstat(detached) is not None and _lstat(target) is None:
            with contextlib.suppress(TransactionError):
                _restore_detached_no_clobber(detached, target)
        raise
    _retire_detached(
        detached,
        transaction_root / prior_state.retired,
        "prior",
        prior_state,
        None,
    )


def _canonical_json(value: object) -> bytes:
    return (json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")) + "\n").encode("utf-8")


def _marker_text(marker: bytes) -> str:
    return base64.b64encode(marker).decode("ascii")


def _marker_bytes(value: object) -> bytes:
    if not isinstance(value, str):
        raise RecoveryRequiredError("generated-output transaction journal marker is invalid")
    try:
        marker = base64.b64decode(value, validate=True)
    except (ValueError, base64.binascii.Error) as exc:
        raise RecoveryRequiredError("generated-output transaction journal marker is invalid") from exc
    try:
        _validate_marker(marker)
    except TransactionError as exc:
        raise RecoveryRequiredError("generated-output transaction journal marker is invalid") from exc
    return marker


def _journal_document(journal: _Journal) -> dict[str, object]:
    return {
        "created_directories": list(journal.created_directories),
        "desired": [
            {"marker": _marker_text(item.marker), "mode": item.mode, "path": item.path, "sha256": item.sha256}
            for item in journal.desired
        ],
        "format_version": JOURNAL_FORMAT_VERSION,
        "phase": journal.phase,
        "prior": [
            {
                "backup": item.backup,
                "apply_detached": item.apply_detached,
                "discard_apply": item.discard_apply,
                "discard_rollback": item.discard_rollback,
                "existed": item.existed,
                "marker": None if item.marker is None else _marker_text(item.marker),
                "mode": item.mode,
                "path": item.path,
                "sha256": item.sha256,
                "rollback_detached": item.rollback_detached,
                "retired": item.retired,
            }
            for item in journal.prior
        ],
        "token": journal.token,
    }


def _write_journal(
    state_root: Path,
    journal: _Journal,
    injector: FaultInjector | None = None,
) -> _Journal:
    payload = _canonical_json(_journal_document(journal))
    if len(payload) > MAX_JOURNAL_BYTES:
        raise TransactionError("generated-output transaction journal exceeds its size limit")
    temporary_name = f".journal-{uuid.uuid4().hex}.tmp"
    published = False
    published_journal = dataclasses.replace(journal, entry_identity=None)
    written_identity: _PathIdentity | None = None
    with _directory_descriptor(state_root) as state_descriptor:
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
        descriptor = os.open(temporary_name, flags, 0o600, dir_fd=state_descriptor)
        try:
            with os.fdopen(descriptor, "wb") as stream:
                stream.write(payload)
                stream.flush()
                os.fchmod(stream.fileno(), 0o600)
                os.fsync(stream.fileno())
                written_identity = _path_identity(os.fstat(stream.fileno()))
            assert written_identity is not None
            os.replace(
                temporary_name,
                JOURNAL_NAME,
                src_dir_fd=state_descriptor,
                dst_dir_fd=state_descriptor,
            )
            published = True
            journal_metadata = os.stat(JOURNAL_NAME, dir_fd=state_descriptor, follow_symlinks=False)
            if not _same_directory_entry(_path_identity(journal_metadata), written_identity):
                published_journal = dataclasses.replace(journal, entry_identity=written_identity)
                raise TransactionError("generated-output transaction journal changed during publication")
            published_journal = dataclasses.replace(journal, entry_identity=written_identity)
            _fault(injector, "journal_published", journal.phase)
            os.fsync(state_descriptor)
            return published_journal
        except Exception as exc:
            if published:
                raise _JournalPublicationError(published_journal) from exc
            with contextlib.suppress(TransactionError):
                opened = _read_regular_file_bounded(
                    state_root / temporary_name,
                    maximum=MAX_JOURNAL_BYTES,
                    missing_ok=True,
                )
                if opened is not None:
                    _, metadata = opened
                    _secure_remove_regular(state_root, temporary_name, _path_identity(metadata))
            raise
        except BaseException:
            with contextlib.suppress(TransactionError):
                opened = _read_regular_file_bounded(
                    state_root / temporary_name,
                    maximum=MAX_JOURNAL_BYTES,
                    missing_ok=True,
                )
                if opened is not None:
                    _, metadata = opened
                    _secure_remove_regular(state_root, temporary_name, _path_identity(metadata))
            raise


def _expect_keys(value: object, expected: set[str], context: str) -> dict[str, object]:
    if not isinstance(value, dict) or set(value) != expected:
        raise RecoveryRequiredError(f"generated-output transaction journal {context} is invalid")
    return value


def _journal_pairs(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise RecoveryRequiredError("generated-output transaction journal contains a duplicate key")
        result[key] = value
    return result


def _read_journal(state_root: Path) -> _Journal | None:
    path = state_root / JOURNAL_NAME
    try:
        opened = _read_regular_file_bounded(path, maximum=MAX_JOURNAL_BYTES, missing_ok=True)
        if opened is None:
            return None
        raw, journal_metadata = opened
        value = json.loads(
            raw,
            object_pairs_hook=_journal_pairs,
            parse_constant=lambda _value: (_ for _ in ()).throw(ValueError("non-finite JSON number")),
        )
    except RecoveryRequiredError:
        raise
    except TransactionError as exc:
        raise RecoveryRequiredError("generated-output transaction journal is not a safe regular file") from exc
    except (OSError, UnicodeDecodeError, json.JSONDecodeError, OverflowError, RecursionError) as exc:
        raise RecoveryRequiredError("generated-output transaction journal cannot be decoded") from exc
    except ValueError as exc:
        raise RecoveryRequiredError("generated-output transaction journal is not strict JSON") from exc
    try:
        canonical = _canonical_json(value)
    except (OverflowError, RecursionError, TypeError, UnicodeError, ValueError) as exc:
        raise RecoveryRequiredError("generated-output transaction journal cannot be canonicalized") from exc
    if raw != canonical:
        raise RecoveryRequiredError("generated-output transaction journal is not canonical JSON")
    root = _expect_keys(
        value,
        {"created_directories", "desired", "format_version", "phase", "prior", "token"},
        "root",
    )
    format_version = root["format_version"]
    phase = root["phase"]
    if (
        type(format_version) is not int
        or format_version != JOURNAL_FORMAT_VERSION
        or not isinstance(phase, str)
        or phase not in {"prepared", "committed"}
    ):
        raise RecoveryRequiredError("generated-output transaction journal version or phase is invalid")
    token = root["token"]
    if not isinstance(token, str) or re.fullmatch(r"[0-9a-f]{32}", token) is None:
        raise RecoveryRequiredError("generated-output transaction journal token is invalid")

    prior: list[_PathState] = []
    if not isinstance(root["prior"], list):
        raise RecoveryRequiredError("generated-output transaction journal prior set is invalid")
    for raw_item in root["prior"]:
        item = _expect_keys(
            raw_item,
            {
                "apply_detached",
                "backup",
                "discard_apply",
                "discard_rollback",
                "existed",
                "marker",
                "mode",
                "path",
                "rollback_detached",
                "retired",
                "sha256",
            },
            "prior entry",
        )
        try:
            path_value = _normalized_output_path(item["path"] if isinstance(item["path"], str) else "")
        except TransactionError as exc:
            raise RecoveryRequiredError("generated-output transaction journal prior path is invalid") from exc
        index = len(prior)
        parent = PurePosixPath(path_value).parent
        expected_apply = (parent / f".defenseclaw-telemetry-{token}-{index:06d}-apply").as_posix()
        expected_rollback = (parent / f".defenseclaw-telemetry-{token}-{index:06d}-rollback").as_posix()
        expected_retired = f"retired/{index:06d}.retired"
        expected_discard_apply = f"discard/{index:06d}.apply"
        expected_discard_rollback = f"discard/{index:06d}.rollback"
        if (
            item["apply_detached"] != expected_apply
            or item["rollback_detached"] != expected_rollback
            or item["retired"] != expected_retired
            or item["discard_apply"] != expected_discard_apply
            or item["discard_rollback"] != expected_discard_rollback
        ):
            raise RecoveryRequiredError("generated-output transaction journal detached path is invalid")
        existed = item["existed"]
        if type(existed) is not bool:
            raise RecoveryRequiredError("generated-output transaction journal existence flag is invalid")
        if existed:
            digest = item["sha256"]
            mode = item["mode"]
            backup = item["backup"]
            if (
                not isinstance(digest, str)
                or _SHA256.fullmatch(digest) is None
                or type(mode) is not int
                or mode not in ALLOWED_OUTPUT_MODES
                or not isinstance(backup, str)
                or re.fullmatch(r"[0-9]{6}\.backup", backup) is None
            ):
                raise RecoveryRequiredError("generated-output transaction journal prior metadata is invalid")
            marker = _marker_bytes(item["marker"])
        else:
            if any(item[key] is not None for key in ("sha256", "mode", "marker", "backup")):
                raise RecoveryRequiredError("generated-output transaction journal absent-path metadata is invalid")
            digest = None
            mode = None
            marker = None
            backup = None
        prior.append(
            _PathState(
                path_value,
                existed,
                digest,
                mode,
                marker,
                backup,
                expected_apply,
                expected_rollback,
                expected_retired,
                expected_discard_apply,
                expected_discard_rollback,
            )
        )

    desired: list[_DesiredState] = []
    if not isinstance(root["desired"], list):
        raise RecoveryRequiredError("generated-output transaction journal desired set is invalid")
    for raw_item in root["desired"]:
        item = _expect_keys(raw_item, {"marker", "mode", "path", "sha256"}, "desired entry")
        try:
            path_value = _normalized_output_path(item["path"] if isinstance(item["path"], str) else "")
        except TransactionError as exc:
            raise RecoveryRequiredError("generated-output transaction journal desired path is invalid") from exc
        digest = item["sha256"]
        mode = item["mode"]
        if not isinstance(digest, str) or _SHA256.fullmatch(digest) is None or type(mode) is not int:
            raise RecoveryRequiredError("generated-output transaction journal desired metadata is invalid")
        try:
            _validate_mode(mode)
        except TransactionError as exc:
            raise RecoveryRequiredError("generated-output transaction journal desired mode is invalid") from exc
        desired.append(_DesiredState(path_value, digest, mode, _marker_bytes(item["marker"])))

    directories = root["created_directories"]
    if not isinstance(directories, list) or not all(isinstance(item, str) for item in directories):
        raise RecoveryRequiredError("generated-output transaction journal directory set is invalid")
    normalized_directories: list[str] = []
    for directory in directories:
        if directory == "" or directory.startswith("/") or "\\" in directory:
            raise RecoveryRequiredError("generated-output transaction journal directory is invalid")
        pure = PurePosixPath(directory)
        if pure.as_posix() != directory or ".." in pure.parts:
            raise RecoveryRequiredError("generated-output transaction journal directory is invalid")
        normalized_directories.append(directory)
    if len({item.path for item in prior}) != len(prior) or len({item.path for item in desired}) != len(desired):
        raise RecoveryRequiredError("generated-output transaction journal contains duplicate paths")
    if len(prior) > MAX_OUTPUTS or len(desired) > MAX_OUTPUTS:
        raise RecoveryRequiredError("generated-output transaction journal exceeds its file inventory limit")
    prior_paths = {item.path for item in prior}
    desired_paths = {item.path for item in desired}
    if MANIFEST_PATH not in desired_paths or not desired_paths.issubset(prior_paths):
        raise RecoveryRequiredError("generated-output transaction journal path sets are inconsistent")
    if [item.path for item in prior] != sorted(prior_paths) or [item.path for item in desired] != sorted(desired_paths):
        raise RecoveryRequiredError("generated-output transaction journal paths are not canonical ordered sets")
    allowed_directories = {
        parent.as_posix()
        for path in desired_paths
        for parent in PurePosixPath(path).parents
        if parent != PurePosixPath(".") and parent.is_relative_to(GENERATED_ROOT)
    }
    if any(directory not in allowed_directories for directory in normalized_directories):
        raise RecoveryRequiredError("generated-output transaction journal created-directory set is unsafe")
    return _Journal(
        token,
        phase,
        tuple(prior),
        tuple(desired),
        tuple(normalized_directories),
        _path_identity(journal_metadata),
    )


@contextlib.contextmanager
def _exclusive_lock(state_root: Path):  # type: ignore[no-untyped-def]
    if fcntl is None:
        raise TransactionError("generated-output transactions require POSIX advisory file locking")
    flags = os.O_RDWR | os.O_CREAT
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    with _directory_descriptor(state_root) as state_descriptor:
        try:
            descriptor = os.open(LOCK_NAME, flags, 0o600, dir_fd=state_descriptor)
        except OSError as exc:
            raise TransactionError("cannot open generated-output transaction lock") from exc
        try:
            metadata = os.fstat(descriptor)
            if not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1:
                raise TransactionError("generated-output transaction lock is not a safe regular file")
            try:
                fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except OSError as exc:
                if exc.errno in {errno.EACCES, errno.EAGAIN}:
                    raise TransactionBusyError("another generated-output writer is active") from exc
                raise TransactionError("cannot acquire generated-output transaction lock") from exc
            os.fchmod(descriptor, 0o600)
            os.fsync(descriptor)
            os.fsync(state_descriptor)
            yield
        finally:
            with contextlib.suppress(OSError):
                if fcntl is not None:
                    fcntl.flock(descriptor, fcntl.LOCK_UN)
            os.close(descriptor)


def _check_one(path: Path, output: RenderedOutput) -> tuple[str, ...]:
    try:
        opened = _read_regular_file_bounded(path, maximum=None, missing_ok=True)
    except TransactionError:
        return (f"unsafe={path.name}",)
    if opened is None:
        return (f"missing={path.name}",)
    payload, metadata = opened
    problems: list[str] = []
    if stat.S_IMODE(metadata.st_mode) != output.mode:
        problems.append(f"mode={path.name}")
    if payload != output.payload:
        problems.append(f"stale={path.name}")
    return tuple(problems)


def check_outputs(
    root: Path,
    outputs: Mapping[str | Path, RenderedOutput],
    prior: Mapping[str | Path, PriorOwnedOutput],
) -> None:
    """Verify exact bytes/modes/ownership without creating locks or state."""

    root = _safe_root(root)
    _validate_required_roots(root)
    normalized_outputs, normalized_prior = _normalize_inputs(outputs, prior)
    state_root = _state_root(root, create=False)
    if state_root.exists() and (_read_journal(state_root) is not None or _has_orphan_state(state_root)):
        raise RecoveryRequiredError("generated-output transaction recovery is required before check mode")

    problems: list[str] = []
    for path, output in sorted(normalized_outputs.items()):
        try:
            _validate_existing_parents(root, path)
        except TransactionError:
            problems.append(f"parent={path}")
            continue
        if path not in normalized_prior and _lstat(root / path) is not None:
            problems.append(f"unowned={path}")
            continue
        problems.extend(item.replace(Path(path).name, path) for item in _check_one(root / path, output))
    for path, ownership in sorted(normalized_prior.items()):
        if path in normalized_outputs:
            continue
        target = root / path
        metadata = _lstat(target)
        if metadata is None:
            continue
        try:
            opened = _read_regular_file_bounded(target, maximum=None, missing_ok=True)
            if opened is None:
                continue
            payload, metadata = opened
            marker_valid = ownership.marker in payload[:MARKER_SCAN_BYTES]
        except TransactionError:
            problems.append(f"unsafe-extra={path}")
            continue
        if not marker_valid or _sha256(payload) != ownership.sha256 or stat.S_IMODE(metadata.st_mode) != ownership.mode:
            problems.append(f"unsafe-extra={path}")
        else:
            problems.append(f"extra={path}")
    if problems:
        raise GeneratedOutputDriftError(tuple(sorted(problems)))


def _copy_backup(source: Path, target: Path, mode: int) -> None:
    payload = _read_regular_file(source)
    _write_file_durable(target, payload, mode)
    _fsync_directory(target.parent)


def _planned_journal(
    token: str,
    outputs: Mapping[str, RenderedOutput],
    prior: Mapping[str, PriorOwnedOutput],
    created_directories: tuple[str, ...],
) -> _Journal:
    prior_states: list[_PathState] = []
    for index, path in enumerate(sorted(set(outputs) | set(prior))):
        parent = PurePosixPath(path).parent
        apply_detached = (parent / f".defenseclaw-telemetry-{token}-{index:06d}-apply").as_posix()
        rollback_detached = (parent / f".defenseclaw-telemetry-{token}-{index:06d}-rollback").as_posix()
        retired = f"retired/{index:06d}.retired"
        discard_apply = f"discard/{index:06d}.apply"
        discard_rollback = f"discard/{index:06d}.rollback"
        ownership = prior.get(path)
        if ownership is None:
            prior_states.append(
                _PathState(
                    path,
                    False,
                    None,
                    None,
                    None,
                    None,
                    apply_detached,
                    rollback_detached,
                    retired,
                    discard_apply,
                    discard_rollback,
                )
            )
            continue
        prior_states.append(
            _PathState(
                path,
                True,
                ownership.sha256,
                ownership.mode,
                ownership.marker,
                f"{index:06d}.backup",
                apply_detached,
                rollback_detached,
                retired,
                discard_apply,
                discard_rollback,
            )
        )
    desired = tuple(
        _DesiredState(path, _sha256(output.payload), output.mode, output.marker)
        for path, output in sorted(outputs.items())
    )
    journal = _Journal(token, "prepared", tuple(prior_states), desired, created_directories)
    committed = dataclasses.replace(journal, phase="committed")
    if (
        max(
            len(_canonical_json(_journal_document(journal))),
            len(_canonical_json(_journal_document(committed))),
        )
        > MAX_JOURNAL_BYTES
    ):
        raise TransactionError("generated-output transaction journal exceeds its size limit")
    return journal


def _prepare_journal(
    root: Path,
    state_root: Path,
    token: str,
    outputs: Mapping[str, RenderedOutput],
    prior: Mapping[str, PriorOwnedOutput],
    created_directories: tuple[str, ...],
    injector: FaultInjector | None,
) -> tuple[_Journal, Path]:
    journal = _planned_journal(token, outputs, prior, created_directories)
    for state in journal.prior:
        if _lstat(root / state.apply_detached) is not None or _lstat(root / state.rollback_detached) is not None:
            raise TransactionError("generated-output transaction detached path collision")
    transaction_root = state_root / "transactions" / token
    stage_root = transaction_root / "stage"
    backup_root = transaction_root / "backup"
    for relative in (
        f"transactions/{token}/stage",
        f"transactions/{token}/backup",
        f"transactions/{token}/retired",
        f"transactions/{token}/discard",
    ):
        _ensure_relative_directory(state_root, relative, 0o700)
    _fault(injector, "stage_created")
    for path, output in sorted(outputs.items()):
        staged = stage_root / path
        _ensure_relative_directory(stage_root, PurePosixPath(path).parent.as_posix(), 0o700)
        _write_file_durable(staged, output.payload, output.mode)
        _fault(injector, "output_staged", path)
    _fsync_directory_tree(stage_root)
    _fault(injector, "staging_fsynced")

    for prior_state in journal.prior:
        if not prior_state.existed:
            continue
        assert prior_state.backup is not None
        assert prior_state.mode is not None
        assert prior_state.sha256 is not None
        assert prior_state.marker is not None
        backup = backup_root / prior_state.backup
        _copy_backup(root / prior_state.path, backup, prior_state.mode)
        backup_payload = _read_regular_file(backup)
        if not _target_matches(backup_payload, prior_state.sha256, prior_state.marker):
            raise TransactionError(f"generated-output backup changed during preparation: {prior_state.path}")
        _fault(injector, "output_backed_up", prior_state.path)
    _fsync_directory_tree(backup_root)
    _fault(injector, "backups_complete")
    _fsync_directory_tree(transaction_root)
    _fsync_directory(transaction_root.parent)
    _fsync_directory(state_root)
    _fault(injector, "transaction_ancestors_fsynced")
    journal = _write_journal(state_root, journal, injector)
    return journal, transaction_root


def _create_target_directories(root: Path, directories: tuple[str, ...]) -> None:
    pending = list(directories)
    generated_relative = GENERATED_ROOT.as_posix()
    if generated_relative in pending:
        _create_generated_root(root)
        pending.remove(generated_relative)
    elif not _generated_root_exists(root):
        raise TransactionError("telemetry generated-output root disappeared during transaction")
    for relative in pending:
        _ensure_relative_directory(root, relative, 0o755)


def _create_generated_root(root: Path) -> None:
    """Create only ``schemas/telemetry/generated`` through its pinned parent."""

    parent = root / GENERATED_ROOT.parent.as_posix()
    flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0)
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    with _directory_descriptor(parent) as parent_descriptor:
        try:
            os.mkdir(GENERATED_ROOT.name, mode=0o755, dir_fd=parent_descriptor)
            descriptor = os.open(GENERATED_ROOT.name, flags, dir_fd=parent_descriptor)
        except FileExistsError as exc:
            raise TransactionError("telemetry generated-output root appeared during transaction") from exc
        except OSError as exc:
            raise TransactionError("cannot safely create the telemetry generated-output root") from exc
        try:
            metadata = os.fstat(descriptor)
            if not stat.S_ISDIR(metadata.st_mode):
                raise TransactionError("created telemetry generated-output root is not a directory")
            os.fchmod(descriptor, 0o755)
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
        os.fsync(parent_descriptor)


def _ensure_relative_directory(root: Path, relative: str, mode: int) -> None:
    if relative in {"", "."}:
        return
    flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0)
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    with _directory_descriptor(root) as root_descriptor:
        descriptor = os.dup(root_descriptor)
        try:
            for part in PurePosixPath(relative).parts:
                created = False
                try:
                    next_descriptor = os.open(part, flags, dir_fd=descriptor)
                except FileNotFoundError:
                    os.mkdir(part, mode=mode, dir_fd=descriptor)
                    os.fsync(descriptor)
                    next_descriptor = os.open(part, flags, dir_fd=descriptor)
                    created = True
                except OSError as exc:
                    raise TransactionError("generated-output parent changed during transaction") from exc
                os.close(descriptor)
                descriptor = next_descriptor
                if created:
                    os.fchmod(descriptor, mode)
                    os.fsync(descriptor)
        finally:
            os.close(descriptor)


def _create_transaction_root(state_root: Path, token: str) -> tuple[Path, _PathIdentity]:
    transactions = state_root / "transactions"
    _ensure_relative_directory(state_root, "transactions", 0o700)
    flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0)
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    with _directory_descriptor(transactions) as transactions_descriptor:
        try:
            os.mkdir(token, mode=0o700, dir_fd=transactions_descriptor)
            descriptor = os.open(token, flags, dir_fd=transactions_descriptor)
        except OSError as exc:
            raise TransactionError("cannot create generated-output transaction root") from exc
        try:
            os.fchmod(descriptor, 0o700)
            os.fsync(descriptor)
            identity = _path_identity(os.fstat(descriptor))
        finally:
            os.close(descriptor)
        os.fsync(transactions_descriptor)
    return transactions / token, identity


def _target_matches(payload: bytes, digest: str, marker: bytes) -> bool:
    return _sha256(payload) == digest and marker in payload[:MARKER_SCAN_BYTES]


def _classify_transaction_file(
    path: Path,
    prior_state: _PathState,
    desired: _DesiredState | None,
) -> str:
    try:
        opened = _read_regular_file_bounded(path, maximum=None, missing_ok=True)
    except (OSError, TransactionError):
        return "unknown"
    if opened is None:
        return "absent"
    payload, _ = opened
    if (
        prior_state.existed
        and prior_state.sha256 is not None
        and prior_state.marker is not None
        and _target_matches(payload, prior_state.sha256, prior_state.marker)
    ):
        return "prior"
    if desired is not None and _target_matches(payload, desired.sha256, desired.marker):
        return "desired"
    return "unknown"


def _remove_detached_exact(
    path: Path,
    private: Path,
    expected_kind: str,
    prior_state: _PathState,
    desired: _DesiredState | None,
) -> None:
    try:
        _retire_detached(path, private, expected_kind, prior_state, desired)
    except TransactionError as exc:
        raise RollbackError(f"detached generated output changed before cleanup: {prior_state.path}") from exc


def _install_prior_from_backup(
    backup: Path,
    slot: Path,
    target: Path,
    prior_state: _PathState,
) -> None:
    assert prior_state.mode is not None
    assert prior_state.sha256 is not None
    assert prior_state.marker is not None
    payload = _read_regular_file(backup)
    if not _target_matches(payload, prior_state.sha256, prior_state.marker):
        raise RollbackError(f"generated-output backup is invalid: {prior_state.path}")
    if _lstat(slot) is None:
        _write_file_durable(slot, payload, prior_state.mode)
        _fsync_directory(slot.parent)
    if _classify_transaction_file(slot, prior_state, None) != "prior":
        raise RollbackError(f"generated-output rollback slot is invalid: {prior_state.path}")
    _rename_no_replace(slot, target)
    _fsync_directory(target.parent)


def _assert_target_precondition(
    root: Path,
    path: str,
    prior: Mapping[str, PriorOwnedOutput],
) -> _PathIdentity | None:
    _validate_existing_parents(root, path)
    target = root / path
    ownership = prior.get(path)
    metadata = _lstat(target)
    if ownership is None:
        if metadata is not None:
            raise TransactionError(f"unowned generated output appeared during transaction: {path}")
        return None
    if metadata is None:
        raise TransactionError(f"prior generated output disappeared during transaction: {path}")
    metadata = _validate_regular_file(target, expected_mode=ownership.mode)
    payload = _read_regular_file(target)
    if not _target_matches(payload, ownership.sha256, ownership.marker):
        raise TransactionError(f"prior generated output changed during transaction: {path}")
    identity = _path_identity(metadata)
    if _identity_at_mutation(target) != identity:
        raise TransactionError(f"prior generated output changed while validating transaction: {path}")
    return identity


def _rollback(root: Path, state_root: Path, journal: _Journal, injector: FaultInjector | None) -> None:
    _fault(injector, "rollback_started")
    transaction_root = state_root / "transactions" / journal.token
    backup_root = transaction_root / "backup"
    desired = {item.path: item for item in journal.desired}
    failures: list[str] = []
    for prior_state in journal.prior:
        if not prior_state.existed:
            continue
        assert prior_state.backup is not None
        assert prior_state.sha256 is not None
        assert prior_state.marker is not None
        backup_payload = _read_regular_file(backup_root / prior_state.backup)
        if not _target_matches(backup_payload, prior_state.sha256, prior_state.marker):
            raise RollbackError(f"generated-output backup is invalid: {prior_state.path}")
    for prior_state in reversed(journal.prior):
        target = root / prior_state.path
        apply_detached = root / prior_state.apply_detached
        rollback_detached = root / prior_state.rollback_detached
        current_desired = desired.get(prior_state.path)
        try:
            _validate_existing_parents(root, prior_state.path)
            apply_kind = _classify_transaction_file(apply_detached, prior_state, current_desired)
            rollback_kind = _classify_transaction_file(rollback_detached, prior_state, current_desired)
            if apply_kind not in {"absent", "prior"} or rollback_kind == "unknown":
                raise RollbackError(f"generated-output detached state is unsafe: {prior_state.path}")

            target_kind = _classify_transaction_file(target, prior_state, current_desired)
            if target_kind != "absent" and rollback_kind == "absent":
                _rename_no_replace(target, rollback_detached)
                _fsync_directory(target.parent)
                rollback_kind = _classify_transaction_file(rollback_detached, prior_state, current_desired)
                target_kind = "absent"
            elif target_kind == "unknown":
                raise RollbackError(f"generated output changed before rollback: {prior_state.path}")

            if rollback_kind == "unknown":
                if _lstat(target) is None:
                    with contextlib.suppress(TransactionError):
                        _restore_detached_no_clobber(rollback_detached, target)
                raise RollbackError(f"generated output changed before rollback: {prior_state.path}")

            if prior_state.existed:
                if target_kind != "prior":
                    if apply_kind == "prior":
                        _rename_no_replace(apply_detached, target)
                        _fsync_directory(target.parent)
                        apply_kind = "absent"
                    elif rollback_kind == "prior":
                        _rename_no_replace(rollback_detached, target)
                        _fsync_directory(target.parent)
                        rollback_kind = "absent"
                    else:
                        assert prior_state.backup is not None
                        _install_prior_from_backup(
                            backup_root / prior_state.backup,
                            apply_detached,
                            target,
                            prior_state,
                        )
                        apply_kind = "absent"
                if _classify_transaction_file(target, prior_state, current_desired) != "prior":
                    raise RollbackError(f"generated output prior state was not restored: {prior_state.path}")
                if apply_kind == "prior":
                    _remove_detached_exact(
                        apply_detached,
                        transaction_root / prior_state.discard_apply,
                        "prior",
                        prior_state,
                        current_desired,
                    )
                if rollback_kind in {"prior", "desired"}:
                    _remove_detached_exact(
                        rollback_detached,
                        transaction_root / prior_state.discard_rollback,
                        rollback_kind,
                        prior_state,
                        current_desired,
                    )
            else:
                if target_kind != "absent":
                    raise RollbackError(f"new generated output changed before rollback: {prior_state.path}")
                if rollback_kind == "desired":
                    _remove_detached_exact(
                        rollback_detached,
                        transaction_root / prior_state.discard_rollback,
                        "desired",
                        prior_state,
                        current_desired,
                    )
                elif rollback_kind != "absent":
                    raise RollbackError(f"new generated output changed before rollback: {prior_state.path}")
            _fault(injector, "output_rolled_back", prior_state.path)
        except (OSError, TransactionError) as exc:
            failures.append(f"{prior_state.path}:{exc.__class__.__name__}")
    if failures:
        raise RollbackError("generated-output rollback was incomplete: " + ",".join(failures))
    _cleanup_transaction(root, state_root, journal, injector)
    _fault(injector, "rollback_complete")


def _retire_exact_journal(
    state_root: Path,
    transaction_root: Path,
    journal: _Journal,
) -> _PathIdentity:
    if journal.entry_identity is None:
        raise RollbackError("generated-output journal identity is unavailable for cleanup")
    retired_name = "retired-journal.json"
    with (
        _directory_descriptor(state_root) as state_descriptor,
        _directory_descriptor(transaction_root) as transaction_descriptor,
    ):
        result = _rename_no_replace_at(
            state_descriptor,
            JOURNAL_NAME,
            transaction_descriptor,
            retired_name,
        )
        if result != 0:
            raise RollbackError("generated-output journal could not be atomically retired")
        transaction_identity = _path_identity(os.fstat(transaction_descriptor))
        os.fsync(state_descriptor)
        os.fsync(transaction_descriptor)
    retired = transaction_root / retired_name
    try:
        opened = _read_regular_file_bounded(retired, maximum=MAX_JOURNAL_BYTES, missing_ok=False)
        assert opened is not None
        payload, metadata = opened
        if not _same_directory_entry(_path_identity(metadata), journal.entry_identity) or payload != _canonical_json(
            _journal_document(journal)
        ):
            raise RollbackError("generated-output journal changed before cleanup")
    except Exception:
        with contextlib.suppress(TransactionError):
            _rename_no_replace(retired, state_root / JOURNAL_NAME)
        raise
    return transaction_identity


def _cleanup_transaction(
    root: Path,
    state_root: Path,
    journal: _Journal,
    injector: FaultInjector | None = None,
) -> None:
    transaction_root = state_root / "transactions" / journal.token
    desired = {item.path: item for item in journal.desired}
    if any(
        _classify_transaction_file(root / detached, state, desired.get(state.path)) != "absent"
        for state in journal.prior
        for detached in (state.apply_detached, state.rollback_detached)
    ):
        raise RollbackError("generated-output detached files remain before transaction cleanup")
    transaction_identity = _retire_exact_journal(state_root, transaction_root, journal)
    _cleanup_journal_temporaries(state_root)
    _fault(injector, "cleanup_journal_removed")
    transactions = state_root / "transactions"
    _secure_rmtree(transactions, journal.token, transaction_identity)
    _fault(injector, "cleanup_backups_removed")


def _cleanup_orphan_transactions(state_root: Path) -> bool:
    transactions = state_root / "transactions"
    try:
        with _directory_descriptor(transactions) as descriptor:
            children = tuple(os.listdir(descriptor))
            child_metadata = {name: os.stat(name, dir_fd=descriptor, follow_symlinks=False) for name in children}
    except TransactionError:
        if _lstat(transactions) is None:
            return False
        raise RecoveryRequiredError("generated-output transaction staging root is unsafe")
    recovered = False
    for name in children:
        metadata = child_metadata[name]
        if (
            re.fullmatch(r"(?:[0-9a-f]{32}|\.cleanup-[0-9a-f]{32})", name) is None
            or stat.S_ISLNK(metadata.st_mode)
            or not stat.S_ISDIR(metadata.st_mode)
        ):
            raise RecoveryRequiredError("generated-output transaction staging entry is unsafe")
        _secure_rmtree(transactions, name, _path_identity(metadata))
        recovered = True
    if recovered:
        _fsync_directory(state_root)
    return recovered


def _journal_temporaries(state_root: Path) -> tuple[tuple[str, _PathIdentity], ...]:
    result: list[tuple[str, _PathIdentity]] = []
    with _directory_descriptor(state_root) as descriptor:
        for name in os.listdir(descriptor):
            if not (name.startswith(".journal-") and name.endswith(".tmp")):
                continue
            metadata = os.stat(name, dir_fd=descriptor, follow_symlinks=False)
            if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1:
                raise RecoveryRequiredError("generated-output transaction journal temporary is unsafe")
            result.append((name, _path_identity(metadata)))
    return tuple(sorted(result, key=lambda item: item[0]))


def _has_orphan_state(state_root: Path) -> bool:
    transactions = state_root / "transactions"
    try:
        with _directory_descriptor(transactions) as descriptor:
            if os.listdir(descriptor):
                return True
    except TransactionError:
        if _lstat(transactions) is not None:
            raise RecoveryRequiredError("generated-output transaction staging root is unsafe")
    return bool(_journal_temporaries(state_root))


def _cleanup_journal_temporaries(state_root: Path) -> bool:
    temporaries = _journal_temporaries(state_root)
    for name, identity in temporaries:
        _secure_remove_regular(state_root, name, identity)
    return bool(temporaries)


def _desired_is_complete(root: Path, journal: _Journal) -> bool:
    desired_paths = {item.path for item in journal.desired}
    desired_by_path = {item.path: item for item in journal.desired}
    if any(
        _classify_transaction_file(root / detached, state, desired_by_path.get(state.path)) != "absent"
        for state in journal.prior
        for detached in (state.apply_detached, state.rollback_detached)
    ):
        return False
    for desired in journal.desired:
        path = root / desired.path
        try:
            opened = _read_regular_file_bounded(path, maximum=None, missing_ok=True)
        except (OSError, TransactionError):
            return False
        if opened is None:
            return False
        payload, metadata = opened
        if stat.S_IMODE(metadata.st_mode) != desired.mode:
            return False
        if _sha256(payload) != desired.sha256 or desired.marker not in payload[:MARKER_SCAN_BYTES]:
            return False
    for state in journal.prior:
        if state.path in desired_paths:
            continue
        try:
            opened = _read_regular_file_bounded(root / state.path, maximum=None, missing_ok=True)
        except (OSError, TransactionError):
            return False
        if opened is not None:
            return False
    return True


def _recover_locked(
    root: Path,
    state_root: Path,
    injector: FaultInjector | None,
) -> RecoveryResult:
    journal = _read_journal(state_root)
    if journal is None:
        recovered = _cleanup_orphan_transactions(state_root)
        recovered = _cleanup_journal_temporaries(state_root) or recovered
        return RecoveryResult(recovered, "discarded_staging" if recovered else "none")
    _fault(injector, "recovery_started")
    if journal.phase == "committed" and _desired_is_complete(root, journal):
        _cleanup_transaction(root, state_root, journal, injector)
        _fault(injector, "recovery_complete")
        return RecoveryResult(True, "completed")
    _rollback(root, state_root, journal, injector)
    _fault(injector, "recovery_complete")
    return RecoveryResult(True, "rolled_back")


def recover_outputs(root: Path, *, fault_injector: FaultInjector | None = None) -> RecoveryResult:
    """Recover an interrupted write while holding the exclusive writer lock."""

    root = _safe_root(root)
    _validate_required_roots(root)
    state_root = _state_root(root, create=True)
    with _exclusive_lock(state_root):
        _fault(fault_injector, "lock_acquired")
        return _recover_locked(root, state_root, fault_injector)


def write_outputs(
    root: Path,
    outputs: Mapping[str | Path, RenderedOutput],
    prior: Mapping[str | Path, PriorOwnedOutput],
    *,
    fault_injector: FaultInjector | None = None,
) -> RecoveryResult:
    """Write all outputs with manifest-last logical commit and recovery.

    The repository-local lock excludes other generated-output writers only.  It
    does not exclude ``go build``, ``go test``, language servers, or other direct
    readers, so the caller must provide a quiescent worktree until this function
    returns.  If the process is interrupted, no reader may consume generated
    paths until a later writer completes journal recovery.

    The return value reports whether this invocation first recovered an older
    interrupted transaction.  A normal successful write returns ``action``
    ``"written"`` regardless of whether the generated bytes were unchanged.
    """

    root = _safe_root(root)
    _validate_required_roots(root, allow_missing_generated=True)
    normalized_outputs, normalized_prior = _normalize_inputs(outputs, prior)
    state_root = _state_root(root, create=True)
    with _exclusive_lock(state_root):
        _fault(fault_injector, "lock_acquired")
        recovered = _recover_locked(root, state_root, fault_injector)
        _fault(fault_injector, "recovery_checked")
        created_directories = _validate_current_ownership(root, normalized_outputs, normalized_prior)
        _fault(fault_injector, "outputs_validated")
        token = uuid.uuid4().hex
        journal: _Journal | None = None
        transaction_root: Path | None = None
        transaction_identity: _PathIdentity | None = None
        try:
            transaction_root, transaction_identity = _create_transaction_root(state_root, token)
            journal, prepared_root = _prepare_journal(
                root,
                state_root,
                token,
                normalized_outputs,
                normalized_prior,
                created_directories,
                fault_injector,
            )
            if prepared_root != transaction_root:
                raise TransactionError("generated-output transaction root identity is inconsistent")
            _fault(fault_injector, "journal_prepared")
            _create_target_directories(root, created_directories)
            _fault(fault_injector, "target_directories_created")
            stage_root = transaction_root / "stage"
            prior_states = {item.path: item for item in journal.prior}
            non_manifest = sorted(path for path in normalized_outputs if path != MANIFEST_PATH)
            deleted = sorted(path for path in normalized_prior if path not in normalized_outputs)
            for path in non_manifest:
                _fault(fault_injector, "before_output_apply", path)
                _assert_target_precondition(root, path, normalized_prior)
                _replace_file_durable(
                    stage_root / path,
                    root / path,
                    prior_states[path],
                    normalized_prior.get(path),
                    transaction_root,
                )
                _fault(fault_injector, "after_output_apply", path)
            for path in deleted:
                _fault(fault_injector, "before_output_delete", path)
                target = root / path
                _assert_target_precondition(root, path, normalized_prior)
                _delete_file_durable(
                    target,
                    prior_states[path],
                    normalized_prior[path],
                    transaction_root,
                )
                _fault(fault_injector, "after_output_delete", path)
            _fault(fault_injector, "before_manifest_apply", MANIFEST_PATH)
            _assert_target_precondition(root, MANIFEST_PATH, normalized_prior)
            _replace_file_durable(
                stage_root / MANIFEST_PATH,
                root / MANIFEST_PATH,
                prior_states[MANIFEST_PATH],
                normalized_prior.get(MANIFEST_PATH),
                transaction_root,
            )
            _fault(fault_injector, "after_manifest_apply", MANIFEST_PATH)
            committed = dataclasses.replace(journal, phase="committed", entry_identity=None)
            journal = _write_journal(state_root, committed, fault_injector)
            _fault(fault_injector, "journal_committed")
            _cleanup_transaction(root, state_root, journal, fault_injector)
            _fault(fault_injector, "cleanup_complete")
        except Exception as exc:
            if isinstance(exc, _JournalPublicationError):
                journal = exc.journal
            if journal is not None and journal.phase == "committed":
                if not (state_root / JOURNAL_NAME).exists():
                    raise TransactionError(
                        "generated-output transaction committed before a post-commit failure"
                    ) from exc
                raise TransactionError("generated-output transaction committed but cleanup requires recovery") from exc
            if journal is not None:
                try:
                    _rollback(root, state_root, journal, fault_injector)
                except Exception as rollback_exc:
                    raise RollbackError("generated-output write and rollback both failed") from rollback_exc
            elif transaction_root is not None and transaction_identity is not None:
                with contextlib.suppress(TransactionError):
                    _secure_rmtree(transaction_root.parent, transaction_root.name, transaction_identity)
            raise TransactionError("generated-output transaction failed and was rolled back") from exc
        return RecoveryResult(recovered.recovered, "written")


__all__ = [
    "EXACT_INTERNAL_OUTPUTS",
    "GeneratedOutputDriftError",
    "MANIFEST_PATH",
    "PriorOwnedOutput",
    "RecoveryRequiredError",
    "RecoveryResult",
    "RenderedOutput",
    "RollbackError",
    "TransactionBusyError",
    "TransactionError",
    "check_outputs",
    "recover_outputs",
    "write_outputs",
]
