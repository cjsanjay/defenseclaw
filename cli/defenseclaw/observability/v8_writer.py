# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# SPDX-License-Identifier: Apache-2.0

"""Comment-preserving, validated writes for ordinary v8 policy mutations."""

from __future__ import annotations

import hashlib
import os
import stat
import tempfile
from collections.abc import Callable, Iterable
from dataclasses import dataclass
from pathlib import Path

from defenseclaw.config import _assert_config_write_allowed, locked_config_yaml
from defenseclaw.config_inspect import inspect_v8_config
from defenseclaw.observability.v8_config import load_validate_v8
from defenseclaw.observability.v8_yaml import V8YAMLMutation, prepare_v8_yaml_write


@dataclass(frozen=True)
class V8PolicyWriteResult:
    """Digest-only result; source bytes and values never enter diagnostics."""

    changed: bool
    before_sha256: str
    after_sha256: str


V8CandidateValidator = Callable[[str, str | None], None]


def mutate_v8_config(
    config_path: str | Path,
    mutations: Iterable[V8YAMLMutation],
    *,
    data_dir: str | None = None,
    validator: V8CandidateValidator | None = None,
    dry_run: bool = False,
) -> V8PolicyWriteResult:
    """Prepare, validate, and atomically install one ordinary v8 edit.

    The shared sibling lock covers the full read/prepare/validate/replace cycle.
    Validation runs first in the strict Python parser and then in the canonical
    Go compiler against a private sibling candidate.  The original file is
    unchanged on every failure.  This is the ordinary setup/TUI mutation path;
    full-version upgrade activation continues to use ``v8_activation``.
    """

    path = os.path.abspath(os.fspath(config_path))
    validate = validator or _validate_candidate
    with locked_config_yaml(path):
        _assert_safe_target(path)
        _assert_config_write_allowed(path)
        original = Path(path).read_bytes()
        prepared = prepare_v8_yaml_write(original, tuple(mutations), source_name=path)
        if not prepared.changed:
            return V8PolicyWriteResult(False, prepared.expected_sha256, prepared.candidate_sha256)

        load_validate_v8(prepared.candidate, source_name=path)
        candidate_path = _stage_candidate(path, prepared.candidate)
        try:
            validate(candidate_path, data_dir)
            if dry_run:
                return V8PolicyWriteResult(True, prepared.expected_sha256, prepared.candidate_sha256)
            current = Path(path).read_bytes()
            if hashlib.sha256(current).hexdigest() != prepared.expected_sha256:
                raise RuntimeError("config.yaml changed while the observability policy edit was being validated")
            os.replace(candidate_path, path)
            candidate_path = ""
            _fsync_directory(os.path.dirname(path) or ".")
        finally:
            if candidate_path:
                try:
                    os.unlink(candidate_path)
                except FileNotFoundError:
                    pass
        return V8PolicyWriteResult(True, prepared.expected_sha256, prepared.candidate_sha256)


def _validate_candidate(path: str, data_dir: str | None) -> None:
    result = inspect_v8_config("validate", config_path=path, data_dir=data_dir)
    if result.valid is not True:
        raise RuntimeError("canonical v8 configuration validator rejected the candidate")


def _assert_safe_target(path: str) -> None:
    try:
        metadata = os.lstat(path)
    except FileNotFoundError as exc:
        raise FileNotFoundError("config.yaml does not exist; initialize DefenseClaw before editing v8 policy") from exc
    if stat.S_ISLNK(metadata.st_mode):
        raise OSError("refusing to edit config.yaml through a symbolic link")
    if not stat.S_ISREG(metadata.st_mode):
        raise OSError("config.yaml must be a regular file")


def _stage_candidate(path: str, candidate: bytes) -> str:
    directory = os.path.dirname(path) or "."
    existing_mode = stat.S_IMODE(os.stat(path, follow_symlinks=False).st_mode)
    target_mode = existing_mode & 0o640
    if target_mode not in {0o600, 0o640}:
        target_mode = 0o600
    descriptor, staged = tempfile.mkstemp(
        prefix=f".{os.path.basename(path)}.observability-v8-",
        suffix=".tmp",
        dir=directory,
    )
    try:
        os.fchmod(descriptor, target_mode)
        with os.fdopen(descriptor, "wb") as stream:
            stream.write(candidate)
            stream.flush()
            os.fsync(stream.fileno())
    except BaseException:
        try:
            os.close(descriptor)
        except OSError:
            pass
        try:
            os.unlink(staged)
        except OSError:
            pass
        raise
    return staged


def _fsync_directory(path: str) -> None:
    try:
        descriptor = os.open(path, os.O_RDONLY)
    except OSError:
        return
    try:
        try:
            os.fsync(descriptor)
        except OSError:
            pass
    finally:
        os.close(descriptor)


__all__ = ["V8PolicyWriteResult", "mutate_v8_config"]
