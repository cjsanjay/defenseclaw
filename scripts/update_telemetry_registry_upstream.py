#!/usr/bin/env python3
# Copyright 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: Apache-2.0
"""Explicitly refresh pinned normalized telemetry semantic-convention snapshots.

This is the only telemetry-registry command that performs network access. It
downloads immutable archives from the primary upstream repositories and derives
reviewable normalized snapshots. Normal registry compilation never imports or
invokes this module.
"""

from __future__ import annotations

import argparse
import ast
import hashlib
import io
import json
import os
import re
import shutil
import sys
import tarfile
import tempfile
import urllib.request
from pathlib import Path
from typing import Any, Final

import yaml
from generate_telemetry_registry import (
    EXPECTED_DEPENDENCIES,
    NORMALIZED_SNAPSHOT_FORMAT,
    RegistryError,
    load_yaml_strict,
)

MAX_ARCHIVE_BYTES: Final = 128 * 1024 * 1024
MAX_SOURCE_FILE_BYTES: Final = 16 * 1024 * 1024
MAX_ARCHIVE_MEMBERS: Final = 100_000
MAX_EXPANDED_BYTES: Final = 512 * 1024 * 1024
ALLOWED_REPOSITORIES: Final = {
    "otel_core": "https://github.com/open-telemetry/semantic-conventions",
    "otel_genai": "https://github.com/open-telemetry/semantic-conventions-genai",
    "openinference": "https://github.com/Arize-ai/openinference",
}
OPENINFERENCE_SEMCONV_FILES: Final = frozenset(
    {
        "python/openinference-semantic-conventions/src/openinference/semconv/resource/__init__.py",
        "python/openinference-semantic-conventions/src/openinference/semconv/trace/__init__.py",
        "python/openinference-semantic-conventions/src/openinference/semconv/version.py",
        "spec/semantic_conventions.md",
    }
)
OPENINFERENCE_PYTHON_FILES: Final = frozenset(
    {
        "python/openinference-semantic-conventions/src/openinference/semconv/resource/__init__.py",
        "python/openinference-semantic-conventions/src/openinference/semconv/trace/__init__.py",
    }
)
OPENINFERENCE_TYPE_MAP: Final = {
    "string": (("string",), "attribute"),
    "json string": (("string",), "attribute"),
    "integer": (("int64",), "attribute"),
    "float": (("double",), "attribute"),
    "boolean": (("boolean",), "attribute"),
    "list of floats": (("double[]",), "attribute"),
    "list of strings": (("string[]",), "attribute"),
    "list of objects": ((), "indexed_prefix"),
    "image object": ((), "object_prefix"),
    "string/integer": (("string", "int64"), "attribute"),
}
EXPECTED_OPENINFERENCE_TABLE_ROWS: Final = 96
EXPECTED_OPENINFERENCE_CONSTANTS: Final = 99
EXPECTED_OPENINFERENCE_DIRECT_INTERSECTION: Final = 92
EXPECTED_OPENINFERENCE_TABLE_ONLY: Final = frozenset(
    {"exception.escaped", "exception.message", "exception.stacktrace", "exception.type"}
)
EXPECTED_OPENINFERENCE_CONSTANTS_ONLY: Final = frozenset(
    {
        "completion.text",
        "llm.cost.completion_details",
        "llm.cost.prompt_details",
        "llm.token_count.prompt_details",
        "llm.token_count.prompt_details.cache_input",
        "openinference.project.name",
        "prompt.text",
    }
)
OPENINFERENCE_ATTRIBUTE_CLASSES: Final = frozenset(
    {
        "ResourceAttributes",
        "SpanAttributes",
        "MessageAttributes",
        "MessageContentAttributes",
        "ImageAttributes",
        "AudioAttributes",
        "DocumentAttributes",
        "RerankerAttributes",
        "EmbeddingAttributes",
        "ToolCallAttributes",
        "PromptAttributes",
        "ChoiceAttributes",
        "ToolAttributes",
    }
)
_ID = re.compile(r"^[A-Za-z][A-Za-z0-9_.:/-]{0,255}$")


def _sha256(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def _archive_url(repository: str, revision: str) -> str:
    return f"{repository.rstrip('/')}/archive/{revision}.tar.gz"


def _download(url: str) -> bytes:
    request = urllib.request.Request(
        url,
        headers={"User-Agent": "DefenseClaw-telemetry-registry-updater/1"},
    )
    try:
        with urllib.request.urlopen(request, timeout=60) as response:  # noqa: S310 - pinned allowlist URL
            length = response.headers.get("Content-Length")
            if length is not None and int(length) > MAX_ARCHIVE_BYTES:
                raise RegistryError("upstream archive exceeds maximum size")
            payload = response.read(MAX_ARCHIVE_BYTES + 1)
    except (OSError, ValueError) as exc:
        raise RegistryError("failed to download pinned upstream archive") from exc
    if len(payload) > MAX_ARCHIVE_BYTES:
        raise RegistryError("upstream archive exceeds maximum size")
    return payload


def _archive_files(payload: bytes) -> dict[str, bytes]:
    result: dict[str, bytes] = {}
    try:
        with tarfile.open(fileobj=io.BytesIO(payload), mode="r:gz") as archive:
            members = archive.getmembers()
            if len(members) > MAX_ARCHIVE_MEMBERS:
                raise RegistryError("upstream archive contains too many entries")
            roots = {member.name.split("/", 1)[0] for member in members if member.name}
            if len(roots) != 1:
                raise RegistryError("upstream archive must have one root directory")
            root = next(iter(roots)) + "/"
            expanded_bytes = 0
            for member in members:
                if member.isdir() or member.issym() or member.islnk():
                    continue
                if not member.isfile():
                    raise RegistryError("upstream archive contains a non-regular entry")
                if not member.name.startswith(root):
                    raise RegistryError("upstream archive entry escapes root")
                relative = member.name[len(root) :]
                path = Path(relative)
                if path.is_absolute() or ".." in path.parts or not relative:
                    raise RegistryError("upstream archive contains an unsafe path")
                if member.size > MAX_SOURCE_FILE_BYTES:
                    raise RegistryError("upstream source file exceeds maximum size")
                expanded_bytes += member.size
                if expanded_bytes > MAX_EXPANDED_BYTES:
                    raise RegistryError("upstream archive exceeds maximum expanded size")
                stream = archive.extractfile(member)
                if stream is None:
                    raise RegistryError("upstream archive member cannot be read")
                normalized = path.as_posix()
                if normalized in result:
                    raise RegistryError("upstream archive contains duplicate paths")
                content = stream.read(MAX_SOURCE_FILE_BYTES + 1)
                if len(content) != member.size:
                    raise RegistryError("upstream archive member size is inconsistent")
                result[normalized] = content
    except (tarfile.TarError, OSError) as exc:
        raise RegistryError("invalid upstream tar archive") from exc
    if not result:
        raise RegistryError("upstream archive contains no source files")
    return result


def _json_pointer(parts: tuple[str, ...]) -> str:
    return "/" + "/".join(part.replace("~", "~0").replace("/", "~1") for part in parts)


def _normalized_type(value: Any) -> tuple[str | None, tuple[str, ...]]:
    if isinstance(value, str):
        token = value.strip().lower().replace(" ", "")
        aliases = {
            "str": "string",
            "string": "string",
            "bool": "boolean",
            "boolean": "boolean",
            "int": "int64",
            "integer": "int64",
            "int64": "int64",
            "double": "double",
            "float": "double",
            "float64": "double",
            "bytes": "bytes",
            "string[]": "string[]",
            "boolean[]": "boolean[]",
            "int64[]": "int64[]",
            "double[]": "double[]",
            "template[string]": "string",
            "template[int]": "int64",
            "any": "any",
        }
        if token in aliases:
            return aliases[token], ()
        if token.startswith("enum"):
            return "string", ()
        return None, ()
    if isinstance(value, dict):
        members = value.get("members")
        if isinstance(members, list):
            enum: list[str] = []
            for member in members:
                if isinstance(member, dict):
                    candidate = member.get("value") or member.get("id")
                else:
                    candidate = member
                if isinstance(candidate, str):
                    enum.append(candidate)
            return "string", tuple(sorted(set(enum)))
        for key in ("type", "template"):
            if key in value:
                return _normalized_type(value[key])
    return None, ()


def _yaml_attributes(path: str, payload: bytes) -> list[dict[str, Any]]:
    try:
        text = payload.decode("utf-8")
        root = yaml.safe_load(text)
    except UnicodeDecodeError as exc:
        raise RegistryError(f"upstream YAML source {path}: invalid UTF-8") from exc
    except yaml.YAMLError as exc:
        raise RegistryError(f"upstream YAML source {path}: parse failure") from exc
    result: list[dict[str, Any]] = []

    def walk(value: Any, pointer: tuple[str, ...], stability: str) -> None:
        if isinstance(value, dict):
            current_stability = value.get("stability", stability)
            if current_stability not in {"development", "stable", "deprecated"}:
                current_stability = stability
            attribute_id = value.get("id") or value.get("key")
            if "attributes" in pointer and isinstance(attribute_id, str) and "type" in value:
                attribute_type, enum = _normalized_type(value["type"])
                if attribute_type is not None and _ID.fullmatch(attribute_id):
                    deprecated = current_stability == "deprecated" or bool(value.get("deprecated"))
                    attribute_shape = "any_value" if attribute_type == "any" else "attribute"
                    result.append(
                        {
                            "id": attribute_id,
                            "allowed_types": [] if attribute_shape == "any_value" else [attribute_type],
                            "shape": attribute_shape,
                            "stability": "deprecated" if deprecated else current_stability,
                            "stability_source": "upstream",
                            "source_pointer": f"{path}#{_json_pointer(pointer)}",
                            "enum": list(enum),
                            "deprecated": deprecated,
                        }
                    )
            for key, item in value.items():
                walk(item, (*pointer, str(key)), current_stability)
        elif isinstance(value, list):
            for index, item in enumerate(value):
                walk(item, (*pointer, str(index)), stability)

    walk(root, (), "development")
    return result


def _python_attributes(path: str, payload: bytes) -> list[dict[str, Any]]:
    try:
        tree = ast.parse(payload.decode("utf-8"), filename=path)
    except (UnicodeDecodeError, SyntaxError) as exc:
        raise RegistryError(f"openinference: invalid canonical constants source {path}") from exc
    result: list[dict[str, Any]] = []
    for class_node in tree.body:
        if not isinstance(class_node, ast.ClassDef) or class_node.name not in OPENINFERENCE_ATTRIBUTE_CLASSES:
            continue
        for node in class_node.body:
            value: str | None = None
            if isinstance(node, (ast.Assign, ast.AnnAssign)):
                candidate = node.value
                if isinstance(candidate, ast.Constant) and isinstance(candidate.value, str):
                    value = candidate.value
            if value is None or not _ID.fullmatch(value):
                continue
            result.append(
                {
                    "id": value,
                    "allowed_types": ["string"],
                    "shape": "attribute",
                    "stability": "stable",
                    "stability_source": "released_package_policy",
                    "source_pointer": f"{path}#L{getattr(node, 'lineno', 0)}",
                    "enum": [],
                    "deprecated": False,
                }
            )
    return result


def _openinference_markdown_attributes(path: str, payload: bytes) -> dict[str, dict[str, Any]]:
    try:
        lines = payload.decode("utf-8").splitlines()
    except UnicodeDecodeError as exc:
        raise RegistryError("openinference: semantic-convention specification is not UTF-8") from exc
    headings = [index for index, line in enumerate(lines) if line == "## Reserved Attributes"]
    if len(headings) != 1:
        raise RegistryError("openinference: expected one Reserved Attributes heading")
    def table_cells(line: str, line_number: int) -> list[str]:
        line = line.strip()
        if not line.startswith("|") or not line.endswith("|"):
            raise RegistryError(
                f"openinference: malformed Reserved Attributes table row at line {line_number}"
            )
        cells = [cell.strip() for cell in line.split("|")]
        if cells[0] or cells[-1] or len(cells) != 6:
            raise RegistryError(
                f"openinference: malformed Reserved Attributes table columns at line {line_number}"
            )
        return cells[1:-1]

    next_heading = next(
        (
            index
            for index in range(headings[0] + 1, len(lines))
            if lines[index].startswith("## ")
        ),
        len(lines),
    )
    header_candidates = [
        index
        for index in range(headings[0] + 1, next_heading)
        if lines[index].strip().startswith("| Attribute")
    ]
    if len(header_candidates) != 1:
        raise RegistryError("openinference: expected one Reserved Attributes table")
    header_index = header_candidates[0]
    if header_index + 1 >= len(lines):
        raise RegistryError("openinference: Reserved Attributes table is incomplete")
    if table_cells(lines[header_index], header_index + 1) != [
        "Attribute",
        "Type",
        "Example",
        "Description",
    ]:
        raise RegistryError("openinference: unexpected Reserved Attributes table header")
    separator = table_cells(lines[header_index + 1], header_index + 2)
    if any(re.fullmatch(r":?-{3,}:?", cell) is None for cell in separator):
        raise RegistryError("openinference: malformed Reserved Attributes table separator")

    result: dict[str, dict[str, Any]] = {}
    row_index = header_index + 2
    while row_index < len(lines) and lines[row_index].strip().startswith("|"):
        cells = table_cells(lines[row_index], row_index + 1)
        line_number = row_index + 1
        if not (cells[0].startswith("`") and cells[0].endswith("`")):
            raise RegistryError("openinference: malformed Reserved Attributes attribute name")
        attribute_id = cells[0][1:-1]
        if not _ID.fullmatch(attribute_id):
            raise RegistryError("openinference: malformed Reserved Attributes attribute ID")
        type_name = re.sub(r"<[^>]+>", "", cells[1]).replace("†", "").strip().lower()
        type_name = " ".join(type_name.split())
        type_definition = OPENINFERENCE_TYPE_MAP.get(type_name)
        if type_definition is None:
            raise RegistryError(
                f"openinference attribute {attribute_id}: unsupported Reserved Attributes type"
            )
        allowed_types, attribute_shape = type_definition
        item = {
            "id": attribute_id,
            "allowed_types": list(allowed_types),
            "shape": attribute_shape,
            "stability": "stable",
            "stability_source": "released_package_policy",
            "source_pointer": f"{path}#L{line_number}",
            "enum": [],
            "deprecated": False,
        }
        existing = result.get(attribute_id)
        if existing is not None:
            raise RegistryError(f"openinference attribute {attribute_id}: duplicate specification row")
        result[attribute_id] = item
        row_index += 1
    if len(result) != EXPECTED_OPENINFERENCE_TABLE_ROWS:
        raise RegistryError(
            f"openinference: expected {EXPECTED_OPENINFERENCE_TABLE_ROWS} Reserved Attributes rows"
        )
    return result


def _openinference_attributes(
    files: dict[str, bytes],
    expected_version: str,
) -> tuple[list[dict[str, Any]], set[str]]:
    missing_sources = OPENINFERENCE_SEMCONV_FILES - files.keys()
    if missing_sources:
        raise RegistryError("openinference: authoritative semantic-convention sources are incomplete")
    version_path = "python/openinference-semantic-conventions/src/openinference/semconv/version.py"
    try:
        version_tree = ast.parse(files[version_path].decode("utf-8"), filename=version_path)
    except (UnicodeDecodeError, SyntaxError) as exc:
        raise RegistryError("openinference: invalid semantic-convention version source") from exc
    versions = [
        node.value.value
        for node in version_tree.body
        if isinstance(node, ast.Assign)
        and any(isinstance(target, ast.Name) and target.id == "__version__" for target in node.targets)
        and isinstance(node.value, ast.Constant)
        and isinstance(node.value.value, str)
    ]
    if versions != [expected_version]:
        raise RegistryError("openinference: semantic-convention package version does not match lock")
    constants: dict[str, dict[str, Any]] = {}
    constants_by_path: dict[str, dict[str, dict[str, Any]]] = {}
    for path in sorted(OPENINFERENCE_PYTHON_FILES):
        path_constants: dict[str, dict[str, Any]] = {}
        for item in _python_attributes(path, files[path]):
            if item["id"] in path_constants or item["id"] in constants:
                raise RegistryError(f"openinference attribute {item['id']}: duplicate canonical constant")
            path_constants[item["id"]] = item
            constants[item["id"]] = item
        constants_by_path[path] = path_constants
    if len(constants) != EXPECTED_OPENINFERENCE_CONSTANTS:
        raise RegistryError(
            f"openinference: expected {EXPECTED_OPENINFERENCE_CONSTANTS} canonical constants"
        )
    specification_path = "spec/semantic_conventions.md"
    specification = _openinference_markdown_attributes(
        specification_path,
        files[specification_path],
    )
    trace_path = "python/openinference-semantic-conventions/src/openinference/semconv/trace/__init__.py"
    trace_ids = set(constants_by_path[trace_path])
    specification_ids = set(specification)
    direct_ids = trace_ids & specification_ids
    if len(direct_ids) != EXPECTED_OPENINFERENCE_DIRECT_INTERSECTION:
        raise RegistryError(
            f"openinference: expected {EXPECTED_OPENINFERENCE_DIRECT_INTERSECTION} direct attributes"
        )
    if specification_ids - trace_ids != EXPECTED_OPENINFERENCE_TABLE_ONLY:
        raise RegistryError("openinference: Reserved Attributes table-only inventory changed")
    if set(constants) - specification_ids != EXPECTED_OPENINFERENCE_CONSTANTS_ONLY:
        raise RegistryError("openinference: constants-only inventory changed")
    attributes = [
        specification[attribute_id]
        for attribute_id in sorted(direct_ids)
    ]
    project_name = constants.get("openinference.project.name")
    if project_name is None or not project_name["source_pointer"].startswith(
        "python/openinference-semantic-conventions/src/openinference/semconv/resource/__init__.py#"
    ):
        raise RegistryError("openinference: resource project-name convention is missing")
    project_name = dict(project_name)
    project_name["allowed_types"] = ["string"]
    project_name["shape"] = "attribute"
    attributes.append(project_name)
    attributes.sort(key=lambda item: item["id"])
    if not attributes:
        raise RegistryError("openinference: no canonical semantic attributes discovered")
    return attributes, set(OPENINFERENCE_SEMCONV_FILES)


def _normalize_snapshot(
    dependency: dict[str, Any],
    archive_url: str,
    files: dict[str, bytes],
) -> bytes:
    if dependency["id"] == "openinference":
        candidates, contributing = _openinference_attributes(files, dependency["version"])
    else:
        candidates = []
        contributing = set()
    for path in sorted(files):
        if dependency["id"] == "openinference":
            continue
        suffix = Path(path).suffix.lower()
        if suffix in {".yaml", ".yml"}:
            extracted = _yaml_attributes(path, files[path])
        else:
            extracted = []
        if extracted:
            candidates.extend(extracted)
            contributing.add(path)
    attributes: dict[str, dict[str, Any]] = {}
    for item in candidates:
        current = attributes.get(item["id"])
        if current is None:
            attributes[item["id"]] = item
            continue
        comparable = (
            item["allowed_types"],
            item["shape"],
            item["stability"],
            item["stability_source"],
            item["enum"],
            item["deprecated"],
        )
        existing = (
            current["allowed_types"],
            current["shape"],
            current["stability"],
            current["stability_source"],
            current["enum"],
            current["deprecated"],
        )
        if comparable != existing:
            raise RegistryError(f"upstream attribute {item['id']}: inconsistent definitions")
        if item["source_pointer"] < current["source_pointer"]:
            attributes[item["id"]] = item
    if not attributes:
        raise RegistryError(f"{dependency['id']}: no semantic attributes discovered")
    source_files = [
        {"path": path, "sha256": _sha256(files[path])}
        for path in sorted(contributing)
    ]
    document = {
        "format_version": 1,
        "format": NORMALIZED_SNAPSHOT_FORMAT,
        "dependency_id": dependency["id"],
        "repository": dependency["repository"],
        "revision": dependency["revision"],
        "source_archive": archive_url,
        "source_files": source_files,
        "attributes": [attributes[key] for key in sorted(attributes)],
    }
    return (json.dumps(document, ensure_ascii=False, indent=2) + "\n").encode("utf-8")


def _load_lock(path: Path) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    document = load_yaml_strict(path)
    if set(document) != {"schema_version", "dependencies"} or document.get("schema_version") != 1:
        raise RegistryError("semconv lock has unsupported shape")
    dependencies = document.get("dependencies")
    if not isinstance(dependencies, list):
        raise RegistryError("semconv lock dependencies must be a sequence")
    ids = tuple(item.get("id") for item in dependencies if isinstance(item, dict))
    if ids != EXPECTED_DEPENDENCIES:
        raise RegistryError("semconv lock dependencies are not in canonical order")
    for item in dependencies:
        if not isinstance(item, dict) or set(item) != {
            "id",
            "repository",
            "version",
            "profile_id",
            "revision",
            "snapshot",
        }:
            raise RegistryError("semconv dependency has unsupported shape")
        if item["repository"] != ALLOWED_REPOSITORIES[item["id"]]:
            raise RegistryError(f"{item['id']}: repository is not the primary allowlisted upstream")
        if not re.fullmatch(r"[0-9a-f]{40}", str(item["revision"])):
            raise RegistryError(f"{item['id']}: revision must be an immutable commit")
    return document, dependencies


def _render_lock(document: dict[str, Any]) -> bytes:
    return yaml.safe_dump(
        document,
        sort_keys=False,
        allow_unicode=True,
        default_flow_style=False,
    ).encode("utf-8")


def _archive_overrides(values: list[str]) -> dict[str, Path]:
    result: dict[str, Path] = {}
    for value in values:
        if "=" not in value:
            raise RegistryError("--archive must use dependency=path")
        dependency, path = value.split("=", 1)
        if dependency not in EXPECTED_DEPENDENCIES or dependency in result:
            raise RegistryError("--archive has an unknown or duplicate dependency")
        result[dependency] = Path(path)
    return result


def _install_rendered(root: Path, rendered: dict[Path, bytes], lock_path: Path) -> None:
    """Install a complete refresh set and restore every prior byte on failure.

    Snapshot files are installed before the lock. A process interruption can
    therefore only leave a lock/snapshot digest mismatch, which the normal
    compiler rejects closed. Synchronous failures are rolled back here.
    """

    staging = Path(tempfile.mkdtemp(prefix="telemetry-upstream-update-", dir=root))
    staged_root = staging / "new"
    backup_root = staging / "backup"
    targets = sorted(
        rendered,
        key=lambda item: (item == lock_path, item.as_posix()),
    )
    staged: dict[Path, Path] = {}
    backups: dict[Path, Path | None] = {}
    installed: list[Path] = []
    try:
        for target in targets:
            relative = target.relative_to(root)
            temporary = staged_root / relative
            temporary.parent.mkdir(parents=True, exist_ok=True)
            temporary.write_bytes(rendered[target])
            staged[target] = temporary
        try:
            for target in targets:
                relative = target.relative_to(root)
                target.parent.mkdir(parents=True, exist_ok=True)
                backup = backup_root / relative
                if target.exists():
                    backup.parent.mkdir(parents=True, exist_ok=True)
                    os.replace(target, backup)
                    backups[target] = backup
                else:
                    backups[target] = None
                os.replace(staged[target], target)
                installed.append(target)
        except BaseException:
            for target in reversed(targets):
                backup = backups.get(target)
                if target in installed and target.exists():
                    target.unlink()
                if backup is not None and backup.exists():
                    target.parent.mkdir(parents=True, exist_ok=True)
                    os.replace(backup, target)
            raise
    finally:
        shutil.rmtree(staging, ignore_errors=True)


def update(root: Path, selected: tuple[str, ...], overrides: dict[str, Path]) -> None:
    root = root.resolve()
    lock_path = root / "schemas/telemetry/v8/semconv.lock.yaml"
    lock, dependencies = _load_lock(lock_path)
    rendered: dict[Path, bytes] = {}
    for dependency in dependencies:
        if dependency["id"] not in selected:
            continue
        url = _archive_url(dependency["repository"], dependency["revision"])
        override = overrides.get(dependency["id"])
        payload = override.read_bytes() if override is not None else _download(url)
        files = _archive_files(payload)
        snapshot = _normalize_snapshot(dependency, url, files)
        snapshot_path = root / dependency["snapshot"]["path"]
        try:
            snapshot_path.resolve().relative_to((root / "schemas/telemetry/v8/upstream").resolve())
        except ValueError as exc:
            raise RegistryError("snapshot path leaves schemas/telemetry/v8/upstream") from exc
        dependency["snapshot"]["format"] = NORMALIZED_SNAPSHOT_FORMAT
        dependency["snapshot"]["sha256"] = _sha256(snapshot)
        rendered[snapshot_path] = snapshot
    rendered[lock_path] = _render_lock(lock)
    _install_rendered(root, rendered, lock_path)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--write", action="store_true", required=True)
    parser.add_argument("--root", type=Path, default=Path(__file__).resolve().parent.parent)
    parser.add_argument("--dependency", action="append", choices=EXPECTED_DEPENDENCIES)
    parser.add_argument(
        "--archive",
        action="append",
        default=[],
        metavar="DEPENDENCY=PATH",
        help="use a local immutable archive (tests/reproducible review only)",
    )
    args = parser.parse_args(argv)
    try:
        selected = tuple(args.dependency or EXPECTED_DEPENDENCIES)
        if len(selected) != len(set(selected)):
            raise RegistryError("--dependency values must be unique")
        overrides = _archive_overrides(args.archive)
        if not set(overrides).issubset(selected):
            raise RegistryError("--archive dependency must also be selected")
        update(args.root, selected, overrides)
    except (RegistryError, OSError) as exc:
        print(f"telemetry upstream update failed: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
