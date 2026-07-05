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

import json
import subprocess
from pathlib import Path
from typing import Any

import pytest
from defenseclaw.observability import schema_resources

ROOT = Path(__file__).resolve().parents[2]
SOURCE_DIR = ROOT / "schemas" / "telemetry" / "generated"
STAGED_DIR = ROOT / "cli" / "defenseclaw" / "_data" / "telemetry" / "v8"
EXPECTED_RESOURCES = {
    "telemetry.schema.json": schema_resources.telemetry_v8_schema_bytes,
    "catalog.json": schema_resources.telemetry_v8_catalog_bytes,
}
EXPECTED_PACKAGE_DATA = {
    "_data/telemetry/v8/telemetry.schema.json",
    "_data/telemetry/v8/catalog.json",
}


def _load_pyproject() -> dict[str, Any]:
    try:
        import tomllib
    except ImportError:  # pragma: no cover - Python 3.10 support
        import tomli as tomllib  # type: ignore[no-redef]

    with (ROOT / "pyproject.toml").open("rb") as stream:
        return tomllib.load(stream)


@pytest.mark.parametrize(("name", "loader"), EXPECTED_RESOURCES.items())
def test_packaged_telemetry_resource_matches_generated_source(
    name: str,
    loader: Any,
) -> None:
    source = (SOURCE_DIR / name).read_bytes()
    staged = (STAGED_DIR / name).read_bytes()
    packaged = loader()

    assert staged == source
    assert packaged == source
    assert type(packaged) is bytes
    with pytest.raises(TypeError):
        packaged[0] = 0  # type: ignore[index]

    document = json.loads(packaged)
    marker = document["x-defenseclaw-generated"]
    assert marker["artifact"] == name
    assert marker["registry_version"] == 1


def test_staged_telemetry_inventory_is_exact() -> None:
    assert {path.name for path in STAGED_DIR.iterdir() if path.is_file()} == set(EXPECTED_RESOURCES)
    assert not any(path.is_dir() for path in STAGED_DIR.iterdir())


@pytest.mark.parametrize(
    "loader",
    [
        schema_resources.telemetry_v8_schema_bytes,
        schema_resources.telemetry_v8_catalog_bytes,
    ],
)
def test_resource_loader_has_no_repository_fallback(
    monkeypatch: pytest.MonkeyPatch,
    loader: Any,
) -> None:
    class MissingResource:
        def joinpath(self, _resource: str) -> MissingResource:
            return self

        def read_bytes(self) -> bytes:
            raise FileNotFoundError("simulated missing package resource")

    monkeypatch.setattr(schema_resources.resources, "files", lambda _package: MissingResource())
    with pytest.raises(FileNotFoundError, match="simulated missing package resource"):
        loader()


def test_telemetry_package_data_is_exact_and_staging_is_untracked() -> None:
    package_data = _load_pyproject()["tool"]["setuptools"]["package-data"]["defenseclaw"]
    telemetry_entries = {entry for entry in package_data if entry.startswith("_data/telemetry/")}
    assert telemetry_entries == EXPECTED_PACKAGE_DATA

    tracked = subprocess.run(
        ["git", "ls-files", "--", "cli/defenseclaw/_data/telemetry"],
        cwd=ROOT,
        check=True,
        capture_output=True,
        text=True,
    )
    assert tracked.stdout == ""
    for name in EXPECTED_RESOURCES:
        ignored = subprocess.run(
            ["git", "check-ignore", "-q", str((STAGED_DIR / name).relative_to(ROOT))],
            cwd=ROOT,
            check=False,
        )
        assert ignored.returncode == 0
