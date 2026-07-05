#!/usr/bin/env python3
# Copyright 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: Apache-2.0
"""Test-only manifest driver for reduced telemetry compiler fixtures.

The compiler-focused fixture intentionally has fewer registry declarations than
the production candidate renderer accepts.  This driver keeps those tests on the
real compiler, manifest validation, and generated-output transaction while
replacing only the production renderer fanout with the historical manifest-only
test projection.
"""

from __future__ import annotations

import importlib.util
import json
import sys
from pathlib import Path
from types import ModuleType

ROOT = Path(__file__).resolve().parents[3]
GENERATOR = ROOT / "scripts/generate_telemetry_registry.py"


def _load_generator() -> ModuleType:
    name = "telemetry_registry_manifest_test_driver_generator"
    spec = importlib.util.spec_from_file_location(name, GENERATOR)
    if spec is None or spec.loader is None:
        raise RuntimeError("cannot load telemetry registry generator")
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


def _manifest_only_outputs(generator: ModuleType, ir: object) -> dict[Path, bytes]:
    manifest = generator._manifest_document(ir, {})  # noqa: SLF001 - explicit test seam
    encoded = (json.dumps(manifest, ensure_ascii=False, indent=2) + "\n").encode("utf-8")
    if generator.OUTPUT_MANIFEST_MARKER not in encoded[: generator.generated_transaction.MARKER_SCAN_BYTES]:
        raise generator.RegistryError("test manifest does not carry its ownership marker")
    return {generator.OUTPUT_MANIFEST: encoded}


def main(argv: list[str] | None = None) -> int:
    generator = _load_generator()
    generator.render_outputs = lambda ir: _manifest_only_outputs(generator, ir)
    return generator.main(argv)


if __name__ == "__main__":
    raise SystemExit(main())
