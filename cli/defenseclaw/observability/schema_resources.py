# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
# SPDX-License-Identifier: Apache-2.0

"""Read-only access to generated telemetry resources shipped in the wheel.

These helpers deliberately have no repository-checkout fallback. A missing
package resource is a broken installation and must fail instead of silently
loading a potentially different schema from the current working tree.
"""

from __future__ import annotations

from importlib import resources
from typing import Final

_SCHEMA_RESOURCE: Final = "_data/telemetry/v8/telemetry.schema.json"
_CATALOG_RESOURCE: Final = "_data/telemetry/v8/catalog.json"
_V7_EXPORTER_SELECTION_RESOURCE: Final = (
    "_data/telemetry/v8/v7-exporter-selection.json"
)


def telemetry_v8_schema_bytes() -> bytes:
    """Return the immutable generated v8 telemetry schema bundle bytes."""
    return resources.files("defenseclaw").joinpath(_SCHEMA_RESOURCE).read_bytes()


def telemetry_v8_catalog_bytes() -> bytes:
    """Return the immutable generated v8 telemetry catalog bytes."""
    return resources.files("defenseclaw").joinpath(_CATALOG_RESOURCE).read_bytes()


def v7_exporter_selection_bytes() -> bytes:
    """Return the generated v7-to-v8 exporter compatibility selection bytes."""
    return resources.files("defenseclaw").joinpath(_V7_EXPORTER_SELECTION_RESOURCE).read_bytes()


__all__ = [
    "telemetry_v8_catalog_bytes",
    "telemetry_v8_schema_bytes",
    "v7_exporter_selection_bytes",
]
