// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
// SPDX-License-Identifier: Apache-2.0

// Package schemas embeds DefenseClaw's canonical public schemas for consumers
// that cannot rely on a repository checkout at runtime.
package schemas

import _ "embed"

//go:embed config/v8/defenseclaw-config.schema.json
var defenseClawConfigV8Schema []byte

//go:embed config/v8/reference/observability.yaml
var defenseClawConfigV8ObservabilityReferenceYAML []byte

//go:embed config/v8/reference/observability.md
var defenseClawConfigV8ObservabilityReferenceMarkdown []byte

//go:embed telemetry/v8/registry.yaml
var telemetryV8Registry []byte

//go:embed telemetry/v8/semconv.lock.yaml
var telemetryV8SemconvLock []byte

//go:embed telemetry/generated/telemetry.schema.json
var telemetryV8Schema []byte

//go:embed telemetry/generated/catalog.json
var telemetryV8Catalog []byte

// DefenseClawConfigV8Schema returns a copy of the exact checked-in canonical v8
// configuration schema bytes. Callers cannot mutate the process-wide embed.
func DefenseClawConfigV8Schema() []byte {
	return append([]byte(nil), defenseClawConfigV8Schema...)
}

// DefenseClawConfigV8ObservabilityReferenceYAML returns a copy of the
// exhaustive, generated source-configuration example owned by the v8 schema.
func DefenseClawConfigV8ObservabilityReferenceYAML() []byte {
	return append([]byte(nil), defenseClawConfigV8ObservabilityReferenceYAML...)
}

// DefenseClawConfigV8ObservabilityReferenceMarkdown returns a copy of the
// generated human-readable v8 observability field catalog.
func DefenseClawConfigV8ObservabilityReferenceMarkdown() []byte {
	return append([]byte(nil), defenseClawConfigV8ObservabilityReferenceMarkdown...)
}

// TelemetryV8Registry returns a copy of the immutable v8 telemetry registry
// manifest, including semantic-profile bindings.
func TelemetryV8Registry() []byte {
	return append([]byte(nil), telemetryV8Registry...)
}

// TelemetryV8SemconvLock returns a copy of the pinned upstream semantic
// convention revisions used to validate those profiles.
func TelemetryV8SemconvLock() []byte {
	return append([]byte(nil), telemetryV8SemconvLock...)
}

// TelemetryV8Schema returns a copy of the generated canonical v8 telemetry
// schema bundle. Callers cannot mutate the process-wide embed.
func TelemetryV8Schema() []byte {
	return append([]byte(nil), telemetryV8Schema...)
}

// TelemetryV8Catalog returns a copy of the generated canonical v8 telemetry
// catalog. Callers cannot mutate the process-wide embed.
func TelemetryV8Catalog() []byte {
	return append([]byte(nil), telemetryV8Catalog...)
}
