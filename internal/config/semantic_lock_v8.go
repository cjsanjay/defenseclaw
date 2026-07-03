// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// SPDX-License-Identifier: Apache-2.0

package config

import (
	"fmt"
	"sync"

	publicschemas "github.com/defenseclaw/defenseclaw/schemas"
	"gopkg.in/yaml.v3"
)

var (
	observabilityV8SemanticLockOnce sync.Once
	observabilityV8SemanticLockErr  error
)

type observabilityV8SemanticProfilesDocument struct {
	SchemaVersion    int                                   `yaml:"schema_version"`
	SemanticProfiles []observabilityV8SemanticProfileEntry `yaml:"semantic_profiles"`
}

type observabilityV8SemanticProfileEntry struct {
	ID                          string `yaml:"id"`
	TraceSchemaVersion          string `yaml:"trace_schema_version"`
	GenAISemconvProfile         string `yaml:"gen_ai_semconv_profile"`
	OpenInferenceProfile        string `yaml:"openinference_profile"`
	GalileoCompatibilityProfile string `yaml:"galileo_compatibility_profile"`
}

type observabilityV8SemconvLockDocument struct {
	SchemaVersion         int    `yaml:"schema_version"`
	OTelCoreVersion       string `yaml:"otel_core_version"`
	OTelCoreRevision      string `yaml:"otel_core_revision"`
	GenAISemconvRevision  string `yaml:"gen_ai_semconv_revision"`
	OpenInferenceVersion  string `yaml:"openinference_version"`
	OpenInferenceRevision string `yaml:"openinference_revision"`
}

func validateObservabilityV8SemanticLock() error {
	observabilityV8SemanticLockOnce.Do(func() {
		observabilityV8SemanticLockErr = validateObservabilityV8SemanticLockDocuments(
			publicschemas.TelemetryV8Registry(),
			publicschemas.TelemetryV8SemconvLock(),
		)
	})
	return observabilityV8SemanticLockErr
}

func validateObservabilityV8SemanticLockDocuments(profileBytes, lockBytes []byte) error {
	var profiles observabilityV8SemanticProfilesDocument
	if err := yaml.Unmarshal(profileBytes, &profiles); err != nil {
		return fmt.Errorf("decode embedded semantic profiles: %w", err)
	}
	var lock observabilityV8SemconvLockDocument
	if err := yaml.Unmarshal(lockBytes, &lock); err != nil {
		return fmt.Errorf("decode embedded semantic convention lock: %w", err)
	}
	if profiles.SchemaVersion != 1 || lock.SchemaVersion != 1 {
		return fmt.Errorf("semantic registry/lock schema version mismatch")
	}
	var selected *observabilityV8SemanticProfileEntry
	for index := range profiles.SemanticProfiles {
		if profiles.SemanticProfiles[index].ID == observabilityV8DefaultSemanticProfile {
			selected = &profiles.SemanticProfiles[index]
			break
		}
	}
	if selected == nil {
		return fmt.Errorf("semantic profile %s is absent from the embedded registry", observabilityV8DefaultSemanticProfile)
	}
	registered := ObservabilityV8SemanticProfileLock{
		TraceSchemaVersion:          selected.TraceSchemaVersion,
		GenAISemconvProfile:         selected.GenAISemconvProfile,
		OpenInferenceProfile:        selected.OpenInferenceProfile,
		GalileoCompatibilityProfile: selected.GalileoCompatibilityProfile,
	}
	if registered != observabilityV8SemanticProfileLock {
		return fmt.Errorf("semantic profile registry differs from the compiled instrumentation lock")
	}
	if selected.GenAISemconvProfile != "otel-genai-"+lock.GenAISemconvRevision ||
		selected.OpenInferenceProfile != "openinference-semantic-conventions-v"+lock.OpenInferenceVersion ||
		lock.OTelCoreVersion != "v1.42.0" || lock.OTelCoreRevision != "ae3a98640194ed405c4c797281502e4d3bd258b3" ||
		lock.OpenInferenceRevision != "789d41974c08a9a13147977f28ef4142a07e2106" {
		return fmt.Errorf("semantic profile members disagree with semconv.lock.yaml")
	}
	return nil
}
