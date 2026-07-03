// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// SPDX-License-Identifier: Apache-2.0

package config

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestParseCompileObservabilityV8Minimal(t *testing.T) {
	wantDataDir, err := normalizeObservabilityV8FilePath("data_dir", "/var/lib/defenseclaw")
	if err != nil {
		t.Fatal(err)
	}
	compiled, err := ParseCompileObservabilityV8(
		"config.yaml",
		[]byte("config_version: 8\nobservability: {}\n"),
		ObservabilityV8CompileOptions{DefaultDataDir: "/var/lib/defenseclaw"},
	)
	if err != nil {
		t.Fatal(err)
	}
	if compiled.DataDir != wantDataDir {
		t.Fatalf("data dir = %q", compiled.DataDir)
	}
	snapshot := compiled.Plan.Snapshot()
	if snapshot.Local.Path != filepath.Join(compiled.DataDir, DefaultAuditDBName) ||
		snapshot.Local.JudgeBodiesPath != filepath.Join(compiled.DataDir, DefaultJudgeBodiesDBName) {
		t.Fatalf("local defaults = %+v", snapshot.Local)
	}
	if len(snapshot.Buckets) != 14 || len(snapshot.Destinations) != 1 {
		t.Fatalf("minimal effective plan = %+v", snapshot)
	}
}

func TestParseCompileObservabilityV8ReferenceConfiguration(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join("..", "..", "docs", "design", "observability-v8", "config-v8-observability-reference.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	compiled, err := ParseCompileObservabilityV8(
		"config-v8-observability-reference.yaml",
		raw,
		ObservabilityV8CompileOptions{DefaultDataDir: "/var/lib/defenseclaw"},
	)
	if err != nil {
		t.Fatal(err)
	}
	if len(compiled.Plan.Destinations()) != 8 { // generated local + seven examples
		t.Fatalf("reference destinations = %d", len(compiled.Plan.Destinations()))
	}
	galileo, ok := compiled.Plan.Destination("galileo")
	if !ok || galileo.PresetProfile != "galileo-rich-v2" {
		t.Fatalf("reference Galileo preset did not compile: %+v", galileo)
	}
}

func TestParseCompileObservabilityV8SchemaErrorIsValueSafe(t *testing.T) {
	secret := "do-not-render-this-value"
	_, err := ParseCompileObservabilityV8(
		"config.yaml",
		[]byte("config_version: 8\nobservability:\n  destinationz: "+secret+"\n"),
		ObservabilityV8CompileOptions{DefaultDataDir: "/tmp/data"},
	)
	var schemaError *V8SchemaError
	if !errors.As(err, &schemaError) {
		t.Fatalf("error = %T, want *V8SchemaError: %v", err, err)
	}
	if strings.Contains(err.Error(), secret) || schemaError.Keyword == "" ||
		schemaError.Line != 3 || schemaError.Column == 0 || schemaError.ReceivedClass != "string" ||
		schemaError.Suggestion != "destinations" {
		t.Fatalf("schema error leaked value or omitted keyword: %+v", schemaError)
	}
}

func TestParseCompileObservabilityV8SchemaErrorReportsExpectedEnum(t *testing.T) {
	_, err := ParseCompileObservabilityV8(
		"config.yaml",
		[]byte("config_version: 8\nobservability:\n  metric_policy:\n    temporality: invalid\n"),
		ObservabilityV8CompileOptions{DefaultDataDir: "/tmp/data"},
	)
	var schemaError *V8SchemaError
	if !errors.As(err, &schemaError) {
		t.Fatalf("error = %T, want *V8SchemaError: %v", err, err)
	}
	if !strings.Contains(schemaError.Expected, "delta") || !strings.Contains(schemaError.Expected, "cumulative") ||
		schemaError.Line != 4 || schemaError.ReceivedClass != "string" {
		t.Fatalf("enum diagnostic = %+v", schemaError)
	}
}

func TestParseCompileObservabilityV8SecretResolution(t *testing.T) {
	config := []byte(`config_version: 8
data_dir: /tmp/defenseclaw
observability:
  destinations:
    - name: enabled
      kind: otlp
      endpoint: https://otel.example.test
      headers:
        Authorization: {env: PRESENT_TOKEN}
        X-Static: visible
    - name: dormant
      kind: splunk_hec
      enabled: false
      endpoint: https://splunk.example.test/services/collector/event
      token_env: MISSING_DORMANT_TOKEN
`)
	var resolved []string
	resolver := ObservabilityV8SecretResolverFunc(func(name string) (string, bool) {
		resolved = append(resolved, name)
		if name == "PRESENT_TOKEN" {
			return "resolved-secret-bytes", true
		}
		return "", false
	})
	compiled, err := ParseCompileObservabilityV8(
		"config.yaml",
		config,
		ObservabilityV8CompileOptions{
			Secrets: resolver,
		},
	)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Join(resolved, ",") != "PRESENT_TOKEN" {
		t.Fatalf("resolved references = %v", resolved)
	}
	if strings.Contains(string(compiled.Plan.EffectiveJSON()), "resolved-secret-bytes") {
		t.Fatal("resolved secret bytes entered the immutable plan")
	}

	missing := strings.ReplaceAll(string(config), "PRESENT_TOKEN", "MISSING_ACTIVE_TOKEN")
	_, err = ParseCompileObservabilityV8(
		"config.yaml",
		[]byte(missing),
		ObservabilityV8CompileOptions{
			Secrets: resolver,
		},
	)
	var secretError *V8SecretReferenceError
	if !errors.As(err, &secretError) {
		t.Fatalf("error = %T, want *V8SecretReferenceError: %v", err, err)
	}
	if strings.Contains(err.Error(), "resolved-secret-bytes") || secretError.Reference != "MISSING_ACTIVE_TOKEN" {
		t.Fatalf("unsafe or incorrect secret error: %v", err)
	}
}

func TestObservabilityV8RuntimeSecretResolverUsesKeyStoreBeforeEnvironment(t *testing.T) {
	const name = "DEFENSECLAW_TEST_KEY"
	SetKey(name, "key-store-value")
	t.Setenv(name, "environment-value")
	value, ok := (observabilityV8RuntimeSecretResolver{}).ResolveObservabilitySecret(name)
	if !ok || value != "key-store-value" {
		t.Fatalf("secret resolver did not prefer the hydrated key store")
	}
}

func TestParseCompileObservabilityV8RequiresDeterministicDataDir(t *testing.T) {
	_, err := ParseCompileObservabilityV8(
		"config.yaml",
		[]byte("config_version: 8\n"),
		ObservabilityV8CompileOptions{},
	)
	var semanticError *V8SemanticError
	if !errors.As(err, &semanticError) || semanticError.Path != "$.data_dir" {
		t.Fatalf("missing data-dir error = %#v", semanticError)
	}
}

func TestParseCompileObservabilityV8PreservesConnectorWebhookCompatibility(t *testing.T) {
	compiled, err := ParseCompileObservabilityV8(
		"config.yaml",
		[]byte("config_version: 8\ndata_dir: /tmp/defenseclaw\nobservability:\n  connectors:\n    codex:\n      webhooks: []\n"),
		ObservabilityV8CompileOptions{},
	)
	if err != nil {
		t.Fatal(err)
	}
	connector, ok := compiled.Observability.Connectors["codex"]
	if !ok || connector.Webhooks == nil || len(*connector.Webhooks) != 0 {
		t.Fatalf("connector webhook tri-state was not preserved: %+v", compiled.Observability.Connectors)
	}
}

func TestParseCompileObservabilityV8RejectsPathAliases(t *testing.T) {
	tests := []struct {
		name  string
		local string
		judge string
		jsonl string
		want  string
	}{
		{name: "same local roles", local: "/tmp/shared.db", judge: "/tmp/shared.db", want: "distinct files"},
		{name: "parent traversal", local: "/tmp/data/../audit.db", judge: "/tmp/judge.db", want: "parent path segments"},
		{name: "jsonl collision", local: "/tmp/audit.db", judge: "/tmp/judge.db", jsonl: "/tmp/audit.db", want: "distinct files"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			jsonl := ""
			if test.jsonl != "" {
				jsonl = "\n  destinations:\n    - {name: jsonl, kind: jsonl, path: " + test.jsonl + "}"
			}
			raw := "config_version: 8\ndata_dir: /tmp/data\nobservability:\n  local:\n    path: " + test.local + "\n    judge_bodies_path: " + test.judge + jsonl + "\n"
			_, err := ParseCompileObservabilityV8("config.yaml", []byte(raw), ObservabilityV8CompileOptions{})
			if err == nil || !semanticV8CauseContains(err, test.want) {
				t.Fatalf("error = %v, want substring %q", err, test.want)
			}
		})
	}
}

func TestParseCompileObservabilityV8RejectsExistingSymlinkAndHardlinkAliases(t *testing.T) {
	tests := []struct {
		name string
		link func(string, string) error
	}{
		{name: "symlink", link: os.Symlink},
		{name: "hardlink", link: os.Link},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			directory := t.TempDir()
			auditPath := filepath.Join(directory, "audit.db")
			judgePath := filepath.Join(directory, "judge.db")
			if err := os.WriteFile(auditPath, []byte("sqlite-placeholder"), 0o600); err != nil {
				t.Fatal(err)
			}
			if err := test.link(auditPath, judgePath); err != nil {
				t.Skipf("link type is unavailable: %v", err)
			}
			raw := "config_version: 8\ndata_dir: " + directory + "\nobservability:\n  local:\n    path: " + auditPath + "\n    judge_bodies_path: " + judgePath + "\n"
			_, err := ParseCompileObservabilityV8("config.yaml", []byte(raw), ObservabilityV8CompileOptions{})
			if err == nil || !semanticV8CauseContains(err, "distinct files") {
				t.Fatalf("alias error = %v", err)
			}
		})
	}
}

func TestParseCompileObservabilityV8ResolvesSymlinkedParentForNewFiles(t *testing.T) {
	directory := t.TempDir()
	realDirectory := filepath.Join(directory, "real")
	aliasDirectory := filepath.Join(directory, "alias")
	if err := os.Mkdir(realDirectory, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(realDirectory, aliasDirectory); err != nil {
		t.Skipf("symlinks are unavailable: %v", err)
	}
	auditPath := filepath.Join(realDirectory, "future.db")
	judgePath := filepath.Join(aliasDirectory, "future.db")
	raw := "config_version: 8\ndata_dir: " + directory + "\nobservability:\n  local:\n    path: " + auditPath + "\n    judge_bodies_path: " + judgePath + "\n"
	_, err := ParseCompileObservabilityV8("config.yaml", []byte(raw), ObservabilityV8CompileOptions{})
	if err == nil || !semanticV8CauseContains(err, "distinct files") {
		t.Fatalf("symlinked-parent alias error = %v", err)
	}
}

func TestParseCompileObservabilityV8FreezesNormalizedEffectiveFilePaths(t *testing.T) {
	directory := t.TempDir()
	realDirectory := filepath.Join(directory, "real")
	aliasDirectory := filepath.Join(directory, "alias")
	if err := os.Mkdir(realDirectory, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(realDirectory, aliasDirectory); err != nil {
		t.Skipf("symlinks are unavailable: %v", err)
	}
	relativeJSONL := filepath.Join("testdata", "future-observability-v8.jsonl")
	relativeJSONLAbsolute, err := normalizeObservabilityV8FilePath(
		"observability.destinations[0].path", relativeJSONL,
	)
	if err != nil {
		t.Fatal(err)
	}
	raw := "config_version: 8\ndata_dir: " + directory + "\nobservability:\n" +
		"  local:\n    path: " + filepath.Join(aliasDirectory, "audit.db") +
		"\n    judge_bodies_path: " + filepath.Join(realDirectory, "judge.db") +
		"\n  destinations:\n    - name: local-jsonl\n      kind: jsonl\n      path: " + relativeJSONL + "\n"
	compiled, err := ParseCompileObservabilityV8(
		"config.yaml", []byte(raw), ObservabilityV8CompileOptions{},
	)
	if err != nil {
		t.Fatal(err)
	}
	snapshot := compiled.Plan.Snapshot()
	if snapshot.Local.Path != filepath.Join(aliasDirectory, "audit.db") ||
		snapshot.Local.JudgeBodiesPath != filepath.Join(realDirectory, "judge.db") {
		t.Fatalf("normalized local paths = %#v", snapshot.Local)
	}
	destination, ok := compiled.Plan.Destination("local-jsonl")
	if !ok || destination.Transport.Path != filepath.Clean(relativeJSONLAbsolute) {
		t.Fatalf("normalized JSONL destination = %#v", destination)
	}
}

func TestParseCompileObservabilityV8RejectsConfigFileAsWritableOutput(t *testing.T) {
	directory := t.TempDir()
	configPath := filepath.Join(directory, "config.yaml")
	raw := []byte("config_version: 8\ndata_dir: " + directory + "\nobservability:\n  local:\n    path: " + configPath + "\n    judge_bodies_path: " + filepath.Join(directory, "judge.db") + "\n")
	if err := os.WriteFile(configPath, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	_, err := ParseCompileObservabilityV8(configPath, raw, ObservabilityV8CompileOptions{})
	if err == nil || !semanticV8CauseContains(err, "distinct files") {
		t.Fatalf("config/output collision error = %v", err)
	}
}

func TestObservabilityV8FileValidationAllowsSharedReadOnlyCA(t *testing.T) {
	caPath := filepath.Join(t.TempDir(), "shared-ca.pem")
	if err := os.WriteFile(caPath, []byte("certificate"), 0o600); err != nil {
		t.Fatal(err)
	}
	source := &ObservabilityV8Source{Destinations: []ObservabilityV8DestinationSource{
		{Name: "one", Kind: ObservabilityV8DestinationHTTPJSONL, TLS: ObservabilityV8TLSSource{CACert: caPath}},
		{Name: "two", Kind: ObservabilityV8DestinationOTLP, TLS: ObservabilityV8TLSSource{CACert: caPath}},
	}}
	if err := validateObservabilityV8FilePaths(source, nil); err != nil {
		t.Fatalf("shared read-only CA was treated as a writable collision: %v", err)
	}
}

func TestParseCompileObservabilityV8SemanticErrorHasSourceLocation(t *testing.T) {
	raw := []byte(`config_version: 8
data_dir: /tmp/defenseclaw
observability:
  destinations:
    - name: archive
      kind: http_jsonl
      endpoint: https://archive.example.test/events
      batch:
        max_queue_size: 10
        max_export_batch_size: 11
`)
	_, err := ParseCompileObservabilityV8("config.yaml", raw, ObservabilityV8CompileOptions{})
	var semanticError *V8SemanticError
	if !errors.As(err, &semanticError) {
		t.Fatalf("error = %T, want *V8SemanticError: %v", err, err)
	}
	if semanticError.Source != "config.yaml" || semanticError.Path != "$.observability.destinations[0].batch.max_export_batch_size" ||
		semanticError.Line != 10 || semanticError.Column == 0 || semanticError.ReceivedClass != "integer" || semanticError.Expected == "" {
		t.Fatalf("semantic diagnostic = %#v", semanticError)
	}
}

func TestParseCompileObservabilityV8EffectiveProvenanceHasSourceLocation(t *testing.T) {
	raw := []byte("config_version: 8\ndata_dir: /tmp/defenseclaw\nobservability:\n  metric_policy:\n    temporality: cumulative\n")
	compiled, err := ParseCompileObservabilityV8("config.yaml", raw, ObservabilityV8CompileOptions{})
	if err != nil {
		t.Fatal(err)
	}
	for _, provenance := range compiled.Plan.Snapshot().Provenance {
		if provenance.Path == "observability.metric_policy.temporality" {
			if provenance.Origin != "source" || provenance.Source != "config.yaml" || provenance.Line != 5 || provenance.Column == 0 {
				t.Fatalf("metric provenance = %+v", provenance)
			}
			return
		}
	}
	t.Fatal("metric temporality provenance was absent")
}

func TestParseCompileObservabilityV8DigestExcludesSourceLocations(t *testing.T) {
	first, err := ParseCompileObservabilityV8(
		"first.yaml",
		[]byte("config_version: 8\ndata_dir: /tmp/defenseclaw\nobservability:\n  metric_policy:\n    temporality: cumulative\n"),
		ObservabilityV8CompileOptions{},
	)
	if err != nil {
		t.Fatal(err)
	}
	second, err := ParseCompileObservabilityV8(
		"second.yaml",
		[]byte("# location-only change\nconfig_version: 8\ndata_dir: /tmp/defenseclaw\nobservability:\n  metric_policy: {temporality: cumulative}\n"),
		ObservabilityV8CompileOptions{},
	)
	if err != nil {
		t.Fatal(err)
	}
	if first.Plan.Digest() != second.Plan.Digest() {
		t.Fatalf("source locations changed the policy digest: %s != %s", first.Plan.Digest(), second.Plan.Digest())
	}
}

func semanticV8CauseContains(err error, substring string) bool {
	for current := err; current != nil; current = errors.Unwrap(current) {
		if strings.Contains(current.Error(), substring) {
			return true
		}
	}
	return false
}
