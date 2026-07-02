// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// SPDX-License-Identifier: Apache-2.0

package observability_test

import (
	"reflect"
	"testing"

	observability "github.com/defenseclaw/defenseclaw/internal/observability"
)

func TestCanonicalTaxonomy(t *testing.T) {
	wantBuckets := [...]observability.Bucket{
		observability.BucketComplianceActivity,
		observability.BucketSecurityFinding,
		observability.BucketGuardrailEvaluation,
		observability.BucketEnforcementAction,
		observability.BucketModelIO,
		observability.BucketToolActivity,
		observability.BucketAssetScan,
		observability.BucketAssetLifecycle,
		observability.BucketNetworkEgress,
		observability.BucketAgentLifecycle,
		observability.BucketAIDiscovery,
		observability.BucketTelemetryIngest,
		observability.BucketPlatformHealth,
		observability.BucketDiagnostic,
	}
	if got := observability.Buckets(); !reflect.DeepEqual(got, wantBuckets[:]) {
		t.Fatalf("bucket order = %v, want %v", got, wantBuckets)
	}
	seen := make(map[observability.Bucket]struct{}, len(observability.Buckets()))
	for _, bucket := range observability.Buckets() {
		if !observability.IsBucket(bucket) {
			t.Errorf("canonical bucket %q is not recognized", bucket)
		}
		if _, duplicate := seen[bucket]; duplicate {
			t.Errorf("canonical bucket %q is duplicated", bucket)
		}
		seen[bucket] = struct{}{}
	}
	if observability.IsBucket("not-a-real-bucket") {
		t.Fatal("unknown bucket was recognized")
	}

	wantSignals := [...]observability.Signal{
		observability.SignalLogs,
		observability.SignalTraces,
		observability.SignalMetrics,
	}
	if got := observability.Signals(); !reflect.DeepEqual(got, wantSignals[:]) {
		t.Fatalf("signal order = %v, want %v", got, wantSignals)
	}

	wantSeverities := [...]observability.Severity{
		observability.SeverityInfo,
		observability.SeverityLow,
		observability.SeverityMedium,
		observability.SeverityHigh,
		observability.SeverityCritical,
	}
	if got := observability.Severities(); !reflect.DeepEqual(got, wantSeverities[:]) {
		t.Fatalf("severity order = %v, want %v", got, wantSeverities)
	}
	for index, severity := range observability.Severities() {
		rank, ok := observability.SeverityRank(severity)
		if !ok || rank != index+1 {
			t.Errorf("SeverityRank(%q) = (%d, %t), want (%d, true)", severity, rank, ok, index+1)
		}
	}
}

func TestCanonicalOrdersReturnCopies(t *testing.T) {
	buckets := observability.Buckets()
	buckets[0] = observability.BucketDiagnostic
	if observability.Buckets()[0] != observability.BucketComplianceActivity {
		t.Fatal("bucket catalog was mutable through returned slice")
	}
	signals := observability.Signals()
	signals[0] = observability.SignalMetrics
	if observability.Signals()[0] != observability.SignalLogs {
		t.Fatal("signal catalog was mutable through returned slice")
	}
	severities := observability.Severities()
	severities[0] = observability.SeverityCritical
	if observability.Severities()[0] != observability.SeverityInfo {
		t.Fatal("severity catalog was mutable through returned slice")
	}
	sources := observability.BuiltInSources()
	sources[0] = observability.SourceSystem
	if observability.BuiltInSources()[0] != observability.SourceGateway {
		t.Fatal("built-in source registry was mutable through returned slice")
	}
	if !observability.IsBuiltInSource(observability.SourceScanner) ||
		observability.IsBuiltInSource("custom_integration") {
		t.Fatal("built-in source recognition is incorrect")
	}
}

func TestNormalizeSeverity(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		severity observability.Severity
		level    observability.LogLevel
		present  bool
		valid    bool
		clean    bool
	}{
		{name: "empty", valid: true},
		{name: "none", input: "NONE", severity: observability.SeverityInfo, present: true, valid: true, clean: true},
		{name: "debug", input: "debug", severity: observability.SeverityInfo, level: observability.LogLevelDebug, present: true, valid: true},
		{name: "info", input: "INFO", severity: observability.SeverityInfo, level: observability.LogLevelInfo, present: true, valid: true},
		{name: "low", input: "LOW", severity: observability.SeverityLow, present: true, valid: true},
		{name: "warn", input: "WARN", severity: observability.SeverityMedium, level: observability.LogLevelWarn, present: true, valid: true},
		{name: "warning", input: "WARNING", severity: observability.SeverityMedium, level: observability.LogLevelWarn, present: true, valid: true},
		{name: "medium", input: "MEDIUM", severity: observability.SeverityMedium, present: true, valid: true},
		{name: "error", input: "ERROR", severity: observability.SeverityHigh, level: observability.LogLevelError, present: true, valid: true},
		{name: "high", input: "HIGH", severity: observability.SeverityHigh, present: true, valid: true},
		{name: "fatal", input: "FATAL", severity: observability.SeverityCritical, level: observability.LogLevelFatal, present: true, valid: true},
		{name: "critical", input: "CRITICAL", severity: observability.SeverityCritical, present: true, valid: true},
		{name: "unknown", input: "NOTICE"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got := observability.NormalizeSeverity(test.input)
			if got.Severity != test.severity || got.LogLevel != test.level ||
				got.Present != test.present || got.Valid != test.valid ||
				got.CleanEvaluation != test.clean {
				t.Fatalf("NormalizeSeverity(%q) = %+v", test.input, got)
			}
		})
	}
}

func TestNormalizeLegacyAuditAcknowledgement(t *testing.T) {
	acknowledgement := observability.NormalizeLegacyAuditSeverity("acknowledge-alerts", "ACK")
	if !acknowledgement.Valid || !acknowledgement.Present || !acknowledgement.LegacyAcknowledged ||
		acknowledgement.Severity != observability.SeverityInfo {
		t.Fatalf("acknowledgement severity = %+v", acknowledgement)
	}

	overwritten := observability.NormalizeLegacyAuditSeverity("scan", "ACK")
	if !overwritten.Valid || overwritten.Present || !overwritten.LegacyAcknowledged ||
		overwritten.Severity != "" {
		t.Fatalf("destructively overwritten severity = %+v", overwritten)
	}
}

func TestEventIdentityAndSelectorValidation(t *testing.T) {
	validIdentity := observability.EventIdentity{
		Bucket: observability.BucketAgentLifecycle,
		Signal: observability.SignalTraces,
		Name:   "agent.session_start",
	}
	if err := validIdentity.Validate(); err != nil {
		t.Fatalf("valid identity: %v", err)
	}
	invalidIdentity := validIdentity
	invalidIdentity.Name = "Agent Session Start"
	if err := invalidIdentity.Validate(); err == nil {
		t.Fatal("identity with an unregistered name shape passed validation")
	}

	validSelector := observability.Selector{
		Buckets:     []observability.Bucket{observability.BucketSecurityFinding},
		Sources:     []observability.Source{observability.SourceScanner},
		EventNames:  []observability.EventName{"finding.observed"},
		MinSeverity: observability.SeverityHigh,
	}
	if err := validSelector.Validate(); err != nil {
		t.Fatalf("valid selector: %v", err)
	}
	invalidSelector := validSelector
	invalidSelector.Buckets = []observability.Bucket{"*", observability.BucketSecurityFinding}
	if err := invalidSelector.Validate(); err == nil {
		t.Fatal("mixed wildcard selector passed validation")
	}
}
