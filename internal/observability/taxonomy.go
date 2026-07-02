// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// SPDX-License-Identifier: Apache-2.0

package observability

import (
	"fmt"
	"regexp"
	"strings"
)

// Bucket is one stable semantic class in bucket catalog version 1.
type Bucket string

const CurrentBucketCatalogVersion = 1

const (
	BucketComplianceActivity  Bucket = "compliance.activity"
	BucketSecurityFinding     Bucket = "security.finding"
	BucketGuardrailEvaluation Bucket = "guardrail.evaluation"
	BucketEnforcementAction   Bucket = "enforcement.action"
	BucketModelIO             Bucket = "model.io"
	BucketToolActivity        Bucket = "tool.activity"
	BucketAssetScan           Bucket = "asset.scan"
	BucketAssetLifecycle      Bucket = "asset.lifecycle"
	BucketNetworkEgress       Bucket = "network.egress"
	BucketAgentLifecycle      Bucket = "agent.lifecycle"
	BucketAIDiscovery         Bucket = "ai.discovery"
	BucketTelemetryIngest     Bucket = "telemetry.ingest"
	BucketPlatformHealth      Bucket = "platform.health"
	BucketDiagnostic          Bucket = "diagnostic"
)

// canonicalBucketOrder is the immutable catalog-v1 display and generation order.
var canonicalBucketOrder = [...]Bucket{
	BucketComplianceActivity,
	BucketSecurityFinding,
	BucketGuardrailEvaluation,
	BucketEnforcementAction,
	BucketModelIO,
	BucketToolActivity,
	BucketAssetScan,
	BucketAssetLifecycle,
	BucketNetworkEgress,
	BucketAgentLifecycle,
	BucketAIDiscovery,
	BucketTelemetryIngest,
	BucketPlatformHealth,
	BucketDiagnostic,
}

// Buckets returns catalog-v1 buckets in stable display/generation order.
func Buckets() []Bucket {
	return append([]Bucket(nil), canonicalBucketOrder[:]...)
}

// IsBucket reports whether bucket belongs to catalog version 1.
func IsBucket(bucket Bucket) bool {
	for _, candidate := range canonicalBucketOrder {
		if candidate == bucket {
			return true
		}
	}
	return false
}

// Signal is one independently collected and routed telemetry signal.
type Signal string

const (
	SignalLogs    Signal = "logs"
	SignalTraces  Signal = "traces"
	SignalMetrics Signal = "metrics"
)

var canonicalSignalOrder = [...]Signal{SignalLogs, SignalTraces, SignalMetrics}

// Signals returns canonical signals in stable display/generation order.
func Signals() []Signal {
	return append([]Signal(nil), canonicalSignalOrder[:]...)
}

func IsSignal(signal Signal) bool {
	for _, candidate := range canonicalSignalOrder {
		if candidate == signal {
			return true
		}
	}
	return false
}

// Severity is the canonical comparable five-rung security severity.
type Severity string

const (
	SeverityInfo     Severity = "INFO"
	SeverityLow      Severity = "LOW"
	SeverityMedium   Severity = "MEDIUM"
	SeverityHigh     Severity = "HIGH"
	SeverityCritical Severity = "CRITICAL"
)

var canonicalSeverityOrder = [...]Severity{
	SeverityInfo,
	SeverityLow,
	SeverityMedium,
	SeverityHigh,
	SeverityCritical,
}

// Severities returns the canonical ladder from lowest to highest.
func Severities() []Severity {
	return append([]Severity(nil), canonicalSeverityOrder[:]...)
}

// LogLevel is operational logging level, separate from security severity.
type LogLevel string

const (
	LogLevelTrace LogLevel = "TRACE"
	LogLevelDebug LogLevel = "DEBUG"
	LogLevelInfo  LogLevel = "INFO"
	LogLevelWarn  LogLevel = "WARN"
	LogLevelError LogLevel = "ERROR"
	LogLevelFatal LogLevel = "FATAL"
)

// SeverityNormalization retains the source-level semantics needed when several
// producer vocabularies merge into the canonical severity ladder.
type SeverityNormalization struct {
	Severity           Severity
	LogLevel           LogLevel
	Present            bool
	Valid              bool
	CleanEvaluation    bool
	LegacyAcknowledged bool
}

// NormalizeSeverity implements the approved cross-producer mapping. NONE is a
// clean evaluation, not a sixth severity; WARN remains available as log level.
func NormalizeSeverity(value string) SeverityNormalization {
	normalized := strings.ToUpper(strings.TrimSpace(value))
	switch normalized {
	case "NONE":
		return SeverityNormalization{
			Severity:        SeverityInfo,
			Present:         true,
			Valid:           true,
			CleanEvaluation: true,
		}
	case "TRACE":
		return SeverityNormalization{
			Severity: SeverityInfo, LogLevel: LogLevelTrace, Present: true, Valid: true,
		}
	case "DEBUG":
		return SeverityNormalization{
			Severity: SeverityInfo, LogLevel: LogLevelDebug, Present: true, Valid: true,
		}
	case "INFO":
		return SeverityNormalization{
			Severity: SeverityInfo, LogLevel: LogLevelInfo, Present: true, Valid: true,
		}
	case "LOW":
		return SeverityNormalization{Severity: SeverityLow, Present: true, Valid: true}
	case "WARN", "WARNING":
		return SeverityNormalization{
			Severity: SeverityMedium, LogLevel: LogLevelWarn, Present: true, Valid: true,
		}
	case "MEDIUM":
		return SeverityNormalization{Severity: SeverityMedium, Present: true, Valid: true}
	case "ERROR":
		return SeverityNormalization{
			Severity: SeverityHigh, LogLevel: LogLevelError, Present: true, Valid: true,
		}
	case "HIGH":
		return SeverityNormalization{Severity: SeverityHigh, Present: true, Valid: true}
	case "FATAL":
		return SeverityNormalization{
			Severity: SeverityCritical, LogLevel: LogLevelFatal, Present: true, Valid: true,
		}
	case "CRITICAL":
		return SeverityNormalization{Severity: SeverityCritical, Present: true, Valid: true}
	case "":
		return SeverityNormalization{Valid: true}
	default:
		return SeverityNormalization{}
	}
}

// NormalizeLegacyAuditSeverity applies the immutable acknowledgement contract.
// Old acknowledgement action rows become INFO. A row whose original severity was
// destructively overwritten with ACK retains acknowledgement metadata without
// inventing the lost severity.
func NormalizeLegacyAuditSeverity(action ProducerKey, value string) SeverityNormalization {
	if !strings.EqualFold(strings.TrimSpace(value), "ACK") {
		return NormalizeSeverity(value)
	}
	result := SeverityNormalization{Valid: true, LegacyAcknowledged: true}
	switch action {
	case ProducerKey("acknowledge-alerts"), ProducerKey("dismiss-alerts"), ProducerKey("dismiss-alert"):
		result.Severity = SeverityInfo
		result.LogLevel = LogLevelInfo
		result.Present = true
	}
	return result
}

// SeverityRank returns the stable comparison rank. The bool is false for an
// unknown or empty value.
func SeverityRank(severity Severity) (int, bool) {
	for index, candidate := range canonicalSeverityOrder {
		if candidate == severity {
			return index + 1, true
		}
	}
	return 0, false
}

// Source is a stable producer identity. It is intentionally extensible: adding a
// producer does not add a bucket.
type Source string

const (
	SourceGateway      Source = "gateway"
	SourceGuardrail    Source = "guardrail"
	SourceOperator     Source = "operator"
	SourceOperatorAPI  Source = "operator_api"
	SourceCLI          Source = "cli"
	SourceAIDefense    Source = "ai_defense"
	SourceCodeGuard    Source = "codeguard"
	SourceScanner      Source = "scanner"
	SourceConnector    Source = "connector"
	SourceOTelReceiver Source = "otel_receiver"
	SourceWatcher      Source = "watcher"
	SourceSystem       Source = "system"
)

var builtInSourceOrder = [...]Source{
	SourceGateway,
	SourceGuardrail,
	SourceOperator,
	SourceOperatorAPI,
	SourceCLI,
	SourceAIDefense,
	SourceCodeGuard,
	SourceScanner,
	SourceConnector,
	SourceOTelReceiver,
	SourceWatcher,
	SourceSystem,
}

// BuiltInSources returns the shipped producer identities in stable display
// order. Source remains extensible; custom integrations need not become buckets.
func BuiltInSources() []Source {
	return append([]Source(nil), builtInSourceOrder[:]...)
}

func IsBuiltInSource(source Source) bool {
	for _, candidate := range builtInSourceOrder {
		if source == candidate {
			return true
		}
	}
	return false
}

// EventName is a stable registry identity. Rendered span names are separate.
type EventName string

var eventNamePattern = regexp.MustCompile(`^[a-z][a-z0-9_]*(?:\.[a-z][a-z0-9_]*)*$`)

func (name EventName) Validate() error {
	if !eventNamePattern.MatchString(string(name)) {
		return fmt.Errorf(
			"event name %q must be lower-case dotted segments or a registered snake_case alias",
			name,
		)
	}
	return nil
}

// EventIdentity is the routing identity of one canonical signal family.
type EventIdentity struct {
	Bucket Bucket
	Signal Signal
	Name   EventName
}

func (identity EventIdentity) Validate() error {
	if !IsBucket(identity.Bucket) {
		return fmt.Errorf("unknown bucket %q", identity.Bucket)
	}
	if !IsSignal(identity.Signal) {
		return fmt.Errorf("unknown signal %q", identity.Signal)
	}
	return identity.Name.Validate()
}

// Selector is the typed metadata-only routing selector. Values in one field are
// ORed; populated fields are ANDed by the route evaluator.
type Selector struct {
	Buckets     []Bucket
	Sources     []Source
	Connectors  []string
	Actions     []ProducerKey
	EventNames  []EventName
	MinSeverity Severity // empty means absent
}

func (selector Selector) Validate() error {
	if err := validateWildcardValues("buckets", selector.Buckets, func(bucket Bucket) error {
		if !IsBucket(bucket) {
			return fmt.Errorf("unknown bucket %q", bucket)
		}
		return nil
	}); err != nil {
		return err
	}
	if err := validateWildcardValues("sources", selector.Sources, nil); err != nil {
		return err
	}
	if err := validateWildcardValues("connectors", selector.Connectors, nil); err != nil {
		return err
	}
	if err := validateWildcardValues("actions", selector.Actions, nil); err != nil {
		return err
	}
	if err := validateWildcardValues("event_names", selector.EventNames, func(name EventName) error {
		return name.Validate()
	}); err != nil {
		return err
	}
	if selector.MinSeverity != "" {
		if _, ok := SeverityRank(selector.MinSeverity); !ok {
			return fmt.Errorf("unknown minimum severity %q", selector.MinSeverity)
		}
	}
	return nil
}

func validateWildcardValues[T ~string](field string, values []T, validate func(T) error) error {
	for _, value := range values {
		if string(value) == "*" {
			if len(values) != 1 {
				return fmt.Errorf("%s wildcard must be the only value", field)
			}
			continue
		}
		if value == "" {
			return fmt.Errorf("%s contains an empty value", field)
		}
		if validate != nil {
			if err := validate(value); err != nil {
				return err
			}
		}
	}
	return nil
}
