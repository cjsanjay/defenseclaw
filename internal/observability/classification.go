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
	"sort"
	"strings"
)

type ProducerKind string

const (
	ProducerGatewayEvent ProducerKind = "gateway_event"
	ProducerAuditAction  ProducerKind = "audit_action"
)

// ProducerKey is an observability-owned typed wire identity. Production metadata
// uses these keys without importing the producer packages that currently emit them.
type ProducerKey string

type EventNamePolicy string

const (
	EventNameFixed           EventNamePolicy = "fixed"
	EventNameContextOptional EventNamePolicy = "context_optional"
	EventNameContextRequired EventNamePolicy = "context_required"
)

type SeverityPolicy string

const (
	SeverityCanonicalOrInfo   SeverityPolicy = "canonical_or_info"
	SeverityFindingRequired   SeverityPolicy = "finding_required"
	SeverityEvaluation        SeverityPolicy = "evaluation"
	SeverityFailureOrSource   SeverityPolicy = "failure_or_source"
	SeverityMalformedOrSource SeverityPolicy = "malformed_or_source"
)

type MandatoryRule string

const (
	MandatoryAlways                        MandatoryRule = "always"
	MandatoryControlPlaneMutation          MandatoryRule = "control_plane_mutation"
	MandatoryApprovalResolution            MandatoryRule = "approval_resolution"
	MandatoryAlertMutation                 MandatoryRule = "alert_mutation"
	MandatoryProtectedBoundaryAuthFailure  MandatoryRule = "protected_boundary_auth_failure"
	MandatoryEnforcedOutcome               MandatoryRule = "enforced_outcome"
	MandatoryEnforcementStateChange        MandatoryRule = "enforcement_state_change"
	MandatorySchemaValidationFailure       MandatoryRule = "schema_validation_failure"
	MandatorySQLiteFailure                 MandatoryRule = "sqlite_failure"
	MandatoryExporterInitializationFailure MandatoryRule = "exporter_initialization_failure"
	MandatoryDurableHealthTransition       MandatoryRule = "durable_health_transition"
)

type CompanionRule string

const (
	CompanionEnforcementWhenEnforced CompanionRule = "enforcement_when_enforced"
	CompanionAssetLifecycleOnChange  CompanionRule = "asset_lifecycle_on_state_change"
	CompanionFindingPerObservation   CompanionRule = "finding_per_observation"
)

// MandatoryFacts are typed call-site facts. Free-form details never participate
// in floor qualification.
type MandatoryFacts struct {
	ControlPlaneMutation          bool
	ApprovalResolution            bool
	AlertMutation                 bool
	ProtectedBoundaryAuthFailure  bool
	EnforcedOutcome               bool
	EnforcementStateChange        bool
	SchemaValidationFailure       bool
	SQLiteFailure                 bool
	ExporterInitializationFailure bool
	DurableHealthTransition       bool
}

// Classification is immutable producer metadata. An empty Bucket means a typed
// call-site bucket is required and must belong to AllowedContextBuckets.
type Classification struct {
	Kind                  ProducerKind
	Key                   ProducerKey
	Bucket                Bucket
	DefaultEventName      EventName
	EventNamePolicy       EventNamePolicy
	SeverityPolicy        SeverityPolicy
	MandatoryRules        []MandatoryRule
	CompanionRules        []CompanionRule
	AllowedContextBuckets []Bucket
}

type ClassificationContext struct {
	Bucket         Bucket
	EventName      EventName
	RawSeverity    string
	MandatoryFacts MandatoryFacts
	Enforced       bool
	StateChanged   bool
	FindingCount   int
}

type ResolvedClassification struct {
	Identity           EventIdentity
	Severity           SeverityNormalization
	Mandatory          bool
	RequiredCompanions []CompanionRule
}

func (classification Classification) RequiresContext() bool {
	return classification.Bucket == "" || classification.EventNamePolicy == EventNameContextRequired
}

func (classification Classification) Resolve(context ClassificationContext) (ResolvedClassification, error) {
	if context.FindingCount < 0 {
		return ResolvedClassification{}, fmt.Errorf("finding count cannot be negative")
	}
	bucket := classification.Bucket
	if bucket == "" {
		if !bucketAllowed(context.Bucket, classification.AllowedContextBuckets) {
			return ResolvedClassification{}, fmt.Errorf(
				"classification %s/%s requires one of context buckets %v, got %q",
				classification.Kind,
				classification.Key,
				classification.AllowedContextBuckets,
				context.Bucket,
			)
		}
		bucket = context.Bucket
	}

	eventName := classification.DefaultEventName
	switch classification.EventNamePolicy {
	case EventNameFixed:
		if context.EventName != "" && context.EventName != eventName {
			return ResolvedClassification{}, fmt.Errorf(
				"classification %s/%s has fixed event name %q, got %q",
				classification.Kind,
				classification.Key,
				eventName,
				context.EventName,
			)
		}
	case EventNameContextOptional:
		if context.EventName != "" {
			eventName = context.EventName
		}
	case EventNameContextRequired:
		if context.EventName == "" {
			return ResolvedClassification{}, fmt.Errorf(
				"classification %s/%s requires a typed event name",
				classification.Kind,
				classification.Key,
			)
		}
		eventName = context.EventName
	default:
		return ResolvedClassification{}, fmt.Errorf(
			"classification %s/%s has unknown event-name policy %q",
			classification.Kind,
			classification.Key,
			classification.EventNamePolicy,
		)
	}

	identity := EventIdentity{Bucket: bucket, Signal: SignalLogs, Name: eventName}
	if err := identity.Validate(); err != nil {
		return ResolvedClassification{}, err
	}
	severity, err := classification.resolveSeverity(context.RawSeverity)
	if err != nil {
		return ResolvedClassification{}, err
	}
	companions := make([]CompanionRule, 0, len(classification.CompanionRules))
	for _, rule := range classification.CompanionRules {
		switch rule {
		case CompanionEnforcementWhenEnforced:
			if context.Enforced && bucket != BucketEnforcementAction {
				companions = append(companions, rule)
			}
		case CompanionAssetLifecycleOnChange:
			if context.StateChanged {
				companions = append(companions, rule)
			}
		case CompanionFindingPerObservation:
			if context.FindingCount > 0 {
				companions = append(companions, rule)
			}
		}
	}
	return ResolvedClassification{
		Identity:           identity,
		Severity:           severity,
		Mandatory:          classification.isMandatory(context.MandatoryFacts),
		RequiredCompanions: companions,
	}, nil
}

func (classification Classification) resolveSeverity(raw string) (SeverityNormalization, error) {
	var normalized SeverityNormalization
	if classification.Kind == ProducerAuditAction {
		normalized = NormalizeLegacyAuditSeverity(classification.Key, raw)
	} else {
		normalized = NormalizeSeverity(raw)
	}
	if !normalized.Valid {
		return SeverityNormalization{}, fmt.Errorf("invalid severity %q", raw)
	}
	if normalized.LegacyAcknowledged && !normalized.Present {
		return SeverityNormalization{}, fmt.Errorf(
			"legacy ACK severity for %s/%s has no recoverable canonical severity; use the compatibility read model",
			classification.Kind,
			classification.Key,
		)
	}
	if normalized.Present {
		return normalized, nil
	}
	switch classification.SeverityPolicy {
	case SeverityFindingRequired:
		return SeverityNormalization{}, fmt.Errorf(
			"classification %s/%s requires finding severity",
			classification.Kind,
			classification.Key,
		)
	case SeverityFailureOrSource:
		return SeverityNormalization{Severity: SeverityHigh, Present: true, Valid: true}, nil
	case SeverityMalformedOrSource:
		return SeverityNormalization{Severity: SeverityMedium, Present: true, Valid: true}, nil
	default:
		return SeverityNormalization{Severity: SeverityInfo, Present: true, Valid: true}, nil
	}
}

func (classification Classification) isMandatory(facts MandatoryFacts) bool {
	for _, rule := range classification.MandatoryRules {
		switch rule {
		case MandatoryAlways:
			return true
		case MandatoryControlPlaneMutation:
			if facts.ControlPlaneMutation {
				return true
			}
		case MandatoryApprovalResolution:
			if facts.ApprovalResolution {
				return true
			}
		case MandatoryAlertMutation:
			if facts.AlertMutation {
				return true
			}
		case MandatoryProtectedBoundaryAuthFailure:
			if facts.ProtectedBoundaryAuthFailure {
				return true
			}
		case MandatoryEnforcedOutcome:
			if facts.EnforcedOutcome {
				return true
			}
		case MandatoryEnforcementStateChange:
			if facts.EnforcementStateChange {
				return true
			}
		case MandatorySchemaValidationFailure:
			if facts.SchemaValidationFailure {
				return true
			}
		case MandatorySQLiteFailure:
			if facts.SQLiteFailure {
				return true
			}
		case MandatoryExporterInitializationFailure:
			if facts.ExporterInitializationFailure {
				return true
			}
		case MandatoryDurableHealthTransition:
			if facts.DurableHealthTransition {
				return true
			}
		}
	}
	return false
}

func bucketAllowed(bucket Bucket, allowed []Bucket) bool {
	for _, candidate := range allowed {
		if bucket == candidate {
			return true
		}
	}
	return false
}

var gatewayEventClassifications = buildGatewayEventClassifications()
var auditActionClassifications = buildAuditActionClassifications()

func GatewayEventClassification(key ProducerKey) (Classification, bool) {
	classification, ok := gatewayEventClassifications[key]
	return cloneClassification(classification), ok
}

func AuditActionClassification(key ProducerKey) (Classification, bool) {
	classification, ok := auditActionClassifications[key]
	return cloneClassification(classification), ok
}

func ClassificationKeys(kind ProducerKind) []ProducerKey {
	var source map[ProducerKey]Classification
	switch kind {
	case ProducerGatewayEvent:
		source = gatewayEventClassifications
	case ProducerAuditAction:
		source = auditActionClassifications
	default:
		return nil
	}
	keys := make([]ProducerKey, 0, len(source))
	for key := range source {
		keys = append(keys, key)
	}
	sort.Slice(keys, func(left, right int) bool { return keys[left] < keys[right] })
	return keys
}

func cloneClassification(classification Classification) Classification {
	classification.MandatoryRules = append([]MandatoryRule(nil), classification.MandatoryRules...)
	classification.CompanionRules = append([]CompanionRule(nil), classification.CompanionRules...)
	classification.AllowedContextBuckets = append(
		[]Bucket(nil), classification.AllowedContextBuckets...,
	)
	return classification
}

func buildGatewayEventClassifications() map[ProducerKey]Classification {
	result := map[ProducerKey]Classification{}
	add := func(classification Classification) {
		classification.Kind = ProducerGatewayEvent
		registerClassification(result, classification)
	}
	add(fixed("verdict", BucketGuardrailEvaluation, "guardrail.evaluation.completed", SeverityEvaluation,
		nil, []CompanionRule{CompanionEnforcementWhenEnforced}))
	add(fixed("judge", BucketGuardrailEvaluation, "guardrail.judge.completed", SeverityEvaluation, nil, nil))
	add(contextual("lifecycle", []Bucket{
		BucketComplianceActivity, BucketAgentLifecycle, BucketPlatformHealth,
	}, SeverityCanonicalOrInfo, []MandatoryRule{
		MandatoryControlPlaneMutation, MandatoryDurableHealthTransition,
	}, nil))
	add(contextual("error", []Bucket{
		BucketModelIO, BucketToolActivity, BucketAgentLifecycle, BucketAssetScan,
		BucketTelemetryIngest, BucketPlatformHealth,
	}, SeverityFailureOrSource, []MandatoryRule{
		MandatorySchemaValidationFailure, MandatorySQLiteFailure,
		MandatoryExporterInitializationFailure, MandatoryDurableHealthTransition,
	}, nil))
	add(fixed("diagnostic", BucketDiagnostic, "diagnostic.message", SeverityCanonicalOrInfo, nil, nil))
	add(optional("scan", BucketAssetScan, "scan.completed", SeverityCanonicalOrInfo,
		nil, []CompanionRule{CompanionFindingPerObservation}))
	add(fixed("scan_finding", BucketSecurityFinding, "finding.observed", SeverityFindingRequired, nil, nil))
	add(Classification{
		Key: "activity", Bucket: BucketComplianceActivity,
		EventNamePolicy: EventNameContextRequired, SeverityPolicy: SeverityCanonicalOrInfo,
		MandatoryRules: []MandatoryRule{
			MandatoryControlPlaneMutation, MandatoryApprovalResolution, MandatoryAlertMutation,
		},
	})
	add(Classification{
		Key: "egress", Bucket: BucketNetworkEgress,
		EventNamePolicy: EventNameContextRequired, SeverityPolicy: SeverityCanonicalOrInfo,
		MandatoryRules: []MandatoryRule{MandatoryEnforcedOutcome},
	})
	add(fixed("llm_prompt", BucketModelIO, "model.request", SeverityCanonicalOrInfo, nil, nil))
	add(optional("llm_response", BucketModelIO, "model.response", SeverityCanonicalOrInfo, nil, nil))
	add(Classification{
		Key: "tool_invocation", Bucket: BucketToolActivity,
		EventNamePolicy: EventNameContextRequired, SeverityPolicy: SeverityCanonicalOrInfo,
		CompanionRules: []CompanionRule{CompanionEnforcementWhenEnforced},
	})
	add(fixed("hook_decision", BucketGuardrailEvaluation, "hook_decision", SeverityEvaluation,
		nil, []CompanionRule{CompanionEnforcementWhenEnforced}))
	add(Classification{
		Key: "ai_discovery", Bucket: BucketAIDiscovery,
		EventNamePolicy: EventNameContextRequired, SeverityPolicy: SeverityCanonicalOrInfo,
	})
	return result
}

func buildAuditActionClassifications() map[ProducerKey]Classification {
	result := map[ProducerKey]Classification{}
	addGroup := func(
		bucket Bucket,
		severity SeverityPolicy,
		mandatory []MandatoryRule,
		companions []CompanionRule,
		actions ...string,
	) {
		for _, action := range actions {
			registerClassification(result, Classification{
				Kind: ProducerAuditAction, Key: ProducerKey(action), Bucket: bucket,
				DefaultEventName: legacyAuditEventName(action),
				EventNamePolicy:  EventNameContextOptional,
				SeverityPolicy:   severity,
				MandatoryRules:   append([]MandatoryRule(nil), mandatory...),
				CompanionRules:   append([]CompanionRule(nil), companions...),
			})
		}
	}

	addGroup(BucketComplianceActivity, SeverityCanonicalOrInfo, []MandatoryRule{
		MandatoryControlPlaneMutation, MandatoryApprovalResolution, MandatoryAlertMutation,
		MandatoryProtectedBoundaryAuthFailure,
	}, nil,
		"approval-request", "approval-granted", "approval-denied",
		"gateway-approval-requested", "gateway-approval-granted", "gateway-approval-denied",
		"gateway-approval-pending", "config-update", "policy-update", "policy-reload", "action",
		"acknowledge-alerts", "dismiss-alerts", "connector-hook-repaired",
		"guardrail-config-reload", "guardrail-disable", "guardrail-enable", "guardrail-fail-mode",
		"guardrail-hilt", "inspect-reveal", "api-auth-failure", "api-config-patch",
		"setup-skill-scanner", "setup-mcp-scanner", "setup-gateway", "setup-guardrail",
		"setup-hook-connector", "setup-connector-mode", "setup-redaction-toggle",
		"setup-notifications-toggle", "setup-notifications-set", "setup-splunk",
		"setup-observability", "setup-local-observability", "setup-webhook", "doctor", "upgrade",
		"init-gateway", "init-guardrail", "init-notifications-toggle", "init-sandbox", "init-sidecar",
		"policy-create", "policy-activate", "policy-delete", "registry-add", "registry-edit",
		"registry-remove", "dismiss-alert",
	)
	addGroup(BucketSecurityFinding, SeverityFindingRequired, nil, nil,
		"connector-hook-tampered", "gateway-session-prompt-alert", "gateway-tool-call-flagged",
		"gateway-tool-call-judge-flagged", "gateway-multi-turn-injection", "tool-result-pii-alert",
		"scan-finding",
	)
	addGroup(BucketGuardrailEvaluation, SeverityEvaluation, nil,
		[]CompanionRule{CompanionEnforcementWhenEnforced},
		"guardrail-block", "guardrail-warn", "guardrail-allow",
		"connector-hook", "connector-hook-synthetic", "asset-policy", "sidecar-watcher-verdict",
		"install-rejected", "install-allowed", "install-allowed-skip-enforce", "install-warning",
		"guardrail-verdict", "guardrail-inspection", "guardrail-opa-inspection",
		"guardrail-opa-verdict", "guardrail-tool-call-parse-error", "guardrail-tool-call-inspect",
		"llm-judge-response", "inspect-tool-confirm", "inspect-tool-block", "inspect-tool-alert",
		"inspect-tool-allow",
	)
	addGroup(BucketEnforcementAction, SeverityCanonicalOrInfo, []MandatoryRule{
		MandatoryEnforcedOutcome, MandatoryEnforcementStateChange,
	}, []CompanionRule{CompanionAssetLifecycleOnChange},
		"quarantine", "restore", "disable", "enable", "sidecar-watcher-disable",
		"sidecar-watcher-disable-plugin", "sidecar-watcher-block-mcp", "watcher-block",
		"install-enforced", "install-blocked", "guardrail-launder", "guardrail-notify-inject",
		"guardrail-block-message", "api-enforce-allow", "api-enforce-block", "api-enforce-unblock",
		"scan-enforced", "skill-block", "skill-unblock", "skill-allow", "skill-disable",
		"skill-enable", "skill-quarantine", "skill-restore", "plugin-block", "plugin-allow",
		"plugin-disable", "plugin-enable", "plugin-quarantine", "plugin-restore", "block-mcp",
		"allow-mcp", "mcp-unblock", "mcp-set-blocked", "tool-block", "tool-allow",
		"tool-unblock", "api-plugin-disable", "api-plugin-enable", "api-skill-disable",
		"api-skill-enable",
	)
	addGroup(BucketModelIO, SeverityCanonicalOrInfo, nil, nil,
		"gateway-session-message", "gateway-chat-error",
	)
	addGroup(BucketToolActivity, SeverityCanonicalOrInfo, nil,
		[]CompanionRule{CompanionEnforcementWhenEnforced},
		"tool-call", "tool-result", "gateway-tool-call", "gateway-tool-call-blocked",
		"gateway-tool-result",
	)
	addGroup(BucketAssetScan, SeverityCanonicalOrInfo, nil,
		[]CompanionRule{CompanionFindingPerObservation},
		"scan", "scan-start", "rescan", "rescan-start", "install-clean", "install-scan-error",
		"api-mcp-scan", "api-plugin-scan", "api-skill-scan",
	)
	addGroup(BucketAssetLifecycle, SeverityCanonicalOrInfo,
		[]MandatoryRule{MandatoryEnforcementStateChange}, nil,
		"deploy", "drift", "install-detected", "install-dep", "api-skill-fetch", "plugin-install",
		"plugin-remove", "mcp-set", "mcp-unset",
	)
	addGroup(BucketNetworkEgress, SeverityCanonicalOrInfo,
		[]MandatoryRule{MandatoryEnforcedOutcome}, nil,
		"network-egress-blocked", "network-egress-allowed",
	)
	addGroup(BucketAgentLifecycle, SeverityCanonicalOrInfo, nil, nil,
		"codex.notify.agent-turn-complete", "sidecar-start", "sidecar-stop", "gateway-agent-start",
		"gateway-agent-end", "gateway-agent-error", "gateway-session-error",
	)
	addGroup(BucketTelemetryIngest, SeverityCanonicalOrInfo, []MandatoryRule{
		MandatorySchemaValidationFailure, MandatoryProtectedBoundaryAuthFailure,
	}, nil,
		"otel.ingest.logs", "otel.ingest.metrics", "otel.ingest.traces", "otel.ingest.malformed",
		"codex.notify", "codex.notify.malformed",
	)
	addGroup(BucketPlatformHealth, SeverityCanonicalOrInfo, []MandatoryRule{
		MandatorySQLiteFailure, MandatoryExporterInitializationFailure, MandatoryDurableHealthTransition,
	}, nil,
		"webhook-delivered", "webhook-failed", "sink-failure", "sink-restored",
		"sidecar-connected", "sidecar-disconnected", "watch-start", "watch-stop", "gateway-ready",
		"gateway-down", "gateway-recovered", "gateway-degraded", "gateway.judge_bodies.ready",
		"gateway.judge_bodies.fallback", "gateway.judge_bodies.close_skipped",
		"gateway.judge_bodies.close_error", "gateway.judge_store.drain_timeout", "guardrail-start",
		"guardrail-healthy", "guardrail-degraded", "sink-flush-error",
	)

	for _, action := range []string{"block", "allow", "warn"} {
		registerClassification(result, Classification{
			Kind: ProducerAuditAction, Key: ProducerKey(action),
			EventNamePolicy: EventNameContextRequired, SeverityPolicy: SeverityEvaluation,
			AllowedContextBuckets: []Bucket{
				BucketGuardrailEvaluation, BucketEnforcementAction,
			},
			MandatoryRules: []MandatoryRule{MandatoryEnforcedOutcome},
			CompanionRules: []CompanionRule{CompanionEnforcementWhenEnforced},
		})
	}

	for _, action := range []string{"init", "stop", "ready", "bootstrap"} {
		registerClassification(result, Classification{
			Kind: ProducerAuditAction, Key: ProducerKey(action),
			EventNamePolicy: EventNameContextRequired, SeverityPolicy: SeverityCanonicalOrInfo,
			AllowedContextBuckets: []Bucket{
				BucketComplianceActivity, BucketAgentLifecycle, BucketPlatformHealth,
			},
			MandatoryRules: []MandatoryRule{
				MandatoryControlPlaneMutation, MandatoryDurableHealthTransition,
			},
		})
	}
	registerClassification(result, Classification{
		Kind: ProducerAuditAction, Key: "alert", EventNamePolicy: EventNameContextRequired,
		SeverityPolicy: SeverityFindingRequired,
		AllowedContextBuckets: []Bucket{
			BucketSecurityFinding, BucketGuardrailEvaluation, BucketPlatformHealth,
		},
		MandatoryRules: []MandatoryRule{
			MandatorySchemaValidationFailure, MandatorySQLiteFailure,
			MandatoryExporterInitializationFailure, MandatoryDurableHealthTransition,
		},
	})

	overrideSeverity(result, "gateway-chat-error", SeverityFailureOrSource)
	overrideSeverity(result, "gateway-agent-error", SeverityFailureOrSource)
	overrideSeverity(result, "gateway-session-error", SeverityFailureOrSource)
	overrideSeverity(result, "install-scan-error", SeverityFailureOrSource)
	overrideSeverity(result, "guardrail-tool-call-parse-error", SeverityFailureOrSource)
	for _, action := range []string{
		"webhook-failed", "sink-failure", "gateway-down", "gateway-degraded",
		"gateway.judge_bodies.fallback", "gateway.judge_bodies.close_error",
		"gateway.judge_store.drain_timeout", "guardrail-degraded", "sink-flush-error",
	} {
		overrideSeverity(result, action, SeverityFailureOrSource)
	}
	overrideSeverity(result, "otel.ingest.malformed", SeverityMalformedOrSource)
	overrideSeverity(result, "codex.notify.malformed", SeverityMalformedOrSource)
	return result
}

func fixed(
	key string,
	bucket Bucket,
	event EventName,
	severity SeverityPolicy,
	mandatory []MandatoryRule,
	companions []CompanionRule,
) Classification {
	return Classification{
		Key: ProducerKey(key), Bucket: bucket, DefaultEventName: event,
		EventNamePolicy: EventNameFixed, SeverityPolicy: severity,
		MandatoryRules: mandatory, CompanionRules: companions,
	}
}

func optional(
	key string,
	bucket Bucket,
	event EventName,
	severity SeverityPolicy,
	mandatory []MandatoryRule,
	companions []CompanionRule,
) Classification {
	classification := fixed(key, bucket, event, severity, mandatory, companions)
	classification.EventNamePolicy = EventNameContextOptional
	return classification
}

func contextual(
	key string,
	allowed []Bucket,
	severity SeverityPolicy,
	mandatory []MandatoryRule,
	companions []CompanionRule,
) Classification {
	return Classification{
		Key: ProducerKey(key), EventNamePolicy: EventNameContextRequired,
		SeverityPolicy: severity, MandatoryRules: mandatory, CompanionRules: companions,
		AllowedContextBuckets: allowed,
	}
}

func registerClassification(target map[ProducerKey]Classification, classification Classification) {
	if classification.Key == "" {
		panic("observability classification has empty producer key")
	}
	if _, exists := target[classification.Key]; exists {
		panic(fmt.Sprintf("duplicate observability classification %s/%s", classification.Kind, classification.Key))
	}
	target[classification.Key] = classification
}

func overrideSeverity(
	target map[ProducerKey]Classification,
	action string,
	policy SeverityPolicy,
) {
	key := ProducerKey(action)
	classification, ok := target[key]
	if !ok {
		panic(fmt.Sprintf("cannot override missing audit action classification %q", action))
	}
	classification.SeverityPolicy = policy
	target[key] = classification
}

func legacyAuditEventName(action string) EventName {
	// This creates only a compatibility identity from an already typed action key;
	// bucket choice and floor behavior never depend on parsing this string.
	return EventName("legacy.audit." + strings.ReplaceAll(action, "-", "."))
}
