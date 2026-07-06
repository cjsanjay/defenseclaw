// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// SPDX-License-Identifier: Apache-2.0

package audit

import (
	"reflect"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/observability"
	"github.com/defenseclaw/defenseclaw/internal/observability/router"
	"github.com/defenseclaw/defenseclaw/internal/redaction"
)

func TestAuditPlatformHealthV8ActionsUseExactGeneratedFamiliesOnly(t *testing.T) {
	const canary = "private-path-token-must-not-escape"
	tests := []struct {
		name      string
		action    Action
		logEvent  bool
		connector string
		eventName observability.EventName
		outcome   observability.Outcome
		severity  observability.Severity
		subsystem string
		health    string
		errorCode string
		mandatory bool
	}{
		{name: "sidecar connected", action: ActionSidecarConnected, eventName: "subsystem.ready", outcome: observability.OutcomeCompleted, severity: observability.SeverityInfo, subsystem: "gateway", health: "ready", mandatory: true},
		{name: "sidecar disconnected", action: ActionSidecarDisconnected, eventName: "subsystem.degraded", outcome: observability.OutcomeFailed, severity: observability.SeverityHigh, subsystem: "gateway", health: "degraded", errorCode: "connection_lost", mandatory: true},
		{name: "guardrail healthy", action: ActionGuardrailHealthy, eventName: "subsystem.ready", outcome: observability.OutcomeCompleted, severity: observability.SeverityInfo, subsystem: "guardrail", health: "ready", mandatory: true},
		{name: "guardrail degraded", action: ActionGuardrailDegraded, connector: "codex", eventName: "subsystem.degraded", outcome: observability.OutcomeFailed, severity: observability.SeverityHigh, subsystem: "guardrail", health: "degraded", errorCode: "guardrail_degraded", mandatory: true},
		{name: "judge bodies ready", action: ActionGatewayJudgeBodiesReady, logEvent: true, eventName: "subsystem.ready", outcome: observability.OutcomeCompleted, severity: observability.SeverityInfo, subsystem: "judge_bodies", health: "ready", mandatory: true},
		{name: "judge store drain timeout", action: ActionGatewayJudgeStoreDrainTimeout, logEvent: true, eventName: "subsystem.degraded", outcome: observability.OutcomeFailed, severity: observability.SeverityHigh, subsystem: "judge_store", health: "degraded", errorCode: "drain_timeout"},
		{name: "judge bodies close error", action: ActionGatewayJudgeBodiesCloseError, logEvent: true, eventName: "subsystem.degraded", outcome: observability.OutcomeFailed, severity: observability.SeverityHigh, subsystem: "judge_bodies", health: "degraded", errorCode: "close_failed"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			logger := newTestLogger(t)
			runtime := newSinkHealthTestRuntime(t, logger, router.AdmissionOrdinary)
			legacy := &countingRuntimeOwnedLegacyEmitter{}
			legacySink := installCaptureSink(t, logger)
			logger.SetStructuredEmitter(legacy)
			logger.SetRuntimeV8Emitter(runtime)

			var err error
			switch {
			case test.logEvent:
				err = logger.LogEvent(Event{
					Action: string(test.action), Actor: "defenseclaw-gateway",
					Severity: "ERROR", Details: "error=" + canary,
				})
			case test.connector != "":
				err = logger.LogActionSeverityConnector(
					string(test.action), canary, "details="+canary, "", test.connector,
				)
			default:
				err = logger.LogAction(string(test.action), canary, "details="+canary)
			}
			if err != nil {
				t.Fatal(err)
			}

			logs, metrics := runtime.snapshot()
			if len(logs) != 1 || len(metrics) != 0 {
				t.Fatalf("generated logs/metrics = %d/%d", len(logs), len(metrics))
			}
			record := logs[0]
			severity, present := record.Severity()
			bodyValue, bodyPresent := record.Body()
			body, bodyErr := bodyValue.Object()
			if record.Bucket() != observability.BucketPlatformHealth ||
				record.EventName() != test.eventName || record.Outcome() != test.outcome ||
				record.Mandatory() != test.mandatory || record.IsFloorOnly() || !present || severity != test.severity ||
				record.Connector() != test.connector || !bodyPresent || bodyErr != nil {
				t.Fatalf("generated record = %#v body=%#v err=%v", record, body, bodyErr)
			}
			wantBody := map[string]any{
				"defenseclaw.health.state":     test.health,
				"defenseclaw.health.subsystem": test.subsystem,
			}
			if test.errorCode != "" {
				wantBody["defenseclaw.schema.error_code"] = test.errorCode
			}
			if !reflect.DeepEqual(body, wantBody) {
				t.Fatalf("generated body = %#v, want %#v", body, wantBody)
			}
			encoded, encodeErr := record.Bytes()
			if encodeErr != nil || strings.Contains(string(encoded), canary) {
				t.Fatalf("generated record leaked source details: %s err=%v", encoded, encodeErr)
			}
			if audits, gateways := legacy.counts(); audits != 0 || gateways != 0 || len(legacySink.snapshot()) != 0 {
				t.Fatalf("legacy fanout audits=%d gateways=%d sinks=%d", audits, gateways, len(legacySink.snapshot()))
			}
		})
	}
}

func TestAuditPlatformHealthV8DisabledCollectionUsesSQLiteFloorOnly(t *testing.T) {
	falseValue := false
	plan, err := config.CompileObservabilityV8(&config.ObservabilityV8Source{
		Buckets: map[observability.Bucket]config.ObservabilityV8BucketPolicySource{
			observability.BucketPlatformHealth: {
				Collect: config.ObservabilityV8CollectSource{Logs: &falseValue},
			},
		},
		Destinations: []config.ObservabilityV8DestinationSource{
			{Name: "remote-logs", Kind: config.ObservabilityV8DestinationConsole},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	evaluator, err := router.New(plan)
	if err != nil {
		t.Fatal(err)
	}
	for _, action := range []Action{ActionSidecarConnected, ActionGuardrailDegraded} {
		t.Run(string(action), func(t *testing.T) {
			logger := newTestLogger(t)
			base := newSinkHealthTestRuntime(t, logger, router.AdmissionOrdinary)
			runtime := &evaluatingSinkHealthRuntime{base: base, evaluator: evaluator}
			legacy := &countingRuntimeOwnedLegacyEmitter{}
			logger.SetStructuredEmitter(legacy)
			legacySink := installCaptureSink(t, logger)
			logger.SetRuntimeV8Emitter(runtime)

			if err := logger.LogAction(string(action), "private-target", "private-details"); err != nil {
				t.Fatal(err)
			}
			logs, metrics := base.snapshot()
			if len(logs) != 1 || len(metrics) != 0 || !logs[0].Mandatory() || !logs[0].IsFloorOnly() {
				t.Fatalf("floor logs/metrics = %d/%d record=%#v", len(logs), len(metrics), logs)
			}
			deliveries := runtime.deliverySnapshot()
			if len(deliveries) != 1 || len(deliveries[0]) != 1 ||
				deliveries[0][0].DestinationName != config.ObservabilityV8LocalDestinationName ||
				!deliveries[0][0].MandatoryFloor {
				t.Fatalf("floor deliveries = %#v", deliveries)
			}
			encoded, encodeErr := logs[0].Bytes()
			if encodeErr != nil || strings.Contains(string(encoded), "private-") {
				t.Fatalf("floor leaked content: %s err=%v", encoded, encodeErr)
			}
			if audits, gateways := legacy.counts(); audits != 0 || gateways != 0 || len(legacySink.snapshot()) != 0 {
				t.Fatalf("floor legacy fanout audits=%d gateways=%d sinks=%d", audits, gateways, len(legacySink.snapshot()))
			}
		})
	}
}

func TestAuditPlatformHealthV8DisabledCollectionDropsNonFloorFailures(t *testing.T) {
	falseValue := false
	plan, err := config.CompileObservabilityV8(&config.ObservabilityV8Source{
		Buckets: map[observability.Bucket]config.ObservabilityV8BucketPolicySource{
			observability.BucketPlatformHealth: {
				Collect: config.ObservabilityV8CollectSource{Logs: &falseValue},
			},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	evaluator, err := router.New(plan)
	if err != nil {
		t.Fatal(err)
	}
	for _, action := range []Action{
		ActionGatewayJudgeStoreDrainTimeout,
		ActionGatewayJudgeBodiesCloseError,
	} {
		t.Run(string(action), func(t *testing.T) {
			logger := newTestLogger(t)
			base := newSinkHealthTestRuntime(t, logger, router.AdmissionOrdinary)
			runtime := &evaluatingSinkHealthRuntime{base: base, evaluator: evaluator}
			legacy := &countingRuntimeOwnedLegacyEmitter{}
			legacySink := installCaptureSink(t, logger)
			logger.SetStructuredEmitter(legacy)
			logger.SetRuntimeV8Emitter(runtime)

			if err := logger.LogEvent(Event{
				Action: string(action), Actor: "defenseclaw-gateway",
				Severity: "ERROR", Details: "private-error",
			}); err != nil {
				t.Fatal(err)
			}
			logs, metrics := base.snapshot()
			deliveries := runtime.deliverySnapshot()
			if len(logs) != 0 || len(metrics) != 0 || len(deliveries) != 1 || len(deliveries[0]) != 0 {
				t.Fatalf("disabled non-floor logs=%d metrics=%d deliveries=%#v", len(logs), len(metrics), deliveries)
			}
			if audits, gateways := legacy.counts(); audits != 0 || gateways != 0 || len(legacySink.snapshot()) != 0 {
				t.Fatalf("disabled non-floor resurrected legacy audits=%d gateways=%d sinks=%d", audits, gateways, len(legacySink.snapshot()))
			}
			events, listErr := logger.store.ListEvents(10)
			if listErr != nil || len(events) != 0 {
				t.Fatalf("disabled non-floor persisted legacy rows=%#v err=%v", events, listErr)
			}
		})
	}
}

func TestAuditPlatformHealthV8DetachAndRuntimeFailureNeverResurrectLegacy(t *testing.T) {
	for _, test := range []struct {
		name  string
		setup func(*Logger)
	}{
		{name: "detach", setup: func(logger *Logger) {
			logger.SetRuntimeV8Emitter(newSinkHealthTestRuntime(t, logger, router.AdmissionOrdinary))
			logger.SetRuntimeV8Emitter(nil)
		}},
		{name: "runtime failure", setup: func(logger *Logger) {
			logger.SetRuntimeV8Emitter(&rejectingSinkHealthRuntime{})
		}},
	} {
		t.Run(test.name, func(t *testing.T) {
			logger := newTestLogger(t)
			legacy := &countingRuntimeOwnedLegacyEmitter{}
			legacySink := installCaptureSink(t, logger)
			logger.SetStructuredEmitter(legacy)
			test.setup(logger)
			if err := logger.LogAction(string(ActionSidecarDisconnected), "", "private"); err == nil {
				t.Fatal("authoritative v8 failure unexpectedly succeeded")
			}
			if audits, gateways := legacy.counts(); audits != 0 || gateways != 0 || len(legacySink.snapshot()) != 0 {
				t.Fatalf("legacy resurrected audits=%d gateways=%d sinks=%d", audits, gateways, len(legacySink.snapshot()))
			}
			events, err := logger.store.ListEvents(10)
			if err != nil || len(events) != 0 {
				t.Fatalf("legacy SQLite resurrected: %#v err=%v", events, err)
			}
		})
	}
}

func TestAuditPlatformHealthV7MappedActionPreservesLegacyFanout(t *testing.T) {
	logger := newTestLogger(t)
	legacy := &sinkLegacyCapture{}
	legacySink := installCaptureSink(t, logger)
	logger.SetStructuredEmitter(legacy)
	if err := logger.LogAction(string(ActionSidecarDisconnected), "gateway", "connection lost"); err != nil {
		t.Fatal(err)
	}
	events, err := logger.store.ListEvents(10)
	audits, gateways := legacy.snapshot()
	if err != nil || len(events) != 1 || len(audits) != 1 || len(gateways) != 0 || len(legacySink.snapshot()) != 1 {
		t.Fatalf("v7 fanout events=%d audits=%d gateways=%d sinks=%d err=%v",
			len(events), len(audits), len(gateways), len(legacySink.snapshot()), err)
	}
	if events[0].Action != string(ActionSidecarDisconnected) || events[0].Target != "gateway" ||
		events[0].Details != redaction.ForSinkString("connection lost") ||
		audits[0].Action != events[0].Action || audits[0].Details != events[0].Details {
		t.Fatalf("v7 event changed: row=%#v audit=%#v", events[0], audits[0])
	}
}

func TestAuditPlatformHealthV7MappedLogEventPreservesLegacyFanout(t *testing.T) {
	logger := newTestLogger(t)
	legacy := &sinkLegacyCapture{}
	legacySink := installCaptureSink(t, logger)
	logger.SetStructuredEmitter(legacy)
	input := Event{
		Action: string(ActionGatewayJudgeBodiesCloseError), Actor: "defenseclaw-gateway",
		Severity: "ERROR", Details: "close failed",
	}
	if err := logger.LogEvent(input); err != nil {
		t.Fatal(err)
	}
	events, err := logger.store.ListEvents(10)
	audits, gateways := legacy.snapshot()
	if err != nil || len(events) != 1 || len(audits) != 1 || len(gateways) != 0 || len(legacySink.snapshot()) != 1 {
		t.Fatalf("v7 fanout events=%d audits=%d gateways=%d sinks=%d err=%v",
			len(events), len(audits), len(gateways), len(legacySink.snapshot()), err)
	}
	if events[0].Action != input.Action || events[0].Actor != input.Actor ||
		events[0].Severity != input.Severity || events[0].Details != redaction.ForSinkString(input.Details) ||
		audits[0].Action != events[0].Action || audits[0].Details != events[0].Details {
		t.Fatalf("v7 LogEvent changed: row=%#v audit=%#v", events[0], audits[0])
	}
}

func TestAuditPlatformHealthV8MappingIsClosedAndTruthful(t *testing.T) {
	mapped := []Action{
		ActionSidecarConnected, ActionSidecarDisconnected,
		ActionGuardrailHealthy, ActionGuardrailDegraded,
		ActionGatewayJudgeBodiesReady, ActionGatewayJudgeStoreDrainTimeout,
		ActionGatewayJudgeBodiesCloseError,
	}
	for _, action := range mapped {
		if _, ok := auditPlatformHealthV8Occurrence(Event{Action: string(action)}); !ok {
			t.Errorf("live health action %q is not mapped", action)
		}
	}
	for _, action := range []Action{
		ActionGuardrailStart, ActionWatchStart, ActionWatchStop,
		ActionGatewayJudgeBodiesFallback, ActionGatewayJudgeBodiesCloseSkipped,
		ActionGatewayReady, ActionGatewayDown, ActionGatewayRecovered, ActionGatewayDegraded,
		ActionWebhookDelivered, ActionWebhookFailed, ActionSinkFlushError,
	} {
		if occurrence, ok := auditPlatformHealthV8Occurrence(Event{Action: string(action)}); ok {
			t.Errorf("non-live or non-representable action %q fabricated occurrence %#v", action, occurrence)
		}
	}

	// Keep the review inventory closed over the generated default
	// classifications. A newly classified platform-health audit action must be
	// consciously mapped here, delegated to the sink-health cutover, or retained
	// as an explicitly unrepresentable/non-live compatibility action above.
	reviewed := map[Action]struct{}{
		ActionWebhookDelivered: {}, ActionWebhookFailed: {},
		ActionSinkFailure: {}, ActionSinkRestored: {}, ActionSinkFlushError: {},
		ActionSidecarConnected: {}, ActionSidecarDisconnected: {},
		ActionWatchStart: {}, ActionWatchStop: {},
		ActionGatewayReady: {}, ActionGatewayDown: {}, ActionGatewayRecovered: {}, ActionGatewayDegraded: {},
		ActionGatewayJudgeBodiesReady: {}, ActionGatewayJudgeBodiesFallback: {},
		ActionGatewayJudgeBodiesCloseSkipped: {}, ActionGatewayJudgeBodiesCloseError: {},
		ActionGatewayJudgeStoreDrainTimeout: {},
		ActionGuardrailStart:                {}, ActionGuardrailHealthy: {}, ActionGuardrailDegraded: {},
	}
	for _, key := range observability.ClassificationKeys(observability.ProducerAuditAction) {
		classification, ok := observability.AuditActionClassification(key)
		if !ok || classification.Bucket != observability.BucketPlatformHealth {
			continue
		}
		action := Action(key)
		if _, ok := reviewed[action]; !ok {
			t.Errorf("unreviewed platform-health audit action %q", action)
			continue
		}
		delete(reviewed, action)
	}
	for action := range reviewed {
		t.Errorf("review inventory action %q is no longer classified platform.health", action)
	}
}

func TestAuditPlatformHealthV8ConcurrentDetachDoesNotRaceOrFallback(t *testing.T) {
	logger := newTestLogger(t)
	legacy := &countingRuntimeOwnedLegacyEmitter{}
	logger.SetStructuredEmitter(legacy)
	runtime := newSinkHealthTestRuntime(t, logger, router.AdmissionOrdinary)
	logger.SetRuntimeV8Emitter(runtime)

	done := make(chan struct{})
	go func() {
		defer close(done)
		for i := 0; i < 50; i++ {
			logger.SetRuntimeV8Emitter(runtime)
			logger.SetRuntimeV8Emitter(nil)
		}
	}()
	for i := 0; i < 50; i++ {
		_ = logger.LogAction(string(ActionGuardrailHealthy), "", "private")
	}
	<-done
	if audits, gateways := legacy.counts(); audits != 0 || gateways != 0 {
		t.Fatalf("concurrent detach resurrected legacy audits=%d gateways=%d", audits, gateways)
	}
}
