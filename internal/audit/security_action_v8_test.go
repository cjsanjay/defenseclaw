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

package audit

import (
	"context"
	"fmt"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/observability"
	"github.com/defenseclaw/defenseclaw/internal/observability/router"
)

func TestApprovalResolutionGeneratedMappingsPersistExactlyOnce(t *testing.T) {
	for _, test := range []struct {
		name    string
		action  Action
		result  string
		outcome observability.Outcome
	}{
		{name: "gateway grant", action: ActionGatewayApprovalGranted, result: "approved", outcome: observability.OutcomeApproved},
		{name: "gateway denial", action: ActionGatewayApprovalDenied, result: "denied", outcome: observability.OutcomeDenied},
		{name: "generic grant", action: ActionApprovalGranted, result: "approved", outcome: observability.OutcomeApproved},
		{name: "generic denial", action: ActionApprovalDenied, result: "denied", outcome: observability.OutcomeDenied},
	} {
		test := test
		t.Run(test.name, func(t *testing.T) {
			logger := newTestLogger(t)
			runtime := newTestRuntimeV8Emitter(t, logger.store, router.AdmissionOrdinary)
			legacy := &captureEmitter{}
			logger.SetRuntimeV8Emitter(runtime)
			logger.SetStructuredEmitter(legacy)
			env := securityActionTestEnvelope()
			if err := logger.LogActionCtx(
				ContextWithEnvelope(context.Background(), env), string(test.action),
				"approval-42", "reason=resolved",
			); err != nil {
				t.Fatalf("LogActionCtx: %v", err)
			}
			rows, err := logger.store.ListEvents(10)
			if err != nil || len(rows) != 1 {
				t.Fatalf("audit rows = %d err=%v, want exactly 1", len(rows), err)
			}
			if got := len(legacy.snapshot()); got != 0 {
				t.Fatalf("legacy structured emissions = %d, want 0", got)
			}
			metadata, records := runtime.snapshot()
			if len(metadata) != 1 || len(records) != 1 {
				t.Fatalf("runtime counts = metadata:%d records:%d", len(metadata), len(records))
			}
			record := records[0]
			assertSecurityActionIdentity(t, record, rows[0], observability.BucketComplianceActivity,
				observability.EventName(observability.TelemetryEventApprovalResolved), test.outcome, true)
			if metadata[0].Source() != observability.SourceGateway || metadata[0].Identity() != record.Identity() {
				t.Fatalf("approval routing metadata = source:%q identity:%#v", metadata[0].Source(), metadata[0].Identity())
			}
			body := securityActionBody(t, record)
			if body["defenseclaw.approval.id"] != "approval-42" ||
				body["defenseclaw.approval.result"] != test.result {
				t.Fatalf("approval body = %#v", body)
			}
			severity, present := record.Severity()
			if !present || severity != observability.SeverityInfo {
				t.Fatalf("approval severity = (%q,%t), want INFO", severity, present)
			}
			assertControlPlaneCorrelation(t, record.Correlation(), env)
		})
	}
}

func TestJudgeCompletionGeneratedMappingsPersistExactlyOnce(t *testing.T) {
	for _, test := range []struct {
		name       string
		action     string
		severity   string
		parseError string
		outcome    observability.Outcome
		want       observability.Severity
	}{
		{name: "clean allow", action: "allow", severity: "NONE", outcome: observability.OutcomeAllowed, want: observability.SeverityInfo},
		{name: "fail-closed block", action: "block", severity: "HIGH", parseError: "invalid judge JSON", outcome: observability.OutcomeBlocked, want: observability.SeverityHigh},
	} {
		test := test
		t.Run(test.name, func(t *testing.T) {
			logger := newTestLogger(t)
			runtime := newTestRuntimeV8Emitter(t, logger.store, router.AdmissionOrdinary)
			legacy := &captureEmitter{}
			logger.SetRuntimeV8Emitter(runtime)
			logger.SetStructuredEmitter(legacy)
			env := securityActionTestEnvelope()
			event := Event{
				Action: string(ActionLLMJudgeResponse), Target: "judge-model", Actor: "defenseclaw-gateway",
				Details: "legacy judge summary", Severity: test.severity, ToolID: "tool-invocation-9",
			}
			if err := logger.LogJudgeCompletion(ContextWithEnvelope(context.Background(), env), event, JudgeCompletionInput{
				Kind: "injection", Action: test.action, LatencyMS: 17, InputBytes: 2048,
				ParseError: test.parseError,
			}); err != nil {
				t.Fatalf("LogJudgeCompletion: %v", err)
			}
			rows, err := logger.store.ListEvents(10)
			if err != nil || len(rows) != 1 {
				t.Fatalf("audit rows = %d err=%v, want exactly 1", len(rows), err)
			}
			if len(legacy.snapshot()) != 0 {
				t.Fatal("runtime-owned judge event reached legacy structured emitter")
			}
			metadata, records := runtime.snapshot()
			if len(metadata) != 1 || len(records) != 1 {
				t.Fatalf("runtime counts = metadata:%d records:%d", len(metadata), len(records))
			}
			record := records[0]
			assertSecurityActionIdentity(t, record, rows[0], observability.BucketGuardrailEvaluation,
				observability.EventName(observability.TelemetryEventGuardrailJudgeCompleted), test.outcome, false)
			severity, present := record.Severity()
			if !present || severity != test.want {
				t.Fatalf("judge severity = (%q,%t), want %q", severity, present, test.want)
			}
			body := securityActionBody(t, record)
			if body["defenseclaw.judge.kind"] != "injection" || body["defenseclaw.judge.action"] != test.action ||
				fmt.Sprint(body["defenseclaw.judge.latency_ms"]) != "17" ||
				fmt.Sprint(body["defenseclaw.judge.input_bytes"]) != "2048" {
				t.Fatalf("judge body = %#v", body)
			}
			if test.parseError == "" {
				if _, present := body["defenseclaw.judge.parse_error"]; present {
					t.Fatalf("clean judge emitted parse_error: %#v", body)
				}
			} else if body["defenseclaw.judge.parse_error"] != test.parseError {
				t.Fatalf("judge parse_error = %#v", body["defenseclaw.judge.parse_error"])
			}
			correlation := record.Correlation()
			assertControlPlaneCorrelation(t, correlation, env)
			if correlation.ToolInvocationID != "tool-invocation-9" {
				t.Fatalf("tool invocation correlation = %q", correlation.ToolInvocationID)
			}
			if metadata[0].Source() != observability.SourceGuardrail {
				t.Fatalf("judge routing source = %q", metadata[0].Source())
			}
		})
	}
}

func TestJudgeCompletionCollectionDropDoesNotResurrectLegacySignal(t *testing.T) {
	logger := newTestLogger(t)
	runtime := newTestRuntimeV8Emitter(t, logger.store, router.AdmissionDrop)
	legacy := &captureEmitter{}
	logger.SetRuntimeV8Emitter(runtime)
	logger.SetStructuredEmitter(legacy)
	if err := logger.LogJudgeCompletion(context.Background(), Event{
		Action: string(ActionLLMJudgeResponse), Severity: "LOW", Details: "must drop",
	}, JudgeCompletionInput{Kind: "pii", Action: "allow", LatencyMS: 1, InputBytes: 4}); err != nil {
		t.Fatalf("LogJudgeCompletion drop: %v", err)
	}
	rows, err := logger.store.ListEvents(10)
	metadata, records := runtime.snapshot()
	if err != nil || len(rows) != 0 || len(metadata) != 1 || len(records) != 0 || len(legacy.snapshot()) != 0 {
		t.Fatalf("drop counts = rows:%d metadata:%d records:%d legacy:%d err=%v",
			len(rows), len(metadata), len(records), len(legacy.snapshot()), err)
	}
}

func TestEnforcementQuarantineGeneratedMappingPersistsExactlyOnce(t *testing.T) {
	logger := newTestLogger(t)
	runtime := newTestRuntimeV8Emitter(t, logger.store, router.AdmissionOrdinary)
	legacy := &captureEmitter{}
	logger.SetRuntimeV8Emitter(runtime)
	logger.SetStructuredEmitter(legacy)
	env := securityActionTestEnvelope()
	event := Event{
		Action: string(ActionQuarantine), Target: "/skills/risky", Actor: "defenseclaw",
		Details: "dest=/quarantine/risky", Severity: "HIGH",
	}
	input := EnforcementQuarantineAppliedInput{
		EnforcementID: "enforcement-77", RequestedAction: "quarantine",
		EffectiveAction: "quarantine", Initiator: "defenseclaw", ResultingState: "quarantined",
	}
	if err := logger.LogEnforcementQuarantineApplied(
		ContextWithEnvelope(context.Background(), env), event, input,
	); err != nil {
		t.Fatalf("LogEnforcementQuarantineApplied: %v", err)
	}
	rows, err := logger.store.ListEvents(10)
	if err != nil || len(rows) != 1 {
		t.Fatalf("audit rows = %d err=%v, want exactly 1", len(rows), err)
	}
	if len(legacy.snapshot()) != 0 {
		t.Fatal("runtime-owned enforcement event reached legacy structured emitter")
	}
	metadata, records := runtime.snapshot()
	if len(metadata) != 1 || len(records) != 1 {
		t.Fatalf("runtime counts = metadata:%d records:%d", len(metadata), len(records))
	}
	record := records[0]
	assertSecurityActionIdentity(t, record, rows[0], observability.BucketEnforcementAction,
		observability.EventName(observability.TelemetryEventEnforcementQuarantineApplied),
		observability.OutcomeQuarantined, true)
	body := securityActionBody(t, record)
	for key, want := range map[string]any{
		"defenseclaw.enforcement.id":               "enforcement-77",
		"defenseclaw.enforcement.requested_action": "quarantine",
		"defenseclaw.enforcement.effective_action": "quarantine",
		"defenseclaw.enforcement.initiator":        "defenseclaw",
		"defenseclaw.enforcement.resulting_state":  "quarantined",
	} {
		if body[key] != want {
			t.Errorf("enforcement body[%q] = %#v, want %#v", key, body[key], want)
		}
	}
	if record.Correlation().EnforcementActionID != "enforcement-77" {
		t.Fatalf("enforcement correlation = %#v", record.Correlation())
	}
	severity, present := record.Severity()
	if !present || severity != observability.SeverityHigh {
		t.Fatalf("enforcement severity = (%q,%t)", severity, present)
	}
	if metadata[0].Source() != observability.SourceWatcher {
		t.Fatalf("enforcement routing source = %q", metadata[0].Source())
	}
}

func TestApprovalAndEnforcementMandatoryFloorsRemainContentFree(t *testing.T) {
	const canary = "security-floor-secret-91ac"
	t.Run("approval", func(t *testing.T) {
		logger := newTestLogger(t)
		runtime := newTestRuntimeV8Emitter(t, logger.store, router.AdmissionFloor)
		legacy := &captureEmitter{}
		logger.SetRuntimeV8Emitter(runtime)
		logger.SetStructuredEmitter(legacy)
		if err := logger.LogAction(
			string(ActionGatewayApprovalDenied), "approval-"+canary, "reason="+canary,
		); err != nil {
			t.Fatalf("approval floor: %v", err)
		}
		rows, err := logger.store.ListEvents(10)
		_, records := runtime.snapshot()
		if err != nil || len(rows) != 1 || len(records) != 1 || !records[0].IsFloorOnly() ||
			records[0].EventName() != observability.EventName(observability.TelemetryEventApprovalResolved) ||
			records[0].Outcome() != observability.OutcomeDenied || len(legacy.snapshot()) != 0 {
			t.Fatalf("approval floor = rows:%d records:%d err=%v", len(rows), len(records), err)
		}
		assertAuditEventRowExcludesCanary(t, logger.store, rows[0].ID, canary)
	})
	t.Run("enforcement", func(t *testing.T) {
		logger := newTestLogger(t)
		runtime := newTestRuntimeV8Emitter(t, logger.store, router.AdmissionFloor)
		legacy := &captureEmitter{}
		logger.SetRuntimeV8Emitter(runtime)
		logger.SetStructuredEmitter(legacy)
		if err := logger.LogEnforcementQuarantineApplied(context.Background(), Event{
			Action: string(ActionQuarantine), Target: "target-" + canary,
			Actor: "defenseclaw", Details: "details-" + canary, Severity: "HIGH",
			Structured: map[string]any{"secret": canary},
		}, EnforcementQuarantineAppliedInput{
			EnforcementID: "enforcement-floor-1", EffectiveAction: "quarantine",
		}); err != nil {
			t.Fatalf("enforcement floor: %v", err)
		}
		rows, err := logger.store.ListEvents(10)
		_, records := runtime.snapshot()
		if err != nil || len(rows) != 1 || len(records) != 1 || !records[0].IsFloorOnly() ||
			records[0].EventName() != observability.EventName(observability.TelemetryEventEnforcementQuarantineApplied) ||
			records[0].Outcome() != observability.OutcomeQuarantined || len(legacy.snapshot()) != 0 {
			t.Fatalf("enforcement floor = rows:%d records:%d err=%v", len(rows), len(records), err)
		}
		assertAuditEventRowExcludesCanary(t, logger.store, rows[0].ID, canary)
	})
}

func TestTypedSecurityActionsPreserveUnboundV7PersistenceAndFanout(t *testing.T) {
	for _, test := range []struct {
		name string
		log  func(*Logger) error
	}{
		{name: "judge", log: func(logger *Logger) error {
			return logger.LogJudgeCompletion(context.Background(), Event{
				Action: string(ActionLLMJudgeResponse), Target: "judge-model", Actor: "gateway",
				Details: "legacy judge", Severity: "HIGH",
			}, JudgeCompletionInput{Kind: "", Action: "", LatencyMS: -1, InputBytes: -1})
		}},
		{name: "enforcement", log: func(logger *Logger) error {
			return logger.LogEnforcementQuarantineApplied(context.Background(), Event{
				Action: string(ActionQuarantine), Target: "/skill", Actor: "watcher",
				Details: "legacy quarantine", Severity: "INFO",
			}, EnforcementQuarantineAppliedInput{})
		}},
	} {
		test := test
		t.Run(test.name, func(t *testing.T) {
			logger := newTestLogger(t)
			legacy := &captureEmitter{}
			logger.SetStructuredEmitter(legacy)
			legacySink := installCaptureSink(t, logger)
			if err := test.log(logger); err != nil {
				t.Fatalf("unbound v7 log: %v", err)
			}
			rows, err := logger.store.ListEvents(10)
			if err != nil || len(rows) != 1 || len(legacy.snapshot()) != 1 || len(legacySink.snapshot()) != 1 {
				t.Fatalf("unbound v7 counts = rows:%d structured:%d sinks:%d err=%v",
					len(rows), len(legacy.snapshot()), len(legacySink.snapshot()), err)
			}
			canonical := loadV8HistoryRow(t, logger.store, rows[0].ID)
			if canonical.Bucket != "" || canonical.ProjectedRecordJSON != "" {
				t.Fatalf("unbound v7 row fabricated as canonical: %#v", canonical)
			}
		})
	}
}

func TestTypedSecurityActionsFailClosedWhenRequiredV8FactsAreMissing(t *testing.T) {
	for _, test := range []struct {
		name string
		log  func(*Logger) error
	}{
		{name: "judge terminal action", log: func(logger *Logger) error {
			return logger.LogJudgeCompletion(context.Background(), Event{
				Action: string(ActionLLMJudgeResponse), Severity: "HIGH",
			}, JudgeCompletionInput{Kind: "injection", Action: "review"})
		}},
		{name: "enforcement id", log: func(logger *Logger) error {
			return logger.LogEnforcementQuarantineApplied(context.Background(), Event{
				Action: string(ActionQuarantine), Severity: "HIGH",
			}, EnforcementQuarantineAppliedInput{EffectiveAction: "quarantine"})
		}},
	} {
		test := test
		t.Run(test.name, func(t *testing.T) {
			logger := newTestLogger(t)
			runtime := newTestRuntimeV8Emitter(t, logger.store, router.AdmissionOrdinary)
			legacy := &captureEmitter{}
			logger.SetRuntimeV8Emitter(runtime)
			logger.SetStructuredEmitter(legacy)
			if err := test.log(logger); err == nil {
				t.Fatal("missing required canonical fact did not fail closed")
			}
			rows, err := logger.store.ListEvents(10)
			metadata, records := runtime.snapshot()
			if err != nil || len(rows) != 0 || len(metadata) != 0 || len(records) != 0 || len(legacy.snapshot()) != 0 {
				t.Fatalf("fail-closed counts = rows:%d metadata:%d records:%d legacy:%d err=%v",
					len(rows), len(metadata), len(records), len(legacy.snapshot()), err)
			}
		})
	}
}

func TestRuntimeV8OutcomeConsistencyFailsClosed(t *testing.T) {
	for _, outcome := range []RuntimeV8EmitOutcome{
		{Admission: router.AdmissionDrop, LocalPersisted: true},
		{Admission: router.AdmissionOrdinary, LocalPersisted: false},
		{Admission: router.AdmissionFloor, LocalPersisted: false},
		{Admission: router.Admission(255), LocalPersisted: true},
	} {
		if _, err := runtimeV8Disposition(outcome, false); err == nil {
			t.Fatalf("inconsistent runtime outcome accepted: %#v", outcome)
		}
	}
}

func securityActionTestEnvelope() CorrelationEnvelope {
	return CorrelationEnvelope{
		RunID: "run-security", TraceID: "trace-security", RequestID: "request-security",
		SessionID: "session-security", TurnID: "turn-security", AgentID: "agent-security",
		AgentName: "agent-name", AgentInstanceID: "agent-instance-security",
		SidecarInstanceID: "sidecar-security", PolicyID: "policy-security", Connector: "codex",
	}
}

func assertSecurityActionIdentity(
	t *testing.T,
	record observability.Record,
	legacy Event,
	bucket observability.Bucket,
	eventName observability.EventName,
	outcome observability.Outcome,
	mandatory bool,
) {
	t.Helper()
	if record.RecordID() != legacy.ID || record.Bucket() != bucket || record.EventName() != eventName ||
		record.Signal() != observability.SignalLogs || record.Outcome() != outcome ||
		record.Mandatory() != mandatory || record.IsFloorOnly() || !record.SchemaDerivedFieldClasses() {
		t.Fatalf("record identity = id:%q identity:%#v outcome:%q mandatory:%t floor:%t schema-derived:%t legacy:%#v",
			record.RecordID(), record.Identity(), record.Outcome(), record.Mandatory(), record.IsFloorOnly(),
			record.SchemaDerivedFieldClasses(), legacy)
	}
	if legacy.Action != record.Action() || legacy.Target == "" || legacy.Actor == "" || legacy.Details == "" {
		t.Fatalf("legacy compatibility changed: %#v", legacy)
	}
}

func securityActionBody(t *testing.T, record observability.Record) map[string]any {
	t.Helper()
	body, ok := record.Body()
	if !ok {
		t.Fatal("record body is absent")
	}
	object, err := body.Object()
	if err != nil {
		t.Fatalf("record body: %v", err)
	}
	return object
}
