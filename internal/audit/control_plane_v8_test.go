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
	"encoding/json"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/observability"
	observabilityredaction "github.com/defenseclaw/defenseclaw/internal/observability/redaction"
	"github.com/defenseclaw/defenseclaw/internal/observability/router"
)

type testControlPlaneV8Emitter struct {
	writer    *EventHistoryWriter
	admission router.Admission
	profile   observabilityredaction.Profile

	mu       sync.Mutex
	metadata []router.Metadata
	records  []observability.Record
}

type rejectingControlPlaneV8Emitter struct {
	localPersisted bool
	err            error
	calls          int
}

func (emitter *rejectingControlPlaneV8Emitter) EmitControlPlaneV8(
	_ context.Context,
	_ router.Metadata,
	_ ControlPlaneV8Builder,
) (bool, error) {
	emitter.calls++
	return emitter.localPersisted, emitter.err
}

func newTestControlPlaneV8Emitter(
	t *testing.T,
	store *Store,
	admission router.Admission,
) *testControlPlaneV8Emitter {
	t.Helper()
	profile, ok := observabilityredaction.BuiltInProfile(observabilityredaction.ProfileNone)
	if !ok {
		t.Fatal("none redaction profile is unavailable")
	}
	writer, err := NewEventHistoryWriter(
		store, nil, nil,
		testLocalProfileResolver{
			profile: observabilityredaction.ProfileNone,
			engine:  testEventHistoryProjectionEngine,
			digest:  testEventHistoryGraphDigest,
		},
	)
	if err != nil {
		t.Fatalf("NewEventHistoryWriter: %v", err)
	}
	return &testControlPlaneV8Emitter{writer: writer, admission: admission, profile: profile}
}

func (emitter *testControlPlaneV8Emitter) EmitControlPlaneV8(
	ctx context.Context,
	metadata router.Metadata,
	builder ControlPlaneV8Builder,
) (bool, error) {
	if emitter == nil || emitter.writer == nil || builder == nil {
		return false, fmt.Errorf("test control-plane emitter is unavailable")
	}
	record, err := builder(ControlPlaneV8BuildContext{
		ConfigGeneration: 23,
		ConfigDigest:     testEventHistoryGraphDigest,
	}, emitter.admission)
	if err != nil {
		return false, err
	}
	projection, _, err := testEventHistoryProjectionEngine.Project(record, emitter.profile)
	if err != nil {
		return false, err
	}
	if err := emitter.writer.AppendContext(ctx, record, projection); err != nil {
		return false, err
	}
	emitter.mu.Lock()
	emitter.metadata = append(emitter.metadata, metadata)
	emitter.records = append(emitter.records, record.Clone())
	emitter.mu.Unlock()
	return true, nil
}

func (emitter *testControlPlaneV8Emitter) snapshot() ([]router.Metadata, []observability.Record) {
	emitter.mu.Lock()
	defer emitter.mu.Unlock()
	metadata := append([]router.Metadata(nil), emitter.metadata...)
	records := make([]observability.Record, len(emitter.records))
	for index := range emitter.records {
		records[index] = emitter.records[index].Clone()
	}
	return metadata, records
}

func TestLogActionControlPlaneV8GeneratedFamiliesPersistOnceAndPreserveV7(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name      string
		action    Action
		eventName observability.EventName
		outcome   observability.Outcome
	}{
		{name: "config manager apply", action: ActionConfigUpdate, eventName: observability.EventName(observability.TelemetryEventConfigChangeApplied), outcome: observability.OutcomeApplied},
		{name: "REST config patch", action: ActionAPIConfigPatch, eventName: observability.EventName(observability.TelemetryEventConfigChangeApplied), outcome: observability.OutcomeApplied},
		{name: "guardrail config reload", action: ActionGuardrailConfigReload, eventName: observability.EventName(observability.TelemetryEventConfigChangeApplied), outcome: observability.OutcomeApplied},
		{name: "policy update", action: ActionPolicyUpdate, eventName: observability.EventName(observability.TelemetryEventPolicyUpdated), outcome: observability.OutcomeApplied},
		{name: "policy reload", action: ActionPolicyReload, eventName: observability.EventName(observability.TelemetryEventPolicyUpdated), outcome: observability.OutcomeApplied},
		{name: "protected boundary auth failure", action: ActionAPIAuthFailure, eventName: observability.EventName(observability.TelemetryEventAuthenticationFailed), outcome: observability.OutcomeRejected},
	}
	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			logger := newTestLogger(t)
			runtime := newTestControlPlaneV8Emitter(t, logger.store, router.AdmissionOrdinary)
			logger.SetControlPlaneV8Emitter(runtime)
			structured := &captureEmitter{}
			logger.SetStructuredEmitter(structured)
			env := CorrelationEnvelope{
				RunID: "run-control-plane", TraceID: "trace-control-plane",
				RequestID: "request-control-plane", SessionID: "session-control-plane",
				TurnID: "turn-control-plane", AgentID: "agent-control-plane",
				AgentName: "operator-agent", AgentInstanceID: "agent-instance-control-plane",
				SidecarInstanceID: "sidecar-control-plane", PolicyID: "policy-control-plane",
				Connector: "codex",
			}
			ctx := ContextWithEnvelope(context.Background(), env)
			if err := logger.LogActionCtx(ctx, string(test.action), "control-plane-target", "successful mutation"); err != nil {
				t.Fatalf("LogActionCtx: %v", err)
			}

			rows, err := logger.store.ListEvents(10)
			if err != nil {
				t.Fatalf("ListEvents: %v", err)
			}
			if len(rows) != 1 {
				t.Fatalf("audit_events count = %d, want exactly 1", len(rows))
			}
			if got := len(structured.snapshot()); got != 1 {
				t.Fatalf("legacy structured emissions = %d, want exactly 1", got)
			}
			metadata, records := runtime.snapshot()
			if len(metadata) != 1 || len(records) != 1 {
				t.Fatalf("runtime counts = metadata:%d records:%d, want 1/1", len(metadata), len(records))
			}

			legacy := rows[0]
			if legacy.Action != string(test.action) || legacy.Target != "control-plane-target" ||
				legacy.Actor != "defenseclaw" || legacy.Details == "" {
				t.Fatalf("legacy view changed: %#v", legacy)
			}
			if legacy.RunID != env.RunID || legacy.TraceID != env.TraceID || legacy.RequestID != env.RequestID ||
				legacy.SessionID != env.SessionID || legacy.AgentName != env.AgentName ||
				legacy.AgentID != env.AgentID || legacy.AgentInstanceID != env.AgentInstanceID ||
				legacy.PolicyID != env.PolicyID || legacy.Connector != env.Connector ||
				legacy.SidecarInstanceID != env.SidecarInstanceID {
				t.Fatalf("legacy correlation changed: %#v", legacy)
			}

			record := records[0]
			if record.RecordID() != legacy.ID || record.EventName() != test.eventName ||
				record.Bucket() != observability.BucketComplianceActivity ||
				record.Signal() != observability.SignalLogs || record.Outcome() != test.outcome ||
				!record.Mandatory() || record.IsFloorOnly() || !record.SchemaDerivedFieldClasses() {
				t.Fatalf("generated record contract = id:%q identity:%#v outcome:%q mandatory:%t floor:%t schema-derived:%t",
					record.RecordID(), record.Identity(), record.Outcome(), record.Mandatory(),
					record.IsFloorOnly(), record.SchemaDerivedFieldClasses())
			}
			if record.Provenance().ConfigDigest != testEventHistoryGraphDigest ||
				record.Provenance().ConfigGeneration != 23 {
				t.Fatalf("record provenance = %#v", record.Provenance())
			}
			if metadata[0].Identity() != record.Identity() || metadata[0].Source() != observability.SourceOperatorAPI {
				t.Fatalf("routing metadata = identity:%#v source:%q", metadata[0].Identity(), metadata[0].Source())
			}
			assertControlPlaneCorrelation(t, record.Correlation(), env)
			body, ok := record.Body()
			if !ok {
				t.Fatal("generated record body is absent")
			}
			bodyObject, err := body.Object()
			if err != nil || bodyObject["defenseclaw.admin.operation"] != string(test.action) {
				t.Fatalf("generated body = %#v err=%v", bodyObject, err)
			}
			if bodyObject["defenseclaw.admin.principal_ref"] != "defenseclaw" {
				t.Fatalf("generated principal_ref = %#v, want defenseclaw", bodyObject["defenseclaw.admin.principal_ref"])
			}

			canonical := loadV8HistoryRow(t, logger.store, legacy.ID)
			if canonical.Bucket != string(observability.BucketComplianceActivity) ||
				canonical.EventName != string(test.eventName) || canonical.Mandatory != 1 ||
				canonical.ID != legacy.ID || canonical.Action != legacy.Action ||
				canonical.Target != legacy.Target || canonical.Actor != legacy.Actor ||
				canonical.Details != legacy.Details {
				t.Fatalf("single-row canonical/legacy projection = %#v", canonical)
			}
			var projected map[string]any
			if err := json.Unmarshal([]byte(canonical.ProjectedRecordJSON), &projected); err != nil {
				t.Fatalf("decode projected record: %v", err)
			}
			provenance, ok := projected["provenance"].(map[string]any)
			if !ok || provenance["config_digest"] != testEventHistoryGraphDigest {
				t.Fatalf("persisted canonical provenance = %#v", provenance)
			}
		})
	}
}

func TestLogActionControlPlaneV8MandatoryFloorPersistsExactlyOnce(t *testing.T) {
	t.Parallel()
	logger := newTestLogger(t)
	runtime := newTestControlPlaneV8Emitter(t, logger.store, router.AdmissionFloor)
	logger.SetControlPlaneV8Emitter(runtime)
	const canary = "floor-secret-canary-7f421c"
	event := Event{
		ID: "floor-control-plane-record", Timestamp: time.Now().UTC(),
		Action: string(ActionConfigUpdate), Target: "target-" + canary,
		Actor: "defenseclaw", Details: "details-" + canary, Severity: "INFO",
		RunID: "run-floor", Structured: map[string]any{"secret": canary},
	}
	stampAuditEventEnvelope(&event)
	handled, err := logger.emitControlPlaneV8(context.Background(), event)
	if err != nil {
		t.Fatalf("emitControlPlaneV8: %v", err)
	}
	if !handled {
		t.Fatal("mandatory floor event was not handled by v8 runtime")
	}
	rows, err := logger.store.ListEvents(10)
	if err != nil || len(rows) != 1 {
		t.Fatalf("floor audit rows = %d err=%v, want exactly 1", len(rows), err)
	}
	metadata, records := runtime.snapshot()
	if len(metadata) != 1 || len(records) != 1 || !records[0].Mandatory() || !records[0].IsFloorOnly() {
		t.Fatalf("floor runtime result = metadata:%d records:%d mandatory:%t floor:%t",
			len(metadata), len(records), records[0].Mandatory(), records[0].IsFloorOnly())
	}
	canonical := loadV8HistoryRow(t, logger.store, rows[0].ID)
	if canonical.Mandatory != 1 || canonical.EventName != observability.TelemetryEventConfigChangeApplied {
		t.Fatalf("floor canonical row = %#v", canonical)
	}
	assertAuditEventRowExcludesCanary(t, logger.store, rows[0].ID, canary)
}

func TestLogActivityControlPlaneV8PersistsOneActivityAndOneCanonicalAuditRow(t *testing.T) {
	t.Parallel()
	logger := newTestLogger(t)
	runtime := newTestControlPlaneV8Emitter(t, logger.store, router.AdmissionOrdinary)
	logger.SetControlPlaneV8Emitter(runtime)
	if err := logger.LogActivity(ActivityInput{
		Actor: "watcher", Action: ActionPolicyReload, TargetType: "policy", TargetID: "default",
		Reason: "filesystem update", RunID: "run-activity", TraceID: "trace-activity",
	}); err != nil {
		t.Fatalf("LogActivity: %v", err)
	}
	activities, err := logger.store.ListActivityEvents(10)
	if err != nil || len(activities) != 1 {
		t.Fatalf("activity_events count = %d err=%v, want exactly 1", len(activities), err)
	}
	rows, err := logger.store.ListEvents(10)
	if err != nil || len(rows) != 1 {
		t.Fatalf("audit_events count = %d err=%v, want exactly 1", len(rows), err)
	}
	metadata, records := runtime.snapshot()
	if len(metadata) != 1 || len(records) != 1 || records[0].EventName() != observability.EventName(observability.TelemetryEventPolicyUpdated) {
		t.Fatalf("activity runtime result = metadata:%d records:%d", len(metadata), len(records))
	}
	if metadata[0].Source() != observability.SourceWatcher || rows[0].Actor != "watcher" || rows[0].Target != "policy:default" {
		t.Fatalf("activity compatibility/source = source:%q row:%#v", metadata[0].Source(), rows[0])
	}
	body, ok := records[0].Body()
	if !ok {
		t.Fatal("activity canonical body is absent")
	}
	bodyObject, bodyErr := body.Object()
	if bodyErr != nil || bodyObject["defenseclaw.admin.principal_ref"] != "watcher" {
		t.Fatalf("activity canonical principal = %#v err=%v", bodyObject, bodyErr)
	}
}

func TestControlPlaneV8PrincipalIncludesOnlySchemaSafeKnownActor(t *testing.T) {
	t.Parallel()
	if principal, known := controlPlaneV8Principal("cli:alice"); !known {
		t.Fatal("schema-safe actor was not marked known")
	} else if value, present := principal.Get(); !present || value != "cli:alice" {
		t.Fatalf("principal = (%q, %t), want (cli:alice, true)", value, present)
	}
	for _, actor := range []string{"", "Alice Example", strings.Repeat("a", 257)} {
		if principal, known := controlPlaneV8Principal(actor); known || principal.IsPresent() {
			t.Fatalf("unsafe actor %q produced a principal", actor)
		}
	}
}

func TestControlPlaneV8UnboundAndNonSelectedPathsRemainLegacyOnly(t *testing.T) {
	t.Parallel()
	t.Run("selected action without runtime", func(t *testing.T) {
		logger := newTestLogger(t)
		if err := logger.LogAction(string(ActionConfigUpdate), "config.yaml", "changed"); err != nil {
			t.Fatal(err)
		}
		rows, err := logger.store.ListEvents(10)
		if err != nil || len(rows) != 1 {
			t.Fatalf("legacy rows = %d err=%v", len(rows), err)
		}
		canonical := loadV8HistoryRow(t, logger.store, rows[0].ID)
		if canonical.Bucket != "" || canonical.ProjectedRecordJSON != "" {
			t.Fatalf("unbound v7 event was fabricated as v8: %#v", canonical)
		}
	})
	t.Run("non-selected action with runtime", func(t *testing.T) {
		logger := newTestLogger(t)
		runtime := newTestControlPlaneV8Emitter(t, logger.store, router.AdmissionOrdinary)
		logger.SetControlPlaneV8Emitter(runtime)
		if err := logger.LogAction(string(ActionSidecarStart), "sidecar", "started"); err != nil {
			t.Fatal(err)
		}
		rows, err := logger.store.ListEvents(10)
		metadata, records := runtime.snapshot()
		if err != nil || len(rows) != 1 || len(metadata) != 0 || len(records) != 0 {
			t.Fatalf("non-selected counts = rows:%d metadata:%d records:%d err=%v", len(rows), len(metadata), len(records), err)
		}
	})
}

func TestControlPlaneV8FailureNeverFallsBackToDuplicateLegacyPersistence(t *testing.T) {
	t.Parallel()
	for _, test := range []struct {
		name    string
		emitter *rejectingControlPlaneV8Emitter
	}{
		{name: "runtime error", emitter: &rejectingControlPlaneV8Emitter{err: fmt.Errorf("runtime rejected")}},
		{name: "local not persisted", emitter: &rejectingControlPlaneV8Emitter{}},
	} {
		test := test
		t.Run(test.name, func(t *testing.T) {
			logger := newTestLogger(t)
			structured := &captureEmitter{}
			logger.SetStructuredEmitter(structured)
			logger.SetControlPlaneV8Emitter(test.emitter)
			if err := logger.LogAction(string(ActionConfigUpdate), "config.yaml", "changed"); err == nil {
				t.Fatal("LogAction succeeded after canonical runtime failure")
			}
			rows, listErr := logger.store.ListEvents(10)
			if listErr != nil || len(rows) != 0 || len(structured.snapshot()) != 0 || test.emitter.calls != 1 {
				t.Fatalf("failure counts = rows:%d emissions:%d calls:%d err=%v",
					len(rows), len(structured.snapshot()), test.emitter.calls, listErr)
			}
		})
	}
}

func assertControlPlaneCorrelation(t *testing.T, got observability.Correlation, want CorrelationEnvelope) {
	t.Helper()
	if got.RunID != want.RunID || got.TraceID != want.TraceID || got.RequestID != want.RequestID ||
		got.SessionID != want.SessionID || got.TurnID != want.TurnID || got.AgentID != want.AgentID ||
		got.AgentInstanceID != want.AgentInstanceID || got.PolicyID != want.PolicyID ||
		got.ConnectorID != want.Connector || got.SidecarInstanceID != want.SidecarInstanceID {
		t.Fatalf("canonical correlation = %#v, want envelope %#v", got, want)
	}
}

func assertAuditEventRowExcludesCanary(t *testing.T, store *Store, recordID, canary string) {
	t.Helper()
	rows, err := store.db.Query(`SELECT * FROM audit_events WHERE id = ?`, recordID)
	if err != nil {
		t.Fatalf("query floor row: %v", err)
	}
	defer rows.Close()
	columns, err := rows.Columns()
	if err != nil {
		t.Fatalf("floor row columns: %v", err)
	}
	if !rows.Next() {
		t.Fatal("floor row is absent")
	}
	values := make([]any, len(columns))
	destinations := make([]any, len(columns))
	for index := range values {
		destinations[index] = &values[index]
	}
	if err := rows.Scan(destinations...); err != nil {
		t.Fatalf("scan floor row: %v", err)
	}
	for index, value := range values {
		var text string
		switch typed := value.(type) {
		case string:
			text = typed
		case []byte:
			text = string(typed)
		default:
			continue
		}
		if strings.Contains(text, canary) {
			t.Fatalf("mandatory floor leaked canary through audit_events.%s", columns[index])
		}
	}
	if rows.Next() {
		t.Fatal("mandatory floor record id produced more than one row")
	}
	if err := rows.Err(); err != nil {
		t.Fatalf("iterate floor rows: %v", err)
	}
}
