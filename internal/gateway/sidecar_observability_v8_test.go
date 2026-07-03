// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/audit"
	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/gatewaylog"
	"github.com/defenseclaw/defenseclaw/internal/observability"
	"github.com/defenseclaw/defenseclaw/internal/observability/pipeline"
	"github.com/defenseclaw/defenseclaw/internal/observability/redaction"
	"github.com/defenseclaw/defenseclaw/internal/observability/router"
	observabilityruntime "github.com/defenseclaw/defenseclaw/internal/observability/runtime"
	"github.com/defenseclaw/defenseclaw/internal/observability/runtimegraph"
)

type discardSidecarGraphReporter struct{}

func (*discardSidecarGraphReporter) PlatformHealth(*runtimegraph.Graph, runtimegraph.Report) error {
	return nil
}

func (*discardSidecarGraphReporter) ComplianceActivity(*runtimegraph.Graph, runtimegraph.Report) error {
	return nil
}

type sidecarRuntimeFixture struct {
	runtime *observabilityruntime.Runtime
	store   *audit.Store
	path    string
	plan    *config.ObservabilityV8Plan
}

func newSidecarRuntimeFixture(t *testing.T, collectLifecycle bool) sidecarRuntimeFixture {
	t.Helper()
	directory := t.TempDir()
	path := filepath.Join(directory, "audit.db")
	store, err := audit.NewStore(path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })
	if err := store.Init(); err != nil {
		t.Fatal(err)
	}
	retentionDays := 0
	source := &config.ObservabilityV8Source{Local: config.ObservabilityV8LocalSource{
		Path: path, JudgeBodiesPath: filepath.Join(directory, "judge-bodies.db"),
		RetentionDays: &retentionDays,
	}}
	if !collectLifecycle {
		disabled := false
		source.Buckets = map[observability.Bucket]config.ObservabilityV8BucketPolicySource{
			observability.BucketAgentLifecycle: {
				Collect: config.ObservabilityV8CollectSource{Logs: &disabled},
			},
		}
	}
	plan, err := config.CompileObservabilityV8(source)
	if err != nil {
		t.Fatal(err)
	}
	engine, err := redaction.NewEngine(nil)
	if err != nil {
		t.Fatal(err)
	}
	var failureIDs atomic.Uint64
	failureBuilder, err := observability.NewRecordBuilder(
		observability.ClockFunc(func() time.Time { return time.Now().UTC() }),
		observability.OccurrenceIDGeneratorFunc(func() (string, error) {
			return fmt.Sprintf("sidecar-failure-%d", failureIDs.Add(1)), nil
		}),
	)
	if err != nil {
		t.Fatal(err)
	}
	reaper, err := audit.NewRetentionReaper(store, nil, 0, audit.RetentionOptions{})
	if err != nil {
		t.Fatal(err)
	}
	retention, err := observabilityruntime.NewRetentionController(
		reaper, observabilityruntime.RetentionControllerOptions{},
	)
	if err != nil {
		t.Fatal(err)
	}
	runtime, err := observabilityruntime.New(
		t.Context(),
		runtimegraph.ConfigFromPlan(plan, false),
		observabilityruntime.Options{
			Store: store, Engine: engine, RecordBuilder: failureBuilder,
			Reporter: &discardSidecarGraphReporter{}, RetentionController: retention,
		},
	)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := runtime.Close(ctx); err != nil {
			t.Errorf("close runtime: %v", err)
		}
	})
	return sidecarRuntimeFixture{runtime: runtime, store: store, path: path, plan: plan}
}

type storedSidecarLifecycle struct {
	action            string
	actor             string
	details           string
	severity          string
	bucket            string
	eventName         string
	source            string
	digest            string
	generation        int64
	runID             string
	sidecarInstanceID string
}

func readStoredSidecarLifecycle(t *testing.T, path string) []storedSidecarLifecycle {
	t.Helper()
	database, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()
	rows, err := database.Query(`SELECT action, actor, details, COALESCE(severity,''), COALESCE(bucket,''), COALESCE(event_name,''),
		COALESCE(source,''), COALESCE(content_hash,''), COALESCE(generation,0),
		COALESCE(run_id,''), COALESCE(sidecar_instance_id,'')
		FROM audit_events WHERE action IN ('sidecar-start','sidecar-stop') ORDER BY action`)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	var result []storedSidecarLifecycle
	for rows.Next() {
		var event storedSidecarLifecycle
		if err := rows.Scan(
			&event.action, &event.actor, &event.details, &event.severity, &event.bucket, &event.eventName, &event.source,
			&event.digest, &event.generation, &event.runID, &event.sidecarInstanceID,
		); err != nil {
			t.Fatal(err)
		}
		result = append(result, event)
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
	return result
}

func installSidecarLifecycleIDs(t *testing.T) {
	t.Helper()
	gatewaylog.SetProcessRunID("sidecar-v8-run")
	gatewaylog.SetSidecarInstanceID("sidecar-v8-instance")
	t.Cleanup(func() {
		gatewaylog.SetProcessRunID("")
		gatewaylog.SetSidecarInstanceID("")
	})
}

func TestSidecarCanonicalLifecyclePersistsExactlyOnceWithGraphProvenance(t *testing.T) {
	fixture := newSidecarRuntimeFixture(t, true)
	installSidecarLifecycleIDs(t)
	sidecar := &Sidecar{logger: audit.NewLogger(fixture.store)}
	if err := sidecar.BindObservabilityRuntime(fixture.runtime); err != nil {
		t.Fatal(err)
	}
	if err := sidecar.recordSidecarLifecycle(t.Context(), audit.ActionSidecarStart); err != nil {
		t.Fatal(err)
	}
	canceled, cancel := context.WithCancel(t.Context())
	cancel()
	if err := sidecar.recordSidecarLifecycle(canceled, audit.ActionSidecarStop); err != nil {
		t.Fatalf("canonical stop rejected canceled run context: %v", err)
	}

	rows := readStoredSidecarLifecycle(t, fixture.path)
	if len(rows) != 2 {
		t.Fatalf("lifecycle rows=%d want 2: %#v", len(rows), rows)
	}
	wantEvents := map[string]string{
		"sidecar-start": "legacy.audit.sidecar.start",
		"sidecar-stop":  "legacy.audit.sidecar.stop",
	}
	wantDetails := map[string]string{
		"sidecar-start": "starting all subsystems",
		"sidecar-stop":  "all subsystems stopped",
	}
	for _, row := range rows {
		if row.bucket != string(observability.BucketAgentLifecycle) ||
			row.eventName != wantEvents[row.action] || row.actor != "defenseclaw" ||
			row.details != wantDetails[row.action] || row.severity != "INFO" ||
			row.source != string(observability.SourceGateway) ||
			row.digest != fixture.plan.Digest() || row.generation != 1 ||
			row.runID != "sidecar-v8-run" || row.sidecarInstanceID != "sidecar-v8-instance" {
			t.Errorf("canonical lifecycle row=%#v", row)
		}
	}
}

type fakeSidecarEmitter struct {
	emit func(context.Context, router.Metadata, observabilityruntime.EmitBuilder) (pipeline.LocalLogOutcome, error)
}

func (emitter *fakeSidecarEmitter) Emit(
	ctx context.Context,
	metadata router.Metadata,
	builder observabilityruntime.EmitBuilder,
) (pipeline.LocalLogOutcome, error) {
	return emitter.emit(ctx, metadata, builder)
}

func TestSidecarBoundFailureFailsRunWithoutFallbackOrFalseStructuredLifecycle(t *testing.T) {
	fixture := newSidecarRuntimeFixture(t, true)
	events := withCapturedEvents(t)
	sidecar := &Sidecar{cfg: &config.Config{}, logger: audit.NewLogger(fixture.store)}
	if err := sidecar.bindObservabilityRuntime(&fakeSidecarEmitter{emit: func(
		context.Context, router.Metadata, observabilityruntime.EmitBuilder,
	) (pipeline.LocalLogOutcome, error) {
		return pipeline.LocalLogOutcome{}, errors.New("unbounded backend detail")
	}}); err != nil {
		t.Fatal(err)
	}
	err := sidecar.Run(t.Context())
	var bounded *sidecarObservabilityError
	if !errors.As(err, &bounded) || bounded.Code() != sidecarObservabilityEmitFailed ||
		err.Error() == "unbounded backend detail" {
		t.Fatalf("run error=%v", err)
	}
	if rows := readStoredSidecarLifecycle(t, fixture.path); len(rows) != 0 {
		t.Fatalf("bound failure fell back to legacy SQLite: %#v", rows)
	}
	count := 0
	for _, event := range *events {
		if event.EventType == gatewaylog.EventLifecycle && event.Lifecycle != nil &&
			event.Lifecycle.Subsystem == "sidecar" && event.Lifecycle.Transition == "start" {
			count++
		}
	}
	if count != 0 {
		t.Fatalf("failed canonical start emitted %d structured lifecycle events", count)
	}
}

func TestSidecarDisabledCollectionDoesNotFallback(t *testing.T) {
	fixture := newSidecarRuntimeFixture(t, false)
	sidecar := &Sidecar{logger: audit.NewLogger(fixture.store)}
	if err := sidecar.BindObservabilityRuntime(fixture.runtime); err != nil {
		t.Fatal(err)
	}
	if err := sidecar.recordSidecarLifecycle(t.Context(), audit.ActionSidecarStart); err != nil {
		t.Fatal(err)
	}
	canceled, cancel := context.WithCancel(t.Context())
	cancel()
	if err := sidecar.recordSidecarLifecycle(canceled, audit.ActionSidecarStop); err != nil {
		t.Fatal(err)
	}
	if rows := readStoredSidecarLifecycle(t, fixture.path); len(rows) != 0 {
		t.Fatalf("disabled collection wrote lifecycle rows: %#v", rows)
	}
}

func TestSidecarAmbiguousBoundOutcomeNeverFallsBack(t *testing.T) {
	fixture := newSidecarRuntimeFixture(t, true)
	sidecar := &Sidecar{logger: audit.NewLogger(fixture.store)}
	if err := sidecar.bindObservabilityRuntime(&fakeSidecarEmitter{emit: func(
		_ context.Context,
		_ router.Metadata,
		builder observabilityruntime.EmitBuilder,
	) (pipeline.LocalLogOutcome, error) {
		// A real Runtime never builds a record and then reports AdmissionDrop.
		// Exercise the bridge's defensive ambiguity check without granting the
		// fake access to LocalLogOutcome's private persistence fields.
		_, _ = builder(observabilityruntime.EmitContext{}, router.AdmissionOrdinary)
		return pipeline.LocalLogOutcome{}, nil
	}}); err != nil {
		t.Fatal(err)
	}
	err := sidecar.recordSidecarLifecycle(t.Context(), audit.ActionSidecarStart)
	var bounded *sidecarObservabilityError
	if !errors.As(err, &bounded) || bounded.Code() != sidecarObservabilityAmbiguous {
		t.Fatalf("ambiguous outcome error=%v", err)
	}
	if rows := readStoredSidecarLifecycle(t, fixture.path); len(rows) != 0 {
		t.Fatalf("ambiguous outcome fell back to legacy SQLite: %#v", rows)
	}
}

func TestSidecarUnboundPreservesLegacySQLitePath(t *testing.T) {
	fixture := newSidecarRuntimeFixture(t, true)
	sidecar := &Sidecar{logger: audit.NewLogger(fixture.store)}
	if err := sidecar.recordSidecarLifecycle(t.Context(), audit.ActionSidecarStart); err != nil {
		t.Fatal(err)
	}
	rows := readStoredSidecarLifecycle(t, fixture.path)
	if len(rows) != 1 || rows[0].action != "sidecar-start" || rows[0].bucket != "" {
		t.Fatalf("legacy lifecycle rows=%#v", rows)
	}
}

var _ sidecarRuntimeEmitter = (*fakeSidecarEmitter)(nil)
var _ runtimegraph.Reporter = (*discardSidecarGraphReporter)(nil)
