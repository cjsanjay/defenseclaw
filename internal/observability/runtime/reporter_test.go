// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// SPDX-License-Identifier: Apache-2.0

package runtime

import (
	"bytes"
	"context"
	"database/sql"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/audit"
	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/observability/redaction"
	"github.com/defenseclaw/defenseclaw/internal/observability/runtimegraph"
	_ "modernc.org/sqlite"
)

type reporterTestClock struct{ now time.Time }

func (clock reporterTestClock) Now() time.Time { return clock.now }

type reporterTestDeadlines struct{}

func (reporterTestDeadlines) Context(parent context.Context, timeout time.Duration) (context.Context, context.CancelFunc) {
	return context.WithTimeout(parent, timeout)
}

type reporterTestRetry struct{}

func (reporterTestRetry) After(delay time.Duration) <-chan time.Time { return time.After(delay) }

func TestReloadReporterPersistsExactGraphAndDeduplicatesStableDelivery(t *testing.T) {
	directory := t.TempDir()
	auditPath := filepath.Join(directory, "audit.db")
	judgePath := filepath.Join(directory, "judge.db")
	store, err := audit.NewStore(auditPath)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })
	if err := store.Init(); err != nil {
		t.Fatal(err)
	}
	engine, err := redaction.NewEngine(bytes.Repeat([]byte{0x7a}, 32))
	if err != nil {
		t.Fatal(err)
	}
	reporter, err := NewReloadReporter(store, engine, nil, "runtime-run-1", "v8-test")
	if err != nil {
		t.Fatal(err)
	}
	plan, err := config.CompileObservabilityV8(&config.ObservabilityV8Source{
		Local: config.ObservabilityV8LocalSource{Path: auditPath, JudgeBodiesPath: judgePath},
	})
	if err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 7, 4, 1, 2, 3, 4, time.FixedZone("offset", -5*60*60))
	manager, err := runtimegraph.New(
		t.Context(),
		runtimegraph.ConfigFromPlan(plan, true),
		nil,
		runtimegraph.Options{
			DrainTimeout: time.Second, CleanupRetryDelay: time.Millisecond,
			Clock: reporterTestClock{now: now}, Deadlines: reporterTestDeadlines{},
			RetryScheduler: reporterTestRetry{}, Reporter: reporter,
		},
	)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = manager.Close(context.Background())
		_ = manager.WaitReporter(context.Background())
	})
	if err := manager.FlushReports(t.Context()); err != nil {
		t.Fatal(err)
	}

	report := runtimegraph.Report{
		Code: runtimegraph.ReportRestartRequired, Outcome: "rejected",
		FieldPath: runtimegraph.FieldLocalPath, Generation: 1,
		OccurredAt: now, DeliverySequence: 99, DeliveryIndex: 0,
	}
	if err := reporter.ComplianceActivity(manager.Active(), report); err != nil {
		t.Fatal(err)
	}
	if err := reporter.ComplianceActivity(manager.Active(), report); err != nil {
		t.Fatalf("idempotent retry: %v", err)
	}
	health := runtimegraph.Report{
		Code: runtimegraph.ReportCleanupFailed, Outcome: "failed", ComponentName: "local-log",
		Generation: 1, OccurredAt: now, DeliverySequence: 100, DeliveryIndex: 0,
	}
	if err := reporter.PlatformHealth(manager.Active(), health); err != nil {
		t.Fatal(err)
	}

	reader, err := sql.Open("sqlite", auditPath)
	if err != nil {
		t.Fatal(err)
	}
	defer reader.Close() //nolint:errcheck
	rows, err := reader.Query(`SELECT bucket, event_name, action, projected_record_json,
		content_hash, generation, timestamp FROM audit_events ORDER BY rowid`)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close() //nolint:errcheck
	type persisted struct {
		bucket, event, action, projected, digest, timestamp string
		generation                                          int64
	}
	var got []persisted
	for rows.Next() {
		var row persisted
		if err := rows.Scan(
			&row.bucket, &row.event, &row.action, &row.projected,
			&row.digest, &row.generation, &row.timestamp,
		); err != nil {
			t.Fatal(err)
		}
		got = append(got, row)
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
	if len(got) != 3 {
		t.Fatalf("persisted reports = %d, want initial + deduplicated rejection + health", len(got))
	}
	if got[0].bucket != "compliance.activity" || got[0].event != "config.change.applied" ||
		got[1].event != "config.reload.rejected" || got[2].bucket != "platform.health" ||
		got[2].event != "subsystem.degraded" {
		t.Fatalf("persisted identities = %#v", got)
	}
	for _, row := range got {
		if row.digest != plan.Digest() || row.generation != 1 ||
			!strings.Contains(row.projected, `"redaction_profile":"none"`) ||
			!strings.Contains(row.timestamp, "2026-07-04") {
			t.Fatalf("persisted graph binding = %#v", row)
		}
	}
}

func TestReloadReporterRejectsInvalidIdentityAndBoundsStorageFailure(t *testing.T) {
	directory := t.TempDir()
	auditPath := filepath.Join(directory, "private-audit.db")
	judgePath := filepath.Join(directory, "private-judge.db")
	store, err := audit.NewStore(auditPath)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.Init(); err != nil {
		t.Fatal(err)
	}
	engine, err := redaction.NewEngine(nil)
	if err != nil {
		t.Fatal(err)
	}
	reporter, err := NewReloadReporter(store, engine, nil, "run", "test")
	if err != nil {
		t.Fatal(err)
	}
	plan, err := config.CompileObservabilityV8(&config.ObservabilityV8Source{
		Local: config.ObservabilityV8LocalSource{Path: auditPath, JudgeBodiesPath: judgePath},
	})
	if err != nil {
		t.Fatal(err)
	}
	manager, err := runtimegraph.New(t.Context(), runtimegraph.ConfigFromPlan(plan, true), nil,
		runtimegraph.Options{
			DrainTimeout: time.Second, CleanupRetryDelay: time.Millisecond,
			Clock: reporterTestClock{now: time.Now()}, Deadlines: reporterTestDeadlines{},
			RetryScheduler: reporterTestRetry{}, Reporter: reporter,
		})
	if err != nil {
		t.Fatal(err)
	}
	if err := manager.FlushReports(t.Context()); err != nil {
		t.Fatal(err)
	}
	invalid := runtimegraph.Report{
		Code: "unknown", Outcome: "failed", Generation: 1,
		OccurredAt: time.Now(), DeliverySequence: 2,
	}
	if err := reporter.PlatformHealth(manager.Active(), invalid); err == nil ||
		err.Error() != "observability runtime report delivery failed" {
		t.Fatalf("invalid report error = %v", err)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	failure := runtimegraph.Report{
		Code: runtimegraph.ReportDrainFailed, Outcome: "failed", Generation: 1,
		OccurredAt: time.Now(), DeliverySequence: 3,
	}
	if err := reporter.PlatformHealth(manager.Active(), failure); err == nil ||
		strings.Contains(err.Error(), directory) || strings.Contains(err.Error(), auditPath) {
		t.Fatalf("storage failure was not bounded: %v", err)
	}
	_ = manager.Close(context.Background())
}
