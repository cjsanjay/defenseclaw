// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"path/filepath"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/audit"
	"github.com/defenseclaw/defenseclaw/internal/gatewaylog"
)

func TestEmitJudge_AuthoritativeStorePersistsRawBeforeFanoutScrub(t *testing.T) {
	capture := withCapturedEvents(t)
	bodyStore, err := audit.NewJudgeBodyStore(filepath.Join(t.TempDir(), "judge_bodies.db"))
	if err != nil {
		t.Fatalf("NewJudgeBodyStore: %v", err)
	}
	t.Cleanup(func() { _ = bodyStore.Close() })
	store := NewJudgeStoreFromBodyStore(bodyStore, nil, 8)
	SetJudgeResponseStore(store)
	t.Cleanup(func() {
		SetJudgeResponseStore(nil)
		_ = store.Shutdown(t.Context())
	})

	raw := `{"verdict":"block","reason":"email found in inspected content"}`
	emitJudge(t.Context(), "pii", "gpt-4", gatewaylog.DirectionPrompt, 128, 42, "block",
		gatewaylog.SeverityHigh, "", raw, JudgeEmitOpts{})
	if err := store.Shutdown(t.Context()); err != nil {
		t.Fatalf("Shutdown: %v", err)
	}

	rows, err := bodyStore.ListJudgeResponses(10)
	if err != nil {
		t.Fatalf("ListJudgeResponses: %v", err)
	}
	if len(rows) != 1 {
		t.Fatalf("authoritative rows=%d want 1", len(rows))
	}
	if rows[0].Raw != raw {
		t.Fatalf("authoritative raw=%q want exact body", rows[0].Raw)
	}
	if rows[0].Direction != string(gatewaylog.DirectionPrompt) {
		t.Fatalf("authoritative direction=%q want %q", rows[0].Direction, gatewaylog.DirectionPrompt)
	}

	if len(*capture) != 1 {
		t.Fatalf("captured %d events want 1", len(*capture))
	}
	judge := (*capture)[0].Judge
	if judge == nil {
		t.Fatal("judge payload missing from captured event")
	}
	if judge.RawResponse == raw {
		t.Fatal("fanout saw unredacted raw body")
	}
}

func TestEmitJudge_NilAuthoritativeStoreNeverWritesAuditDB(t *testing.T) {
	capture := withCapturedEvents(t)
	SetJudgeResponseStore(nil)
	t.Cleanup(func() { SetJudgeResponseStore(nil) })

	auditStore, err := audit.NewStore(filepath.Join(t.TempDir(), "audit.db"))
	if err != nil {
		t.Fatalf("NewStore: %v", err)
	}
	t.Cleanup(func() { _ = auditStore.Close() })
	if err := auditStore.Init(); err != nil {
		t.Fatalf("Init: %v", err)
	}

	raw := `{"verdict":"allow","reason":"retention disabled"}`
	emitJudge(t.Context(), "injection", "gpt-4", gatewaylog.DirectionPrompt, 16, 1, "allow",
		gatewaylog.SeverityInfo, "", raw, JudgeEmitOpts{})

	rows, err := auditStore.ListJudgeResponses(10)
	if err != nil {
		t.Fatalf("ListJudgeResponses(audit.db): %v", err)
	}
	if len(rows) != 0 {
		t.Fatalf("nil authoritative store wrote %d raw bodies to audit.db", len(rows))
	}
	if len(*capture) != 1 || (*capture)[0].Judge == nil {
		t.Fatalf("redacted judge metadata event was lost: %+v", *capture)
	}
	if (*capture)[0].Judge.RawResponse == raw {
		t.Fatal("nil-store metadata fanout exposed raw body")
	}
}

func TestEmitJudge_EmptyRawWithNilAuthoritativeStoreStillLogsMetadata(t *testing.T) {
	capture := withCapturedEvents(t)
	SetJudgeResponseStore(nil)
	t.Cleanup(func() { SetJudgeResponseStore(nil) })

	emitJudge(t.Context(), "injection", "gpt-4", gatewaylog.DirectionPrompt, 0, 1, "allow",
		gatewaylog.SeverityInfo, "", "", JudgeEmitOpts{})
	if len(*capture) != 1 || (*capture)[0].Judge == nil {
		t.Fatalf("empty-raw judge metadata event missing: %+v", *capture)
	}
}
