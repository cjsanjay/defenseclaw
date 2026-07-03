// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package telemetry

import (
	"context"
	"database/sql"
	"os"
	"sync"
	"sync/atomic"
	"time"
)

var registeredAuditDB atomic.Pointer[sql.DB]

// auditDBRegistry retains ready registrations in activation order. Production
// constructs exactly one mandatory audit Store, but tests, reload hand-off,
// and defensive recovery can briefly have more than one ready connection. The
// atomic pointer remains the lock-free read path used by metric collection;
// this registry only serializes the uncommon register/unregister transitions.
var auditDBRegistry struct {
	sync.Mutex
	ready []*sql.DB
}

// RegisterAuditDB wires a fully initialized audit SQLite connection for
// PRAGMA-based health metrics. Store construction alone is not sufficient:
// callers register only after migrations and the mandatory write probe pass.
func RegisterAuditDB(db *sql.DB) {
	if db == nil {
		return
	}
	auditDBRegistry.Lock()
	defer auditDBRegistry.Unlock()

	// Registration is idempotent. Move an existing connection to the end so a
	// repeated readiness transition makes it the active connection without
	// leaving a duplicate fallback entry behind.
	for i := len(auditDBRegistry.ready) - 1; i >= 0; i-- {
		if auditDBRegistry.ready[i] == db {
			auditDBRegistry.ready = append(auditDBRegistry.ready[:i], auditDBRegistry.ready[i+1:]...)
			break
		}
	}
	auditDBRegistry.ready = append(auditDBRegistry.ready, db)
	registeredAuditDB.Store(db)
}

// UnregisterAuditDB removes db from the ready registry. If db was active, the
// most recently registered still-live connection is restored atomically. The
// return value reports whether db was the active connection; closing an older
// Store therefore still cannot detach the newer ready Store.
func UnregisterAuditDB(db *sql.DB) bool {
	if db == nil {
		return false
	}
	auditDBRegistry.Lock()
	defer auditDBRegistry.Unlock()

	index := -1
	for i := len(auditDBRegistry.ready) - 1; i >= 0; i-- {
		if auditDBRegistry.ready[i] == db {
			index = i
			break
		}
	}
	if index < 0 {
		return false
	}
	wasActive := index == len(auditDBRegistry.ready)-1
	auditDBRegistry.ready = append(auditDBRegistry.ready[:index], auditDBRegistry.ready[index+1:]...)
	if !wasActive {
		return false
	}
	if len(auditDBRegistry.ready) == 0 {
		registeredAuditDB.Store(nil)
	} else {
		registeredAuditDB.Store(auditDBRegistry.ready[len(auditDBRegistry.ready)-1])
	}
	return true
}

func collectSQLiteHealth(ctx context.Context, db *sql.DB) SQLiteHealthMetrics {
	var h SQLiteHealthMetrics
	if db == nil {
		return h
	}

	var mainPath string
	rows, err := db.QueryContext(ctx, "PRAGMA database_list")
	if err != nil {
		return h
	}
	defer rows.Close()
	for rows.Next() {
		var seq int
		var name, file string
		if scanErr := rows.Scan(&seq, &name, &file); scanErr != nil {
			continue
		}
		if name == "main" && file != "" {
			mainPath = file
			break
		}
	}
	if mainPath != "" {
		if st, err := os.Stat(mainPath); err == nil {
			h.DBSizeBytes = st.Size()
		}
		wal := mainPath + "-wal"
		if st, err := os.Stat(wal); err == nil {
			h.WALSizeBytes = st.Size()
		}
	}

	_ = db.QueryRowContext(ctx, "PRAGMA page_count").Scan(&h.PageCount)
	_ = db.QueryRowContext(ctx, "PRAGMA freelist_count").Scan(&h.FreelistCount)

	t0 := time.Now()
	_, _ = db.ExecContext(ctx, "PRAGMA wal_checkpoint(PASSIVE)")
	h.CheckpointMs = float64(time.Since(t0).Milliseconds())

	return h
}
