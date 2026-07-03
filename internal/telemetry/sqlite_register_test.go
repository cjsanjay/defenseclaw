// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package telemetry

import (
	"database/sql"
	"sync"
	"testing"
)

func TestAuditDBRegistrationUsesConnectionOwnership(t *testing.T) {
	resetAuditDBRegistry(t)
	first := &sql.DB{}
	second := &sql.DB{}
	RegisterAuditDB(first)
	RegisterAuditDB(second)
	if UnregisterAuditDB(first) {
		t.Fatal("older connection detached the active audit database")
	}
	if got := registeredAuditDB.Load(); got != second {
		t.Fatalf("active registration = %p, want %p", got, second)
	}
	if !UnregisterAuditDB(second) || registeredAuditDB.Load() != nil {
		t.Fatal("active connection did not detach its own registration")
	}
}

func TestAuditDBRegistrationRestoresPreviousLiveConnection(t *testing.T) {
	resetAuditDBRegistry(t)
	first := &sql.DB{}
	second := &sql.DB{}
	RegisterAuditDB(first)
	RegisterAuditDB(second)

	if !UnregisterAuditDB(second) {
		t.Fatal("active connection did not report an active unregister")
	}
	if got := registeredAuditDB.Load(); got != first {
		t.Fatalf("restored registration = %p, want previous live connection %p", got, first)
	}
	if !UnregisterAuditDB(first) || registeredAuditDB.Load() != nil {
		t.Fatal("restored connection did not detach cleanly")
	}
}

func TestAuditDBRegistrationIsIdempotentAndMovesToNewest(t *testing.T) {
	resetAuditDBRegistry(t)
	first := &sql.DB{}
	second := &sql.DB{}
	RegisterAuditDB(first)
	RegisterAuditDB(second)
	RegisterAuditDB(first)

	if got := registeredAuditDB.Load(); got != first {
		t.Fatalf("active registration = %p, want re-registered connection %p", got, first)
	}
	if !UnregisterAuditDB(first) {
		t.Fatal("re-registered connection was not active")
	}
	if got := registeredAuditDB.Load(); got != second {
		t.Fatalf("restored registration = %p, want %p", got, second)
	}
	if !UnregisterAuditDB(second) || registeredAuditDB.Load() != nil {
		t.Fatal("duplicate registration left a stale fallback entry")
	}
}

func TestAuditDBRegistrationConcurrentTransitionsLeaveNoStaleEntry(t *testing.T) {
	resetAuditDBRegistry(t)
	const count = 32
	dbs := make([]*sql.DB, count)
	var registered sync.WaitGroup
	var unregistered sync.WaitGroup
	registered.Add(count)
	unregistered.Add(count)
	release := make(chan struct{})
	for i := range dbs {
		dbs[i] = &sql.DB{}
		db := dbs[i]
		go func() {
			RegisterAuditDB(db)
			registered.Done()
			<-release
			UnregisterAuditDB(db)
			unregistered.Done()
		}()
	}
	registered.Wait()
	if registeredAuditDB.Load() == nil {
		t.Fatal("concurrent ready registrations did not expose an active connection")
	}
	close(release)
	unregistered.Wait()
	if got := registeredAuditDB.Load(); got != nil {
		t.Fatalf("concurrent unregister left stale registration %p", got)
	}
}

func resetAuditDBRegistry(t *testing.T) {
	t.Helper()
	auditDBRegistry.Lock()
	auditDBRegistry.ready = nil
	registeredAuditDB.Store(nil)
	auditDBRegistry.Unlock()
	t.Cleanup(func() {
		auditDBRegistry.Lock()
		auditDBRegistry.ready = nil
		registeredAuditDB.Store(nil)
		auditDBRegistry.Unlock()
	})
}
