// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"context"
	"database/sql"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sort"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/gatewaylog"
	"github.com/defenseclaw/defenseclaw/internal/observability"
	"github.com/defenseclaw/defenseclaw/internal/telemetry"
	sdkmetric "go.opentelemetry.io/otel/sdk/metric"
	"go.opentelemetry.io/otel/sdk/metric/metricdata"
)

type storedAgentDiscoveryV8 struct {
	eventName string
	bucket    string
	source    string
	connector string
	body      map[string]any
}

func readStoredAgentDiscoveryV8(t *testing.T, path string) []storedAgentDiscoveryV8 {
	t.Helper()
	database, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()
	rows, err := database.Query(`SELECT event_name, bucket, source, COALESCE(connector,''), projected_record_json
		FROM audit_events WHERE action = 'agent_discovery' ORDER BY event_name, connector`)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	var result []storedAgentDiscoveryV8
	for rows.Next() {
		var item storedAgentDiscoveryV8
		var projectedJSON string
		if err := rows.Scan(&item.eventName, &item.bucket, &item.source, &item.connector, &projectedJSON); err != nil {
			t.Fatal(err)
		}
		var projected map[string]any
		if err := json.Unmarshal([]byte(projectedJSON), &projected); err != nil {
			t.Fatal(err)
		}
		item.body, _ = projected["body"].(map[string]any)
		result = append(result, item)
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
	return result
}

func TestAgentDiscoveryV8BuildsExactFamiliesAndSuppressesGenericLifecycleDuplicate(t *testing.T) {
	fixture := newOTLPV8MetricFixture(t)
	runtime := &discoveryMetricFailureRuntime{aiDiscoveryV8Runtime: fixture.runtime}
	api := &APIServer{scannerCfg: &config.Config{ConfigVersion: 8}}
	api.bindObservabilityV8Runtimes(runtime, nil, nil, nil)
	legacy := withCapturedEvents(t)

	request := httptest.NewRequest(http.MethodPost, "/api/v1/agents/discovery", strings.NewReader(validAgentDiscoveryBody()))
	request.Header.Set("Content-Type", "application/json")
	response := httptest.NewRecorder()
	api.handleAgentDiscovery(response, request)
	if response.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", response.Code, response.Body.String())
	}

	rows := readStoredAgentDiscoveryV8(t, fixture.path)
	if len(rows) != 3 {
		t.Fatalf("canonical rows=%d want summary + two signals: %#v", len(rows), rows)
	}
	want := []string{"agent.discovery.completed", "agent.discovery.signal", "agent.discovery.signal"}
	for index, row := range rows {
		if row.eventName != want[index] || row.bucket != "agent.lifecycle" || row.source != "cli" || row.body == nil {
			t.Fatalf("row[%d]=%+v want event=%s/agent.lifecycle/cli", index, row, want[index])
		}
	}
	connectors := []string{rows[1].connector, rows[2].connector}
	sort.Strings(connectors)
	if strings.Join(connectors, ",") != "claudecode,codex" {
		t.Fatalf("signal connectors=%v", connectors)
	}
	for _, event := range *legacy {
		if event.EventType == gatewaylog.EventLifecycle && event.Lifecycle != nil && event.Lifecycle.Subsystem == "agent_discovery" {
			t.Fatalf("v8 resurrected generic lifecycle duplicate: %#v", event)
		}
	}
	wantMetrics := map[string]int{
		observability.TelemetryInstrumentDefenseClawAgentDiscoveryRuns:      1,
		observability.TelemetryInstrumentDefenseClawAgentDiscoveryDuration:  1,
		observability.TelemetryInstrumentDefenseClawAgentDiscoverySignals:   2,
		observability.TelemetryInstrumentDefenseClawAgentDiscoveryInstalled: 2,
	}
	gotMetrics := make(map[string]int, len(wantMetrics))
	for _, family := range runtime.snapshot() {
		gotMetrics[string(family)]++
	}
	if len(gotMetrics) != len(wantMetrics) {
		t.Fatalf("agent discovery metric set=%v want=%v", gotMetrics, wantMetrics)
	}
	for family, count := range wantMetrics {
		if gotMetrics[family] != count {
			t.Fatalf("agent metric %s calls=%d want=%d; all=%v", family, gotMetrics[family], count, gotMetrics)
		}
	}
}

func TestAgentDiscoveryV8DetachNeverResurrectsLegacyOTelOrLifecycle(t *testing.T) {
	api := &APIServer{scannerCfg: &config.Config{ConfigVersion: 8}}
	legacy := withCapturedEvents(t)
	request := httptest.NewRequest(http.MethodPost, "/api/v1/agents/discovery", strings.NewReader(validAgentDiscoveryBody()))
	request.Header.Set("Content-Type", "application/json")
	response := httptest.NewRecorder()
	api.handleAgentDiscovery(response, request)
	if response.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", response.Code, response.Body.String())
	}
	for _, event := range *legacy {
		if event.EventType == gatewaylog.EventLifecycle && event.Lifecycle != nil && event.Lifecycle.Subsystem == "agent_discovery" {
			t.Fatalf("detached v8 resurrected lifecycle event: %#v", event)
		}
	}
}

func TestAgentDiscoveryV8MalformedAndRejectedUseCanonicalSummaryWithoutLegacyFallback(t *testing.T) {
	for _, test := range []struct {
		name       string
		body       string
		wantResult string
	}{
		{name: "malformed", body: `{not-json`, wantResult: "malformed"},
		{
			name:       "rejected",
			body:       `{"source":"cli","scanned_at":"2026-05-04T18:21:00Z","duration_ms":-1,"agents":{"codex":{"installed":true,"has_config":false,"has_binary":false}}}`,
			wantResult: "rejected",
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			fixture := newOTLPV8MetricFixture(t)
			legacyReader := sdkmetric.NewManualReader()
			legacyProvider, err := telemetry.NewProviderForTest(legacyReader)
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = legacyProvider.Shutdown(context.Background()) })
			api := &APIServer{scannerCfg: &config.Config{ConfigVersion: 8}, otel: legacyProvider}
			api.bindObservabilityV8Runtimes(fixture.runtime, nil, nil, nil)
			legacyEvents := withCapturedEvents(t)

			request := httptest.NewRequest(http.MethodPost, "/api/v1/agents/discovery", strings.NewReader(test.body))
			request.Header.Set("Content-Type", "application/json")
			response := httptest.NewRecorder()
			api.handleAgentDiscovery(response, request)
			if response.Code != http.StatusBadRequest {
				t.Fatalf("status=%d body=%s", response.Code, response.Body.String())
			}

			rows := readStoredAgentDiscoveryV8(t, fixture.path)
			if len(rows) != 1 || rows[0].eventName != "agent.discovery.rejected" ||
				rows[0].bucket != "agent.lifecycle" || rows[0].body["defenseclaw.agent.discovery.result"] != test.wantResult {
				t.Fatalf("canonical rejected rows=%#v", rows)
			}
			for _, event := range *legacyEvents {
				if event.EventType == gatewaylog.EventLifecycle && event.Lifecycle != nil && event.Lifecycle.Subsystem == "agent_discovery" {
					t.Fatalf("v8 %s resurrected legacy lifecycle: %#v", test.name, event)
				}
			}
			var legacyMetrics metricdata.ResourceMetrics
			if err := legacyReader.Collect(t.Context(), &legacyMetrics); err != nil {
				t.Fatal(err)
			}
			if metric := findMetric(legacyMetrics, "defenseclaw.agent.discovery.runs"); metric != nil {
				t.Fatalf("v8 %s resurrected legacy discovery metric", test.name)
			}
		})
	}
}

func TestAgentDiscoveryV8DisabledCollectionIsLazyAndNeverFallsBack(t *testing.T) {
	fixture := newSidecarRuntimeFixture(t, false)
	legacyReader := sdkmetric.NewManualReader()
	legacyProvider, err := telemetry.NewProviderForTest(legacyReader)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = legacyProvider.Shutdown(context.Background()) })
	api := &APIServer{scannerCfg: &config.Config{ConfigVersion: 8}, otel: legacyProvider}
	api.bindObservabilityV8Runtimes(fixture.runtime, nil, nil, nil)
	legacyEvents := withCapturedEvents(t)

	request := httptest.NewRequest(http.MethodPost, "/api/v1/agents/discovery", strings.NewReader(validAgentDiscoveryBody()))
	request.Header.Set("Content-Type", "application/json")
	response := httptest.NewRecorder()
	api.handleAgentDiscovery(response, request)
	if response.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", response.Code, response.Body.String())
	}
	if rows := readStoredAgentDiscoveryV8(t, fixture.path); len(rows) != 0 {
		t.Fatalf("disabled agent.lifecycle collection built/stored rows: %#v", rows)
	}
	for _, event := range *legacyEvents {
		if event.EventType == gatewaylog.EventLifecycle && event.Lifecycle != nil && event.Lifecycle.Subsystem == "agent_discovery" {
			t.Fatalf("disabled v8 collection resurrected legacy lifecycle: %#v", event)
		}
	}
	var legacyMetrics metricdata.ResourceMetrics
	if err := legacyReader.Collect(t.Context(), &legacyMetrics); err != nil {
		t.Fatal(err)
	}
	if metric := findMetric(legacyMetrics, "defenseclaw.agent.discovery.runs"); metric != nil {
		t.Fatal("disabled v8 collection resurrected legacy discovery metric")
	}
}

func TestAgentDiscoveryV7RetainsGenericLifecycleCompatibilityEvent(t *testing.T) {
	api := &APIServer{scannerCfg: &config.Config{ConfigVersion: 7}}
	legacy := withCapturedEvents(t)
	request := httptest.NewRequest(http.MethodPost, "/api/v1/agents/discovery", strings.NewReader(validAgentDiscoveryBody()))
	request.Header.Set("Content-Type", "application/json")
	response := httptest.NewRecorder()
	api.handleAgentDiscovery(response, request)
	if response.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", response.Code, response.Body.String())
	}
	count := 0
	for _, event := range *legacy {
		if event.EventType == gatewaylog.EventLifecycle && event.Lifecycle != nil && event.Lifecycle.Subsystem == "agent_discovery" {
			count++
		}
	}
	if count != 1 {
		t.Fatalf("v7 agent-discovery lifecycle events=%d want exactly one", count)
	}
}
