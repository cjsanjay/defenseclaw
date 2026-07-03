// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"bytes"
	"database/sql"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/audit"
	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/observability"
	"github.com/defenseclaw/defenseclaw/internal/observability/runtimegraph"
	legacyredaction "github.com/defenseclaw/defenseclaw/internal/redaction"
	collectorlogspb "go.opentelemetry.io/proto/otlp/collector/logs/v1"
	commonpb "go.opentelemetry.io/proto/otlp/common/v1"
	logspb "go.opentelemetry.io/proto/otlp/logs/v1"
	"google.golang.org/protobuf/encoding/protowire"
	"google.golang.org/protobuf/proto"
)

type storedOTLPV8Event struct {
	action    string
	eventName string
	bucket    string
	source    string
	connector string
	severity  string
	payload   string
	mandatory int
}

func readStoredOTLPV8Events(t *testing.T, path string) []storedOTLPV8Event {
	t.Helper()
	database, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()
	rows, err := database.Query(`SELECT action, COALESCE(event_name,''), COALESCE(bucket,''),
		COALESCE(source,''), COALESCE(connector,''), COALESCE(severity,''),
		COALESCE(payload_json,''), COALESCE(mandatory,0)
		FROM audit_events WHERE bucket = 'telemetry.ingest' ORDER BY timestamp, id`)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	var result []storedOTLPV8Event
	for rows.Next() {
		var event storedOTLPV8Event
		if err := rows.Scan(
			&event.action, &event.eventName, &event.bucket, &event.source,
			&event.connector, &event.severity, &event.payload, &event.mandatory,
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

func disableOTLPV8Collection(t *testing.T, fixture sidecarRuntimeFixture) {
	t.Helper()
	disabled := false
	retentionDays := 0
	source := &config.ObservabilityV8Source{
		Local: config.ObservabilityV8LocalSource{
			Path:            fixture.path,
			JudgeBodiesPath: filepath.Join(filepath.Dir(fixture.path), "judge-bodies.db"),
			RetentionDays:   &retentionDays,
		},
		Buckets: map[observability.Bucket]config.ObservabilityV8BucketPolicySource{
			observability.BucketTelemetryIngest: {
				Collect: config.ObservabilityV8CollectSource{Logs: &disabled},
			},
		},
	}
	plan, err := config.CompileObservabilityV8(source)
	if err != nil {
		t.Fatal(err)
	}
	result, reloadErr := fixture.runtime.Reload(t.Context(), runtimegraph.ConfigFromPlan(plan, false))
	if reloadErr != nil || result.Status() != runtimegraph.ReloadApplied {
		t.Fatalf("disable telemetry.ingest collection: result=%+v err=%v", result, reloadErr)
	}
}

func TestOTLPIngestV8AcceptedBatchUsesCanonicalRouterWithoutRawBody(t *testing.T) {
	fixture := newSidecarRuntimeFixture(t, true)
	api := &APIServer{}
	api.bindOTLPObservabilityRuntime(fixture.runtime)
	body := `{"resourceLogs":[{"scopeLogs":[{"logRecords":[{"body":{"stringValue":"secret prompt must not persist"}}]}]}]}`
	request := httptest.NewRequest(http.MethodPost, "/v1/logs", strings.NewReader(body))
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set(otelSourceHeader, "codex")
	response := httptest.NewRecorder()

	api.handleOTLPLogs(response, request)

	if response.Code != http.StatusOK || response.Body.String() != "{}" {
		t.Fatalf("response=%d %q", response.Code, response.Body.String())
	}
	events := readStoredOTLPV8Events(t, fixture.path)
	if len(events) != 1 {
		t.Fatalf("events=%d want one: %#v", len(events), events)
	}
	event := events[0]
	if event.action != "otel.ingest.logs" || event.eventName != "telemetry.batch.accepted" ||
		event.bucket != "telemetry.ingest" || event.source != "otel_receiver" ||
		event.connector != "codex" || event.severity != "INFO" || event.mandatory != 0 {
		t.Fatalf("canonical event=%#v", event)
	}
	if strings.Contains(event.payload, "secret prompt") || strings.Contains(event.payload, "_splunk_hec_events") {
		t.Fatalf("canonical ingest metadata retained opaque body: %s", event.payload)
	}
	for _, want := range []string{`"record_count":1`, `"signal":"logs"`, `"normalization_result":"normalized"`} {
		if !strings.Contains(event.payload, want) {
			t.Errorf("payload missing %s: %s", want, event.payload)
		}
	}
}

func TestOTLPIngestV8RegistersEveryInboundSignalAsTelemetryIngestMetadata(t *testing.T) {
	fixture := newSidecarRuntimeFixture(t, true)
	api := &APIServer{}
	api.bindOTLPObservabilityRuntime(fixture.runtime)
	for _, test := range []struct {
		path string
		body string
	}{
		{path: "/v1/logs", body: `{"resourceLogs":[]}`},
		{path: "/v1/traces", body: `{"resourceSpans":[]}`},
		{path: "/v1/metrics", body: `{"resourceMetrics":[]}`},
	} {
		request := httptest.NewRequest(http.MethodPost, test.path, strings.NewReader(test.body))
		request.Header.Set("Content-Type", "application/json")
		response := httptest.NewRecorder()
		switch test.path {
		case "/v1/logs":
			api.handleOTLPLogs(response, request)
		case "/v1/traces":
			api.handleOTLPTraces(response, request)
		case "/v1/metrics":
			api.handleOTLPMetrics(response, request)
		}
		if response.Code != http.StatusOK {
			t.Fatalf("%s status=%d body=%q", test.path, response.Code, response.Body.String())
		}
	}
	events := readStoredOTLPV8Events(t, fixture.path)
	if len(events) != 3 {
		t.Fatalf("events=%d want three: %#v", len(events), events)
	}
	wantActions := map[string]bool{
		"otel.ingest.logs": false, "otel.ingest.traces": false, "otel.ingest.metrics": false,
	}
	for _, event := range events {
		if event.eventName != "telemetry.batch.accepted" || event.bucket != "telemetry.ingest" {
			t.Fatalf("unexpected signal metadata: %#v", event)
		}
		if _, ok := wantActions[event.action]; !ok {
			t.Fatalf("unregistered action: %#v", event)
		}
		wantActions[event.action] = true
	}
	for action, seen := range wantActions {
		if !seen {
			t.Errorf("missing canonical metadata for %s", action)
		}
	}
}

func TestOTLPIngestV8CollectionDropConstructsNoAcceptedRecord(t *testing.T) {
	fixture := newSidecarRuntimeFixture(t, true)
	disableOTLPV8Collection(t, fixture)
	api := &APIServer{}
	api.bindOTLPObservabilityRuntime(fixture.runtime)
	request := httptest.NewRequest(http.MethodPost, "/v1/metrics", strings.NewReader(`{"resourceMetrics":[]}`))
	request.Header.Set("Content-Type", "application/json")
	response := httptest.NewRecorder()

	api.handleOTLPMetrics(response, request)

	if response.Code != http.StatusOK {
		t.Fatalf("status=%d body=%q", response.Code, response.Body.String())
	}
	if events := readStoredOTLPV8Events(t, fixture.path); len(events) != 0 {
		t.Fatalf("collection-disabled accepted batch constructed records: %#v", events)
	}
}

func TestOTLPIngestV8MalformedBatchPersistsMandatoryFloorWhenCollectionDisabled(t *testing.T) {
	fixture := newSidecarRuntimeFixture(t, true)
	disableOTLPV8Collection(t, fixture)
	api := &APIServer{}
	api.bindOTLPObservabilityRuntime(fixture.runtime)
	request := httptest.NewRequest(http.MethodPost, "/v1/traces", strings.NewReader(`{"resourceSpans":[],"opaque":"raw"}`))
	request.Header.Set("Content-Type", "application/json")
	response := httptest.NewRecorder()

	api.handleOTLPTraces(response, request)

	if response.Code != http.StatusOK {
		t.Fatalf("status=%d body=%q", response.Code, response.Body.String())
	}
	events := readStoredOTLPV8Events(t, fixture.path)
	if len(events) != 1 {
		t.Fatalf("events=%d want mandatory floor: %#v", len(events), events)
	}
	if events[0].eventName != "telemetry.batch.rejected" || events[0].action != "otel.ingest.malformed" ||
		events[0].severity != "MEDIUM" || events[0].mandatory != 1 {
		t.Fatalf("malformed floor=%#v", events[0])
	}
	if strings.Contains(events[0].payload, "opaque") || strings.Contains(events[0].payload, "raw") {
		t.Fatalf("mandatory floor retained malformed body: %s", events[0].payload)
	}
}

func TestOTLPIngestV8AuthenticationFailurePersistsMandatoryTelemetryIngest(t *testing.T) {
	fixture := newSidecarRuntimeFixture(t, true)
	disableOTLPV8Collection(t, fixture)
	api := &APIServer{scannerCfg: &config.Config{}}
	api.scannerCfg.Gateway.Token = "configured-token"
	api.bindOTLPObservabilityRuntime(fixture.runtime)
	handler := api.tokenAuth(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		t.Fatal("unauthenticated request reached OTLP handler")
	}))
	request := httptest.NewRequest(http.MethodPost, "/v1/logs", strings.NewReader(`{"resourceLogs":[]}`))
	response := httptest.NewRecorder()

	handler.ServeHTTP(response, request)

	if response.Code != http.StatusUnauthorized {
		t.Fatalf("status=%d body=%q", response.Code, response.Body.String())
	}
	events := readStoredOTLPV8Events(t, fixture.path)
	if len(events) != 1 || events[0].eventName != "telemetry.authentication.failed" ||
		events[0].mandatory != 1 || events[0].connector != "unknown" {
		t.Fatalf("authentication floor=%#v", events)
	}
}

func TestNormalizeOTLPIngestBodyRejectsNestedUnknownProtobufFields(t *testing.T) {
	record := &logspb.LogRecord{Body: &commonpb.AnyValue{
		Value: &commonpb.AnyValue_StringValue{StringValue: "safe"},
	}}
	record.ProtoReflect().SetUnknown(protowire.AppendVarint(
		protowire.AppendTag(nil, 999, protowire.VarintType), 1,
	))
	payload := &collectorlogspb.ExportLogsServiceRequest{ResourceLogs: []*logspb.ResourceLogs{{
		ScopeLogs: []*logspb.ScopeLogs{{LogRecords: []*logspb.LogRecord{record}}},
	}}}
	body, err := proto.Marshal(payload)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := normalizeOTLPIngestBody(body, otelSignalLogs, "application/x-protobuf"); err == nil {
		t.Fatal("nested unknown protobuf field was silently preserved or dropped")
	}
}

func TestNormalizeOTLPIngestBodyRejectsUnknownJSONFields(t *testing.T) {
	body := []byte(`{"resourceLogs":[],"_splunk_hec_events":[{"event":"raw prompt"}]}`)
	if _, _, err := normalizeOTLPIngestBody(body, otelSignalLogs, "application/json"); err == nil {
		t.Fatal("unknown transport-specific field was silently accepted")
	}
}

func TestOTLPIngestV8SelfExportMarkersStopRecursiveEmission(t *testing.T) {
	fixture := newSidecarRuntimeFixture(t, true)
	api := &APIServer{}
	api.bindOTLPObservabilityRuntime(fixture.runtime)
	body := `{"resourceLogs":[{"scopeLogs":[{"logRecords":[{"body":{"stringValue":"{}"},"attributes":[
		{"key":"defenseclaw.record.id","value":{"stringValue":"record-1"}},
		{"key":"defenseclaw.bucket","value":{"stringValue":"telemetry.ingest"}},
		{"key":"defenseclaw.signal","value":{"stringValue":"logs"}},
		{"key":"defenseclaw.event.name","value":{"stringValue":"telemetry.batch.accepted"}}
	]}]}]}]}`
	request := httptest.NewRequest(http.MethodPost, "/v1/logs", bytes.NewBufferString(body))
	request.Header.Set("Content-Type", "application/json")
	response := httptest.NewRecorder()

	api.handleOTLPLogs(response, request)

	if response.Code != http.StatusOK {
		t.Fatalf("status=%d body=%q", response.Code, response.Body.String())
	}
	if events := readStoredOTLPV8Events(t, fixture.path); len(events) != 0 {
		t.Fatalf("self export recursively emitted telemetry: %#v", events)
	}
}

func TestOTLPIngestV8MixedSelfExportBatchIsNotSilentlyDropped(t *testing.T) {
	fixture := newSidecarRuntimeFixture(t, true)
	api := &APIServer{}
	api.bindOTLPObservabilityRuntime(fixture.runtime)
	body := `{"resourceLogs":[{"scopeLogs":[{"logRecords":[
		{"body":{"stringValue":"{}"},"attributes":[
			{"key":"defenseclaw.record.id","value":{"stringValue":"record-1"}},
			{"key":"defenseclaw.bucket","value":{"stringValue":"telemetry.ingest"}},
			{"key":"defenseclaw.signal","value":{"stringValue":"logs"}},
			{"key":"defenseclaw.event.name","value":{"stringValue":"telemetry.batch.accepted"}}
		]},
		{"body":{"stringValue":"external record must keep the batch alive"}}
	]}]}]}`
	request := httptest.NewRequest(http.MethodPost, "/v1/logs", bytes.NewBufferString(body))
	request.Header.Set("Content-Type", "application/json")
	response := httptest.NewRecorder()

	api.handleOTLPLogs(response, request)

	if response.Code != http.StatusOK {
		t.Fatalf("status=%d body=%q", response.Code, response.Body.String())
	}
	events := readStoredOTLPV8Events(t, fixture.path)
	if len(events) != 1 || events[0].eventName != "telemetry.batch.accepted" ||
		!strings.Contains(events[0].payload, `"record_count":2`) {
		t.Fatalf("mixed batch was dropped or misclassified: %#v", events)
	}
}

func TestDefenseClawSelfExportRequiresEveryTraceOrMetricItem(t *testing.T) {
	traceOwned := `{"resourceSpans":[{"resource":{"attributes":[
		{"key":"defenseclaw.instance.id","value":{"stringValue":"sidecar-1"}}
	]},"scopeSpans":[{"spans":[{"attributes":[
		{"key":"defenseclaw.bucket","value":{"stringValue":"agent.lifecycle"}},
		{"key":"defenseclaw.config.generation","value":{"intValue":"1"}}
	]}]}]}]}`
	traceMixed := strings.Replace(traceOwned, `]}]}]}]}`, `]},{"name":"external"}]}]}]}`, 1)
	metricOwned := `{"resourceMetrics":[{"resource":{"attributes":[
		{"key":"defenseclaw.instance.id","value":{"stringValue":"sidecar-1"}}
	]},"scopeMetrics":[{"metrics":[{"name":"defenseclaw.otel.ingest.requests"}]}]}]}`
	metricMixed := strings.Replace(metricOwned, `}]}]}]}`, `},{"name":"external.metric"}]}]}]}`, 1)
	for _, test := range []struct {
		name   string
		signal otelIngestSignal
		body   string
		want   bool
	}{
		{name: "all trace items owned", signal: otelSignalTraces, body: traceOwned, want: true},
		{name: "mixed trace items", signal: otelSignalTraces, body: traceMixed, want: false},
		{name: "all metric items owned", signal: otelSignalMetrics, body: metricOwned, want: true},
		{name: "mixed metric items", signal: otelSignalMetrics, body: metricMixed, want: false},
	} {
		t.Run(test.name, func(t *testing.T) {
			if got := isDefenseClawSelfExport([]byte(test.body), test.signal); got != test.want {
				t.Fatalf("isDefenseClawSelfExport()=%t want %t body=%s", got, test.want, test.body)
			}
		})
	}
}

func TestOTLPIngestUnboundPreservesLegacyRawAndHECCompatibility(t *testing.T) {
	legacyredaction.SetDisableAll(true)
	t.Cleanup(func() { legacyredaction.SetDisableAll(false) })
	store, logger := newOTLPIngestTestStore(t)
	api := NewAPIServer("127.0.0.1:0", NewSidecarHealth(), nil, store, logger)
	if api.hasOTLPObservabilityRuntime() {
		t.Fatal("NewAPIServer silently activated the incomplete v8 OTLP bridge")
	}
	body := `{"resourceLogs":[{"scopeLogs":[{"logRecords":[{
		"body":{"stringValue":"legacy raw prompt"},
		"attributes":[{"key":"event.name","value":{"stringValue":"legacy.event"}}]
	}]}]}]}`
	request := httptest.NewRequest(http.MethodPost, "/v1/logs", strings.NewReader(body))
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set(otelSourceHeader, "codex")
	response := httptest.NewRecorder()

	api.handleOTLPLogs(response, request)
	logger.Close()

	if response.Code != http.StatusOK {
		t.Fatalf("status=%d body=%q", response.Code, response.Body.String())
	}
	var details, structured string
	database, err := sql.Open("sqlite", store.DatabasePath())
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()
	if err := database.QueryRow(`SELECT COALESCE(details,''), COALESCE(structured_json,'')
		FROM audit_events WHERE action = ?`, string(audit.ActionOTelIngestLogs)).Scan(&details, &structured); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(details, "legacy raw prompt") || !strings.Contains(structured, "_splunk_hec_events") {
		t.Fatalf("unbound v7 compatibility changed: details=%q structured=%q", details, structured)
	}
}
