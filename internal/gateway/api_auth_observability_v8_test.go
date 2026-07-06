// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"context"
	"database/sql"
	"errors"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/audit"
	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/gateway/connector"
	"github.com/defenseclaw/defenseclaw/internal/gatewaylog"
	"github.com/defenseclaw/defenseclaw/internal/observability"
	"github.com/defenseclaw/defenseclaw/internal/observability/pipeline"
	"github.com/defenseclaw/defenseclaw/internal/observability/router"
	observabilityruntime "github.com/defenseclaw/defenseclaw/internal/observability/runtime"
	"github.com/defenseclaw/defenseclaw/internal/observability/runtimegraph"
	"github.com/defenseclaw/defenseclaw/internal/telemetry"
	sdkmetric "go.opentelemetry.io/otel/sdk/metric"
	"go.opentelemetry.io/otel/sdk/metric/metricdata"
)

type storedAPIAuthenticationFailure struct {
	action     string
	eventName  string
	bucket     string
	source     string
	severity   string
	mandatory  int
	payload    string
	projection string
	details    string
	structured string
	target     string
	actor      string
}

func readStoredAPIAuthenticationFailures(t *testing.T, path string) []storedAPIAuthenticationFailure {
	t.Helper()
	database, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()
	rows, err := database.Query(`SELECT action, COALESCE(event_name,''), COALESCE(bucket,''),
		COALESCE(source,''), COALESCE(severity,''), COALESCE(mandatory,0),
		COALESCE(payload_json,''), COALESCE(projected_record_json,''), COALESCE(details,''),
		COALESCE(structured_json,''), COALESCE(target,''), COALESCE(actor,'')
		FROM audit_events
		WHERE bucket = 'compliance.activity' AND event_name = 'authentication.failed'
		ORDER BY timestamp, id`)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	var events []storedAPIAuthenticationFailure
	for rows.Next() {
		var event storedAPIAuthenticationFailure
		if err := rows.Scan(
			&event.action, &event.eventName, &event.bucket, &event.source,
			&event.severity, &event.mandatory, &event.payload, &event.projection,
			&event.details, &event.structured, &event.target, &event.actor,
		); err != nil {
			t.Fatal(err)
		}
		events = append(events, event)
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
	return events
}

func newAPIAuthenticationTestProvider(t *testing.T) (*telemetry.Provider, *sdkmetric.ManualReader) {
	t.Helper()
	reader := sdkmetric.NewManualReader()
	provider, err := telemetry.NewProviderForTest(reader)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = provider.Shutdown(context.Background()) })
	return provider, reader
}

func apiAuthenticationMetricTotal(t *testing.T, reader *sdkmetric.ManualReader) int64 {
	t.Helper()
	counts := apiAuthenticationMetricCounts(t, reader)
	var total int64
	for _, count := range counts {
		total += count
	}
	return total
}

func apiAuthenticationMetricCounts(t *testing.T, reader *sdkmetric.ManualReader) map[string]int64 {
	t.Helper()
	var resources metricdata.ResourceMetrics
	if err := reader.Collect(t.Context(), &resources); err != nil {
		t.Fatal(err)
	}
	counts := make(map[string]int64)
	for _, scope := range resources.ScopeMetrics {
		for _, metric := range scope.Metrics {
			if metric.Name != "defenseclaw.http.auth.failures" {
				continue
			}
			sum, ok := metric.Data.(metricdata.Sum[int64])
			if !ok {
				t.Fatalf("auth failure metric type=%T", metric.Data)
			}
			for _, point := range sum.DataPoints {
				var route, reason string
				for _, attribute := range point.Attributes.ToSlice() {
					switch string(attribute.Key) {
					case "http.route":
						route = attribute.Value.AsString()
					case "reason":
						reason = attribute.Value.AsString()
					}
				}
				counts[route+"\x00"+reason] += point.Value
			}
		}
	}
	return counts
}

func configuredAPIAuthenticationServer(token string, provider *telemetry.Provider) *APIServer {
	cfg := &config.Config{}
	cfg.Gateway.Token = token
	return &APIServer{scannerCfg: cfg, otel: provider}
}

func TestAPIAuthenticationFailureV8ExclusivelyOwnsBearerAndCSRFFailures(t *testing.T) {
	fixture := newSidecarRuntimeFixture(t, true)
	provider, reader := newAPIAuthenticationTestProvider(t)
	api := configuredAPIAuthenticationServer("gateway-token", provider)
	api.bindOTLPObservabilityRuntime(fixture.runtime)
	events := withCapturedEvents(t)

	tests := []struct {
		name              string
		csrf              bool
		method            string
		token             string
		customToken       string
		contentType       string
		client            string
		origin            string
		secFetchSite      string
		noConfiguredToken bool
		wantStatus        int
		wantBody          string
		wantReason        string
	}{
		{
			name: "gateway token is not configured", method: http.MethodPost, noConfiguredToken: true,
			wantStatus: http.StatusServiceUnavailable,
			wantBody:   "{\"error\":\"sidecar misconfigured: no gateway token\"}\n",
			wantReason: "no_token_configured",
		},
		{
			name: "missing bearer", method: http.MethodPost,
			wantStatus: http.StatusUnauthorized, wantBody: "{\"error\":\"unauthorized\"}\n",
			wantReason: "missing_token",
		},
		{
			name: "invalid bearer", method: http.MethodPost, token: "attacker-bearer-secret",
			wantStatus: http.StatusUnauthorized, wantBody: "{\"error\":\"unauthorized\"}\n",
			wantReason: "invalid_token",
		},
		{
			name: "invalid custom token", method: http.MethodPost, customToken: "attacker-custom-secret",
			wantStatus: http.StatusUnauthorized, wantBody: "{\"error\":\"unauthorized\"}\n",
			wantReason: "invalid_token",
		},
		{
			name: "cross-site browser request", csrf: true, method: http.MethodPost, token: "gateway-token",
			secFetchSite: "cross-site", wantStatus: http.StatusForbidden,
			wantBody: "{\"error\":\"cross-site request rejected\"}\n", wantReason: "sec_fetch_site_rejected",
		},
		{
			name: "missing csrf marker", csrf: true, method: http.MethodPost, token: "gateway-token",
			contentType: "application/json", wantStatus: http.StatusForbidden,
			wantBody: "{\"error\":\"missing X-DefenseClaw-Client header\"}\n", wantReason: "csrf_mismatch",
		},
		{
			name: "blocked origin", csrf: true, method: http.MethodPost, token: "gateway-token",
			contentType: "application/json", client: "cli", origin: "https://attacker.example",
			wantStatus: http.StatusForbidden, wantBody: "{\"error\":\"non-localhost Origin rejected\"}\n",
			wantReason: "origin_blocked",
		},
		{
			name: "invalid content type", csrf: true, method: http.MethodPost, token: "gateway-token",
			contentType: "text/plain", client: "cli", wantStatus: http.StatusUnsupportedMediaType,
			wantBody:   "{\"error\":\"Content-Type must be application/json\"}\n",
			wantReason: "bad_content_type",
		},
		{
			name: "options missing csrf marker", csrf: true, method: http.MethodOptions, token: "gateway-token",
			wantStatus: http.StatusForbidden,
			wantBody:   "{\"error\":\"missing X-DefenseClaw-Client header\"}\n",
			wantReason: "csrf_mismatch_options",
		},
	}

	for i, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if test.noConfiguredToken {
				api.scannerCfg.Gateway.Token = ""
			} else {
				api.scannerCfg.Gateway.Token = "gateway-token"
			}
			next := http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
				t.Fatal("rejected authentication request reached handler")
			})
			var handler http.Handler = api.tokenAuth(next)
			if test.csrf {
				handler = api.tokenAuth(api.apiCSRFProtect(next))
			}
			request := httptest.NewRequest(test.method, "/v1/config?token=query-secret", nil)
			request.RemoteAddr = "203.0.113.77:4242"
			request.Header.Set("User-Agent", "attacker-user-agent-secret")
			if test.token != "" {
				request.Header.Set("Authorization", "Bearer "+test.token)
			}
			if test.customToken != "" {
				request.Header.Set("X-DefenseClaw-Token", test.customToken)
			}
			if test.contentType != "" {
				request.Header.Set("Content-Type", test.contentType)
			}
			if test.client != "" {
				request.Header.Set("X-DefenseClaw-Client", test.client)
			}
			if test.origin != "" {
				request.Header.Set("Origin", test.origin)
			}
			if test.secFetchSite != "" {
				request.Header.Set("Sec-Fetch-Site", test.secFetchSite)
			}
			response := httptest.NewRecorder()

			handler.ServeHTTP(response, request)

			if response.Code != test.wantStatus || response.Body.String() != test.wantBody {
				t.Fatalf("response=(%d,%q) want=(%d,%q)",
					response.Code, response.Body.String(), test.wantStatus, test.wantBody)
			}
			stored := readStoredAPIAuthenticationFailures(t, fixture.path)
			if len(stored) != i+1 {
				t.Fatalf("canonical events=%d want=%d: %#v", len(stored), i+1, stored)
			}
			event := stored[len(stored)-1]
			if event.action != string(audit.ActionAPIAuthFailure) ||
				event.eventName != string(observability.TelemetryEventAuthenticationFailed) ||
				event.bucket != string(observability.BucketComplianceActivity) ||
				event.source != string(observability.SourceOperatorAPI) ||
				event.severity != string(observability.SeverityMedium) || event.mandatory != 1 {
				t.Fatalf("canonical authentication event=%#v", event)
			}
			if !strings.Contains(event.payload, `"defenseclaw.admin.operation":"api-auth-failure"`) ||
				!strings.Contains(event.payload, `"defenseclaw.admin.reason":"`+test.wantReason+`"`) {
				t.Fatalf("canonical payload=%s", event.payload)
			}
			allStoredText := strings.Join([]string{
				event.payload, event.projection, event.details, event.structured,
				event.target, event.actor,
			}, " ")
			for _, forbidden := range []string{
				"attacker-bearer-secret", "attacker-custom-secret", "gateway-token", "query-secret",
				"203.0.113.77", "attacker-user-agent-secret", "attacker.example",
			} {
				if strings.Contains(allStoredText, forbidden) {
					t.Fatalf("canonical authentication event retained %q: %s", forbidden, allStoredText)
				}
			}
		})
	}

	if len(*events) != 0 {
		t.Fatalf("v8 authentication failures also emitted %d legacy gateway events: %#v", len(*events), *events)
	}
	metricCounts := apiAuthenticationMetricCounts(t, reader)
	wantMetricCounts := make(map[string]int64)
	for _, test := range tests {
		wantMetricCounts["sidecar-api\x00"+test.wantReason]++
	}
	if len(metricCounts) != len(wantMetricCounts) {
		t.Fatalf("v8 authentication metric series=%#v want=%#v", metricCounts, wantMetricCounts)
	}
	for key, want := range wantMetricCounts {
		if got := metricCounts[key]; got != want {
			t.Fatalf("v8 authentication metric %q count=%d want=%d; all=%#v",
				key, got, want, metricCounts)
		}
	}
}

func TestAPIAuthenticationFailureV8DisabledCollectionUsesLocalMandatoryFloor(t *testing.T) {
	fixture := newSidecarRuntimeFixture(t, true)
	disableAPIAuthenticationCollection(t, fixture)
	provider, reader := newAPIAuthenticationTestProvider(t)
	api := configuredAPIAuthenticationServer("gateway-token", provider)
	api.bindOTLPObservabilityRuntime(fixture.runtime)
	events := withCapturedEvents(t)
	handler := api.tokenAuth(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		t.Fatal("unauthenticated request reached handler")
	}))
	request := httptest.NewRequest(http.MethodPost, "/v1/config?token=floor-query-secret", nil)
	request.Header.Set("User-Agent", "floor-user-agent-secret")
	response := httptest.NewRecorder()

	handler.ServeHTTP(response, request)

	if response.Code != http.StatusUnauthorized || response.Body.String() != "{\"error\":\"unauthorized\"}\n" {
		t.Fatalf("response=%d %q", response.Code, response.Body.String())
	}
	stored := readStoredAPIAuthenticationFailures(t, fixture.path)
	if len(stored) != 1 || stored[0].mandatory != 1 ||
		stored[0].eventName != string(observability.TelemetryEventAuthenticationFailed) {
		t.Fatalf("authentication floor=%#v", stored)
	}
	allStoredText := stored[0].payload + stored[0].projection + stored[0].details + stored[0].structured
	for _, forbidden := range []string{
		"missing_token", "floor-query-secret", "floor-user-agent-secret", "defenseclaw.admin.reason",
	} {
		if strings.Contains(allStoredText, forbidden) {
			t.Fatalf("mandatory floor retained ordinary or request content %q: %s", forbidden, allStoredText)
		}
	}
	if len(*events) != 0 || apiAuthenticationMetricTotal(t, reader) != 1 {
		t.Fatalf("mandatory floor log ownership or independent metric count changed: events=%#v", *events)
	}
}

func disableAPIAuthenticationCollection(t *testing.T, fixture sidecarRuntimeFixture) {
	t.Helper()
	disabled := false
	retentionDays := 0
	source := &config.ObservabilityV8Source{
		Local: config.ObservabilityV8LocalSource{
			Path: fixture.path, JudgeBodiesPath: filepath.Join(filepath.Dir(fixture.path), "judge-bodies.db"),
			RetentionDays: &retentionDays,
		},
		Buckets: map[observability.Bucket]config.ObservabilityV8BucketPolicySource{
			observability.BucketComplianceActivity: {
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
		t.Fatalf("disable compliance collection: result=%+v err=%v", result, reloadErr)
	}
}

type failingAPIAuthenticationEmitter struct {
	mu       sync.Mutex
	calls    int
	metadata router.Metadata
}

func (emitter *failingAPIAuthenticationEmitter) Emit(
	_ context.Context,
	metadata router.Metadata,
	_ observabilityruntime.EmitBuilder,
) (pipeline.LocalLogOutcome, error) {
	emitter.mu.Lock()
	emitter.calls++
	emitter.metadata = metadata
	emitter.mu.Unlock()
	return pipeline.LocalLogOutcome{}, errors.New("simulated canonical persistence failure containing secret-input")
}

func TestAPIAuthenticationFailureV8EmissionFailureNeverFallsBack(t *testing.T) {
	provider, reader := newAPIAuthenticationTestProvider(t)
	emitter := &failingAPIAuthenticationEmitter{}
	api := configuredAPIAuthenticationServer("gateway-token", provider)
	api.bindOTLPObservabilityRuntime(emitter)
	events := withCapturedEvents(t)
	handler := api.tokenAuth(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		t.Fatal("unauthenticated request reached handler")
	}))
	request := httptest.NewRequest(http.MethodPost, "/v1/config", nil)
	request.Header.Set("Authorization", "Bearer failure-secret")
	response := httptest.NewRecorder()

	handler.ServeHTTP(response, request)

	if response.Code != http.StatusUnauthorized || response.Body.String() != "{\"error\":\"unauthorized\"}\n" {
		t.Fatalf("response=%d %q", response.Code, response.Body.String())
	}
	emitter.mu.Lock()
	calls, metadata := emitter.calls, emitter.metadata
	emitter.mu.Unlock()
	if calls != 1 || metadata.Identity().Name != observability.EventName(observability.TelemetryEventAuthenticationFailed) ||
		metadata.Identity().Bucket != observability.BucketComplianceActivity ||
		metadata.Source() != observability.SourceOperatorAPI ||
		metadata.Action() != observability.ProducerKey(audit.ActionAPIAuthFailure) {
		t.Fatalf("canonical attempts=%d metadata=%+v", calls, metadata)
	}
	if len(*events) != 0 || apiAuthenticationMetricTotal(t, reader) != 1 {
		t.Fatalf("failed canonical emission resurrected the legacy log or lost its metric: events=%#v", *events)
	}
}

func TestAPIAuthenticationFailureV7PreservesResponseAndLegacyTelemetry(t *testing.T) {
	provider, reader := newAPIAuthenticationTestProvider(t)
	api := configuredAPIAuthenticationServer("gateway-token", provider)
	events := withCapturedEvents(t)
	handler := api.tokenAuth(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		t.Fatal("unauthenticated request reached handler")
	}))
	request := httptest.NewRequest(http.MethodPost, "/v1/config", nil)
	request.Header.Set("Authorization", "Bearer legacy-invalid-token")
	response := httptest.NewRecorder()

	handler.ServeHTTP(response, request)

	if response.Code != http.StatusUnauthorized || response.Body.String() != "{\"error\":\"unauthorized\"}\n" {
		t.Fatalf("legacy response=%d %q", response.Code, response.Body.String())
	}
	if len(*events) != 1 || (*events)[0].EventType != gatewaylog.EventError ||
		(*events)[0].Error == nil || (*events)[0].Error.Code != string(gatewaylog.ErrCodeAuthInvalidToken) {
		t.Fatalf("legacy gateway events=%#v", *events)
	}
	if got := apiAuthenticationMetricTotal(t, reader); got != 1 {
		t.Fatalf("legacy auth metric=%d want=1", got)
	}
}

func TestOTLPPathAuthenticationFailureKeepsSpecializedTelemetryOwner(t *testing.T) {
	fixture := newSidecarRuntimeFixture(t, true)
	provider, reader := newAPIAuthenticationTestProvider(t)
	api := configuredAPIAuthenticationServer("gateway-token", provider)
	api.SetOTLPPathTokens(map[connector.OTLPPathTokenScope]string{
		connector.OTLPScopeGeminiCLI: "scoped-token",
	})
	api.bindOTLPObservabilityRuntime(fixture.runtime)
	events := withCapturedEvents(t)
	handler := api.tokenAuth(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		t.Fatal("invalid scoped path token reached handler")
	}))
	request := httptest.NewRequest(
		http.MethodPost, "/otlp/geminicli/path-token-secret/v1/logs", strings.NewReader(`{"resourceLogs":[]}`),
	)
	request.RemoteAddr = "127.0.0.1:4242"
	response := httptest.NewRecorder()

	handler.ServeHTTP(response, request)

	if response.Code != http.StatusUnauthorized || response.Body.String() != "{\"error\":\"unauthorized\"}\n" {
		t.Fatalf("response=%d %q", response.Code, response.Body.String())
	}
	if generic := readStoredAPIAuthenticationFailures(t, fixture.path); len(generic) != 0 {
		t.Fatalf("OTLP path failure duplicated into compliance.activity: %#v", generic)
	}
	specialized := readStoredOTLPV8Events(t, fixture.path)
	if len(specialized) != 1 || specialized[0].eventName != "telemetry.authentication.failed" ||
		specialized[0].bucket != string(observability.BucketTelemetryIngest) || specialized[0].mandatory != 1 {
		t.Fatalf("specialized OTLP authentication event=%#v", specialized)
	}
	if strings.Contains(specialized[0].payload, "path-token-secret") {
		t.Fatalf("specialized OTLP event retained path token: %s", specialized[0].payload)
	}
	// This branch is explicitly outside the generic API cutover; pin the current
	// specialized OTLP behavior rather than silently changing it here.
	if len(*events) != 1 || apiAuthenticationMetricTotal(t, reader) != 1 {
		t.Fatalf("OTLP compatibility telemetry changed: events=%#v", *events)
	}
}
