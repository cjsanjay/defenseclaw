// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/audit"
	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/observability"
	"github.com/defenseclaw/defenseclaw/internal/observability/redaction"
	observabilityruntime "github.com/defenseclaw/defenseclaw/internal/observability/runtime"
	"github.com/defenseclaw/defenseclaw/internal/observability/runtimegraph"
	"github.com/defenseclaw/defenseclaw/internal/telemetry"
)

type proxyCanonicalCapture struct {
	mu     sync.Mutex
	spans  []telemetry.V8CanonicalEndedSpan
	closed atomic.Bool
}

func (capture *proxyCanonicalCapture) TryEnqueue(span telemetry.V8CanonicalEndedSpan) telemetry.V8CanonicalSpanEnqueueResult {
	if capture.closed.Load() {
		return telemetry.V8CanonicalSpanEnqueueClosed
	}
	capture.mu.Lock()
	capture.spans = append(capture.spans, span)
	capture.mu.Unlock()
	return telemetry.V8CanonicalSpanEnqueueAccepted
}

func (*proxyCanonicalCapture) ForceFlush(context.Context) error { return nil }
func (capture *proxyCanonicalCapture) Shutdown(context.Context) error {
	capture.closed.Store(true)
	return nil
}

func (capture *proxyCanonicalCapture) snapshot() []telemetry.V8CanonicalEndedSpan {
	capture.mu.Lock()
	defer capture.mu.Unlock()
	return append([]telemetry.V8CanonicalEndedSpan(nil), capture.spans...)
}

func newProxyGeneratedTraceRuntime(t *testing.T) (*observabilityruntime.Runtime, *proxyCanonicalCapture) {
	t.Helper()
	directory := t.TempDir()
	store, err := audit.NewStore(filepath.Join(directory, "audit.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })
	if err := store.Init(); err != nil {
		t.Fatal(err)
	}
	retentionDays := 0
	plan, err := config.CompileObservabilityV8(&config.ObservabilityV8Source{
		Local: config.ObservabilityV8LocalSource{
			Path:            filepath.Join(directory, "audit.db"),
			JudgeBodiesPath: filepath.Join(directory, "judge-bodies.db"), RetentionDays: &retentionDays,
		},
		TracePolicy: config.ObservabilityV8TracePolicySource{Sampler: "always_on"},
		Destinations: []config.ObservabilityV8DestinationSource{{
			Name: "capture", Kind: config.ObservabilityV8DestinationOTLP,
			Protocol: "http/protobuf", Endpoint: "https://otel.example.test",
			Send: &config.ObservabilityV8SendSource{
				Signals: []observability.Signal{observability.SignalTraces},
				Buckets: []observability.Bucket{"*"}, RedactionProfile: "none",
			},
		}},
	})
	if err != nil {
		t.Fatal(err)
	}
	engine, err := redaction.NewEngine(nil)
	if err != nil {
		t.Fatal(err)
	}
	var sequence atomic.Uint64
	builder, err := observability.NewRecordBuilder(
		observability.ClockFunc(func() time.Time { return time.Now().UTC() }),
		observability.OccurrenceIDGeneratorFunc(func() (string, error) {
			return fmt.Sprintf("proxy-trace-failure-%d", sequence.Add(1)), nil
		}),
	)
	if err != nil {
		t.Fatal(err)
	}
	reaper, err := audit.NewRetentionReaper(store, nil, 0, audit.RetentionOptions{})
	if err != nil {
		t.Fatal(err)
	}
	retention, err := observabilityruntime.NewRetentionController(reaper, observabilityruntime.RetentionControllerOptions{})
	if err != nil {
		t.Fatal(err)
	}
	capture := &proxyCanonicalCapture{}
	providerFactory := telemetry.NewV8ProviderFactory(telemetry.V8ProviderOptions{
		Version: "proxy-test", Environment: "test", ServiceInstanceID: "proxy-test",
		GenerationPipelines: func(context.Context, *config.ObservabilityV8Plan, uint64, telemetry.V8MetricReaderSpec) (telemetry.V8GenerationPipelines, error) {
			return telemetry.V8GenerationPipelines{SpanPipelines: []telemetry.V8GenerationSpanPipeline{{
				Destination: "capture", Canonical: capture,
			}}}, nil
		},
	})
	runtime, err := observabilityruntime.New(t.Context(), runtimegraph.ConfigFromPlan(plan, false), observabilityruntime.Options{
		Store: store, Engine: engine, RecordBuilder: builder,
		Reporter: &discardSidecarGraphReporter{}, RetentionController: retention,
		TelemetryProviderFactory: providerFactory,
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if closeErr := runtime.Close(ctx); closeErr != nil {
			t.Errorf("close runtime: %v", closeErr)
		}
	})
	return runtime, capture
}

func TestHandleChatCompletionGeneratedTraceRejectsEmptyModelBeforeConstruction(t *testing.T) {
	runtime, capture := newProxyGeneratedTraceRuntime(t)
	provider := &mockProvider{}
	proxy := newTestProxy(t, provider, newMockInspector(), "action")
	proxy.SetDefaultAgentName("openclaw")
	proxy.bindObservabilityV8Trace(runtime)
	recorder := postChat(t, proxy, mustJSON(t, map[string]any{
		"messages": []map[string]any{{"role": "user", "content": "hello"}},
	}))
	if recorder.Code != 400 || provider.getLastReq() != nil || len(capture.snapshot()) != 0 {
		t.Fatalf("status=%d provider=%v spans=%d", recorder.Code, provider.getLastReq(), len(capture.snapshot()))
	}
}

func TestHandleChatCompletionGeneratedTraceNonStreamingOutcomes(t *testing.T) {
	toolCalls := json.RawMessage(`[{"id":"call-1","type":"function","function":{"name":"weather","arguments":"{\"city\":\"Austin\"}"}}]`)
	tests := []struct {
		name      string
		provider  *mockProvider
		inspect   func(*mockInspector)
		wantCode  int
		outcome   observability.Outcome
		status    string
		tools     int
		errorType string
	}{
		{name: "completed", provider: &mockProvider{}, wantCode: 200, outcome: observability.OutcomeCompleted, status: "Ok"},
		{name: "upstream failed", provider: &mockProvider{err: errors.New("upstream unavailable")}, wantCode: 502, outcome: observability.OutcomeFailed, status: "Error", errorType: "upstream_error"},
		{name: "output blocked", provider: &mockProvider{}, inspect: func(inspector *mockInspector) {
			inspector.setVerdict("completion", &ScanVerdict{Action: "block", Severity: "HIGH", Reason: "blocked"})
		}, wantCode: 200, outcome: observability.OutcomeBlocked, status: "Ok"},
		{name: "proposed tool call", provider: &mockProvider{response: &ChatResponse{
			ID: "chatcmpl-tool", Model: "gpt-4", Choices: []ChatChoice{{
				Message: &ChatMessage{Role: "assistant", ToolCalls: toolCalls}, FinishReason: strPtr("tool_calls"),
			}},
		}}, wantCode: 200, outcome: observability.OutcomeCompleted, status: "Ok", tools: 1},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			runtime, capture := newProxyGeneratedTraceRuntime(t)
			inspector := newMockInspector()
			if test.inspect != nil {
				test.inspect(inspector)
			}
			proxy := newTestProxy(t, test.provider, inspector, "action")
			proxy.SetDefaultAgentName("openclaw")
			proxy.bindObservabilityV8Trace(runtime)
			recorder := postChat(t, proxy, mustJSON(t, map[string]any{
				"model": "gpt-4", "messages": []map[string]any{{"role": "user", "content": "hello"}},
			}))
			if recorder.Code != test.wantCode {
				t.Fatalf("status=%d body=%s", recorder.Code, recorder.Body.String())
			}
			agent, model := assertProxyGeneratedAgentModel(t, capture.snapshot(), test.outcome, test.status)
			if model.EndTime().After(agent.EndTime()) {
				t.Fatalf("model ended after agent: model=%s agent=%s", model.EndTime(), agent.EndTime())
			}
			attributes := proxyCanonicalAttributes(t, model.Record())
			toolCount, countErr := attributes["defenseclaw.model.tool_call_count"].(json.Number).Int64()
			if countErr != nil || int(toolCount) != test.tools {
				t.Fatalf("tool count=%d error=%v want=%d", toolCount, countErr, test.tools)
			}
			if test.tools > 0 {
				if _, reported := attributes["gen_ai.output.messages"]; !reported {
					t.Fatal("tool-call-only model output was not represented structurally")
				}
			}
			if test.errorType != "" && attributes["error.type"] != test.errorType {
				t.Fatalf("error.type=%v want=%s", attributes["error.type"], test.errorType)
			}
			if _, fabricated := attributes["gen_ai.conversation.id"]; fabricated || model.Record().Correlation().SessionID != "" {
				t.Fatal("proxy fabricated conversation correlation")
			}
		})
	}
}

func TestHandleChatCompletionGeneratedTraceStreamingOutcomes(t *testing.T) {
	completedChunks := []StreamChunk{
		{ID: "chatcmpl-stream", Model: "gpt-4-actual", Choices: []ChatChoice{{Delta: &ChatMessage{Content: "hello "}}}},
		{ID: "chatcmpl-stream", Model: "gpt-4-actual", Choices: []ChatChoice{{Delta: &ChatMessage{Content: "world"}, FinishReason: strPtr("stop")}}},
	}
	tests := []struct {
		name     string
		provider *mockProvider
		inspect  func(*mockInspector)
		outcome  observability.Outcome
		status   string
	}{
		{name: "completed", provider: &mockProvider{streamChunks: completedChunks}, outcome: observability.OutcomeCompleted, status: "Ok"},
		{name: "upstream failed", provider: &mockProvider{err: errors.New("stream unavailable")}, outcome: observability.OutcomeFailed, status: "Error"},
		{name: "output blocked", provider: &mockProvider{streamChunks: completedChunks}, inspect: func(inspector *mockInspector) {
			inspector.setVerdict("completion", &ScanVerdict{Action: "block", Severity: "HIGH", Reason: "blocked"})
		}, outcome: observability.OutcomeBlocked, status: "Ok"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			runtime, capture := newProxyGeneratedTraceRuntime(t)
			inspector := newMockInspector()
			if test.inspect != nil {
				test.inspect(inspector)
			}
			proxy := newTestProxy(t, test.provider, inspector, "action")
			proxy.SetDefaultAgentName("openclaw")
			proxy.bindObservabilityV8Trace(runtime)
			recorder := postChat(t, proxy, mustJSON(t, map[string]any{
				"model": "gpt-4", "stream": true,
				"messages": []map[string]any{{"role": "user", "content": "hello"}},
			}))
			if recorder.Code != 200 {
				t.Fatalf("status=%d body=%s", recorder.Code, recorder.Body.String())
			}
			_, model := assertProxyGeneratedAgentModel(t, capture.snapshot(), test.outcome, test.status)
			attributes := proxyCanonicalAttributes(t, model.Record())
			if streaming, ok := attributes["defenseclaw.model.streaming"].(bool); !ok || !streaming {
				t.Fatalf("streaming=%v", attributes["defenseclaw.model.streaming"])
			}
		})
	}
}

func TestHandleChatCompletionGeneratedTraceUsesReportedConversationAndHonestModelRoot(t *testing.T) {
	t.Run("reported conversation", func(t *testing.T) {
		runtime, capture := newProxyGeneratedTraceRuntime(t)
		proxy := newTestProxy(t, &mockProvider{}, newMockInspector(), "action")
		proxy.SetDefaultAgentName("openclaw")
		proxy.bindObservabilityV8Trace(runtime)
		body := mustJSON(t, map[string]any{
			"model": "gpt-4", "messages": []map[string]any{{"role": "user", "content": "hello"}},
		})
		request := httptest.NewRequest(http.MethodPost, "/v1/chat/completions", bytes.NewReader(body))
		request.RemoteAddr = "127.0.0.1:12345"
		request.Header.Set("X-Conversation-ID", "conversation-reported")
		recorder := httptest.NewRecorder()
		proxy.handleChatCompletion(recorder, request)
		agent, model := assertProxyGeneratedAgentModel(
			t, capture.snapshot(), observability.OutcomeCompleted, "Ok",
		)
		for _, span := range []telemetry.V8CanonicalEndedSpan{agent, model} {
			if span.Record().Correlation().SessionID != "conversation-reported" ||
				proxyCanonicalAttributes(t, span.Record())["gen_ai.conversation.id"] != "conversation-reported" {
				t.Fatalf("family=%s conversation=%+v", span.Record().EventName(), span.Record().Correlation())
			}
		}
	})

	t.Run("no observed agent", func(t *testing.T) {
		runtime, capture := newProxyGeneratedTraceRuntime(t)
		proxy := newTestProxy(t, &mockProvider{}, newMockInspector(), "action")
		proxy.bindObservabilityV8Trace(runtime)
		recorder := postChat(t, proxy, mustJSON(t, map[string]any{
			"model": "gpt-4", "messages": []map[string]any{{"role": "user", "content": "hello"}},
		}))
		spans := capture.snapshot()
		if recorder.Code != 200 || len(spans) != 1 ||
			spans[0].Record().EventName() != observability.EventName(observability.TelemetryFamilyModelChat) {
			t.Fatalf("status=%d spans=%v", recorder.Code, spans)
		}
		attributes := proxyCanonicalAttributes(t, spans[0].Record())
		for _, key := range []string{"gen_ai.agent.id", "gen_ai.agent.name", "defenseclaw.agent.type"} {
			if _, fabricated := attributes[key]; fabricated {
				t.Fatalf("model root fabricated %s", key)
			}
		}
	})
}

func assertProxyGeneratedAgentModel(
	t *testing.T,
	spans []telemetry.V8CanonicalEndedSpan,
	outcome observability.Outcome,
	status string,
) (telemetry.V8CanonicalEndedSpan, telemetry.V8CanonicalEndedSpan) {
	t.Helper()
	if len(spans) != 2 {
		t.Fatalf("canonical spans=%d, want agent+model", len(spans))
	}
	var agent, model telemetry.V8CanonicalEndedSpan
	for _, span := range spans {
		switch span.Record().EventName() {
		case observability.EventName(observability.TelemetryFamilyAgentInvoke):
			agent = span
		case observability.EventName(observability.TelemetryFamilyModelChat):
			model = span
		default:
			t.Fatalf("unexpected canonical family %s", span.Record().EventName())
		}
	}
	if !agent.SpanID().IsValid() || !model.SpanID().IsValid() || agent.TraceID() != model.TraceID() {
		t.Fatalf("invalid topology agent=%s/%s model=%s/%s", agent.TraceID(), agent.SpanID(), model.TraceID(), model.SpanID())
	}
	parent, ok := model.ParentSpanID()
	if !ok || parent != agent.SpanID() {
		t.Fatalf("model parent=%s/%v want=%s", parent, ok, agent.SpanID())
	}
	for _, span := range []telemetry.V8CanonicalEndedSpan{agent, model} {
		if span.Record().Outcome() != outcome || span.StatusCode().String() != status {
			t.Fatalf("family=%s outcome/status=%s/%s want=%s/%s", span.Record().EventName(), span.Record().Outcome(), span.StatusCode(), outcome, status)
		}
	}
	return agent, model
}

func proxyCanonicalAttributes(t *testing.T, record observability.Record) map[string]any {
	t.Helper()
	body, ok := record.Body()
	if !ok {
		t.Fatal("canonical record has no body")
	}
	object, err := body.Object()
	if err != nil {
		t.Fatal(err)
	}
	attributes, ok := object["attributes"].(map[string]any)
	if !ok {
		t.Fatalf("attributes=%T", object["attributes"])
	}
	return attributes
}
