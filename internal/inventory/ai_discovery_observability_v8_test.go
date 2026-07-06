// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package inventory

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/telemetry"
	otellog "go.opentelemetry.io/otel/log"
	sdklog "go.opentelemetry.io/otel/sdk/log"
	sdkmetric "go.opentelemetry.io/otel/sdk/metric"
	"go.opentelemetry.io/otel/sdk/metric/metricdata"
	"go.opentelemetry.io/otel/sdk/trace/tracetest"
)

type captureAIDiscoveryV8 struct {
	mu         sync.Mutex
	starts     []AIDiscoveryV8ScanStart
	reports    []AIDiscoveryReport
	components [][]AIDiscoveryV8ComponentObservation
	trace      *captureAIDiscoveryV8Trace
}

func (capture *captureAIDiscoveryV8) StartScan(
	ctx context.Context,
	start AIDiscoveryV8ScanStart,
) (context.Context, AIDiscoveryV8ScanTrace, error) {
	capture.mu.Lock()
	defer capture.mu.Unlock()
	capture.starts = append(capture.starts, start)
	capture.trace = &captureAIDiscoveryV8Trace{}
	return context.WithValue(ctx, aiDiscoveryV8ContextKey{}, "v8"), capture.trace, nil
}

func (capture *captureAIDiscoveryV8) EmitReport(
	_ context.Context,
	report AIDiscoveryReport,
	components []AIDiscoveryV8ComponentObservation,
) error {
	capture.mu.Lock()
	defer capture.mu.Unlock()
	capture.reports = append(capture.reports, cloneAIDiscoveryReport(report))
	capture.components = append(capture.components, append([]AIDiscoveryV8ComponentObservation(nil), components...))
	return nil
}

type aiDiscoveryV8ContextKey struct{}

type captureAIDiscoveryV8Trace struct {
	mu        sync.Mutex
	starts    []AIDiscoveryV8DetectorStart
	results   []AIDiscoveryV8DetectorResult
	ended     []AIDiscoveryReport
	abortCall int
}

func (capture *captureAIDiscoveryV8Trace) StartDetector(start AIDiscoveryV8DetectorStart) (AIDiscoveryV8DetectorTrace, error) {
	capture.mu.Lock()
	capture.starts = append(capture.starts, start)
	capture.mu.Unlock()
	return &captureAIDiscoveryV8DetectorCapture{parent: capture}, nil
}

func (capture *captureAIDiscoveryV8Trace) End(report AIDiscoveryReport) error {
	capture.mu.Lock()
	capture.ended = append(capture.ended, cloneAIDiscoveryReport(report))
	capture.mu.Unlock()
	return nil
}

func (capture *captureAIDiscoveryV8Trace) Abort() {
	capture.mu.Lock()
	capture.abortCall++
	capture.mu.Unlock()
}

type captureAIDiscoveryV8DetectorCapture struct{ parent *captureAIDiscoveryV8Trace }

func (capture *captureAIDiscoveryV8DetectorCapture) End(result AIDiscoveryV8DetectorResult) error {
	capture.parent.mu.Lock()
	capture.parent.results = append(capture.parent.results, result)
	capture.parent.mu.Unlock()
	return nil
}

func (*captureAIDiscoveryV8DetectorCapture) Abort() {}

func TestAIDiscoveryV8AuthorityOwnsTraceAcrossEndAndDetach(t *testing.T) {
	service := &ContinuousDiscoveryService{opts: AIDiscoveryOptions{ConfigVersion: 8}}
	capture := &captureAIDiscoveryV8{}
	service.BindObservabilityV8(capture)
	start := time.Now().UTC().Add(-time.Second)
	ctx, observation := service.startScanObservation(t.Context(), AIDiscoveryV8ScanStart{
		ScanID: "scan-1", Source: "api", PrivacyMode: "enhanced", StartedAt: start,
	})
	if got := ctx.Value(aiDiscoveryV8ContextKey{}); got != "v8" || observation == nil || !observation.v8 {
		t.Fatalf("started context=%v observation=%+v", got, observation)
	}
	detector := observation.startDetector(ctx, service, AIDiscoveryV8DetectorStart{
		ScanID: "scan-1", Detector: "process", StartedAt: start.Add(time.Millisecond),
	})
	detector.end(AIDiscoveryV8DetectorResult{
		EndedAt: start.Add(2 * time.Millisecond), DurationMs: 1, SignalsTotal: 2,
	})
	report := AIDiscoveryReport{Summary: AIDiscoverySummary{ScanID: "scan-1", Result: "ok"}}
	observation.end(report)
	observation.abort()
	if len(capture.starts) != 1 || capture.trace == nil || len(capture.trace.starts) != 1 ||
		len(capture.trace.results) != 1 || len(capture.trace.ended) != 1 || capture.trace.abortCall != 1 {
		t.Fatalf("capture=%+v trace=%+v", capture, capture.trace)
	}

	service.BindObservabilityV8(nil)
	_, detached := service.startScanObservation(t.Context(), AIDiscoveryV8ScanStart{
		ScanID: "scan-2", Source: "scheduled", PrivacyMode: "enhanced", StartedAt: start,
	})
	if detached == nil || !detached.v8 || detached.generated != nil || len(capture.starts) != 1 {
		t.Fatalf("detached observation=%+v starts=%d", detached, len(capture.starts))
	}
}

func TestAIDiscoveryV8FanoutUsesOneRollupAndDoesNotResurrectLegacyAfterDetach(t *testing.T) {
	policy, err := LoadDefaultConfidencePolicy()
	if err != nil {
		t.Fatal(err)
	}
	service := &ContinuousDiscoveryService{
		opts:             AIDiscoveryOptions{ConfigVersion: 8, EmitOTel: true},
		confidenceParams: ConfidenceParams{Policy: policy},
	}
	capture := &captureAIDiscoveryV8{}
	service.BindObservabilityV8(capture)
	report := AIDiscoveryReport{
		Summary: AIDiscoverySummary{
			ScanID: "scan-1", Source: "scheduled", PrivacyMode: "enhanced", Result: "ok",
			TotalSignals: 1, ActiveSignals: 1, NewSignals: 1,
		},
		Signals: []AISignal{newComponentSignal(
			"signal-1", "pypi", "openai", "1.0.0", "workspace-1", AIStateNew, "OpenAI SDK",
		)},
	}
	service.fanoutReport(t.Context(), report)
	if len(capture.reports) != 1 || len(capture.components) != 1 || len(capture.components[0]) != 1 {
		t.Fatalf("reports=%d components=%v", len(capture.reports), capture.components)
	}
	component := capture.components[0][0]
	if component.ComponentID == "" || component.ComponentType == "" || !component.HasLifecycleChange ||
		component.Metrics.Ecosystem != "pypi" || component.Metrics.Name != "openai" {
		t.Fatalf("component=%+v", component)
	}

	service.BindObservabilityV8(nil)
	service.fanoutReport(t.Context(), report)
	if len(capture.reports) != 1 {
		t.Fatalf("detached v8 fanout resurrected an emitter: reports=%d", len(capture.reports))
	}
}

var _ AIDiscoveryObservabilityV8 = (*captureAIDiscoveryV8)(nil)

type droppedAIDiscoveryV8 struct{ reports int }

func (*droppedAIDiscoveryV8) StartScan(
	ctx context.Context,
	_ AIDiscoveryV8ScanStart,
) (context.Context, AIDiscoveryV8ScanTrace, error) {
	return ctx, nil, nil
}

func (observer *droppedAIDiscoveryV8) EmitReport(
	_ context.Context,
	_ AIDiscoveryReport,
	_ []AIDiscoveryV8ComponentObservation,
) error {
	observer.reports++
	return nil
}

func TestAIDiscoveryV8DroppedTraceAndReportNeverResurrectLegacyProvider(t *testing.T) {
	reader := sdkmetric.NewManualReader()
	traceExporter := tracetest.NewInMemoryExporter()
	legacy, err := telemetry.NewProviderForTraceTest(reader, traceExporter)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = legacy.Shutdown(context.Background()) })
	observer := &droppedAIDiscoveryV8{}
	service := &ContinuousDiscoveryService{
		opts: AIDiscoveryOptions{ConfigVersion: 8, EmitOTel: true}, otel: legacy,
	}
	service.BindObservabilityV8(observer)
	start := time.Now().UTC().Add(-time.Second)
	ctx, observation := service.startScanObservation(t.Context(), AIDiscoveryV8ScanStart{
		ScanID: "scan-drop", Source: "scheduled", PrivacyMode: "enhanced", StartedAt: start,
	})
	detector := observation.startDetector(ctx, service, AIDiscoveryV8DetectorStart{
		ScanID: "scan-drop", Detector: "process", StartedAt: start,
	})
	detector.end(AIDiscoveryV8DetectorResult{EndedAt: start.Add(time.Millisecond), DurationMs: 1})
	report := AIDiscoveryReport{Summary: AIDiscoverySummary{
		ScanID: "scan-drop", Source: "scheduled", PrivacyMode: "enhanced", Result: "ok",
	}}
	service.fanoutReport(ctx, report)
	observation.end(report)
	observation.abort()

	if observer.reports != 1 {
		t.Fatalf("canonical report calls=%d want one", observer.reports)
	}
	if spans := traceExporter.GetSpans(); len(spans) != 0 {
		t.Fatalf("dropped v8 trace resurrected %d legacy spans", len(spans))
	}
	var metrics metricdata.ResourceMetrics
	if err := reader.Collect(t.Context(), &metrics); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{
		"defenseclaw.ai.discovery.runs", "defenseclaw.ai.discovery.signals",
		"defenseclaw.ai.components.observations",
	} {
		if metric := findMetric(metrics, name); metric != nil {
			t.Fatalf("dropped v8 path resurrected legacy metric %q", name)
		}
	}
}

type captureAIDiscoveryV7Logs struct {
	mu      sync.Mutex
	records []sdklog.Record
}

func (capture *captureAIDiscoveryV7Logs) Export(_ context.Context, records []sdklog.Record) error {
	capture.mu.Lock()
	capture.records = append(capture.records, records...)
	capture.mu.Unlock()
	return nil
}

func (*captureAIDiscoveryV7Logs) Shutdown(context.Context) error { return nil }
func (*captureAIDiscoveryV7Logs) ForceFlush(context.Context) error {
	return nil
}

func (capture *captureAIDiscoveryV7Logs) eventNames() []string {
	capture.mu.Lock()
	defer capture.mu.Unlock()
	names := make([]string, 0, len(capture.records))
	for _, record := range capture.records {
		name := ""
		record.WalkAttributes(func(attribute otellog.KeyValue) bool {
			if attribute.Key == "event.name" && attribute.Value.Kind() == otellog.KindString {
				name = attribute.Value.AsString()
				return false
			}
			return true
		})
		names = append(names, name)
	}
	return names
}

func TestAIDiscoveryV7PreservesRootDetectorLogsMetricsAndSingleEnd(t *testing.T) {
	reader := sdkmetric.NewManualReader()
	traceExporter := tracetest.NewInMemoryExporter()
	logExporter := &captureAIDiscoveryV7Logs{}
	legacy, err := telemetry.NewProviderForTraceLogTest(reader, traceExporter, logExporter)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = legacy.Shutdown(context.Background()) })
	policy, err := LoadDefaultConfidencePolicy()
	if err != nil {
		t.Fatal(err)
	}
	service := &ContinuousDiscoveryService{
		opts: AIDiscoveryOptions{ConfigVersion: 7, EmitOTel: true}, otel: legacy,
		confidenceParams: ConfidenceParams{Policy: policy},
	}
	start := time.Now().UTC().Add(-time.Second)
	ctx, observation := service.startScanObservation(t.Context(), AIDiscoveryV8ScanStart{
		ScanID: "scan-v7", Source: "scheduled", PrivacyMode: "enhanced", StartedAt: start,
	})
	detector := observation.startDetector(ctx, service, AIDiscoveryV8DetectorStart{
		ScanID: "scan-v7", Detector: "process", StartedAt: start,
	})
	detector.end(AIDiscoveryV8DetectorResult{
		EndedAt: start.Add(time.Millisecond), DurationMs: 1, SignalsTotal: 1,
	})
	report := AIDiscoveryReport{
		Summary: AIDiscoverySummary{
			ScanID: "scan-v7", Source: "scheduled", PrivacyMode: "enhanced", Result: "ok",
			DurationMs: 5, TotalSignals: 1, ActiveSignals: 1, NewSignals: 1, FilesScanned: 1,
		},
		Signals: []AISignal{newComponentSignal(
			"signal-v7", "pypi", "openai", "1.0.0", "workspace-v7", AIStateNew, "OpenAI SDK",
		)},
	}
	service.fanoutReport(ctx, report)
	observation.end(report)
	observation.abort()

	spans := traceExporter.GetSpans()
	if len(spans) != 2 {
		t.Fatalf("legacy spans=%d want one detector + one root", len(spans))
	}
	byName := make(map[string]tracetest.SpanStub, len(spans))
	for _, span := range spans {
		byName[span.Name] = span
	}
	root, rootOK := byName["defenseclaw.ai.discovery"]
	detectorSpan, detectorOK := byName["defenseclaw.ai.discovery.detector"]
	if !rootOK || !detectorOK || detectorSpan.Parent.SpanID() != root.SpanContext.SpanID() ||
		detectorSpan.SpanContext.TraceID() != root.SpanContext.TraceID() {
		t.Fatalf("legacy discovery topology root=%+v detector=%+v", root, detectorSpan)
	}

	wantLogs := map[string]bool{
		"defenseclaw.ai.discovery":            false,
		"defenseclaw.ai.discovery.signal":     false,
		"defenseclaw.ai.confidence.component": false,
	}
	for _, name := range logExporter.eventNames() {
		if _, expected := wantLogs[name]; expected {
			wantLogs[name] = true
		}
	}
	for name, found := range wantLogs {
		if !found {
			t.Fatalf("legacy discovery log %q missing; got %v", name, logExporter.eventNames())
		}
	}

	var metrics metricdata.ResourceMetrics
	if err := reader.Collect(t.Context(), &metrics); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{
		"defenseclaw.ai.discovery.runs", "defenseclaw.ai.discovery.signals",
		"defenseclaw.ai.components.observations", "defenseclaw.ai.confidence.identity_score",
	} {
		if metric := findMetric(metrics, name); metric == nil {
			t.Fatalf("legacy discovery metric %q missing", name)
		}
	}
}

var _ AIDiscoveryObservabilityV8 = (*droppedAIDiscoveryV8)(nil)
var _ sdklog.Exporter = (*captureAIDiscoveryV7Logs)(nil)
