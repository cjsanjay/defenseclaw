// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// SPDX-License-Identifier: Apache-2.0

package destinations

import (
	"context"
	"encoding/pem"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/observability"
	"github.com/defenseclaw/defenseclaw/internal/observability/delivery"
	"github.com/defenseclaw/defenseclaw/internal/observability/destinations/galileo"
	"github.com/defenseclaw/defenseclaw/internal/observability/redaction"
	"github.com/defenseclaw/defenseclaw/internal/telemetry"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/sdk/instrumentation"
	sdkmetric "go.opentelemetry.io/otel/sdk/metric"
	"go.opentelemetry.io/otel/sdk/metric/metricdata"
	"go.opentelemetry.io/otel/sdk/resource"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	"go.opentelemetry.io/otel/sdk/trace/tracetest"
	"go.opentelemetry.io/otel/trace"
	collectormetricpb "go.opentelemetry.io/proto/otlp/collector/metrics/v1"
	collectortracepb "go.opentelemetry.io/proto/otlp/collector/trace/v1"
	"google.golang.org/protobuf/proto"
)

type otlpGenerationCapture struct {
	mu      sync.Mutex
	traces  []*collectortracepb.ExportTraceServiceRequest
	metrics []*collectormetricpb.ExportMetricsServiceRequest
	headers []http.Header
	partial bool
}

func (capture *otlpGenerationCapture) handler(writer http.ResponseWriter, request *http.Request) {
	body, _ := io.ReadAll(request.Body)
	capture.mu.Lock()
	capture.headers = append(capture.headers, request.Header.Clone())
	partial := capture.partial
	switch request.URL.Path {
	case "/v1/traces":
		decoded := &collectortracepb.ExportTraceServiceRequest{}
		if err := proto.Unmarshal(body, decoded); err == nil {
			capture.traces = append(capture.traces, decoded)
		}
		capture.mu.Unlock()
		if partial {
			response, _ := proto.Marshal(&collectortracepb.ExportTraceServiceResponse{
				PartialSuccess: &collectortracepb.ExportTracePartialSuccess{RejectedSpans: 1},
			})
			writer.Header().Set("Content-Type", "application/x-protobuf")
			_, _ = writer.Write(response)
			return
		}
	case "/v1/metrics":
		decoded := &collectormetricpb.ExportMetricsServiceRequest{}
		if err := proto.Unmarshal(body, decoded); err == nil {
			capture.metrics = append(capture.metrics, decoded)
		}
		capture.mu.Unlock()
	default:
		capture.mu.Unlock()
		writer.WriteHeader(http.StatusNotFound)
		return
	}
	writer.Header().Set("Content-Type", "application/x-protobuf")
	writer.WriteHeader(http.StatusOK)
}

func (capture *otlpGenerationCapture) snapshot() ([]*collectortracepb.ExportTraceServiceRequest, []*collectormetricpb.ExportMetricsServiceRequest, []http.Header) {
	capture.mu.Lock()
	defer capture.mu.Unlock()
	return append([]*collectortracepb.ExportTraceServiceRequest(nil), capture.traces...),
		append([]*collectormetricpb.ExportMetricsServiceRequest(nil), capture.metrics...),
		append([]http.Header(nil), capture.headers...)
}

func generationMetricSpec() telemetry.V8MetricReaderSpec {
	return telemetry.V8MetricReaderSpec{
		ExportInterval: time.Hour, ExportTimeout: time.Second,
		Temporality: metricdata.DeltaTemporality, CardinalityLimit: 2_000,
	}
}

func compileGenerationPlan(t *testing.T, destinations ...config.ObservabilityV8DestinationSource) *config.ObservabilityV8Plan {
	t.Helper()
	plan, err := config.CompileObservabilityV8(&config.ObservabilityV8Source{Destinations: destinations})
	if err != nil {
		t.Fatal(err)
	}
	return plan
}

func traceSend(name, endpoint string, buckets []observability.Bucket) config.ObservabilityV8DestinationSource {
	return config.ObservabilityV8DestinationSource{
		Name: name, Kind: config.ObservabilityV8DestinationOTLP,
		Protocol: "http/protobuf", Endpoint: endpoint,
		Send: &config.ObservabilityV8SendSource{
			Signals: []observability.Signal{observability.SignalTraces}, Buckets: buckets,
			RedactionProfile: "none",
		},
		TLS:           config.ObservabilityV8TLSSource{Insecure: true},
		NetworkSafety: config.ObservabilityV8NetworkSafetySource{AllowPrivateNetworks: true},
		Batch:         config.ObservabilityV8BatchSource{ScheduledDelayMS: 1},
	}
}

func metricSend(name, endpoint string, buckets []observability.Bucket) config.ObservabilityV8DestinationSource {
	return config.ObservabilityV8DestinationSource{
		Name: name, Kind: config.ObservabilityV8DestinationOTLP,
		Protocol: "http/protobuf", Endpoint: endpoint,
		Send: &config.ObservabilityV8SendSource{
			Signals: []observability.Signal{observability.SignalMetrics}, Buckets: buckets,
		},
		TLS:           config.ObservabilityV8TLSSource{Insecure: true},
		NetworkSafety: config.ObservabilityV8NetworkSafetySource{AllowPrivateNetworks: true},
	}
}

func TestOTLPGenerationAssemblerUsesUnmaskedRuntimeTransportAndDefaultAllSignals(t *testing.T) {
	capture := &otlpGenerationCapture{}
	server := httptest.NewTLSServer(http.HandlerFunc(capture.handler))
	defer server.Close()
	certificate := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: server.Certificate().Raw})
	const caPath = "/trusted/generation-ca.pem"
	secrets := &secretResolver{values: map[string]string{"OTLP_AUTH": "Bearer resolved-secret"}, calls: map[string]int{}}
	loader := &caLoader{bundles: map[string][]byte{caPath: certificate}, errors: map[string]error{}, calls: map[string]int{}}
	factory := newTestFactory(t, io.Discard, secrets, loader, net.Dialer{}, nil)
	plan := compileGenerationPlan(t, config.ObservabilityV8DestinationSource{
		Name: "all-signals", Kind: config.ObservabilityV8DestinationOTLP,
		Protocol: "http/protobuf", Endpoint: server.URL,
		Headers: map[string]config.ObservabilityV8HeaderValue{
			"Authorization": config.ObservabilityV8EnvironmentHeader("OTLP_AUTH"),
			"X-Static":      config.ObservabilityV8StaticHeader("runtime-unmasked-value"),
		},
		TLS:           config.ObservabilityV8TLSSource{CACert: caPath},
		NetworkSafety: config.ObservabilityV8NetworkSafetySource{AllowPrivateNetworks: true},
		Batch:         config.ObservabilityV8BatchSource{ScheduledDelayMS: 1},
	})
	pipelines, err := factory.PrepareOTLPGenerationPipelines(context.Background(), plan, 1, generationMetricSpec())
	if err != nil {
		t.Fatal(err)
	}
	if len(pipelines.SpanPipelines) != 1 || len(pipelines.MetricReaders) != 1 ||
		pipelines.CanaryAcknowledged == nil || secrets.callCount("OTLP_AUTH") != 1 || loader.callCount(caPath) != 1 {
		t.Fatalf("pipelines=%d/%d secret=%d CA=%d", len(pipelines.SpanPipelines), len(pipelines.MetricReaders), secrets.callCount("OTLP_AUTH"), loader.callCount(caPath))
	}
	if pipelines.SpanPipelines[0].Destination != "all-signals" ||
		pipelines.SpanPipelines[0].Legacy == nil || pipelines.SpanPipelines[0].Canonical != nil {
		t.Fatalf("OTLP trace pipeline is not a named legacy XOR: %+v", pipelines.SpanPipelines[0])
	}

	tracerProvider := sdktrace.NewTracerProvider(
		sdktrace.WithSampler(sdktrace.AlwaysSample()), sdktrace.WithSpanProcessor(pipelines.SpanPipelines[0].Legacy),
	)
	_, span := tracerProvider.Tracer("test").Start(context.Background(), "generation.trace",
		trace.WithAttributes(attribute.String("defenseclaw.bucket", string(observability.BucketAgentLifecycle))),
	)
	span.End()
	if err := tracerProvider.ForceFlush(context.Background()); err != nil {
		t.Fatal(err)
	}

	meterProvider := sdkmetric.NewMeterProvider(sdkmetric.WithReader(pipelines.MetricReaders[0]))
	meter := meterProvider.Meter("test")
	counter, err := meter.Int64Counter("defenseclaw.scan.count")
	if err != nil {
		t.Fatal(err)
	}
	counter.Add(context.Background(), 1)
	if err := meterProvider.ForceFlush(context.Background()); err != nil {
		t.Fatal(err)
	}

	traces, metrics, headers := capture.snapshot()
	if len(traces) != 1 || len(metrics) != 1 {
		t.Fatalf("requests traces=%d metrics=%d", len(traces), len(metrics))
	}
	for _, header := range headers {
		if header.Get("Authorization") != "Bearer resolved-secret" || header.Get("X-Static") != "runtime-unmasked-value" {
			t.Fatalf("masked or unresolved runtime headers: %+v", header)
		}
	}
	if err := tracerProvider.Shutdown(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err := meterProvider.Shutdown(context.Background()); err != nil {
		t.Fatal(err)
	}
}

func TestOTLPGenerationAssemblerAppliesBucketRoutesAcrossMultipleDestinations(t *testing.T) {
	agentCapture, toolCapture, metricCapture := &otlpGenerationCapture{}, &otlpGenerationCapture{}, &otlpGenerationCapture{}
	agentServer := httptest.NewServer(http.HandlerFunc(agentCapture.handler))
	toolServer := httptest.NewServer(http.HandlerFunc(toolCapture.handler))
	metricServer := httptest.NewServer(http.HandlerFunc(metricCapture.handler))
	defer agentServer.Close()
	defer toolServer.Close()
	defer metricServer.Close()
	factory := newTestFactory(t, io.Discard, nil, nil, net.Dialer{}, nil)
	plan := compileGenerationPlan(t,
		traceSend("agent-traces", agentServer.URL, []observability.Bucket{observability.BucketAgentLifecycle}),
		traceSend("tool-traces", toolServer.URL, []observability.Bucket{observability.BucketToolActivity}),
		metricSend("scan-metrics", metricServer.URL, []observability.Bucket{observability.BucketAssetScan}),
	)
	pipelines, err := factory.PrepareOTLPGenerationPipelines(context.Background(), plan, 7, generationMetricSpec())
	if err != nil {
		t.Fatal(err)
	}
	if len(pipelines.SpanPipelines) != 2 || len(pipelines.MetricReaders) != 1 {
		t.Fatalf("pipelines = %d/%d", len(pipelines.SpanPipelines), len(pipelines.MetricReaders))
	}
	if pipelines.SpanPipelines[0].Destination != "agent-traces" ||
		pipelines.SpanPipelines[1].Destination != "tool-traces" {
		t.Fatalf("named OTLP pipeline order = %q/%q", pipelines.SpanPipelines[0].Destination, pipelines.SpanPipelines[1].Destination)
	}
	tracerOptions := []sdktrace.TracerProviderOption{sdktrace.WithSampler(sdktrace.AlwaysSample())}
	for _, pipeline := range pipelines.SpanPipelines {
		tracerOptions = append(tracerOptions, sdktrace.WithSpanProcessor(pipeline.Legacy))
	}
	tracerProvider := sdktrace.NewTracerProvider(tracerOptions...)
	tracer := tracerProvider.Tracer("test")
	for _, bucket := range []observability.Bucket{observability.BucketAgentLifecycle, observability.BucketToolActivity} {
		_, span := tracer.Start(context.Background(), "route."+string(bucket),
			trace.WithAttributes(attribute.String("defenseclaw.bucket", string(bucket))),
		)
		span.End()
	}
	if err := tracerProvider.ForceFlush(context.Background()); err != nil {
		t.Fatal(err)
	}

	meterProvider := sdkmetric.NewMeterProvider(sdkmetric.WithReader(pipelines.MetricReaders[0]))
	meter := meterProvider.Meter("test")
	for _, name := range []string{"defenseclaw.scan.count", "defenseclaw.activity.total"} {
		counter, err := meter.Int64Counter(name)
		if err != nil {
			t.Fatal(err)
		}
		counter.Add(context.Background(), 1)
	}
	if err := meterProvider.ForceFlush(context.Background()); err != nil {
		t.Fatal(err)
	}

	agentTraces, _, _ := agentCapture.snapshot()
	toolTraces, _, _ := toolCapture.snapshot()
	_, metricRequests, _ := metricCapture.snapshot()
	if traceNames(agentTraces) != "route.agent.lifecycle" || traceNames(toolTraces) != "route.tool.activity" {
		t.Fatalf("trace routes agent=%q tool=%q", traceNames(agentTraces), traceNames(toolTraces))
	}
	if names := metricNames(metricRequests); len(names) != 1 || names[0] != "defenseclaw.scan.count" {
		t.Fatalf("metric route names=%v", names)
	}
	_ = tracerProvider.Shutdown(context.Background())
	_ = meterProvider.Shutdown(context.Background())
}

func TestOTLPGenerationAssemblerAppliesMetricEventNameFirstMatchRoutes(t *testing.T) {
	capture := &otlpGenerationCapture{}
	server := httptest.NewServer(http.HandlerFunc(capture.handler))
	defer server.Close()
	factory := newTestFactory(t, io.Discard, nil, nil, net.Dialer{}, nil)
	plan := compileGenerationPlan(t, config.ObservabilityV8DestinationSource{
		Name: "metric-event-route", Kind: config.ObservabilityV8DestinationOTLP,
		Protocol: "http/protobuf", Endpoint: server.URL,
		Routes: []config.ObservabilityV8RouteSource{
			{
				Name: "scan-count", Signals: []observability.Signal{observability.SignalMetrics},
				Selector: &config.ObservabilityV8SelectorSource{
					Buckets: []observability.Bucket{observability.BucketAssetScan},
					EventNames: []observability.EventName{
						"defenseclaw.scan.count",
					},
				},
				Action: config.ObservabilityV8RouteSend,
			},
			{
				Name: "drop-rest", Signals: []observability.Signal{observability.SignalMetrics},
				Selector: &config.ObservabilityV8SelectorSource{
					Buckets:    []observability.Bucket{"*"},
					EventNames: []observability.EventName{"*"},
				},
				Action: config.ObservabilityV8RouteDrop,
			},
		},
		TLS:           config.ObservabilityV8TLSSource{Insecure: true},
		NetworkSafety: config.ObservabilityV8NetworkSafetySource{AllowPrivateNetworks: true},
	})
	pipelines, err := factory.PrepareOTLPGenerationPipelines(context.Background(), plan, 8, generationMetricSpec())
	if err != nil {
		t.Fatal(err)
	}
	if len(pipelines.SpanPipelines) != 0 || len(pipelines.MetricReaders) != 1 {
		t.Fatalf("pipelines=%d/%d", len(pipelines.SpanPipelines), len(pipelines.MetricReaders))
	}
	if pipelines.CanaryAcknowledged != nil {
		t.Fatal("metric-only pipeline exposed a trace acknowledgement callback")
	}
	meterProvider := sdkmetric.NewMeterProvider(sdkmetric.WithReader(pipelines.MetricReaders[0]))
	meter := meterProvider.Meter("test")
	for _, name := range []string{"defenseclaw.scan.count", "defenseclaw.scan.errors"} {
		counter, counterErr := meter.Int64Counter(name)
		if counterErr != nil {
			t.Fatal(counterErr)
		}
		counter.Add(context.Background(), 1)
	}
	if err := meterProvider.ForceFlush(context.Background()); err != nil {
		t.Fatal(err)
	}
	_, requests, _ := capture.snapshot()
	if names := metricNames(requests); len(names) != 1 || names[0] != "defenseclaw.scan.count" {
		t.Fatalf("metric event-name route names=%v", names)
	}
	if err := meterProvider.Shutdown(context.Background()); err != nil {
		t.Fatal(err)
	}
}

func TestOTLPGenerationAssemblerRejectsTransformedAndUnsupportedTracePoliciesBeforeResolution(t *testing.T) {
	secrets := &secretResolver{values: map[string]string{"SECRET": "value"}, calls: map[string]int{}}
	factory := newTestFactory(t, io.Discard, secrets, nil, net.Dialer{}, nil)
	tests := []struct {
		name        string
		destination config.ObservabilityV8DestinationSource
	}{
		{name: "redacted", destination: func() config.ObservabilityV8DestinationSource {
			value := traceSend("redacted", "https://8.8.8.8:4318", []observability.Bucket{observability.BucketAgentLifecycle})
			value.Send.RedactionProfile = "sensitive"
			return value
		}()},
		{name: "advanced source selector", destination: config.ObservabilityV8DestinationSource{
			Name: "advanced", Kind: config.ObservabilityV8DestinationOTLP,
			Protocol: "http/protobuf", Endpoint: "https://8.8.8.8:4318",
			Routes: []config.ObservabilityV8RouteSource{{
				Name: "source", Signals: []observability.Signal{observability.SignalTraces},
				Selector:         &config.ObservabilityV8SelectorSource{Sources: []observability.Source{observability.SourceGateway}},
				RedactionProfile: "none",
			}},
		}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			test.destination.Headers = map[string]config.ObservabilityV8HeaderValue{
				"Authorization": config.ObservabilityV8EnvironmentHeader("SECRET"),
			}
			plan := compileGenerationPlan(t, test.destination)
			pipelines, err := factory.PrepareOTLPGenerationPipelines(context.Background(), plan, 20, generationMetricSpec())
			if len(pipelines.SpanPipelines) != 0 || len(pipelines.MetricReaders) != 0 || !IsError(err, ErrorUnsupportedPolicy) {
				t.Fatalf("pipelines=%+v error=%v", pipelines, err)
			}
		})
	}
	if secrets.callCount("SECRET") != 0 {
		t.Fatalf("unsupported policies resolved secret %d times", secrets.callCount("SECRET"))
	}
}

func TestOTLPGenerationAssemblerPreparesCanonicalGalileoAndNeverRawLegacy(t *testing.T) {
	capture := &otlpGenerationCapture{}
	server := httptest.NewServer(http.HandlerFunc(capture.handler))
	defer server.Close()
	factory := newTestFactory(t, io.Discard, nil, nil, net.Dialer{}, nil)
	enableGalileoGeneration(t, factory)
	destination := traceSend("galileo", server.URL, []observability.Bucket{"*"})
	destination.Preset = "galileo"
	plan := compileGenerationPlan(t, destination)

	pipelines, err := factory.PrepareOTLPGenerationPipelines(
		context.Background(), plan, 21, generationMetricSpec(),
	)
	if err != nil {
		t.Fatal(err)
	}
	if len(pipelines.SpanPipelines) != 1 || pipelines.SpanPipelines[0].Destination != "galileo" ||
		pipelines.SpanPipelines[0].Canonical == nil || pipelines.SpanPipelines[0].Legacy != nil ||
		pipelines.CanaryAcknowledged == nil {
		t.Fatalf("Galileo pipeline is not canonical XOR: %+v", pipelines)
	}
	// A zero handoff is intentionally invalid, but returning failed rather than
	// closed proves activation happened only after the generation was complete.
	if result := pipelines.SpanPipelines[0].Canonical.TryEnqueue(telemetry.V8CanonicalEndedSpan{}); result != telemetry.V8CanonicalSpanEnqueueFailed {
		t.Fatalf("activated canonical consumer result=%s", result)
	}
	if traces, _, _ := capture.snapshot(); len(traces) != 0 {
		t.Fatalf("invalid canonical handoff reached network: %d requests", len(traces))
	}
	if err := pipelines.SpanPipelines[0].Canonical.Shutdown(context.Background()); err != nil {
		t.Fatal(err)
	}
	if factory.OTLPGenerationAcknowledgedCanaryTrace(21, "galileo", "0102030405060708090a0b0c0d0e0f10") {
		t.Fatal("Galileo canary registry outlived canonical consumer")
	}
}

func TestOTLPGenerationAssemblerRejectsGalileoWithoutCentralDependenciesBeforeSecrets(t *testing.T) {
	secrets := &secretResolver{values: map[string]string{"SECRET": "value"}, calls: map[string]int{}}
	factory := newTestFactory(t, io.Discard, secrets, nil, net.Dialer{}, nil)
	destination := traceSend("galileo", "https://8.8.8.8:4318", []observability.Bucket{"*"})
	destination.Preset = "galileo"
	destination.Headers = map[string]config.ObservabilityV8HeaderValue{
		"Authorization": config.ObservabilityV8EnvironmentHeader("SECRET"),
	}
	plan := compileGenerationPlan(t, destination)
	pipelines, err := factory.PrepareOTLPGenerationPipelines(context.Background(), plan, 22, generationMetricSpec())
	if len(pipelines.SpanPipelines) != 0 || !IsError(err, ErrorInvalidDependencies) {
		t.Fatalf("pipelines=%+v error=%v", pipelines, err)
	}
	if secrets.callCount("SECRET") != 0 {
		t.Fatalf("missing Galileo dependencies resolved secret %d times", secrets.callCount("SECRET"))
	}
}

func enableGalileoGeneration(t *testing.T, factory *Factory) {
	t.Helper()
	engine, err := redaction.NewEngine(nil)
	if err != nil {
		t.Fatal(err)
	}
	factory.redaction = engine
	factory.deliveryObserver = delivery.ObserverFunc(func(delivery.HealthTransition) {})
	factory.galileoObserver = galileo.CanonicalObserverFunc(func(galileo.CanonicalFailure) {})
}

func TestOTLPGenerationCanaryTargetIsolationAcknowledgementAndSplitBatch(t *testing.T) {
	for _, test := range []struct {
		name      string
		batchSize int
		partial   bool
		wantAck   bool
		wantCalls int
	}{
		{name: "complete zero rejection", batchSize: 2, wantAck: true, wantCalls: 1},
		{name: "split batch is not exact trace", batchSize: 1, wantCalls: 2},
		{name: "partial rejection", batchSize: 2, partial: true, wantCalls: 1},
	} {
		t.Run(test.name, func(t *testing.T) {
			targetCapture, otherCapture := &otlpGenerationCapture{partial: test.partial}, &otlpGenerationCapture{}
			targetServer := httptest.NewServer(http.HandlerFunc(targetCapture.handler))
			otherServer := httptest.NewServer(http.HandlerFunc(otherCapture.handler))
			defer targetServer.Close()
			defer otherServer.Close()
			target := traceSend("target", targetServer.URL, generationCanaryBuckets())
			other := traceSend("other", otherServer.URL, generationCanaryBuckets())
			target.Batch.MaxExportBatchSize = test.batchSize
			other.Batch.MaxExportBatchSize = test.batchSize
			plan := compileGenerationPlan(t, target, other)
			factory := newTestFactory(t, io.Discard, nil, nil, net.Dialer{}, nil)
			pipelines, err := factory.PrepareOTLPGenerationPipelines(context.Background(), plan, 31, generationMetricSpec())
			if err != nil {
				t.Fatal(err)
			}
			traceID := trace.TraceID{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16}
			for _, operation := range []string{"chat", "invoke_agent"} {
				span := generationCanarySpan(traceID, operation, "target")
				for _, pipeline := range pipelines.SpanPipelines {
					pipeline.Legacy.OnEnd(span)
				}
			}
			for _, pipeline := range pipelines.SpanPipelines {
				if err := pipeline.Legacy.ForceFlush(context.Background()); err != nil {
					t.Fatal(err)
				}
			}
			targetTraces, _, _ := targetCapture.snapshot()
			otherTraces, _, _ := otherCapture.snapshot()
			if len(targetTraces) != test.wantCalls || len(otherTraces) != 0 {
				t.Fatalf("target/other calls=%d/%d", len(targetTraces), len(otherTraces))
			}
			if got := factory.OTLPGenerationAcknowledgedCanaryTrace(31, "target", traceID.String()); got != test.wantAck {
				t.Fatalf("acknowledged=%t want=%t", got, test.wantAck)
			}
			for _, pipeline := range pipelines.SpanPipelines {
				_ = pipeline.Legacy.Shutdown(context.Background())
			}
			if factory.OTLPGenerationAcknowledgedCanaryTrace(31, "target", traceID.String()) {
				t.Fatal("acknowledgement outlived generation processors")
			}
		})
	}
}

func TestOTLPGenerationAssemblerKeepsReloadGenerationsIsolated(t *testing.T) {
	capture := &otlpGenerationCapture{}
	server := httptest.NewServer(http.HandlerFunc(capture.handler))
	defer server.Close()
	factory := newTestFactory(t, io.Discard, nil, nil, net.Dialer{}, nil)
	plan := compileGenerationPlan(t,
		traceSend("reload-traces", server.URL, generationCanaryBuckets()),
	)
	oldPipelines, err := factory.PrepareOTLPGenerationPipelines(context.Background(), plan, 41, generationMetricSpec())
	if err != nil {
		t.Fatal(err)
	}
	newPipelines, err := factory.PrepareOTLPGenerationPipelines(context.Background(), plan, 42, generationMetricSpec())
	if err != nil {
		cleanupOTLPGenerationPipelines(oldPipelines)
		t.Fatal(err)
	}
	if len(oldPipelines.SpanPipelines) != 1 || len(newPipelines.SpanPipelines) != 1 {
		t.Fatalf("old/new processors=%d/%d", len(oldPipelines.SpanPipelines), len(newPipelines.SpanPipelines))
	}

	oldTraceID := trace.TraceID{1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1}
	newTraceID := trace.TraceID{2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2}
	emitGenerationCanary(t, oldPipelines.SpanPipelines, oldTraceID, "reload-traces")
	emitGenerationCanary(t, newPipelines.SpanPipelines, newTraceID, "reload-traces")
	if oldPipelines.CanaryAcknowledged == nil || newPipelines.CanaryAcknowledged == nil ||
		!oldPipelines.CanaryAcknowledged("reload-traces", oldTraceID.String()) ||
		!newPipelines.CanaryAcknowledged("reload-traces", newTraceID.String()) {
		t.Fatal("reload generations did not retain independent acknowledgements")
	}
	if oldPipelines.CanaryAcknowledged("reload-traces", newTraceID.String()) ||
		newPipelines.CanaryAcknowledged("reload-traces", oldTraceID.String()) {
		t.Fatal("acknowledgement leaked across generation boundary")
	}

	cleanupOTLPGenerationPipelines(oldPipelines)
	if oldPipelines.CanaryAcknowledged("reload-traces", oldTraceID.String()) {
		t.Fatal("retired generation remained queryable")
	}
	if !newPipelines.CanaryAcknowledged("reload-traces", newTraceID.String()) {
		t.Fatal("retiring the old generation removed the active generation")
	}
	cleanupOTLPGenerationPipelines(newPipelines)
	if newPipelines.CanaryAcknowledged("reload-traces", newTraceID.String()) {
		t.Fatal("active generation remained queryable after shutdown")
	}

	traceRequests, _, _ := capture.snapshot()
	if len(traceRequests) != 2 {
		t.Fatalf("reload export requests=%d want=2", len(traceRequests))
	}
}

func TestOTLPGenerationAssemblerCleansPartialFailureWithoutAffectingActiveGeneration(t *testing.T) {
	capture := &otlpGenerationCapture{}
	server := httptest.NewTLSServer(http.HandlerFunc(capture.handler))
	defer server.Close()
	certificate := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: server.Certificate().Raw})
	const validCA = "/trusted/valid-generation-ca.pem"
	const invalidCA = "/trusted/invalid-generation-ca.pem"
	loader := &caLoader{
		bundles: map[string][]byte{validCA: certificate, invalidCA: []byte("not a certificate")},
		errors:  map[string]error{}, calls: map[string]int{},
	}
	factory := newTestFactory(t, io.Discard, nil, loader, net.Dialer{}, nil)
	activePlan := compileGenerationPlan(t, secureTraceSend(
		"active-traces", server.URL, validCA, generationCanaryBuckets(),
	))
	active, err := factory.PrepareOTLPGenerationPipelines(context.Background(), activePlan, 51, generationMetricSpec())
	if err != nil {
		t.Fatal(err)
	}

	failingPlan := compileGenerationPlan(t,
		secureTraceSend("a-prepared", server.URL, validCA, generationCanaryBuckets()),
		secureTraceSend("z-invalid-ca", server.URL, invalidCA, generationCanaryBuckets()),
	)
	failed, err := factory.PrepareOTLPGenerationPipelines(context.Background(), failingPlan, 52, generationMetricSpec())
	if err == nil || len(failed.SpanPipelines) != 0 || len(failed.MetricReaders) != 0 {
		t.Fatalf("failed pipelines=%d/%d error=%v", len(failed.SpanPipelines), len(failed.MetricReaders), err)
	}
	factory.canaryMu.RLock()
	_, failedGenerationPresent := factory.canary[52]
	_, activeGenerationPresent := factory.canary[51]
	factory.canaryMu.RUnlock()
	if failedGenerationPresent || !activeGenerationPresent {
		t.Fatalf("canary registries failed=%t active=%t", failedGenerationPresent, activeGenerationPresent)
	}
	if loader.callCount(invalidCA) != 1 {
		t.Fatalf("invalid CA resolutions=%d want=1", loader.callCount(invalidCA))
	}

	traceID := trace.TraceID{5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5}
	emitGenerationCanary(t, active.SpanPipelines, traceID, "active-traces")
	if !factory.OTLPGenerationAcknowledgedCanaryTrace(51, "active-traces", traceID.String()) {
		t.Fatal("later assembly failure disrupted the active generation")
	}
	cleanupOTLPGenerationPipelines(active)
}

func TestOTLPGenerationCanaryRegistryReleasesAfterProcessorShutdownError(t *testing.T) {
	const generation = 71
	factory := &Factory{canary: make(map[uint64]*otlpGenerationCanaryRegistry)}
	registry := &otlpGenerationCanaryRegistry{processors: 1}
	factory.canary[generation] = registry
	inner := &shutdownErrorSpanProcessor{}
	processor := &canaryRegisteredSpanProcessor{
		SpanProcessor: inner,
		release:       func() { factory.releaseOTLPCanaryProcessor(generation, registry) },
	}
	if err := processor.Shutdown(context.Background()); err == nil {
		t.Fatal("shutdown error was suppressed")
	}
	factory.canaryMu.RLock()
	_, retained := factory.canary[generation]
	factory.canaryMu.RUnlock()
	if retained {
		t.Fatal("failed processor shutdown retained a stale generation registry")
	}
	if !inner.terminal {
		t.Fatal("shutdown error returned before the owned processor reached terminal state")
	}
	if err := processor.Shutdown(context.Background()); err != nil || inner.shutdowns != 1 {
		t.Fatalf("second shutdown error=%v inner calls=%d", err, inner.shutdowns)
	}
}

func TestOTLPGenerationCanaryOwnershipWaitsForTerminalCleanupAfterShutdownTimeout(t *testing.T) {
	const generation = 72
	factory := &Factory{canary: make(map[uint64]*otlpGenerationCanaryRegistry)}
	registry := &otlpGenerationCanaryRegistry{processors: 1}
	factory.canary[generation] = registry
	inner := &terminalTimeoutSpanProcessor{terminal: make(chan struct{})}
	processor := &canaryRegisteredSpanProcessor{
		SpanProcessor: inner,
		release:       func() { factory.releaseOTLPCanaryProcessor(generation, registry) },
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := processor.Shutdown(ctx); err == nil {
		t.Fatal("timed-out processor shutdown unexpectedly succeeded")
	}
	factory.canaryMu.RLock()
	_, retained := factory.canary[generation]
	factory.canaryMu.RUnlock()
	if !retained {
		t.Fatal("canary ownership released before worker/exporter terminal cleanup")
	}
	close(inner.terminal)
	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		factory.canaryMu.RLock()
		_, retained = factory.canary[generation]
		factory.canaryMu.RUnlock()
		if !retained {
			break
		}
		time.Sleep(time.Millisecond)
	}
	if retained {
		t.Fatal("terminal cleanup did not release canary ownership")
	}
	if err := processor.Shutdown(context.Background()); err != nil || inner.shutdowns.Load() != 1 {
		t.Fatalf("second shutdown error/calls = %v/%d", err, inner.shutdowns.Load())
	}
}

type terminalTimeoutSpanProcessor struct {
	terminal  chan struct{}
	shutdowns atomic.Int64
}

func (*terminalTimeoutSpanProcessor) OnStart(context.Context, sdktrace.ReadWriteSpan) {}
func (*terminalTimeoutSpanProcessor) OnEnd(sdktrace.ReadOnlySpan)                     {}
func (*terminalTimeoutSpanProcessor) ForceFlush(context.Context) error                { return nil }
func (processor *terminalTimeoutSpanProcessor) Shutdown(context.Context) error {
	processor.shutdowns.Add(1)
	return context.DeadlineExceeded
}
func (processor *terminalTimeoutSpanProcessor) TerminalDone() <-chan struct{} {
	return processor.terminal
}

type shutdownErrorSpanProcessor struct {
	shutdowns int
	terminal  bool
}

func (*shutdownErrorSpanProcessor) OnStart(context.Context, sdktrace.ReadWriteSpan) {}
func (*shutdownErrorSpanProcessor) OnEnd(sdktrace.ReadOnlySpan)                     {}
func (*shutdownErrorSpanProcessor) ForceFlush(context.Context) error                { return nil }
func (processor *shutdownErrorSpanProcessor) Shutdown(context.Context) error {
	processor.shutdowns++
	processor.terminal = true
	return context.DeadlineExceeded
}

type cleanupDualSpanChild struct {
	shutdowns atomic.Int64
	panic     bool
}

func (*cleanupDualSpanChild) OnStart(context.Context, sdktrace.ReadWriteSpan) {}
func (*cleanupDualSpanChild) OnEnd(sdktrace.ReadOnlySpan)                     {}
func (*cleanupDualSpanChild) ForceFlush(context.Context) error                { return nil }
func (*cleanupDualSpanChild) TryEnqueue(telemetry.V8CanonicalEndedSpan) telemetry.V8CanonicalSpanEnqueueResult {
	return telemetry.V8CanonicalSpanEnqueueAccepted
}
func (child *cleanupDualSpanChild) Shutdown(context.Context) error {
	child.shutdowns.Add(1)
	if child.panic {
		panic("cleanup panic")
	}
	return nil
}

func TestCleanupOTLPGenerationPipelinesVisitsBothMalformedArmsDedupesAndContainsPanic(t *testing.T) {
	panicking := &cleanupDualSpanChild{panic: true}
	good := &cleanupDualSpanChild{}
	cleanupOTLPGenerationPipelines(telemetry.V8GenerationPipelines{SpanPipelines: []telemetry.V8GenerationSpanPipeline{
		{Destination: "bad", Canonical: panicking, Legacy: panicking},
		{Destination: "bad-reused", Canonical: panicking, Legacy: good},
	}})
	if panicking.shutdowns.Load() != 1 || good.shutdowns.Load() != 1 {
		t.Fatalf("shutdowns = %d/%d", panicking.shutdowns.Load(), good.shutdowns.Load())
	}
}

func secureTraceSend(name, endpoint, caPath string, buckets []observability.Bucket) config.ObservabilityV8DestinationSource {
	destination := traceSend(name, endpoint, buckets)
	destination.TLS = config.ObservabilityV8TLSSource{CACert: caPath}
	return destination
}

func emitGenerationCanary(
	t *testing.T,
	pipelines []telemetry.V8GenerationSpanPipeline,
	traceID trace.TraceID,
	destination string,
) {
	t.Helper()
	for _, operation := range []string{"chat", "invoke_agent"} {
		span := generationCanarySpan(traceID, operation, destination)
		for _, pipeline := range pipelines {
			pipeline.Legacy.OnEnd(span)
		}
	}
	for _, pipeline := range pipelines {
		if err := pipeline.Legacy.ForceFlush(context.Background()); err != nil {
			t.Fatal(err)
		}
	}
}

func generationCanaryBuckets() []observability.Bucket {
	return []observability.Bucket{
		observability.BucketAgentLifecycle,
		observability.BucketModelIO,
	}
}

func generationCanarySpan(traceID trace.TraceID, operation, destination string) sdktrace.ReadOnlySpan {
	rootID := trace.SpanID{1, 2, 3, 4, 5, 6, 7, 8}
	childID := trace.SpanID{8, 7, 6, 5, 4, 3, 2, 1}
	rootContext := trace.NewSpanContext(trace.SpanContextConfig{
		TraceID: traceID, SpanID: rootID, TraceFlags: trace.FlagsSampled,
	})
	spanID := childID
	parent := rootContext
	name := "chat gpt-4o-mini"
	kind := trace.SpanKindClient
	bucket := observability.BucketModelIO
	family := observability.TelemetryFamilyModelChat
	if operation == "invoke_agent" {
		name = "invoke_agent diagnostic"
		kind = trace.SpanKindInternal
		bucket = observability.BucketAgentLifecycle
		family = observability.TelemetryFamilyAgentInvoke
		spanID = rootID
		parent = trace.SpanContext{}
	}
	canaryResource := resource.NewWithAttributes(
		"https://opentelemetry.io/schemas/1.42.0",
		attribute.String("service.name", "defenseclaw"),
		attribute.String("service.version", "v8-test"),
		attribute.String("service.namespace", "cisco.ai-defense"),
		attribute.String("service.instance.id", "instance-1"),
		attribute.String("deployment.environment.name", "test"),
		attribute.String("defenseclaw.instance.id", "instance-1"),
	)
	canaryScope := instrumentation.Scope{
		Name: "defenseclaw.telemetry", Version: "v8-test",
		SchemaURL: "https://defenseclaw.io/schemas/telemetry/v8",
		Attributes: attribute.NewSet(
			attribute.String("defenseclaw.trace.schema_version", observability.RuntimeTraceSchemaVersion),
			attribute.String("defenseclaw.semantic_profile", observability.RuntimeSemanticProfileID),
		),
	}
	return tracetest.SpanStub{
		Name: name, Parent: parent, SpanKind: kind, Status: sdktrace.Status{Code: codes.Ok},
		SpanContext: trace.NewSpanContext(trace.SpanContextConfig{
			TraceID: traceID, SpanID: spanID, TraceFlags: trace.FlagsSampled,
		}),
		Attributes: []attribute.KeyValue{
			attribute.String("defenseclaw.bucket", string(bucket)),
			attribute.String("defenseclaw.span.family", family),
			attribute.Int64("defenseclaw.span.family_schema_version", 1),
			attribute.Int64("defenseclaw.config.generation", 8),
			attribute.String("defenseclaw.source", string(observability.SourceSystem)),
			attribute.String("defenseclaw.outcome", string(observability.OutcomeCompleted)),
			attribute.Bool("defenseclaw.telemetry.canary", true),
			attribute.String("defenseclaw.telemetry.canary.operation", "runtime-pipeline-test"),
			attribute.String("defenseclaw.telemetry.canary.destination", destination),
			attribute.String("gen_ai.operation.name", operation),
		},
		StartTime: time.Now().Add(-time.Millisecond), EndTime: time.Now(),
		Resource: canaryResource, InstrumentationScope: canaryScope,
	}.Snapshot()
}

func traceNames(requests []*collectortracepb.ExportTraceServiceRequest) string {
	for _, request := range requests {
		for _, resource := range request.ResourceSpans {
			for _, scope := range resource.ScopeSpans {
				for _, span := range scope.Spans {
					return span.Name
				}
			}
		}
	}
	return ""
}

func metricNames(requests []*collectormetricpb.ExportMetricsServiceRequest) []string {
	result := make([]string, 0)
	for _, request := range requests {
		for _, resource := range request.ResourceMetrics {
			for _, scope := range resource.ScopeMetrics {
				for _, metric := range scope.Metrics {
					result = append(result, metric.Name)
				}
			}
		}
	}
	return result
}
