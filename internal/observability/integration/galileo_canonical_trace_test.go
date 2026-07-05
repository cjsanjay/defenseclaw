// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package integration

import (
	"bytes"
	"context"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/audit"
	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/observability"
	"github.com/defenseclaw/defenseclaw/internal/observability/delivery"
	"github.com/defenseclaw/defenseclaw/internal/observability/destinations"
	"github.com/defenseclaw/defenseclaw/internal/observability/destinations/galileo"
	"github.com/defenseclaw/defenseclaw/internal/observability/redaction"
	observabilityruntime "github.com/defenseclaw/defenseclaw/internal/observability/runtime"
	"github.com/defenseclaw/defenseclaw/internal/observability/runtimegraph"
	"github.com/defenseclaw/defenseclaw/internal/telemetry"
	collectortracepb "go.opentelemetry.io/proto/otlp/collector/trace/v1"
	"google.golang.org/protobuf/proto"
)

type galileoTraceCapture struct {
	mu       sync.Mutex
	requests []*collectortracepb.ExportTraceServiceRequest
}

func (capture *galileoTraceCapture) handle(writer http.ResponseWriter, request *http.Request) {
	if request.URL.Path != "/v1/traces" {
		writer.WriteHeader(http.StatusNotFound)
		return
	}
	body, _ := io.ReadAll(request.Body)
	decoded := &collectortracepb.ExportTraceServiceRequest{}
	if err := proto.Unmarshal(body, decoded); err != nil {
		writer.WriteHeader(http.StatusBadRequest)
		return
	}
	capture.mu.Lock()
	capture.requests = append(capture.requests, proto.Clone(decoded).(*collectortracepb.ExportTraceServiceRequest))
	capture.mu.Unlock()
	writer.Header().Set("Content-Type", "application/x-protobuf")
	writer.WriteHeader(http.StatusOK)
}

func (capture *galileoTraceCapture) snapshot() []*collectortracepb.ExportTraceServiceRequest {
	capture.mu.Lock()
	defer capture.mu.Unlock()
	return append([]*collectortracepb.ExportTraceServiceRequest(nil), capture.requests...)
}

func TestRuntimeGeneratedCanaryUsesCanonicalGalileoProjectionAndAcknowledges(t *testing.T) {
	directory := t.TempDir()
	storePath := filepath.Join(directory, "audit.db")
	judgePath := filepath.Join(directory, "judge-bodies.db")
	store, err := audit.NewStore(storePath)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })
	if err := store.Init(); err != nil {
		t.Fatal(err)
	}

	capture := &galileoTraceCapture{}
	server := httptest.NewServer(http.HandlerFunc(capture.handle))
	defer server.Close()
	plan, err := config.CompileObservabilityV8(observabilitySource(
		storePath, judgePath,
		[]config.ObservabilityV8DestinationSource{{
			Name: "galileo", Kind: config.ObservabilityV8DestinationOTLP, Preset: "galileo",
			Endpoint: server.URL,
			Send: &config.ObservabilityV8SendSource{
				Signals: []observability.Signal{observability.SignalTraces},
				Buckets: []observability.Bucket{"*"}, RedactionProfile: "none",
			},
			TLS: config.ObservabilityV8TLSSource{Insecure: true},
			NetworkSafety: config.ObservabilityV8NetworkSafetySource{
				AllowPrivateNetworks: true,
			},
		}},
	))
	if err != nil {
		t.Fatal(err)
	}
	engine, err := redaction.NewEngine(bytes.Repeat([]byte{0x61}, 32))
	if err != nil {
		t.Fatal(err)
	}
	health := &integrationDeliveryHealth{}
	factory, err := destinations.NewFactory(destinations.Options{
		ConsoleStream: destinations.ConsoleStderr, Stdout: io.Discard, Stderr: io.Discard,
		Secrets:  &integrationSecrets{values: map[string]string{}, calls: map[string]int{}},
		CALoader: &integrationCALoader{}, Resolver: net.DefaultResolver, Dialer: &net.Dialer{},
		Warnings: &integrationWarnings{}, RedactionEngine: engine, DeliveryObserver: health,
		GalileoObserver: galileo.CanonicalObserverFunc(func(galileo.CanonicalFailure) {}),
	})
	if err != nil {
		t.Fatal(err)
	}
	providerFactory := telemetry.NewV8ProviderFactory(telemetry.V8ProviderOptions{
		Version: "integration-test", Environment: "test",
		ServiceInstanceID: "galileo-canary-service", DefenseClawInstanceID: "galileo-canary-instance",
		GenerationPipelines: factory.OTLPGenerationPipelineFactory(),
	})
	reaper, err := audit.NewRetentionReaper(store, nil, 0, audit.RetentionOptions{})
	if err != nil {
		t.Fatal(err)
	}
	retention, err := observabilityruntime.NewRetentionController(
		reaper, observabilityruntime.RetentionControllerOptions{},
	)
	if err != nil {
		t.Fatal(err)
	}
	runtime, err := observabilityruntime.New(
		context.Background(), runtimegraph.ConfigFromPlan(plan, false),
		observabilityruntime.Options{
			Store: store, Engine: engine, RecordBuilder: mustRecordBuilder(t, "galileo-canary-failure"),
			Reporter: &discardReporter{}, RetentionController: retention,
			DestinationAdapterFactory: factory, DestinationObserver: health,
			TelemetryProviderFactory: providerFactory,
		},
	)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		if closeErr := runtime.Close(ctx); closeErr != nil {
			t.Errorf("close runtime: %v", closeErr)
		}
	})

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	result, err := runtime.EmitTraceCanary(ctx, "galileo")
	if err != nil {
		t.Fatal(err)
	}
	if !result.Acknowledged || result.Destination != "galileo" || result.Generation != 1 || result.TraceID == "" {
		t.Fatalf("canary result=%+v", result)
	}
	requests := capture.snapshot()
	if len(requests) != 1 {
		t.Fatalf("Galileo requests=%d, want one exact batch", len(requests))
	}
	spans := 0
	for _, resourceSpans := range requests[0].ResourceSpans {
		for _, scopeSpans := range resourceSpans.ScopeSpans {
			for _, span := range scopeSpans.Spans {
				spans++
				if len(span.TraceId) != 16 || len(span.SpanId) != 8 {
					t.Fatalf("invalid projected identity trace=%x span=%x", span.TraceId, span.SpanId)
				}
			}
		}
	}
	if spans != 2 {
		t.Fatalf("projected canary spans=%d, want agent and model", spans)
	}
}

var _ delivery.Observer = (*integrationDeliveryHealth)(nil)
