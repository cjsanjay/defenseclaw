// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// SPDX-License-Identifier: Apache-2.0

package galileo

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"reflect"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/observability"
	compatibility "github.com/defenseclaw/defenseclaw/internal/observability/compatibility/galileo"
	"github.com/defenseclaw/defenseclaw/internal/observability/delivery"
	"github.com/defenseclaw/defenseclaw/internal/observability/pipeline"
	"github.com/defenseclaw/defenseclaw/internal/observability/redaction"
	"github.com/defenseclaw/defenseclaw/internal/observability/router"
	"github.com/defenseclaw/defenseclaw/internal/telemetry"
)

const canonicalRawPII = "canonical-consumer@example.test"

type canonicalCaptureAdapter struct {
	deliveries chan [][]byte
	deliver    delivery.DeliveryResult
	block      chan struct{}
	closeGate  chan struct{}
	closeErr   error
	closeCalls atomic.Uint64
	mu         sync.Mutex
	closed     bool
}

func (adapter *canonicalCaptureAdapter) EncodedSize(sizes []int) (int, bool) {
	total := 1
	for _, size := range sizes {
		if size < 0 {
			return 0, false
		}
		total += size
	}
	return total, true
}

func (adapter *canonicalCaptureAdapter) Deliver(
	ctx context.Context,
	batch delivery.Batch,
) delivery.DeliveryResult {
	if adapter.block != nil {
		select {
		case <-ctx.Done():
			return delivery.DeliveryResult{Outcome: delivery.OutcomeTransient}
		case <-adapter.block:
		}
	}
	items := batch.Items()
	encoded := make([][]byte, len(items))
	for index := range items {
		encoded[index] = items[index].Bytes()
	}
	if adapter.deliveries != nil {
		select {
		case adapter.deliveries <- encoded:
		default:
		}
	}
	if adapter.deliver.Outcome != "" {
		return adapter.deliver
	}
	return delivery.DeliveryResult{Outcome: delivery.OutcomeDelivered}
}

func (adapter *canonicalCaptureAdapter) Close(ctx context.Context) error {
	adapter.closeCalls.Add(1)
	if adapter.closeGate != nil {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-adapter.closeGate:
		}
	}
	if adapter.closeErr != nil {
		return adapter.closeErr
	}
	adapter.mu.Lock()
	adapter.closed = true
	adapter.mu.Unlock()
	return nil
}

type canonicalFailureCapture struct {
	mu     sync.Mutex
	events []CanonicalFailure
	panic  bool
}

func (capture *canonicalFailureCapture) ObserveGalileoCanonicalFailure(failure CanonicalFailure) {
	if capture.panic {
		panic("observer panic must be isolated")
	}
	capture.mu.Lock()
	capture.events = append(capture.events, failure)
	capture.mu.Unlock()
}

func (capture *canonicalFailureCapture) snapshot() []CanonicalFailure {
	capture.mu.Lock()
	defer capture.mu.Unlock()
	return append([]CanonicalFailure(nil), capture.events...)
}

func TestCanonicalConsumerRequiresExplicitActivationAndPerformsNoPreparedIO(t *testing.T) {
	t.Parallel()
	fixture := newCanonicalFixture(t, "galileo-prepared", observability.BucketModelIO, "none", 1)
	if result := fixture.consumer.tryEnqueueRecord(fixture.modelRecord(t, canonicalRawPII)); result != telemetry.V8CanonicalSpanEnqueueClosed {
		t.Fatalf("prepared enqueue = %s", result)
	}
	select {
	case <-fixture.adapter.deliveries:
		t.Fatal("prepared consumer performed destination I/O")
	default:
	}
	fixture.consumer.Activate()
	fixture.consumer.Activate()
	if result := fixture.consumer.tryEnqueueRecord(fixture.modelRecord(t, canonicalRawPII)); result != telemetry.V8CanonicalSpanEnqueueAccepted {
		t.Fatalf("active enqueue = %s failures=%+v", result, fixture.failures.snapshot())
	}
	flushCanonical(t, fixture.consumer)
	shutdownCanonical(t, fixture.consumer)
}

func TestCanonicalConsumerPreparationRejectsCrossKindAndUnboundedDependencies(t *testing.T) {
	t.Parallel()
	fixture := newCanonicalFixture(t, "galileo-validation", observability.BucketModelIO, "none", 1)
	base := CanonicalTraceConsumerOptions{
		Destination: fixture.destination, Generation: 1, Pipeline: fixture.pipeline,
		Adapter: fixture.adapter, Dispatcher: canonicalDispatcherConfig(fixture.destination.Name, 1),
		Limits: compatibility.DefaultLimits(), Observer: fixture.failures,
	}
	tests := []struct {
		name string
		code CanonicalConsumerErrorCode
		edit func(*CanonicalTraceConsumerOptions)
	}{
		{name: "zero generation", code: CanonicalConsumerErrorInvalidDependencies, edit: func(value *CanonicalTraceConsumerOptions) { value.Generation = 0 }},
		{name: "nil pipeline", code: CanonicalConsumerErrorInvalidDependencies, edit: func(value *CanonicalTraceConsumerOptions) { value.Pipeline = nil }},
		{name: "nil adapter", code: CanonicalConsumerErrorInvalidDependencies, edit: func(value *CanonicalTraceConsumerOptions) { value.Adapter = (*canonicalCaptureAdapter)(nil) }},
		{name: "nil observer", code: CanonicalConsumerErrorInvalidDependencies, edit: func(value *CanonicalTraceConsumerOptions) { value.Observer = (*canonicalFailureCapture)(nil) }},
		{name: "general otlp", code: CanonicalConsumerErrorInvalidDestination, edit: func(value *CanonicalTraceConsumerOptions) { value.Destination.Preset = "" }},
		{name: "wrong profile", code: CanonicalConsumerErrorInvalidDestination, edit: func(value *CanonicalTraceConsumerOptions) { value.Destination.PresetProfile = "galileo-rich-v3" }},
		{name: "non trace selection", code: CanonicalConsumerErrorInvalidDestination, edit: func(value *CanonicalTraceConsumerOptions) {
			value.Destination.SelectedSignals = []observability.Signal{observability.SignalLogs}
		}},
		{name: "dispatcher identity", code: CanonicalConsumerErrorInvalidDispatcher, edit: func(value *CanonicalTraceConsumerOptions) { value.Dispatcher.Destination = "other" }},
	}
	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			value := base
			test.edit(&value)
			consumer, err := NewCanonicalTraceConsumer(value)
			if consumer != nil || !IsCanonicalConsumerError(err, test.code) ||
				bytes.Contains([]byte(fmt.Sprint(err)), []byte(canonicalRawPII)) {
				t.Fatalf("consumer=%v err=%v code=%s", consumer, err, test.code)
			}
		})
	}
	shutdownCanonical(t, fixture.consumer)
}

func TestCanonicalConsumerRoutesRedactsAndGalileoProjectsExactlyOnce(t *testing.T) {
	t.Parallel()
	fixture := newCanonicalFixture(t, "galileo-redacted", observability.BucketModelIO, "strict", 8)
	originalProcess := fixture.consumer.process
	var processCalls atomic.Uint64
	fixture.consumer.process = func(record observability.Record) (pipeline.TraceProjectionOutcome, error) {
		processCalls.Add(1)
		return originalProcess(record)
	}
	fixture.consumer.Activate()
	record := fixture.modelRecord(t, "contact "+canonicalRawPII)
	if result := fixture.consumer.tryEnqueueRecord(record); result != telemetry.V8CanonicalSpanEnqueueAccepted {
		t.Fatalf("enqueue = %s failures=%+v", result, fixture.failures.snapshot())
	}
	flushCanonical(t, fixture.consumer)
	batch := waitCanonicalDelivery(t, fixture.adapter.deliveries)
	if len(batch) != 1 {
		t.Fatalf("batch items = %d", len(batch))
	}
	if bytes.Contains(batch[0], []byte(canonicalRawPII)) {
		t.Fatal("Galileo payload recovered content removed by central redaction")
	}
	wire, ok := decodeProjection(batch[0])
	if !ok || wire.Profile != compatibility.ProfileID || wire.Shape != compatibility.ShapeLLM ||
		wire.RecordID != record.RecordID() || wire.Signal != string(observability.SignalTraces) {
		t.Fatalf("Galileo projection identity = %+v ok=%v", wire, ok)
	}
	if got := fixture.consumer.Counters(); got.Accepted != 1 || got.RouteDropped != 0 ||
		got.QueueDropped != 0 || got.Failed != 0 {
		t.Fatalf("consumer counters = %+v", got)
	}
	if got := processCalls.Load(); got != 1 {
		t.Fatalf("central trace projection calls = %d, want exactly one", got)
	}
	if events := fixture.failures.snapshot(); len(events) != 0 {
		t.Fatalf("unexpected failures = %+v", events)
	}
	shutdownCanonical(t, fixture.consumer)
}

func TestCanonicalConsumerConfiguredRouteDropAndWrongDestinationDoNotLeakToAdapter(t *testing.T) {
	t.Parallel()
	routeDrop := newCanonicalFixture(t, "galileo-tool-only", observability.BucketToolActivity, "none", 4)
	routeDrop.consumer.Activate()
	if result := routeDrop.consumer.tryEnqueueRecord(routeDrop.modelRecord(t, "safe")); result != telemetry.V8CanonicalSpanEnqueueDropped {
		t.Fatalf("unmatched route = %s", result)
	}
	assertNoCanonicalDelivery(t, routeDrop.adapter.deliveries)
	shutdownCanonical(t, routeDrop.consumer)

	source := newCanonicalFixture(t, "galileo-source", observability.BucketModelIO, "none", 4)
	other := newCanonicalFixture(t, "galileo-other", observability.BucketModelIO, "none", 4)
	wrongAdapter := &canonicalCaptureAdapter{deliveries: make(chan [][]byte, 1)}
	wrongFailures := &canonicalFailureCapture{}
	wrong, err := NewCanonicalTraceConsumer(CanonicalTraceConsumerOptions{
		Destination: other.destination, Generation: 4, Pipeline: source.pipeline,
		Adapter: wrongAdapter, Dispatcher: canonicalDispatcherConfig(other.destination.Name, 4),
		Limits: compatibility.DefaultLimits(), Observer: wrongFailures,
	})
	if err != nil {
		t.Fatal(err)
	}
	wrong.Activate()
	if result := wrong.tryEnqueueRecord(source.modelRecord(t, "safe")); result != telemetry.V8CanonicalSpanEnqueueDropped {
		t.Fatalf("wrong destination = %s", result)
	}
	assertNoCanonicalDelivery(t, wrongAdapter.deliveries)
	shutdownCanonical(t, wrong)
	shutdownCanonical(t, source.consumer)
	shutdownCanonical(t, other.consumer)
}

func TestCanonicalConsumerRejectsUnsupportedGalileoShapeAndGenerationMismatch(t *testing.T) {
	t.Parallel()
	fixture := newCanonicalFixture(t, "galileo-shape", observability.BucketDiagnostic, "none", 5)
	fixture.consumer.Activate()
	if result := fixture.consumer.tryEnqueueRecord(fixture.diagnosticRecord(t, 5)); result != telemetry.V8CanonicalSpanEnqueueDropped {
		t.Fatalf("unsupported shape = %s", result)
	}
	if result := fixture.consumer.tryEnqueueRecord(fixture.diagnosticRecord(t, 6)); result != telemetry.V8CanonicalSpanEnqueueFailed {
		t.Fatalf("generation mismatch = %s", result)
	}
	assertNoCanonicalDelivery(t, fixture.adapter.deliveries)
	want := []CanonicalFailure{
		{Destination: fixture.destination.Name, Generation: 5, Code: CanonicalFailureUnsupportedShape},
		{Destination: fixture.destination.Name, Generation: 5, Code: CanonicalFailureGenerationMismatch},
	}
	if got := fixture.failures.snapshot(); !reflect.DeepEqual(got, want) {
		t.Fatalf("failures = %+v, want %+v", got, want)
	}
	shutdownCanonical(t, fixture.consumer)
}

func TestCanonicalConsumerQueueFullIsBoundedAndFlushLeavesIntakeLive(t *testing.T) {
	t.Parallel()
	fixture := newCanonicalFixture(t, "galileo-queue", observability.BucketModelIO, "none", 3)
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	if err := fixture.consumer.dispatcher.Close(ctx); err != nil {
		cancel()
		t.Fatal(err)
	}
	cancel()
	replacement, err := delivery.NewDispatcher(
		canonicalDispatcherConfigWithDelay(fixture.destination.Name, 1, time.Hour), fixture.adapter,
	)
	if err != nil {
		t.Fatal(err)
	}
	fixture.consumer.dispatcher = replacement
	fixture.consumer.Activate()
	if result := fixture.consumer.tryEnqueueRecord(fixture.modelRecord(t, "first")); result != telemetry.V8CanonicalSpanEnqueueAccepted {
		t.Fatalf("first enqueue = %s failures=%+v", result, fixture.failures.snapshot())
	}
	if result := fixture.consumer.tryEnqueueRecord(fixture.modelRecord(t, "second")); result != telemetry.V8CanonicalSpanEnqueueDropped {
		t.Fatalf("queue-full enqueue = %s", result)
	}
	if got := fixture.consumer.Counters(); got.Accepted != 1 || got.QueueDropped != 1 {
		t.Fatalf("queue counters = %+v", got)
	}
	shutdownCanonical(t, fixture.consumer)

	live := newCanonicalFixture(t, "galileo-flush", observability.BucketModelIO, "none", 3)
	live.consumer.Activate()
	for _, content := range []string{"before flush", "after flush"} {
		if result := live.consumer.tryEnqueueRecord(live.modelRecord(t, content)); result != telemetry.V8CanonicalSpanEnqueueAccepted {
			t.Fatalf("enqueue %q = %s", content, result)
		}
		flushCanonical(t, live.consumer)
	}
	if got := live.consumer.Counters(); got.Accepted != 2 || got.Closed != 0 {
		t.Fatalf("flush stopped intake: %+v", got)
	}
	shutdownCanonical(t, live.consumer)
}

func TestCanonicalConsumerShutdownIsRetryableIdempotentAndCannotReactivate(t *testing.T) {
	t.Parallel()
	fixture := newCanonicalFixture(t, "galileo-shutdown", observability.BucketModelIO, "none", 2)
	fixture.adapter.closeGate = make(chan struct{})
	fixture.consumer.Activate()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Millisecond)
	defer cancel()
	if err := fixture.consumer.Shutdown(ctx); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("first shutdown = %v", err)
	}
	close(fixture.adapter.closeGate)
	shutdownCanonical(t, fixture.consumer)
	shutdownCanonical(t, fixture.consumer)
	fixture.consumer.Activate()
	if result := fixture.consumer.tryEnqueueRecord(fixture.modelRecord(t, "late")); result != telemetry.V8CanonicalSpanEnqueueClosed {
		t.Fatalf("post-shutdown enqueue = %s", result)
	}
	if got := fixture.adapter.closeCalls.Load(); got != 2 {
		t.Fatalf("adapter close calls = %d, want one timed-out and one successful attempt", got)
	}
}

func TestCanonicalConsumerIsolatesPipelineAndObserverPanics(t *testing.T) {
	t.Parallel()
	fixture := newCanonicalFixture(t, "galileo-panic", observability.BucketModelIO, "none", 7)
	fixture.failures.panic = true
	fixture.consumer.process = func(observability.Record) (pipeline.TraceProjectionOutcome, error) {
		panic("pipeline panic must not escape")
	}
	fixture.consumer.Activate()
	if result := fixture.consumer.tryEnqueueRecord(fixture.modelRecord(t, "safe")); result != telemetry.V8CanonicalSpanEnqueueFailed {
		t.Fatalf("panic result = %s", result)
	}
	if got := fixture.consumer.Counters(); got.Failed != 1 {
		t.Fatalf("panic counters = %+v", got)
	}
	shutdownCanonical(t, fixture.consumer)
}

func TestCanonicalConsumerPublicSurfaceHasNoRawRecordOrSDKSpanBypass(t *testing.T) {
	t.Parallel()
	typeOf := reflect.TypeOf((*CanonicalTraceConsumer)(nil))
	for _, forbidden := range []string{"EnqueueRecord", "EnqueueProjection", "OnEnd", "ExportSpans"} {
		if _, exists := typeOf.MethodByName(forbidden); exists {
			t.Fatalf("public bypass method %q exists", forbidden)
		}
	}
	if method, exists := typeOf.MethodByName("TryEnqueue"); !exists ||
		method.Type.NumIn() != 2 || method.Type.In(1) != reflect.TypeOf(telemetry.V8CanonicalEndedSpan{}) {
		t.Fatalf("TryEnqueue signature = %+v exists=%v", method, exists)
	}
}

type canonicalFixture struct {
	destination config.ObservabilityV8EffectiveDestination
	plan        *config.ObservabilityV8Plan
	pipeline    *pipeline.TraceProjectionPipeline
	adapter     *canonicalCaptureAdapter
	failures    *canonicalFailureCapture
	consumer    *CanonicalTraceConsumer
	generation  uint64
	sequence    atomic.Uint64
}

func newCanonicalFixture(
	t *testing.T,
	name string,
	bucket observability.Bucket,
	profile string,
	generation uint64,
) *canonicalFixture {
	t.Helper()
	signals := []observability.Signal{observability.SignalTraces}
	buckets := []observability.Bucket{bucket}
	plan, err := config.CompileObservabilityV8(&config.ObservabilityV8Source{
		Destinations: []config.ObservabilityV8DestinationSource{{
			Name: name, Kind: config.ObservabilityV8DestinationOTLP, Preset: "galileo",
			Endpoint: "https://example.test/otel/traces",
			Send: &config.ObservabilityV8SendSource{
				Signals: signals, Buckets: buckets, RedactionProfile: profile,
			},
		}},
	})
	if err != nil {
		t.Fatal(err)
	}
	destination, ok := plan.RuntimeDestination(name)
	if !ok {
		t.Fatal("compiled Galileo destination missing")
	}
	evaluator, err := router.New(plan)
	if err != nil {
		t.Fatal(err)
	}
	engine, err := redaction.NewEngine(bytes.Repeat([]byte{0x43}, 32))
	if err != nil {
		t.Fatal(err)
	}
	projection, err := pipeline.NewTraceProjectionPipeline(plan, evaluator, engine)
	if err != nil {
		t.Fatal(err)
	}
	adapter := &canonicalCaptureAdapter{deliveries: make(chan [][]byte, 8)}
	failures := &canonicalFailureCapture{}
	consumer, err := NewCanonicalTraceConsumer(CanonicalTraceConsumerOptions{
		Destination: destination, Generation: generation, Pipeline: projection,
		Adapter: adapter, Dispatcher: canonicalDispatcherConfig(name, 4),
		Limits: compatibility.DefaultLimits(), Observer: failures,
	})
	if err != nil {
		t.Fatal(err)
	}
	return &canonicalFixture{
		destination: destination, plan: plan, pipeline: projection, adapter: adapter,
		failures: failures, consumer: consumer, generation: generation,
	}
}

func (fixture *canonicalFixture) modelRecord(t *testing.T, content string) observability.Record {
	t.Helper()
	builder := fixture.builder(t)
	sequence := fixture.sequence.Add(1)
	input := observability.TelemetryStructuredGenAIInputMessages{Items: []observability.TelemetryStructuredGenAIChatMessage{{
		Role: "user", Parts: observability.TelemetryStructuredGenAIMessageParts{Items: []observability.TelemetryStructuredGenAIMessagePart{
			observability.TelemetryStructuredArmGenAIMessagePartText{Value: observability.TelemetryStructuredGenAITextPart{Content: content}},
		}},
	}}}
	output := observability.TelemetryStructuredGenAIOutputMessages{Items: []observability.TelemetryStructuredGenAIOutputMessage{{
		Role: "assistant", FinishReason: "stop",
		Parts: observability.TelemetryStructuredGenAIMessageParts{Items: []observability.TelemetryStructuredGenAIMessagePart{
			observability.TelemetryStructuredArmGenAIMessagePartText{Value: observability.TelemetryStructuredGenAITextPart{Content: "done"}},
		}},
	}}}
	record, err := builder.BuildSpanModelChat(observability.SpanModelChatInput{
		Envelope: observability.FamilyEnvelopeInput{
			Source: observability.SourceGateway,
			Correlation: observability.Correlation{
				RunID: "run-1", TurnID: "turn-1",
				TraceID: "0123456789abcdef0123456789abcdef",
				SpanID:  fmt.Sprintf("%016x", sequence),
			},
			Provenance: observability.FamilyProvenanceInput{
				Producer: "defenseclaw", BinaryVersion: "8.0.0",
				ConfigGeneration: int64(fixture.generation), ConfigDigest: fixture.plan.Digest(),
			},
		},
		Outcome: observability.OutcomeCompleted, Kind: "CLIENT",
		StartTimeUnixNano: 1_783_278_000_000_000_000 + sequence,
		EndTimeUnixNano:   1_783_278_000_100_000_000 + sequence,
		TraceState:        observability.Present("dc=canonical-consumer"),
		Flags:             0x101,
		Status:            observability.NewTraceStatusOK(),
		Resource: observability.TraceResourceInput{
			SchemaURL: "https://opentelemetry.io/schemas/1.42.0",
		},
		ResourceServiceName: "defenseclaw", ResourceServiceNamespace: "cisco.ai-defense",
		ResourceServiceInstanceID: "instance-1", ResourceDeploymentEnvironmentName: "test",
		ResourceDefenseClawInstanceID: "instance-1",
		GenAIInputMessages:            observability.Present(input), DefenseClawTelemetryInputReported: true,
		DefenseClawContentInputState: "preserved", DefenseClawContentInputOriginalBytes: observability.Present(int64(len(content))),
		GenAIOutputMessages: observability.Present(output), DefenseClawTelemetryOutputReported: true,
		DefenseClawContentOutputState: "preserved", DefenseClawContentOutputOriginalBytes: observability.Present(int64(4)),
		GenAIOperationName: observability.Present("chat"), GenAIProviderName: observability.Present("openai"),
		GenAIRequestModel: "gpt-test", DefenseClawTelemetryTokensReported: observability.Present(false),
		ConditionOperationTerminal: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	return record
}

func (fixture *canonicalFixture) diagnosticRecord(t *testing.T, generation uint64) observability.Record {
	t.Helper()
	builder := fixture.builder(t)
	sequence := fixture.sequence.Add(1)
	record, err := builder.BuildSpanDiagnosticCanary(observability.SpanDiagnosticCanaryInput{
		Envelope: observability.FamilyEnvelopeInput{
			Source: observability.SourceSystem,
			Correlation: observability.Correlation{
				TraceID: "1123456789abcdef0123456789abcdef", SpanID: fmt.Sprintf("%016x", sequence),
			},
			Provenance: observability.FamilyProvenanceInput{
				Producer: "defenseclaw", BinaryVersion: "8.0.0",
				ConfigGeneration: int64(generation), ConfigDigest: fixture.plan.Digest(),
			},
		},
		Outcome: observability.OutcomeCompleted, Kind: "INTERNAL",
		StartTimeUnixNano: 1_783_278_000_000_000_000 + sequence,
		EndTimeUnixNano:   1_783_278_000_100_000_000 + sequence,
		TraceState:        observability.Present("dc=canonical-consumer"),
		Flags:             0x101,
		Status:            observability.NewTraceStatusOK(),
		Resource: observability.TraceResourceInput{
			SchemaURL: "https://opentelemetry.io/schemas/1.42.0",
		},
		ResourceServiceName: "defenseclaw", ResourceServiceNamespace: "cisco.ai-defense",
		ResourceServiceInstanceID: "instance-1", ResourceDeploymentEnvironmentName: "test",
		ResourceDefenseClawInstanceID: "instance-1",
		DefenseClawDestinationID:      observability.Present(fixture.destination.Name),
		DefenseClawDestinationSignal:  observability.Present("traces"),
		ConditionOperationTerminal:    true,
	})
	if err != nil {
		t.Fatal(err)
	}
	return record
}

func (fixture *canonicalFixture) builder(t *testing.T) *observability.FamilyBuilder {
	t.Helper()
	builder, err := observability.NewFamilyBuilder(
		observability.ClockFunc(func() time.Time {
			return time.Date(2026, time.July, 5, 20, 0, 0, 0, time.UTC)
		}),
		observability.OccurrenceIDGeneratorFunc(func() (string, error) {
			return fmt.Sprintf("galileo-canonical-%d", fixture.sequence.Load()+1), nil
		}),
	)
	if err != nil {
		t.Fatal(err)
	}
	return builder
}

func canonicalDispatcherConfig(destination string, queue int) delivery.Config {
	return canonicalDispatcherConfigWithDelay(destination, queue, 0)
}

func canonicalDispatcherConfigWithDelay(destination string, queue int, delay time.Duration) delivery.Config {
	return delivery.Config{
		Destination: destination, Enabled: true, MaxQueueItems: queue, MaxQueueBytes: 8 * 1024 * 1024,
		MaxBatchItems: queue, MaxBatchBytes: 8 * 1024 * 1024, ScheduledDelay: delay,
		AttemptTimeout: time.Second,
		Retry: delivery.RetryPolicy{
			MaxAttempts: 1, InitialBackoff: 0, MaxBackoff: 0,
		},
		Observer: delivery.ObserverFunc(func(delivery.HealthTransition) {}),
	}
}

func flushCanonical(t *testing.T, consumer *CanonicalTraceConsumer) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	if err := consumer.ForceFlush(ctx); err != nil {
		t.Fatalf("ForceFlush: %v", err)
	}
}

func shutdownCanonical(t *testing.T, consumer *CanonicalTraceConsumer) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	if err := consumer.Shutdown(ctx); err != nil {
		t.Fatalf("Shutdown: %v", err)
	}
}

func waitCanonicalDelivery(t *testing.T, deliveries <-chan [][]byte) [][]byte {
	t.Helper()
	select {
	case result := <-deliveries:
		return result
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for canonical Galileo delivery")
		return nil
	}
}

func assertNoCanonicalDelivery(t *testing.T, deliveries <-chan [][]byte) {
	t.Helper()
	select {
	case result := <-deliveries:
		t.Fatalf("unexpected canonical Galileo delivery: %d items", len(result))
	case <-time.After(20 * time.Millisecond):
	}
}
