// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// SPDX-License-Identifier: Apache-2.0

package telemetry

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	"go.opentelemetry.io/otel/trace"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/observability"
)

const v8HandoffTestGeneration = 7

type v8HandoffConsumer struct {
	mu             sync.Mutex
	spans          []V8CanonicalEndedSpan
	order          *[]string
	name           string
	panicEnqueue   bool
	panicFlush     bool
	panicShutdown  bool
	flushErr       error
	shutdownErr    error
	enqueueEntered chan struct{}
	enqueueRelease chan struct{}
	shutdowns      atomic.Int64
}

func (consumer *v8HandoffConsumer) TryEnqueue(span V8CanonicalEndedSpan) V8CanonicalSpanEnqueueResult {
	if consumer.panicEnqueue {
		panic("consumer enqueue panic")
	}
	if consumer.enqueueEntered != nil {
		select {
		case <-consumer.enqueueEntered:
		default:
			close(consumer.enqueueEntered)
		}
	}
	if consumer.enqueueRelease != nil {
		<-consumer.enqueueRelease
	}
	consumer.mu.Lock()
	consumer.spans = append(consumer.spans, span)
	consumer.mu.Unlock()
	return V8CanonicalSpanEnqueueAccepted
}

func (consumer *v8HandoffConsumer) ForceFlush(context.Context) error {
	if consumer.panicFlush {
		panic("consumer flush panic")
	}
	if consumer.order != nil {
		*consumer.order = append(*consumer.order, "flush:"+consumer.name)
	}
	return consumer.flushErr
}

func (consumer *v8HandoffConsumer) Shutdown(context.Context) error {
	consumer.shutdowns.Add(1)
	if consumer.panicShutdown {
		panic("consumer shutdown panic")
	}
	if consumer.order != nil {
		*consumer.order = append(*consumer.order, "shutdown:"+consumer.name)
	}
	return consumer.shutdownErr
}

func (consumer *v8HandoffConsumer) snapshot() []V8CanonicalEndedSpan {
	consumer.mu.Lock()
	defer consumer.mu.Unlock()
	return append([]V8CanonicalEndedSpan(nil), consumer.spans...)
}

type v8HandoffLegacyProcessor struct {
	starts        atomic.Int64
	ends          atomic.Int64
	mu            sync.Mutex
	endedAt       []time.Time
	order         *[]string
	name          string
	panicStart    bool
	panicEnd      bool
	panicFlush    bool
	panicShutdown bool
	flushErr      error
	shutdownErr   error
	shutdowns     atomic.Int64
}

func (processor *v8HandoffLegacyProcessor) OnStart(context.Context, sdktrace.ReadWriteSpan) {
	processor.starts.Add(1)
	if processor.panicStart {
		panic("legacy start panic")
	}
}

func (processor *v8HandoffLegacyProcessor) OnEnd(span sdktrace.ReadOnlySpan) {
	processor.mu.Lock()
	processor.endedAt = append(processor.endedAt, span.EndTime())
	processor.mu.Unlock()
	processor.ends.Add(1)
	if processor.panicEnd {
		panic("legacy end panic")
	}
}

func (processor *v8HandoffLegacyProcessor) endTimes() []time.Time {
	processor.mu.Lock()
	defer processor.mu.Unlock()
	return append([]time.Time(nil), processor.endedAt...)
}

func (processor *v8HandoffLegacyProcessor) ForceFlush(context.Context) error {
	if processor.panicFlush {
		panic("legacy flush panic")
	}
	if processor.order != nil {
		*processor.order = append(*processor.order, "flush:"+processor.name)
	}
	return processor.flushErr
}

func (processor *v8HandoffLegacyProcessor) Shutdown(context.Context) error {
	processor.shutdowns.Add(1)
	if processor.panicShutdown {
		panic("legacy shutdown panic")
	}
	if processor.order != nil {
		*processor.order = append(*processor.order, "shutdown:"+processor.name)
	}
	return processor.shutdownErr
}

type v8HandoffRig struct {
	provider  *Provider
	composite *v8CompositeSpanProcessor
	sdk       *sdktrace.TracerProvider
}

func newV8HandoffRig(t *testing.T, pipelines ...V8GenerationSpanPipeline) *v8HandoffRig {
	t.Helper()
	plan := v8PlanForTest(t, "always_on", "", nil)
	provider, err := NewProviderV8Inactive(context.Background(), plan, v8HandoffTestGeneration, V8ProviderOptions{
		Version: "8.0.0", Environment: "test", ServiceInstanceID: "instance-001",
		DefenseClawInstanceID: "instance-001",
		GenerationPipelines: func(
			context.Context, *config.ObservabilityV8Plan, uint64, V8MetricReaderSpec,
		) (V8GenerationPipelines, error) {
			return V8GenerationPipelines{SpanPipelines: pipelines}, nil
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	provider.v8.active.Store(true)
	provider.v8.handoff.setActive(true)
	t.Cleanup(func() { _ = provider.Shutdown(context.Background()) })
	return &v8HandoffRig{provider: provider, composite: provider.v8.spanProcessor, sdk: provider.tracerProvider}
}

var v8HandoffRecordSequence atomic.Uint64

func v8HandoffRecord(
	t *testing.T,
	traceID trace.TraceID,
	spanID trace.SpanID,
	start, end time.Time,
	configDigest string,
	parentSpanID string,
	resourceProvider *Provider,
) observability.Record {
	t.Helper()
	builder, err := observability.NewFamilyBuilder(
		observability.ClockFunc(func() time.Time { return end }),
		observability.OccurrenceIDGeneratorFunc(func() (string, error) {
			return fmt.Sprintf("handoff-record-%d", v8HandoffRecordSequence.Add(1)), nil
		}),
	)
	if err != nil {
		t.Fatal(err)
	}
	record, err := builder.BuildSpanDiagnosticCanary(observability.SpanDiagnosticCanaryInput{
		Envelope: observability.FamilyEnvelopeInput{
			Source: observability.SourceGateway,
			Correlation: observability.Correlation{
				TraceID: traceID.String(), SpanID: spanID.String(),
			},
			Provenance: observability.FamilyProvenanceInput{
				Producer: "defenseclaw", BinaryVersion: "8.0.0",
				ConfigGeneration: v8HandoffTestGeneration, ConfigDigest: configDigest,
			},
		},
		Outcome: observability.OutcomeCompleted,
		Kind:    "INTERNAL", StartTimeUnixNano: uint64(start.UnixNano()), EndTimeUnixNano: uint64(end.UnixNano()),
		ParentSpanID: func() observability.Optional[string] {
			if parentSpanID == "" {
				return observability.Absent[string]()
			}
			return observability.Present(parentSpanID)
		}(), Status: observability.NewTraceStatusUnset(),
		Resource: observability.TraceResourceInput{
			SchemaURL: "https://opentelemetry.io/schemas/1.42.0",
		},
		Scope:                             observability.TraceScopeInput{},
		ResourceServiceName:               "defenseclaw",
		ResourceServiceNamespace:          "defenseclaw",
		ResourceServiceInstanceID:         "instance-001",
		ResourceDeploymentEnvironmentName: "test",
		ResourceHostName:                  v8OptionalResourceAttribute(resourceProvider, "host.name"),
		ResourceHostArch:                  v8OptionalResourceAttribute(resourceProvider, "host.arch"),
		ResourceOsType:                    v8OptionalResourceAttribute(resourceProvider, "os.type"),
		ResourceTenantID:                  v8OptionalResourceAttribute(resourceProvider, "tenant.id"),
		ResourceWorkspaceID:               v8OptionalResourceAttribute(resourceProvider, "workspace.id"),
		ResourceDefenseClawDeploymentMode: v8OptionalResourceAttribute(resourceProvider, "defenseclaw.deployment.mode"),
		ResourceDefenseClawClawMode:       v8OptionalResourceAttribute(resourceProvider, "defenseclaw.claw.mode"),
		ResourceDefenseClawInstanceID:     "instance-001",
		ResourceDefenseClawDevicePublicKeyFingerprint: v8OptionalResourceAttribute(
			resourceProvider, "defenseclaw.device.public_key_fingerprint",
		),
		ConditionOperationTerminal: true,
	})
	if err != nil {
		t.Fatalf("build generated trace record: %v", err)
	}
	return record
}

func v8OptionalResourceAttribute(provider *Provider, key string) observability.Optional[string] {
	if provider != nil {
		if value := resourceAttribute(provider, key); value != "" {
			return observability.Present(value)
		}
	}
	return observability.Absent[string]()
}

func mustV8CanonicalEndedSpan(t *testing.T, record observability.Record) V8CanonicalEndedSpan {
	t.Helper()
	canonical, ok := newV8CanonicalEndedSpan(record)
	if !ok {
		t.Fatal("generated trace record did not parse as canonical")
	}
	return canonical
}

func v8StartHandoffSpan(
	t *testing.T,
	rig *v8HandoffRig,
	start, end time.Time,
	mutateControls func([]attribute.KeyValue) []attribute.KeyValue,
) (trace.Span, observability.Record) {
	return v8StartHandoffSpanContext(t, rig, context.Background(), start, end, mutateControls)
}

func v8StartHandoffSpanContext(
	t *testing.T,
	rig *v8HandoffRig,
	ctx context.Context,
	start, end time.Time,
	mutateControls func([]attribute.KeyValue) []attribute.KeyValue,
) (trace.Span, observability.Record) {
	t.Helper()
	_, span := rig.provider.Tracer().Start(
		ctx, "pending", trace.WithTimestamp(start), trace.WithSpanKind(trace.SpanKindInternal),
	)
	parentSpanID := ""
	if parent := trace.SpanContextFromContext(ctx); parent.IsValid() {
		parentSpanID = parent.SpanID().String()
	}
	record := v8HandoffRecord(
		t, span.SpanContext().TraceID(), span.SpanContext().SpanID(), start, end,
		rig.provider.v8.planDigest, parentSpanID, rig.provider,
	)
	canonical, ok := newV8CanonicalEndedSpan(record)
	if !ok {
		t.Fatal("generated trace record did not parse as canonical")
	}
	span.SetName(record.SpanName())
	controls := []attribute.KeyValue{
		attribute.String("defenseclaw.bucket", canonical.bucket),
		attribute.Int64("defenseclaw.config.generation", canonical.configGeneration),
		attribute.String("defenseclaw.span.family", canonical.family),
		attribute.Int64("defenseclaw.span.family_schema_version", canonical.familyVersion),
	}
	if mutateControls != nil {
		controls = mutateControls(controls)
	}
	span.SetAttributes(controls...)
	return span, record
}

func TestV8CompositeMixedFanoutExactlyOnceAndCopyIsolation(t *testing.T) {
	first := &v8HandoffConsumer{name: "first"}
	second := &v8HandoffConsumer{name: "second"}
	legacy := &v8HandoffLegacyProcessor{name: "legacy"}
	rig := newV8HandoffRig(t,
		V8GenerationSpanPipeline{Destination: "canonical-a", Canonical: first},
		V8GenerationSpanPipeline{Destination: "legacy", Legacy: legacy},
		V8GenerationSpanPipeline{Destination: "canonical-b", Canonical: second},
	)
	start := time.Unix(1_783_080_000, 0).UTC()
	end := start.Add(250 * time.Millisecond)
	span, record := v8StartHandoffSpan(t, rig, start, end, nil)
	if result := rig.provider.EndV8CanonicalSpan(span, record); result != V8CanonicalSpanRegistered {
		t.Fatalf("end result = %s", result)
	}
	if got := legacy.starts.Load(); got != 1 {
		t.Fatalf("legacy starts = %d", got)
	}
	if got := legacy.ends.Load(); got != 1 {
		t.Fatalf("legacy ends = %d", got)
	}
	firstSpans, secondSpans := first.snapshot(), second.snapshot()
	if len(firstSpans) != 1 || len(secondSpans) != 1 {
		t.Fatalf("canonical fanout = %d/%d", len(firstSpans), len(secondSpans))
	}
	if !firstSpans[0].EndTime().Equal(end) || firstSpans[0].TraceID() != span.SpanContext().TraceID() {
		t.Fatal("canonical value metadata was not preserved")
	}
	body, _ := firstSpans[0].Record().Body()
	object, _ := body.Object()
	object["kind"] = "CLIENT"
	secondBody, _ := secondSpans[0].Record().Body()
	secondObject, _ := secondBody.Object()
	if secondObject["kind"] != "INTERNAL" {
		t.Fatal("consumer-local mutation escaped immutable record accessor")
	}
	if rig.composite.handoff.pendingBytes != 0 || len(rig.composite.handoff.pending) != 0 {
		t.Fatal("successful End retained a pending canonical record")
	}
}

func TestV8CanonicalHandoffCopiesTraceStateFlagsScopeAndResource(t *testing.T) {
	consumer := &v8HandoffConsumer{}
	rig := newV8HandoffRig(t, V8GenerationSpanPipeline{Destination: "canonical", Canonical: consumer})
	state, err := trace.ParseTraceState("vendor=value")
	if err != nil {
		t.Fatal(err)
	}
	parent := trace.NewSpanContext(trace.SpanContextConfig{
		TraceID: trace.TraceID{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16},
		SpanID:  trace.SpanID{1, 2, 3, 4, 5, 6, 7, 8}, TraceFlags: trace.FlagsSampled,
		TraceState: state, Remote: true,
	})
	ctx := trace.ContextWithRemoteSpanContext(context.Background(), parent)
	start := time.Unix(1_783_080_050, 0).UTC()
	span, record := v8StartHandoffSpanContext(t, rig, ctx, start, start.Add(time.Millisecond), nil)
	if got := rig.provider.EndV8CanonicalSpan(span, record); got != V8CanonicalSpanRegistered {
		t.Fatalf("end result = %s", got)
	}
	spans := consumer.snapshot()
	if len(spans) != 1 || spans[0].TraceState() != "vendor=value" ||
		spans[0].TraceFlags() != byte(trace.FlagsSampled) || spans[0].OTLPFlags() != 0x301 {
		t.Fatalf("trace metadata = %d/%q/%d/%#x", len(spans), spans[0].TraceState(), spans[0].TraceFlags(), spans[0].OTLPFlags())
	}
	canonical, ok := newV8CanonicalEndedSpan(record)
	if !ok || canonical.scopeName != v8TraceScopeName || canonical.scopeSchemaURL != v8TraceScopeSchemaURL ||
		canonical.resourceSchemaURL != v8ResourceSchemaURL ||
		canonical.resourceAttributes["service.namespace"] != "defenseclaw" ||
		canonical.resourceAttributes["service.version"] != "8.0.0" {
		t.Fatal("generated record and actual v8 provider scope/resource contracts diverged")
	}

	localParent := trace.NewSpanContext(trace.SpanContextConfig{
		TraceID: trace.TraceID{2, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16},
		SpanID:  trace.SpanID{2, 2, 3, 4, 5, 6, 7, 8}, TraceFlags: trace.FlagsSampled,
	})
	localCtx := trace.ContextWithSpanContext(context.Background(), localParent)
	localSpan, localRecord := v8StartHandoffSpanContext(t, rig, localCtx, start, start.Add(time.Millisecond), nil)
	if got := rig.provider.EndV8CanonicalSpan(localSpan, localRecord); got != V8CanonicalSpanRegistered {
		t.Fatalf("local-parent end result = %s", got)
	}
	rootSpan, rootRecord := v8StartHandoffSpan(t, rig, start, start.Add(time.Millisecond), nil)
	if got := rig.provider.EndV8CanonicalSpan(rootSpan, rootRecord); got != V8CanonicalSpanRegistered {
		t.Fatalf("root end result = %s", got)
	}
	spans = consumer.snapshot()
	if len(spans) != 3 || spans[1].OTLPFlags() != 0x101 || spans[2].OTLPFlags() != 0x101 {
		t.Fatalf("local/root OTLP flags = %d/%#x/%#x", len(spans), spans[1].OTLPFlags(), spans[2].OTLPFlags())
	}
}

func TestV8SpanPipelineValidationRejectsXORNilDuplicateAndReuse(t *testing.T) {
	consumer := &v8HandoffConsumer{}
	legacy := &v8HandoffLegacyProcessor{}
	var typedNil *v8HandoffConsumer
	tests := []struct {
		name      string
		pipelines []V8GenerationSpanPipeline
	}{
		{name: "empty destination", pipelines: []V8GenerationSpanPipeline{{Canonical: consumer}}},
		{name: "space destination", pipelines: []V8GenerationSpanPipeline{{Destination: "not stable", Canonical: consumer}}},
		{name: "slash destination", pipelines: []V8GenerationSpanPipeline{{Destination: "not/stable", Canonical: consumer}}},
		{name: "unicode destination", pipelines: []V8GenerationSpanPipeline{{Destination: "télémétrie", Canonical: consumer}}},
		{name: "neither mode", pipelines: []V8GenerationSpanPipeline{{Destination: "a"}}},
		{name: "both modes", pipelines: []V8GenerationSpanPipeline{{Destination: "a", Canonical: consumer, Legacy: legacy}}},
		{name: "typed nil", pipelines: []V8GenerationSpanPipeline{{Destination: "a", Canonical: typedNil}}},
		{name: "duplicate destination", pipelines: []V8GenerationSpanPipeline{
			{Destination: "a", Canonical: consumer}, {Destination: "a", Legacy: legacy},
		}},
		{name: "reused child", pipelines: []V8GenerationSpanPipeline{
			{Destination: "a", Canonical: consumer}, {Destination: "b", Canonical: consumer},
		}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if validV8SpanPipelines(test.pipelines) {
				t.Fatal("invalid pipeline set accepted")
			}
			if composite, err := newV8CompositeSpanProcessor(1, 1, test.pipelines); err == nil || composite != nil {
				t.Fatalf("composite/error = %v/%v", composite, err)
			}
		})
	}
}

func TestCleanupV8SpanPipelinesVisitsBothInvalidArmsAndDeduplicates(t *testing.T) {
	consumer := &v8HandoffConsumer{}
	legacy := &v8HandoffLegacyProcessor{}
	cleanupV8SpanPipelines([]V8GenerationSpanPipeline{
		{Destination: "invalid-both", Canonical: consumer, Legacy: legacy},
		{Destination: "invalid-reused", Canonical: consumer, Legacy: legacy},
	}, time.Second)
	if consumer.shutdowns.Load() != 1 || legacy.shutdowns.Load() != 1 {
		t.Fatalf("cleanup shutdowns = %d/%d", consumer.shutdowns.Load(), legacy.shutdowns.Load())
	}
}

func TestV8CompositeMissingOrMismatchedHandoffDropsCanonicalOnly(t *testing.T) {
	consumer := &v8HandoffConsumer{}
	legacy := &v8HandoffLegacyProcessor{}
	rig := newV8HandoffRig(t,
		V8GenerationSpanPipeline{Destination: "canonical", Canonical: consumer},
		V8GenerationSpanPipeline{Destination: "legacy", Legacy: legacy},
	)
	start := time.Unix(1_783_080_100, 0).UTC()
	_, missing := rig.sdk.Tracer("test").Start(context.Background(), "missing", trace.WithTimestamp(start))
	missing.End(trace.WithTimestamp(start.Add(time.Millisecond)))

	span, record := v8StartHandoffSpan(t, rig, start, start.Add(2*time.Millisecond), func(values []attribute.KeyValue) []attribute.KeyValue {
		values[2] = attribute.String("defenseclaw.span.family", "span.wrong")
		return values
	})
	if got := rig.provider.EndV8CanonicalSpan(span, record); got != V8CanonicalSpanHandoffNotConsumed {
		t.Fatalf("mismatch registration = %s", got)
	}
	if got := len(consumer.snapshot()); got != 0 {
		t.Fatalf("canonical deliveries = %d", got)
	}
	if got := legacy.ends.Load(); got != 2 {
		t.Fatalf("legacy deliveries = %d", got)
	}
}

func TestV8EndHelperAlwaysEndsAndUsesCanonicalTimeOnlyAfterRegistration(t *testing.T) {
	consumer := &v8HandoffConsumer{}
	legacy := &v8HandoffLegacyProcessor{}
	rig := newV8HandoffRig(t,
		V8GenerationSpanPipeline{Destination: "canonical", Canonical: consumer},
		V8GenerationSpanPipeline{Destination: "legacy", Legacy: legacy},
	)
	start := time.Now().UTC()
	canonicalEnd := start.Add(24 * time.Hour)
	span, _ := v8StartHandoffSpan(t, rig, start, canonicalEnd, nil)
	wrongPlan := v8HandoffRecord(
		t, span.SpanContext().TraceID(), span.SpanContext().SpanID(), start, canonicalEnd,
		"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", "", rig.provider,
	)
	if got := rig.provider.EndV8CanonicalSpan(span, wrongPlan); got != V8CanonicalSpanPlanMismatch {
		t.Fatalf("plan mismatch result = %s", got)
	}

	_, invalidSpan := rig.provider.Tracer().Start(context.Background(), "invalid", trace.WithTimestamp(start))
	if got := rig.provider.EndV8CanonicalSpan(invalidSpan, observability.Record{}); got != V8CanonicalSpanInvalidRecord {
		t.Fatalf("invalid record result = %s", got)
	}
	ends := legacy.endTimes()
	if len(ends) != 2 || ends[0].Equal(canonicalEnd) {
		t.Fatalf("ordinary rejected end timestamps = %v", ends)
	}
	if len(consumer.snapshot()) != 0 || len(rig.composite.handoff.pending) != 0 {
		t.Fatal("rejected record was delivered or retained")
	}
}

func TestV8CompositeContainsDestinationPanicsAndFailures(t *testing.T) {
	panickingConsumer := &v8HandoffConsumer{panicEnqueue: true, panicFlush: true, panicShutdown: true}
	goodConsumer := &v8HandoffConsumer{}
	panickingLegacy := &v8HandoffLegacyProcessor{panicStart: true, panicEnd: true, panicFlush: true, panicShutdown: true}
	goodLegacy := &v8HandoffLegacyProcessor{}
	rig := newV8HandoffRig(t,
		V8GenerationSpanPipeline{Destination: "bad-canonical", Canonical: panickingConsumer},
		V8GenerationSpanPipeline{Destination: "good-canonical", Canonical: goodConsumer},
		V8GenerationSpanPipeline{Destination: "bad-legacy", Legacy: panickingLegacy},
		V8GenerationSpanPipeline{Destination: "good-legacy", Legacy: goodLegacy},
	)
	start := time.Unix(1_783_080_200, 0).UTC()
	span, record := v8StartHandoffSpan(t, rig, start, start.Add(time.Millisecond), nil)
	if got := rig.provider.EndV8CanonicalSpan(span, record); got != V8CanonicalSpanRegistered {
		t.Fatalf("end result = %s", got)
	}
	if len(goodConsumer.snapshot()) != 1 || goodLegacy.ends.Load() != 1 {
		t.Fatal("a panicking destination interrupted later destinations")
	}
	if err := rig.composite.ForceFlush(context.Background()); err == nil {
		t.Fatal("contained flush panic was not reported")
	}
	if err := rig.composite.Shutdown(context.Background()); err == nil {
		t.Fatal("contained shutdown panic was not reported")
	}
}

func TestV8CompositeFlushForwardShutdownReverseAndGenerationOwnership(t *testing.T) {
	order := []string{}
	first := &v8HandoffConsumer{name: "first", order: &order}
	second := &v8HandoffLegacyProcessor{name: "second", order: &order}
	third := &v8HandoffConsumer{name: "third", order: &order}
	composite, err := newV8CompositeSpanProcessor(9, 4, []V8GenerationSpanPipeline{
		{Destination: "first", Canonical: first},
		{Destination: "second", Legacy: second},
		{Destination: "third", Canonical: third},
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := composite.ForceFlush(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err := composite.Shutdown(context.Background()); err != nil {
		t.Fatal(err)
	}
	want := []string{"flush:first", "flush:second", "flush:third", "shutdown:third", "shutdown:second", "shutdown:first"}
	if fmt.Sprint(order) != fmt.Sprint(want) {
		t.Fatalf("order = %v, want %v", order, want)
	}
	if err := composite.Shutdown(context.Background()); err != nil || len(order) != len(want) {
		t.Fatal("composite shutdown was not generation-owned and idempotent")
	}
}

func TestV8ProviderShutdownWaitsForInFlightEndBeforeChildShutdown(t *testing.T) {
	consumer := &v8HandoffConsumer{
		enqueueEntered: make(chan struct{}), enqueueRelease: make(chan struct{}),
	}
	legacy := &v8HandoffLegacyProcessor{}
	rig := newV8HandoffRig(t,
		V8GenerationSpanPipeline{Destination: "canonical", Canonical: consumer},
		V8GenerationSpanPipeline{Destination: "legacy", Legacy: legacy},
	)
	start := time.Unix(1_783_080_250, 0).UTC()
	span, record := v8StartHandoffSpan(t, rig, start, start.Add(time.Millisecond), nil)
	endDone := make(chan V8CanonicalSpanRegistrationCode, 1)
	go func() { endDone <- rig.provider.EndV8CanonicalSpan(span, record) }()
	<-consumer.enqueueEntered
	shutdownDone := make(chan error, 1)
	go func() { shutdownDone <- rig.provider.Shutdown(context.Background()) }()
	select {
	case err := <-shutdownDone:
		t.Fatalf("shutdown crossed an in-flight callback: %v", err)
	case <-time.After(20 * time.Millisecond):
	}
	if consumer.shutdowns.Load() != 0 {
		t.Fatal("canonical consumer shut down while TryEnqueue was in flight")
	}
	close(consumer.enqueueRelease)
	if got := <-endDone; got != V8CanonicalSpanRegistered {
		t.Fatalf("end result = %s", got)
	}
	if err := <-shutdownDone; err != nil {
		t.Fatal(err)
	}
	if consumer.shutdowns.Load() != 1 || legacy.ends.Load() != 1 {
		t.Fatalf("shutdowns/legacy ends = %d/%d", consumer.shutdowns.Load(), legacy.ends.Load())
	}
}

func TestV8EndHelperReportsRetirementBetweenRegisterAndSDKEnd(t *testing.T) {
	consumer := &v8HandoffConsumer{}
	rig := newV8HandoffRig(t, V8GenerationSpanPipeline{Destination: "canonical", Canonical: consumer})
	start := time.Unix(1_783_080_275, 0).UTC()
	span, record := v8StartHandoffSpan(t, rig, start, start.Add(time.Millisecond), nil)
	wrapped := &v8ShutdownBeforeEndSpan{Span: span, before: func() {
		if err := rig.composite.Shutdown(context.Background()); err != nil {
			t.Fatal(err)
		}
	}}
	result := rig.provider.EndV8CanonicalSpan(wrapped, record)
	if result != V8CanonicalSpanGenerationInactive {
		t.Fatalf("register/close/End result = %s", result)
	}
	if len(consumer.snapshot()) != 0 || len(rig.composite.handoff.pending) != 0 ||
		rig.composite.handoff.pendingBytes != 0 {
		t.Fatal("retired handoff reported success or retained canonical data")
	}
}

type v8ShutdownBeforeEndSpan struct {
	trace.Span
	once   sync.Once
	before func()
}

func (span *v8ShutdownBeforeEndSpan) End(options ...trace.SpanEndOption) {
	span.once.Do(span.before)
	span.Span.End(options...)
}

type v8PanickingEndSpan struct{ trace.Span }

func (*v8PanickingEndSpan) End(...trace.SpanEndOption) { panic("test End panic") }

func TestV8EndHelperPanicStillCancelsPendingBytes(t *testing.T) {
	consumer := &v8HandoffConsumer{}
	rig := newV8HandoffRig(t, V8GenerationSpanPipeline{Destination: "canonical", Canonical: consumer})
	start := time.Unix(1_783_080_280, 0).UTC()
	span, record := v8StartHandoffSpan(t, rig, start, start.Add(time.Millisecond), nil)
	func() {
		defer func() {
			if recover() == nil {
				t.Fatal("panicking span End did not panic")
			}
		}()
		_ = rig.provider.EndV8CanonicalSpan(&v8PanickingEndSpan{Span: span}, record)
	}()
	if len(rig.composite.handoff.pending) != 0 || rig.composite.handoff.pendingBytes != 0 {
		t.Fatal("panicking End leaked pending canonical handoff capacity")
	}
	span.End()
	var typedNil *v8PanickingEndSpan
	if got := rig.provider.EndV8CanonicalSpan(typedNil, record); got != V8CanonicalSpanProviderUnavailable {
		t.Fatalf("typed-nil span result = %s", got)
	}
}

func TestV8HandoffCountBytesDuplicateInactiveSamplingAndShutdown(t *testing.T) {
	consumer := &v8HandoffConsumer{}
	composite, err := newV8CompositeSpanProcessor(7, 1, []V8GenerationSpanPipeline{{Destination: "canonical", Canonical: consumer}})
	if err != nil {
		t.Fatal(err)
	}
	composite.handoff = newV8SpanHandoff(7, 1, v8DefaultCanonicalSpanHandoffBytes)
	composite.handoff.setActive(true)
	sdk := sdktrace.NewTracerProvider(sdktrace.WithSampler(sdktrace.AlwaysSample()))
	defer func() { _ = sdk.Shutdown(context.Background()) }()
	start := time.Unix(1_783_080_300, 0).UTC()
	_, firstSpan := sdk.Tracer("test").Start(context.Background(), "first", trace.WithTimestamp(start))
	firstRecord := v8HandoffRecord(t, firstSpan.SpanContext().TraceID(), firstSpan.SpanContext().SpanID(), start, start.Add(time.Millisecond), "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", "", nil)
	first, got := composite.handoff.register(firstSpan, mustV8CanonicalEndedSpan(t, firstRecord))
	if got != V8CanonicalSpanRegistered {
		t.Fatalf("first registration = %s", got)
	}
	if _, got = composite.handoff.register(firstSpan, mustV8CanonicalEndedSpan(t, firstRecord)); got != V8CanonicalSpanDuplicate {
		t.Fatalf("duplicate registration = %s", got)
	}
	_, secondSpan := sdk.Tracer("test").Start(context.Background(), "second", trace.WithTimestamp(start))
	secondRecord := v8HandoffRecord(t, secondSpan.SpanContext().TraceID(), secondSpan.SpanContext().SpanID(), start, start.Add(time.Millisecond), "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", "", nil)
	if _, got = composite.handoff.register(secondSpan, mustV8CanonicalEndedSpan(t, secondRecord)); got != V8CanonicalSpanCapacityExceeded {
		t.Fatalf("count capacity = %s", got)
	}
	first.cancel()

	encoded, _ := firstRecord.Bytes()
	byteBounded := newV8SpanHandoff(7, 2, len(encoded)-1)
	byteBounded.setActive(true)
	if _, got = byteBounded.register(firstSpan, mustV8CanonicalEndedSpan(t, firstRecord)); got != V8CanonicalSpanCapacityExceeded {
		t.Fatalf("byte capacity = %s", got)
	}
	byteBounded.setActive(false)
	if _, got = byteBounded.register(firstSpan, mustV8CanonicalEndedSpan(t, firstRecord)); got != V8CanonicalSpanGenerationInactive {
		t.Fatalf("inactive registration = %s", got)
	}

	recordOnly := sdktrace.NewTracerProvider(sdktrace.WithSampler(v8RecordOnlySampler{}))
	defer func() { _ = recordOnly.Shutdown(context.Background()) }()
	_, unsampled := recordOnly.Tracer("test").Start(context.Background(), "unsampled", trace.WithTimestamp(start))
	unsampledRecord := v8HandoffRecord(t, unsampled.SpanContext().TraceID(), unsampled.SpanContext().SpanID(), start, start.Add(time.Millisecond), "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", "", nil)
	composite.handoff.setActive(true)
	if _, got = composite.handoff.register(unsampled, mustV8CanonicalEndedSpan(t, unsampledRecord)); got != V8CanonicalSpanNotSampled {
		t.Fatalf("unsampled registration = %s", got)
	}

	registration, got := composite.handoff.register(firstSpan, mustV8CanonicalEndedSpan(t, firstRecord))
	if got != V8CanonicalSpanRegistered {
		t.Fatalf("pending registration = %s", got)
	}
	_ = registration
	if err := composite.Shutdown(context.Background()); err != nil {
		t.Fatal(err)
	}
	if len(composite.handoff.pending) != 0 || composite.handoff.pendingBytes != 0 || composite.handoff.active.Load() {
		t.Fatal("shutdown did not retire and clear the generation handoff")
	}
}

type v8RecordOnlySampler struct{}

func (v8RecordOnlySampler) ShouldSample(sdktrace.SamplingParameters) sdktrace.SamplingResult {
	return sdktrace.SamplingResult{Decision: sdktrace.RecordOnly}
}
func (v8RecordOnlySampler) Description() string { return "record-only" }

func TestV8EndHelperConcurrentEndNeverLeaksPendingRecord(t *testing.T) {
	consumer := &v8HandoffConsumer{}
	legacy := &v8HandoffLegacyProcessor{}
	for iteration := 0; iteration < 100; iteration++ {
		rig := newV8HandoffRig(t,
			V8GenerationSpanPipeline{Destination: "canonical", Canonical: consumer},
			V8GenerationSpanPipeline{Destination: "legacy", Legacy: legacy},
		)
		start := time.Unix(1_783_080_400, int64(iteration)).UTC()
		end := start.Add(time.Millisecond)
		span, record := v8StartHandoffSpan(t, rig, start, end, nil)
		ready := make(chan struct{})
		done := make(chan struct{})
		go func() {
			close(ready)
			span.End(trace.WithTimestamp(end))
			close(done)
		}()
		<-ready
		result := rig.provider.EndV8CanonicalSpan(span, record)
		<-done
		// The deliberately out-of-contract competing End may win after the
		// helper's recording check but before handoff registration. In that
		// interleaving the SDK does not invoke OnEnd twice, so an unconsumed
		// result is honest; the invariant under test is exact capacity cleanup.
		if result != V8CanonicalSpanRegistered && result != V8CanonicalSpanNotRecording &&
			result != V8CanonicalSpanHandoffNotConsumed {
			t.Fatalf("concurrent result = %s", result)
		}
		if len(rig.composite.handoff.pending) != 0 || rig.composite.handoff.pendingBytes != 0 {
			t.Fatalf("iteration %d leaked a pending record", iteration)
		}
	}
}

func TestV8ProviderRejectsTestProcessorFactoryCombinedWithNamedPipelines(t *testing.T) {
	plan := v8PlanForTest(t, "always_on", "", nil)
	provider, err := NewProviderV8Inactive(context.Background(), plan, 1, V8ProviderOptions{
		SpanProcessorFactory: func(uint64) (sdktrace.SpanProcessor, error) {
			return &v8HandoffLegacyProcessor{}, nil
		},
		GenerationPipelines: func(context.Context, *config.ObservabilityV8Plan, uint64, V8MetricReaderSpec) (V8GenerationPipelines, error) {
			return V8GenerationPipelines{}, nil
		},
	})
	if provider != nil || err == nil {
		t.Fatalf("provider/error = %v/%v", provider, err)
	}
	var providerError *V8ProviderError
	if !errors.As(err, &providerError) || providerError.Code() != V8ProviderErrorInitialization {
		t.Fatalf("error = %T/%v", err, err)
	}
}

func TestV8ProviderRequiresHonestVersionAndEnvironmentOnlyWhenTracesCollected(t *testing.T) {
	plan := v8PlanForTest(t, "always_on", "", nil)
	for _, options := range []V8ProviderOptions{{Environment: "test"}, {Version: "8.0.0"}} {
		provider, err := NewProviderV8Inactive(context.Background(), plan, 1, options)
		if provider != nil || err == nil {
			t.Fatalf("trace provider accepted missing required identity: %v/%v", provider, err)
		}
	}
	configuredEnvironment := v8PlanForTest(t, "always_on", "", func(source *config.ObservabilityV8Source) {
		source.Resource.Attributes = map[string]string{"deployment.environment.name": "test"}
	})
	provider, err := NewProviderV8Inactive(
		context.Background(), configuredEnvironment, 1, V8ProviderOptions{Version: "8.0.0"},
	)
	if err != nil {
		t.Fatalf("configured resource environment did not satisfy trace identity: %v", err)
	}
	if err := provider.Shutdown(context.Background()); err != nil {
		t.Fatal(err)
	}
	no := false
	metricsOnly := v8PlanForTest(t, "always_on", "", func(source *config.ObservabilityV8Source) {
		source.Defaults.Collect.Traces = &no
	})
	provider, err = NewProviderV8Inactive(context.Background(), metricsOnly, 1, V8ProviderOptions{})
	if err != nil {
		t.Fatalf("metrics-only provider rejected optional trace identity: %v", err)
	}
	_ = provider.Shutdown(context.Background())
}

func TestV8CanonicalStatusParity(t *testing.T) {
	// A focused closed-code assertion keeps canonical/SDK status vocabulary
	// pinned independently from the larger fanout test.
	if got, _, ok := v8CanonicalSpanStatus(map[string]any{"code": "ERROR", "description": "bounded"}); !ok || got != codes.Error {
		t.Fatalf("status = %v/%t", got, ok)
	}
}
