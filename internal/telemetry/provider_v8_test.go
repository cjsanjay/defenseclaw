// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// SPDX-License-Identifier: Apache-2.0

package telemetry

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
	"unicode/utf8"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	logglobal "go.opentelemetry.io/otel/log/global"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	"go.opentelemetry.io/otel/sdk/trace/tracetest"
	"go.opentelemetry.io/otel/trace"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/observability"
	"github.com/defenseclaw/defenseclaw/internal/observability/runtimegraph"
)

func boolPointer(value bool) *bool { return &value }

func v8PlanForTest(t *testing.T, sampler, argument string, mutate func(*config.ObservabilityV8Source)) *config.ObservabilityV8Plan {
	t.Helper()
	dir := t.TempDir()
	source := &config.ObservabilityV8Source{
		TracePolicy: config.ObservabilityV8TracePolicySource{Sampler: sampler, SamplerArg: argument},
		Local: config.ObservabilityV8LocalSource{
			Path: filepath.Join(dir, "audit.db"), JudgeBodiesPath: filepath.Join(dir, "judge.db"),
		},
	}
	if mutate != nil {
		mutate(source)
	}
	plan, err := config.CompileObservabilityV8(source)
	if err != nil {
		t.Fatalf("compile v8 plan: %v", err)
	}
	return plan
}

func activeV8ProviderForTest(
	t *testing.T,
	plan *config.ObservabilityV8Plan,
	generation uint64,
) (*Provider, *tracetest.InMemoryExporter) {
	t.Helper()
	exporter := tracetest.NewInMemoryExporter()
	provider, err := NewProviderV8Inactive(context.Background(), plan, generation, V8ProviderOptions{
		Version: "test-version", Environment: "test", ServiceInstanceID: "test-instance",
		SpanProcessorFactory: func(uint64) (sdktrace.SpanProcessor, error) {
			return sdktrace.NewSimpleSpanProcessor(exporter), nil
		},
	})
	if err != nil {
		t.Fatalf("new v8 provider: %v", err)
	}
	provider.v8.active.Store(true)
	t.Cleanup(func() { _ = provider.Shutdown(context.Background()) })
	return provider, exporter
}

func TestV8SamplerSupportsClosedVocabularyAndFailsClosed(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name, argument string
		wantRoot       sdktrace.SamplingDecision
	}{
		{name: "always_on", wantRoot: sdktrace.RecordAndSample},
		{name: "always_off", wantRoot: sdktrace.Drop},
		{name: "parentbased_always_on", wantRoot: sdktrace.RecordAndSample},
		{name: "parentbased_always_off", wantRoot: sdktrace.Drop},
		{name: "traceidratio", argument: "1", wantRoot: sdktrace.RecordAndSample},
		{name: "parentbased_traceidratio", argument: "0", wantRoot: sdktrace.Drop},
	}
	traceID := trace.TraceID{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			sampler, err := newV8Sampler(test.name, test.argument, newV8SamplingDebug(nil))
			if err != nil {
				t.Fatalf("new sampler: %v", err)
			}
			got := sampler.ShouldSample(sdktrace.SamplingParameters{ParentContext: context.Background(), TraceID: traceID, Name: "ordinary"})
			if got.Decision != test.wantRoot {
				t.Fatalf("root decision=%v, want %v", got.Decision, test.wantRoot)
			}
		})
	}
	for _, invalid := range []struct{ name, argument string }{
		{"future", ""}, {"always_on", "0.5"}, {"traceidratio", ""},
		{"traceidratio", "-0.1"}, {"traceidratio", "1.1"}, {"traceidratio", "NaN"},
	} {
		if _, err := newV8Sampler(invalid.name, invalid.argument, newV8SamplingDebug(nil)); err == nil {
			t.Errorf("newV8Sampler(%q, %q) succeeded, want fail-closed error", invalid.name, invalid.argument)
		}
	}
}

func TestV8ParentSamplerPreservesParentCoherenceAndTraceState(t *testing.T) {
	t.Parallel()
	traceID := trace.TraceID{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16}
	spanID := trace.SpanID{1, 2, 3, 4, 5, 6, 7, 8}
	state, _ := trace.ParseTraceState("vendor=value")
	for _, test := range []struct {
		name   string
		flags  trace.TraceFlags
		want   sdktrace.SamplingDecision
		reason string
	}{
		{"sampled", trace.FlagsSampled, sdktrace.RecordAndSample, v8SamplingReasonParentSampled},
		{"unsampled", 0, sdktrace.Drop, v8SamplingReasonParentUnsampled},
	} {
		t.Run(test.name, func(t *testing.T) {
			debug := newV8SamplingDebug(nil)
			parentSampler, _ := newV8Sampler("parentbased_always_off", "", debug)
			parent := trace.NewSpanContext(trace.SpanContextConfig{TraceID: traceID, SpanID: spanID, TraceFlags: test.flags, TraceState: state})
			result := parentSampler.ShouldSample(sdktrace.SamplingParameters{
				ParentContext: trace.ContextWithSpanContext(context.Background(), parent), TraceID: traceID, Name: "child",
			})
			if result.Decision != test.want || result.Tracestate.String() != "vendor=value" {
				t.Fatalf("decision/state=%v/%q, want %v/vendor=value", result.Decision, result.Tracestate.String(), test.want)
			}
			counts := debug.snapshot()
			if len(counts) != 1 || counts[0].Reason != test.reason {
				t.Fatalf("debug=%+v, want reason %s", counts, test.reason)
			}
		})
	}
}

func TestV8CollectionGatePrecedesSpanConstructionAndRouteCannotResurrect(t *testing.T) {
	plan := v8PlanForTest(t, "always_on", "", func(source *config.ObservabilityV8Source) {
		source.Buckets = map[observability.Bucket]config.ObservabilityV8BucketPolicySource{
			observability.BucketModelIO: {Collect: config.ObservabilityV8CollectSource{Traces: boolPointer(false)}},
		}
	})
	provider, exporter := activeV8ProviderForTest(t, plan, 7)
	if digest, generation, ok := provider.V8PlanBinding(); !ok || digest != plan.Digest() || generation != 7 {
		t.Fatalf("plan binding=%q/%d/%v, want %q/7/true", digest, generation, ok, plan.Digest())
	}

	_, llm := provider.StartLLMSpan(context.Background(), "openai", "private-model", "openai", 1, 0)
	if llm != nil || len(exporter.GetSpans()) != 0 {
		t.Fatalf("disabled model.io constructed/exported a span: span=%v exported=%d", llm, len(exporter.GetSpans()))
	}
	_, agent := provider.StartAgentSpan(context.Background(), "conversation", "agent", "root", "id", "openai", "connector")
	if agent == nil {
		t.Fatal("enabled agent.lifecycle did not construct a span")
	}
	provider.EndAgentSpan(agent, "")
	if len(exporter.GetSpans()) != 1 {
		t.Fatalf("exported spans=%d, want 1", len(exporter.GetSpans()))
	}
	var samplingDecisions uint64
	for _, count := range provider.SamplingDebugSnapshot() {
		samplingDecisions += count.Count
	}
	if samplingDecisions != 1 {
		t.Fatalf("sampler decisions=%d, want only enabled agent span; disabled model.io reached construction", samplingDecisions)
	}
	unsampled := trace.NewSpanContext(trace.SpanContextConfig{
		TraceID: trace.TraceID{1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1},
		SpanID:  trace.SpanID{1, 1, 1, 1, 1, 1, 1, 1},
	})
	if provider.TraceExportEligible(observability.BucketModelIO, unsampled) ||
		provider.TraceExportEligible(observability.BucketAgentLifecycle, unsampled) {
		t.Fatal("route eligibility resurrected disabled or unsampled trace")
	}
}

func TestV8TargetedCanaryBypassesSamplingExactlyAndDebugIsSafe(t *testing.T) {
	var observed atomic.Uint64
	plan := v8PlanForTest(t, "always_off", "", nil)
	exporter := tracetest.NewInMemoryExporter()
	provider, err := NewProviderV8Inactive(context.Background(), plan, 1, V8ProviderOptions{
		SpanProcessorFactory: func(uint64) (sdktrace.SpanProcessor, error) {
			return sdktrace.NewSimpleSpanProcessor(exporter), nil
		},
		SamplingObserver: func(value SamplingDecisionDebug) {
			observed.Add(1)
			if value.Reason == v8SamplingReasonTargetedCanary {
				panic("observer isolation")
			}
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	provider.v8.active.Store(true)
	t.Cleanup(func() { _ = provider.Shutdown(context.Background()) })

	if _, err := provider.EmitGenAICanary(context.Background()); err != nil {
		t.Fatalf("untargeted canary: %v", err)
	}
	if got := len(exporter.GetSpans()); got != 0 {
		t.Fatalf("untargeted canary bypassed always_off: %d spans", got)
	}
	if _, err := provider.EmitGenAICanaryToDestination(context.Background(), "galileo"); err != nil {
		t.Fatalf("targeted canary: %v", err)
	}
	spans := exporter.GetSpans()
	if len(spans) != 2 {
		t.Fatalf("targeted canary exported %d spans, want 2", len(spans))
	}
	for _, span := range spans {
		if !span.SpanContext.IsSampled() || !provider.TraceExportEligible(observability.BucketDiagnostic, span.SpanContext) {
			t.Fatalf("canary span %q was not sampled/eligible", span.Name)
		}
	}
	counts := provider.SamplingDebugSnapshot()
	if observed.Load() < 4 {
		t.Fatalf("observer calls=%d, want decisions for both attempts", observed.Load())
	}
	foundTargeted := false
	for _, count := range counts {
		if count.Reason == v8SamplingReasonTargetedCanary && count.Decision == v8SamplingDecisionSampled && count.Count == 2 {
			foundTargeted = true
		}
		if strings.Contains(fmt.Sprintf("%+v", count), "galileo") {
			t.Fatal("sampling debug leaked destination data")
		}
	}
	if !foundTargeted {
		t.Fatalf("debug counts=%+v, want two targeted_canary samples", counts)
	}
}

func TestV8TraceLimitsAreAppliedAndComplete(t *testing.T) {
	plan := v8PlanForTest(t, "always_on", "", func(source *config.ObservabilityV8Source) {
		source.TracePolicy.Limits = config.ObservabilityV8TraceLimitsSource{
			MaxAttributesPerSpan: 32, MaxEventsPerSpan: 1, MaxLinksPerSpan: 1,
			MaxAttributesPerEvent: 4, MaxAttributeValueBytes: 256,
			MaxProjectedSpanBytes: 4_096, MaxStacktraceBytes: 256, MaxMessageItems: 1,
		}
	})
	provider, exporter := activeV8ProviderForTest(t, plan, 1)
	limits := provider.TraceLimits()
	if limits != plan.Snapshot().TracePolicy.Limits {
		t.Fatalf("provider limits=%+v, want %+v", limits, plan.Snapshot().TracePolicy.Limits)
	}
	linkOne := trace.NewSpanContext(trace.SpanContextConfig{
		TraceID: trace.TraceID{1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1}, SpanID: trace.SpanID{1, 1, 1, 1, 1, 1, 1, 1},
	})
	linkTwo := trace.NewSpanContext(trace.SpanContextConfig{
		TraceID: trace.TraceID{2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2}, SpanID: trace.SpanID{2, 2, 2, 2, 2, 2, 2, 2},
	})
	_, span := provider.tracer.Start(context.Background(), "limited",
		trace.WithAttributes(attribute.String("long", strings.Repeat("x", 400))),
		trace.WithLinks(trace.Link{SpanContext: linkOne}, trace.Link{SpanContext: linkTwo}),
	)
	for index := 0; index < 40; index++ {
		span.SetAttributes(attribute.Int(fmt.Sprintf("attr.%02d", index), index))
	}
	span.AddEvent("old", trace.WithAttributes(
		attribute.Int("1", 1), attribute.Int("2", 2), attribute.Int("3", 3), attribute.Int("4", 4), attribute.Int("5", 5),
	))
	span.AddEvent("new")
	span.End()

	spans := exporter.GetSpans()
	if len(spans) != 1 {
		t.Fatalf("spans=%d, want 1", len(spans))
	}
	got := spans[0]
	if len(got.Attributes) != 32 || len(got.Events) != 1 || got.Events[0].Name != "new" || len(got.Links) != 1 {
		t.Fatalf("limits not applied: attrs=%d events=%+v links=%d", len(got.Attributes), got.Events, len(got.Links))
	}
	long, ok := attrByKey(got.Attributes, "long")
	if !ok || len(long.AsString()) != 256 {
		t.Fatalf("long attribute len=%d ok=%v, want 256", len(long.AsString()), ok)
	}
}

func TestV8AttributeByteLimitPreservesUTF8AcrossSpanEventsErrorsAndLinks(t *testing.T) {
	plan := v8PlanForTest(t, "always_on", "", func(source *config.ObservabilityV8Source) {
		source.TracePolicy.Limits.MaxAttributeValueBytes = 256
	})
	provider, exporter := activeV8ProviderForTest(t, plan, 1)
	long := strings.Repeat("界", 200)
	linkContext := trace.NewSpanContext(trace.SpanContextConfig{
		TraceID: trace.TraceID{3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3},
		SpanID:  trace.SpanID{3, 3, 3, 3, 3, 3, 3, 3},
	})
	_, span := provider.TracerForBucket(observability.BucketDiagnostic).Start(
		context.Background(), "unicode",
		trace.WithAttributes(attribute.String("start.unicode", long)),
		trace.WithLinks(trace.Link{SpanContext: linkContext, Attributes: []attribute.KeyValue{attribute.String("link.unicode", long)}}),
	)
	span.SetAttributes(
		attribute.String("set.unicode", long),
		attribute.StringSlice("set.slice", []string{long, "short"}),
	)
	span.AddEvent("unicode.event", trace.WithAttributes(attribute.String("event.unicode", long)))
	span.RecordError(errors.New(long), trace.WithAttributes(attribute.String("error.unicode", long)))
	_, derivedSpan := span.TracerProvider().Tracer("derived").Start(
		context.Background(), "derived-unicode", trace.WithAttributes(attribute.String("derived.unicode", long)),
	)
	derivedSpan.End()
	span.End()

	spans := exporter.GetSpans()
	if len(spans) != 2 {
		t.Fatalf("spans=%d, want 2", len(spans))
	}
	assertBounded := func(label, value string) {
		t.Helper()
		if len(value) > 256 || !utf8.ValidString(value) {
			t.Errorf("%s bytes=%d valid=%v, want <=256 valid UTF-8", label, len(value), utf8.ValidString(value))
		}
	}
	checkAttrs := func(prefix string, attrs []attribute.KeyValue) {
		t.Helper()
		for _, item := range attrs {
			switch item.Value.Type() {
			case attribute.STRING:
				assertBounded(prefix+"."+string(item.Key), item.Value.AsString())
			case attribute.STRINGSLICE:
				for index, value := range item.Value.AsStringSlice() {
					assertBounded(fmt.Sprintf("%s.%s[%d]", prefix, item.Key, index), value)
				}
			}
		}
	}
	for _, recorded := range spans {
		checkAttrs("span", recorded.Attributes)
		for _, event := range recorded.Events {
			checkAttrs("event", event.Attributes)
		}
		for _, link := range recorded.Links {
			checkAttrs("link", link.Attributes)
		}
	}
}

func TestV8AlwaysOffDoesNotDisableDurableFindingOrEnforcementLogs(t *testing.T) {
	plan := v8PlanForTest(t, "always_off", "", nil)
	provider, exporter := activeV8ProviderForTest(t, plan, 1)
	_, span := provider.StartGuardrailSpan(context.Background(), "policy", "prompt", "model")
	if span == nil || span.IsRecording() || len(exporter.GetSpans()) != 0 {
		t.Fatalf("always_off trace result span=%v recording=%v exported=%d", span, span != nil && span.IsRecording(), len(exporter.GetSpans()))
	}
	collectedLogs := make(map[observability.Bucket]bool)
	for _, bucket := range plan.Snapshot().Buckets {
		collectedLogs[bucket.Bucket] = bucket.Collect.Logs
	}
	if !collectedLogs[observability.BucketSecurityFinding] || !collectedLogs[observability.BucketEnforcementAction] {
		t.Fatal("trace sampling changed durable finding/enforcement log collection")
	}
}

type v8TestClock struct{}

func (v8TestClock) Now() time.Time { return time.Unix(1_700_000_000, 0).UTC() }

type v8TestDeadlines struct{}

func (v8TestDeadlines) Context(parent context.Context, timeout time.Duration) (context.Context, context.CancelFunc) {
	return context.WithTimeout(parent, timeout)
}

type v8TestReporter struct{}

func (v8TestReporter) PlatformHealth(*runtimegraph.Graph, runtimegraph.Report) error     { return nil }
func (v8TestReporter) ComplianceActivity(*runtimegraph.Graph, runtimegraph.Report) error { return nil }

type generationExporters struct {
	mu        sync.Mutex
	exporters map[uint64]*tracetest.InMemoryExporter
	fail      atomic.Uint64
}

func (value *generationExporters) processor(generation uint64) (sdktrace.SpanProcessor, error) {
	if value.fail.Load() == generation {
		return nil, errors.New("injected processor failure")
	}
	exporter := tracetest.NewInMemoryExporter()
	value.mu.Lock()
	value.exporters[generation] = exporter
	value.mu.Unlock()
	return sdktrace.NewSimpleSpanProcessor(exporter), nil
}

func providerFromGraph(t *testing.T, manager *runtimegraph.Manager) (*Provider, *runtimegraph.Lease) {
	t.Helper()
	lease, err := manager.Acquire(context.Background())
	if err != nil {
		t.Fatalf("acquire graph: %v", err)
	}
	provider, ok := V8ProviderFromLease(lease)
	if !ok {
		lease.Release()
		t.Fatal("active graph has no v8 provider")
	}
	return provider, lease
}

func TestV8ProviderRuntimeGraphLifecycleIsGenerationOwned(t *testing.T) {
	dir := t.TempDir()
	compile := func(sampler string) *config.ObservabilityV8Plan {
		source := &config.ObservabilityV8Source{
			TracePolicy: config.ObservabilityV8TracePolicySource{Sampler: sampler},
			Local: config.ObservabilityV8LocalSource{
				Path: filepath.Join(dir, "audit.db"), JudgeBodiesPath: filepath.Join(dir, "judge.db"),
			},
		}
		plan, err := config.CompileObservabilityV8(source)
		if err != nil {
			t.Fatal(err)
		}
		return plan
	}
	exporters := &generationExporters{exporters: make(map[uint64]*tracetest.InMemoryExporter)}
	factory := NewV8ProviderFactory(V8ProviderOptions{
		Version: "test", Environment: "test", ServiceInstanceID: "process-stable",
		SpanProcessorFactory: exporters.processor,
	})
	firstPlan := compile("always_on")
	manager, err := runtimegraph.New(
		context.Background(), runtimegraph.ConfigFromPlan(firstPlan, false),
		[]runtimegraph.ComponentFactory{factory},
		runtimegraph.Options{DrainTimeout: time.Second, Clock: v8TestClock{}, Deadlines: v8TestDeadlines{}, Reporter: v8TestReporter{}},
	)
	if err != nil {
		t.Fatalf("new graph: %v", err)
	}
	t.Cleanup(func() { _ = manager.Close(context.Background()) })
	firstProvider, firstLease := providerFromGraph(t, manager)
	firstInstance := resourceAttribute(firstProvider, "service.instance.id")
	_, firstSpan := firstProvider.StartAgentSpan(context.Background(), "c", "first", "root", "id", "", "")
	firstProvider.EndAgentSpan(firstSpan, "")
	firstLease.Release()
	exporters.mu.Lock()
	firstCount := len(exporters.exporters[1].GetSpans())
	exporters.mu.Unlock()
	if firstCount != 1 {
		t.Fatalf("generation one emitted %d spans, want exactly one", firstCount)
	}

	secondPlan := compile("always_off")
	result, reloadErr := manager.Reload(context.Background(), runtimegraph.ConfigFromPlan(secondPlan, false))
	if reloadErr != nil || result.Status() != runtimegraph.ReloadApplied {
		t.Fatalf("reload=%s err=%v", result.Status(), reloadErr)
	}
	if firstProvider.Enabled() {
		t.Fatal("retired provider still accepts intake")
	}
	if _, span := firstProvider.StartAgentSpan(context.Background(), "c", "retired", "root", "id", "", ""); span != nil {
		t.Fatal("retired provider constructed a span")
	}
	secondProvider, secondLease := providerFromGraph(t, manager)
	if secondProvider == firstProvider || resourceAttribute(secondProvider, "service.instance.id") != firstInstance {
		t.Fatal("reload reused provider or changed process-stable resource identity")
	}
	activeBeforeReject := manager.Active()
	exporters.fail.Store(3)
	thirdPlan := compile("always_on")
	rejected, rejectErr := manager.Reload(context.Background(), runtimegraph.ConfigFromPlan(thirdPlan, false))
	if rejectErr == nil || rejected.Status() != runtimegraph.ReloadRejected || manager.Active() != activeBeforeReject {
		t.Fatalf("prepare rejection status=%s err=%v old_preserved=%v", rejected.Status(), rejectErr, manager.Active() == activeBeforeReject)
	}
	current, ok := V8ProviderFromLease(secondLease)
	if !ok || current != secondProvider {
		t.Fatal("rejected prepare replaced active provider")
	}
	secondLease.Release()
	if closeErr := manager.Close(context.Background()); closeErr != nil {
		t.Fatalf("close graph: %v", closeErr)
	}
	if secondProvider.Enabled() || !firstProvider.shutdown.Load() || !secondProvider.shutdown.Load() {
		t.Fatal("graph close leaked an active or unclosed SDK provider")
	}
}

func resourceAttribute(provider *Provider, key string) string {
	if provider == nil || provider.res == nil {
		return ""
	}
	iter := provider.res.Iter()
	for iter.Next() {
		item := iter.Attribute()
		if string(item.Key) == key {
			return item.Value.AsString()
		}
	}
	return ""
}

func TestV8ResourceUsesPlanAndSafeProcessMetadataOnly(t *testing.T) {
	t.Setenv("OTEL_SERVICE_NAME", "ambient-must-not-apply")
	_, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	keyFile := filepath.Join(t.TempDir(), "device.pem")
	block := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: privateKey.Seed()})
	if err := os.WriteFile(keyFile, block, 0o600); err != nil {
		t.Fatal(err)
	}
	plan := v8PlanForTest(t, "always_on", "", func(source *config.ObservabilityV8Source) {
		source.Resource.Attributes = map[string]string{
			"service.name": "custom-service", "service.instance.id": "config-must-not-override",
			"tenant.id": "config-must-not-override", "deployment.mode": "config-must-not-override",
			"workspace.id": "config-must-not-override", "deployment.environment": "config-must-not-override",
			"deployment.environment.name": "config-must-not-override", "defenseclaw.claw.mode": "config-must-not-override",
			"defenseclaw.instance.id": "config-must-not-override", "discovery.source": "config-must-not-override",
			"defenseclaw.device.id": "config-must-not-override", "service.version": "config-must-not-override",
			"custom.safe": "configured",
		}
	})
	provider, err := NewProviderV8Inactive(context.Background(), plan, 9, V8ProviderOptions{
		Version: "test-version", Environment: "test", ServiceInstanceID: "test-instance",
		DefenseClawInstanceID: "defenseclaw-instance", TenantID: "tenant-a", WorkspaceID: "workspace-a",
		DeploymentMode: "unmanaged", ConnectorMode: "multi", DiscoverySource: "registry", DeviceKeyFile: keyFile,
	})
	if err != nil {
		t.Fatal(err)
	}
	provider.v8.active.Store(true)
	t.Cleanup(func() { _ = provider.Shutdown(context.Background()) })
	fingerprint := deviceFingerprint(keyFile)
	for key, want := range map[string]string{
		"service.name": "custom-service", "service.namespace": "defenseclaw",
		"service.instance.id": "test-instance", "service.version": "test-version",
		"deployment.environment.name": "test", "deployment.environment": "test", "tenant.id": "tenant-a",
		"workspace.id": "workspace-a", "deployment.mode": "unmanaged", "defenseclaw.claw.mode": "multi",
		"defenseclaw.instance.id": "defenseclaw-instance", "discovery.source": "registry",
		"defenseclaw.device.id": fingerprint, "custom.safe": "configured",
	} {
		if got := resourceAttribute(provider, key); got != want {
			t.Errorf("resource %s=%q, want %q", key, got, want)
		}
	}
	if got := resourceAttribute(provider, "defenseclaw.claw.home_dir"); got != "" {
		t.Fatalf("v8 resource captured ambient home dir %q", got)
	}
}

func TestV8ResourceTrustedPrecedenceFallsBackToValidatedPlanValues(t *testing.T) {
	plan := v8PlanForTest(t, "always_on", "", func(source *config.ObservabilityV8Source) {
		source.Resource.Attributes = map[string]string{
			"tenant.id": "plan-tenant", "workspace.id": "plan-workspace",
			"deployment.environment": "plan-environment", "deployment.environment.name": "plan-environment",
			"deployment.mode": "plan-mode", "defenseclaw.claw.mode": "plan-connector",
			"discovery.source": "plan-discovery", "defenseclaw.device.id": "plan-device",
			"service.version": "plan-must-not-override", "defenseclaw.instance.id": "plan-must-not-override",
		}
	})
	provider, err := NewProviderV8Inactive(context.Background(), plan, 1, V8ProviderOptions{
		Version: "trusted-version", ServiceInstanceID: "trusted-service-instance",
	})
	if err != nil {
		t.Fatal(err)
	}
	provider.v8.active.Store(true)
	t.Cleanup(func() { _ = provider.Shutdown(context.Background()) })
	for key, want := range map[string]string{
		"tenant.id": "plan-tenant", "workspace.id": "plan-workspace",
		"deployment.environment": "plan-environment", "deployment.environment.name": "plan-environment",
		"service.version": "trusted-version", "service.instance.id": "trusted-service-instance",
		"defenseclaw.instance.id": "trusted-service-instance",
	} {
		if got := resourceAttribute(provider, key); got != want {
			t.Errorf("resource %s=%q, want %q", key, got, want)
		}
	}
	for _, key := range []string{"deployment.mode", "defenseclaw.claw.mode", "discovery.source", "defenseclaw.device.id"} {
		if got := resourceAttribute(provider, key); got != "" {
			t.Errorf("resource %s=%q, want spoofed plan value omitted", key, got)
		}
	}
}

type v8TypedTestError struct{ message string }

func (err *v8TypedTestError) Error() string { return err.message }

func TestV8RecordErrorBoundsStacktraceAndZeroTimestampUsesNow(t *testing.T) {
	plan := v8PlanForTest(t, "always_on", "", func(source *config.ObservabilityV8Source) {
		source.TracePolicy.Limits.MaxAttributeValueBytes = 65_536
		source.TracePolicy.Limits.MaxStacktraceBytes = 256
	})
	provider, exporter := activeV8ProviderForTest(t, plan, 1)
	_, span := provider.TracerForBucket(observability.BucketDiagnostic).Start(context.Background(), "error-bounds")
	span.AddEvent("zero-time", trace.WithTimestamp(time.Time{}))
	span.RecordError(&v8TypedTestError{message: "preserved-message"},
		trace.WithTimestamp(time.Time{}), trace.WithStackTrace(true),
		trace.WithAttributes(
			attribute.String("exception.type", "spoofed"),
			attribute.String("exception.message", "spoofed"),
		),
	)
	span.End()

	spans := exporter.GetSpans()
	eventCount := 0
	if len(spans) == 1 {
		eventCount = len(spans[0].Events)
	}
	if len(spans) != 1 || eventCount != 2 {
		t.Fatalf("spans/events=%d/%d, want 1/2", len(spans), eventCount)
	}
	for _, event := range spans[0].Events {
		if event.Time.IsZero() {
			t.Errorf("event %q retained an explicit zero timestamp", event.Name)
		}
	}
	var stacktrace, message, exceptionType string
	for _, event := range spans[0].Events {
		for _, item := range event.Attributes {
			switch string(item.Key) {
			case "exception.stacktrace":
				stacktrace = item.Value.AsString()
			case "exception.message":
				message = item.Value.AsString()
			case "exception.type":
				exceptionType = item.Value.AsString()
			}
		}
	}
	if stacktrace == "" || len(stacktrace) > 256 || !utf8.ValidString(stacktrace) {
		t.Fatalf("stacktrace bytes=%d valid=%v, want 1..256 valid UTF-8", len(stacktrace), utf8.ValidString(stacktrace))
	}
	if message != "preserved-message" || exceptionType != "*telemetry.v8TypedTestError" {
		t.Fatalf("exception semantics type/message=%q/%q", exceptionType, message)
	}
}

type v8FailingProcessor struct {
	forceFlushError error
	shutdownError   error
}

func (*v8FailingProcessor) OnStart(context.Context, sdktrace.ReadWriteSpan) {}
func (*v8FailingProcessor) OnEnd(sdktrace.ReadOnlySpan)                     {}
func (processor *v8FailingProcessor) Shutdown(context.Context) error        { return processor.shutdownError }
func (processor *v8FailingProcessor) ForceFlush(context.Context) error {
	return processor.forceFlushError
}

func TestV8BackendErrorsAreBoundedAndPreserveOnlyContextIdentity(t *testing.T) {
	secret := "https://user:token@collector.internal/v1/traces"
	plan := v8PlanForTest(t, "always_on", "", nil)
	factory := NewV8ProviderFactory(V8ProviderOptions{
		SpanProcessorFactory: func(uint64) (sdktrace.SpanProcessor, error) {
			return nil, fmt.Errorf("connect %s: %w", secret, context.Canceled)
		},
	})
	_, err := factory.Prepare(context.Background(), runtimegraph.BuildInput{
		Config: runtimegraph.ConfigFromPlan(plan, false), Generation: 1,
	}, &runtimegraph.Acquisitions{})
	if err == nil || strings.Contains(err.Error(), secret) || !errors.Is(err, context.Canceled) {
		t.Fatalf("prepare error=%v, want bounded cancellation without backend text", err)
	}
	var providerError *V8ProviderError
	if !errors.As(err, &providerError) || providerError.Code() != V8ProviderErrorProcessorInitialization {
		t.Fatalf("prepare error type/code=%T/%v", err, providerError)
	}

	processor := &v8FailingProcessor{
		forceFlushError: fmt.Errorf("flush %s: %w", secret, context.DeadlineExceeded),
		shutdownError:   fmt.Errorf("shutdown %s", secret),
	}
	provider, err := NewProviderV8Inactive(context.Background(), plan, 1, V8ProviderOptions{
		SpanProcessorFactory: func(uint64) (sdktrace.SpanProcessor, error) { return processor, nil },
	})
	if err != nil {
		t.Fatal(err)
	}
	provider.v8.active.Store(true)
	_, flushErr := provider.EmitGenAICanaryToDestination(context.Background(), "galileo")
	if flushErr == nil || strings.Contains(flushErr.Error(), secret) || !errors.Is(flushErr, context.DeadlineExceeded) {
		t.Fatalf("canary flush error=%v, want bounded error", flushErr)
	}
	if !errors.As(flushErr, &providerError) || providerError.Code() != V8ProviderErrorFlush {
		t.Fatalf("flush error type/code=%T/%v", flushErr, providerError)
	}
	shutdownErr := provider.Shutdown(context.Background())
	if shutdownErr == nil || strings.Contains(shutdownErr.Error(), secret) {
		t.Fatalf("shutdown error=%v, want bounded error", shutdownErr)
	}
}

func TestNewProviderV8InactiveDoesNotMutateGlobalProviders(t *testing.T) {
	beforeTracer := otel.GetTracerProvider()
	beforeMeter := otel.GetMeterProvider()
	beforeLogger := logglobal.GetLoggerProvider()
	plan := v8PlanForTest(t, "always_on", "", nil)
	provider, err := NewProviderV8Inactive(context.Background(), plan, 1, V8ProviderOptions{})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = provider.Shutdown(context.Background()) })
	if otel.GetTracerProvider() != beforeTracer || otel.GetMeterProvider() != beforeMeter ||
		logglobal.GetLoggerProvider() != beforeLogger {
		t.Fatal("inactive v8 constructor mutated a global OTel provider")
	}
}

func TestNewProviderV8InactiveRejectsCanceledContextBeforeAllocation(t *testing.T) {
	plan := v8PlanForTest(t, "always_on", "", nil)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	var processorCalls atomic.Uint64
	provider, err := NewProviderV8Inactive(ctx, plan, 1, V8ProviderOptions{
		SpanProcessorFactory: func(uint64) (sdktrace.SpanProcessor, error) {
			processorCalls.Add(1)
			return &v8FailingProcessor{}, nil
		},
	})
	if provider != nil || err == nil || !errors.Is(err, context.Canceled) || processorCalls.Load() != 0 {
		t.Fatalf("provider/error/calls=%v/%v/%d, want nil/canceled/0", provider, err, processorCalls.Load())
	}
}
