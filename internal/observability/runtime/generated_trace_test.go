// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package runtime

import (
	"context"
	"encoding/json"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/observability"
	"github.com/defenseclaw/defenseclaw/internal/observability/runtimegraph"
	"github.com/defenseclaw/defenseclaw/internal/telemetry"
	"go.opentelemetry.io/otel/trace"
)

type generatedTraceConsumer struct {
	mu     sync.Mutex
	spans  []telemetry.V8CanonicalEndedSpan
	closed atomic.Uint64
}

type generatedPanickingEndSpan struct{ trace.Span }

func (*generatedPanickingEndSpan) End(...trace.SpanEndOption) {
	panic("generated trace end panic")
}

func (consumer *generatedTraceConsumer) TryEnqueue(
	span telemetry.V8CanonicalEndedSpan,
) telemetry.V8CanonicalSpanEnqueueResult {
	consumer.mu.Lock()
	consumer.spans = append(consumer.spans, span)
	consumer.mu.Unlock()
	return telemetry.V8CanonicalSpanEnqueueAccepted
}

func (*generatedTraceConsumer) ForceFlush(context.Context) error { return nil }
func (consumer *generatedTraceConsumer) Shutdown(context.Context) error {
	consumer.closed.Add(1)
	return nil
}

func (consumer *generatedTraceConsumer) snapshot() []telemetry.V8CanonicalEndedSpan {
	consumer.mu.Lock()
	defer consumer.mu.Unlock()
	return append([]telemetry.V8CanonicalEndedSpan(nil), consumer.spans...)
}

type generatedTracePipelines struct {
	mu        sync.Mutex
	consumers map[uint64]*generatedTraceConsumer
}

func (pipelines *generatedTracePipelines) build(
	_ context.Context,
	_ *config.ObservabilityV8Plan,
	generation uint64,
	_ telemetry.V8MetricReaderSpec,
) (telemetry.V8GenerationPipelines, error) {
	consumer := &generatedTraceConsumer{}
	pipelines.mu.Lock()
	pipelines.consumers[generation] = consumer
	pipelines.mu.Unlock()
	return telemetry.V8GenerationPipelines{SpanPipelines: []telemetry.V8GenerationSpanPipeline{{
		Destination: "otlp-all", Canonical: consumer,
	}}}, nil
}

func (pipelines *generatedTracePipelines) consumer(t *testing.T, generation uint64) *generatedTraceConsumer {
	t.Helper()
	pipelines.mu.Lock()
	defer pipelines.mu.Unlock()
	consumer := pipelines.consumers[generation]
	if consumer == nil {
		t.Fatalf("generation %d consumer is unavailable", generation)
	}
	return consumer
}

func generatedTracePlan(
	t *testing.T,
	dependencies runtimeTestDependencies,
	retentionDays int,
	sampler string,
	buckets []observability.Bucket,
) *config.ObservabilityV8Plan {
	t.Helper()
	return runtimeTestPlan(t, dependencies.storePath, dependencies.judgePath, retentionDays,
		func(source *config.ObservabilityV8Source) {
			source.TracePolicy.Sampler = sampler
			source.Destinations = []config.ObservabilityV8DestinationSource{{
				Name: "otlp-all", Kind: config.ObservabilityV8DestinationOTLP,
				Protocol: "http/protobuf", Endpoint: "https://otel.example.test",
				Send: &config.ObservabilityV8SendSource{
					Signals: []observability.Signal{observability.SignalTraces}, Buckets: buckets,
				},
			}}
		},
	)
}

func newGeneratedTraceRuntime(
	t *testing.T,
	dependencies runtimeTestDependencies,
	pipelines *generatedTracePipelines,
	plan *config.ObservabilityV8Plan,
) *Runtime {
	t.Helper()
	options := dependencies.options()
	options.TelemetryProviderFactory = telemetry.NewV8ProviderFactory(telemetry.V8ProviderOptions{
		Version: "8.0.0", Environment: "test", ServiceInstanceID: "generated-trace-runtime",
		GenerationPipelines: pipelines.build,
	})
	runtime, err := New(t.Context(), runtimegraph.ConfigFromPlan(plan, false), options)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if closeErr := runtime.Close(ctx); closeErr != nil {
			t.Errorf("close generated trace runtime: %v", closeErr)
		}
	})
	return runtime
}

func generatedTraceEnvelope() observability.FamilyEnvelopeInput {
	return observability.FamilyEnvelopeInput{
		Source: observability.SourceGateway, Connector: "openai_codex", Action: "invoke",
		Correlation: observability.Correlation{
			RunID: "run-001", RequestID: "request-001", SessionID: "session-001",
			TurnID: "turn-001", AgentID: "agent-root", PolicyID: "policy-001",
		},
		Provenance: observability.FamilyProvenanceInput{
			Producer: "defenseclaw", BuildCommit: "0123456789abcdef",
		},
	}
}

func generatedAgentInput(agentType string, start, end time.Time) observability.SpanAgentInvokeInput {
	return observability.SpanAgentInvokeInput{
		Envelope: generatedTraceEnvelope(), Outcome: observability.OutcomeCompleted, Kind: "INTERNAL",
		StartTimeUnixNano: generatedTimeNanos(start), EndTimeUnixNano: generatedTimeNanos(end),
		Status:                     observability.NewTraceStatusOK(),
		DefenseClawConnectorSource: observability.Present("openai_codex"),
		DefenseClawRunID:           observability.Present("run-001"),
		DefenseClawOperationID:     observability.Present("operation-agent-001"),
		DefenseClawRequestID:       observability.Present("request-001"),
		DefenseClawTurnID:          observability.Present("turn-001"),
		GenAIConversationID:        observability.Present("session-001"),
		GenAIAgentID:               observability.Present("agent-root"),
		GenAIAgentName:             observability.Present("codex"), DefenseClawAgentType: agentType,
		DefenseClawAgentInstanceID:          observability.Present("agent-instance-001"),
		DefenseClawAgentRootID:              observability.Present("agent-root"),
		DefenseClawSessionRootID:            observability.Present("session-001"),
		DefenseClawAgentLifecycleID:         observability.Present("lifecycle-001"),
		DefenseClawAgentExecutionID:         observability.Present("execution-001"),
		DefenseClawAgentDepth:               observability.Present[int64](0),
		DefenseClawAgentLifecycleEvent:      observability.Present("session_start"),
		DefenseClawAgentLifecycleState:      observability.Present("active"),
		DefenseClawAgentPhase:               observability.Present("model"),
		DefenseClawAgentPhasePrevious:       observability.Present("planning"),
		DefenseClawAgentPhaseCode:           observability.Present[int64](3),
		DefenseClawAgentSequence:            observability.Present[int64](7),
		DefenseClawAgentReportedCostPresent: true,
		DefenseClawAgentReportedCostUsd:     observability.Present(0.25),
		DefenseClawTelemetryInputReported:   false, DefenseClawContentInputState: "not_reported",
		DefenseClawTelemetryOutputReported: false, DefenseClawContentOutputState: "not_reported",
		GenAIOperationName:      observability.Present("invoke_agent"),
		ConditionConnectorKnown: true, ConditionOperationTerminal: true,
	}
}

func generatedModelInput(model string, start, end time.Time) observability.SpanModelChatInput {
	envelope := generatedTraceEnvelope()
	envelope.Phase = "model"
	envelope.Correlation.ModelRequestID = "model-request-001"
	return observability.SpanModelChatInput{
		Envelope: envelope, Outcome: observability.OutcomeCompleted, Kind: "CLIENT",
		StartTimeUnixNano: generatedTimeNanos(start), EndTimeUnixNano: generatedTimeNanos(end),
		Status:                              observability.NewTraceStatusOK(),
		DefenseClawConnectorSource:          observability.Present("openai_codex"),
		DefenseClawRunID:                    observability.Present("run-001"),
		DefenseClawOperationID:              observability.Present("operation-model-001"),
		DefenseClawTurnID:                   observability.Present("turn-001"),
		GenAIConversationID:                 observability.Present("session-001"),
		GenAIAgentID:                        observability.Present("agent-root"),
		GenAIAgentName:                      observability.Present("codex"),
		DefenseClawAgentType:                observability.Present("root"),
		DefenseClawAgentRootID:              observability.Present("agent-root"),
		DefenseClawAgentLifecycleID:         observability.Present("lifecycle-001"),
		DefenseClawAgentExecutionID:         observability.Present("execution-001"),
		DefenseClawAgentPhase:               observability.Present("model"),
		DefenseClawAgentPhaseCode:           observability.Present[int64](3),
		DefenseClawAgentReportedCostPresent: false,
		DefenseClawTelemetryInputReported:   false, DefenseClawContentInputState: "not_reported",
		DefenseClawTelemetryOutputReported: false, DefenseClawContentOutputState: "not_reported",
		GenAIOperationName: observability.Present("chat"),
		GenAIProviderName:  observability.Present("openai"), GenAIRequestModel: model,
		GenAIResponseModel:                 observability.Present(model),
		GenAIUsageInputTokens:              observability.Present[int64](11),
		GenAIUsageOutputTokens:             observability.Present[int64](7),
		DefenseClawModelRequestID:          observability.Present("model-request-001"),
		DefenseClawModelResponseID:         observability.Present("model-response-001"),
		DefenseClawModelAttempt:            observability.Present[int64](2),
		DefenseClawModelRetryCount:         observability.Present[int64](1),
		DefenseClawTelemetryTokensReported: observability.Present(true),
		ConditionConnectorKnown:            true, ConditionOperationTerminal: true,
	}
}

func generatedToolInput(tool string, start, end time.Time) observability.SpanToolExecuteInput {
	envelope := generatedTraceEnvelope()
	envelope.Phase = "tool"
	envelope.Correlation.ToolInvocationID = "tool-call-001"
	return observability.SpanToolExecuteInput{
		Envelope: envelope, Outcome: observability.OutcomeCompleted, Kind: "INTERNAL",
		StartTimeUnixNano: generatedTimeNanos(start), EndTimeUnixNano: generatedTimeNanos(end),
		Status:                              observability.NewTraceStatusOK(),
		DefenseClawConnectorSource:          observability.Present("openai_codex"),
		DefenseClawRunID:                    observability.Present("run-001"),
		DefenseClawOperationID:              observability.Present("operation-tool-001"),
		DefenseClawTurnID:                   observability.Present("turn-001"),
		GenAIConversationID:                 observability.Present("session-001"),
		GenAIAgentID:                        observability.Present("agent-root"),
		GenAIAgentName:                      observability.Present("codex"),
		DefenseClawAgentType:                observability.Present("root"),
		DefenseClawAgentRootID:              observability.Present("agent-root"),
		DefenseClawAgentLifecycleID:         observability.Present("lifecycle-001"),
		DefenseClawAgentExecutionID:         observability.Present("execution-001"),
		DefenseClawAgentPhase:               observability.Present("tool"),
		DefenseClawAgentPhasePrevious:       observability.Present("model"),
		DefenseClawAgentPhaseCode:           observability.Present[int64](4),
		DefenseClawAgentSequence:            observability.Present[int64](8),
		DefenseClawAgentReportedCostPresent: false,
		DefenseClawTelemetryInputReported:   false, DefenseClawContentInputState: "not_reported",
		DefenseClawTelemetryOutputReported: false, DefenseClawContentOutputState: "not_reported",
		GenAIOperationName: observability.Present("execute_tool"), GenAIToolName: tool,
		GenAIToolType:               observability.Present("function"),
		GenAIToolCallID:             observability.Present("tool-call-001"),
		DefenseClawToolID:           observability.Present("tool-001"),
		DefenseClawToolProvider:     observability.Present("builtin"),
		DefenseClawToolDangerous:    observability.Present(false),
		DefenseClawToolExitCode:     observability.Present[int64](0),
		DefenseClawToolStatus:       observability.Present("completed"),
		DefenseClawToolArgsLength:   observability.Present[int64](0),
		DefenseClawToolOutputLength: observability.Present[int64](0),
		ConditionConnectorKnown:     true, ConditionOperationTerminal: true,
	}
}

func generatedTimeNanos(value time.Time) uint64 {
	if value.IsZero() {
		return 0
	}
	return uint64(value.UnixNano())
}

func TestGeneratedTraceSessionPreservesRichHierarchyAndMissingData(t *testing.T) {
	dependencies := newRuntimeTestDependencies(t)
	pipelines := &generatedTracePipelines{consumers: make(map[uint64]*generatedTraceConsumer)}
	plan := generatedTracePlan(t, dependencies, 90, "always_on", []observability.Bucket{"*"})
	runtime := newGeneratedTraceRuntime(t, dependencies, pipelines, plan)

	base := time.Now().UTC().Add(-time.Second)
	agentInput := generatedAgentInput("root", base, base.Add(900*time.Millisecond))
	ctx, agent, err := runtime.StartAgentTrace(t.Context(), agentInput)
	if err != nil || agent == nil || ctx == nil || agent.Generation() != 1 {
		t.Fatalf("start agent=%v context=%v error=%v", agent, ctx, err)
	}
	modelInput := generatedModelInput("gpt-5.5", base.Add(100*time.Millisecond), base.Add(700*time.Millisecond))
	retry, eventErr := observability.NewSpanModelChatModelRetryEvent(observability.SpanModelChatModelRetryEventInput{
		TimeUnixNano:               uint64(base.Add(300 * time.Millisecond).UnixNano()),
		DefenseClawModelAttempt:    observability.Present[int64](2),
		DefenseClawModelRetryCount: observability.Present[int64](1),
		ErrorType:                  observability.Present("upstream_unavailable"),
	})
	if eventErr != nil {
		t.Fatal(eventErr)
	}
	link, linkErr := observability.NewSpanModelChatCausedByLink(observability.SpanModelChatCausedByLinkInput{
		TraceID: "0123456789abcdef0123456789abcdef", SpanID: "0123456789abcdef",
	})
	if linkErr != nil {
		t.Fatal(linkErr)
	}
	modelInput.Events = []observability.TraceEventInput{retry}
	modelInput.Links = []observability.TraceLinkInput{link}
	model, err := agent.StartModel(modelInput)
	if err != nil || model == nil || model.TraceID() != agent.TraceID() {
		t.Fatalf("start model=%v error=%v", model, err)
	}
	toolInput := generatedToolInput("shell", base.Add(200*time.Millisecond), base.Add(500*time.Millisecond))
	tool, err := model.StartTool(toolInput)
	if err != nil || tool == nil || tool.TraceID() != agent.TraceID() {
		t.Fatalf("start tool=%v error=%v", tool, err)
	}
	if err := tool.End(toolInput); err != nil {
		t.Fatal(err)
	}
	if err := model.End(modelInput); err != nil {
		t.Fatal(err)
	}
	if err := agent.End(agentInput); err != nil {
		t.Fatal(err)
	}

	spans := pipelines.consumer(t, 1).snapshot()
	if len(spans) != 3 {
		t.Fatalf("canonical spans=%d, want 3", len(spans))
	}
	byFamily := make(map[observability.EventName]telemetry.V8CanonicalEndedSpan, len(spans))
	for _, ended := range spans {
		byFamily[ended.Record().EventName()] = ended
		if ended.Record().Provenance().ConfigGeneration != 1 ||
			ended.Record().Provenance().ConfigDigest != runtime.Active().Digest() {
			t.Fatalf("span %s has stale provenance %+v", ended.Record().EventName(), ended.Record().Provenance())
		}
	}
	root := byFamily[observability.EventName(observability.TelemetryFamilyAgentInvoke)]
	modelSpan := byFamily[observability.EventName(observability.TelemetryFamilyModelChat)]
	toolSpan := byFamily[observability.EventName(observability.TelemetryFamilyToolExecute)]
	if root.TraceID() != modelSpan.TraceID() || root.TraceID() != toolSpan.TraceID() {
		t.Fatal("hierarchy split across traces")
	}
	modelParent, modelHasParent := modelSpan.ParentSpanID()
	toolParent, toolHasParent := toolSpan.ParentSpanID()
	if !modelHasParent || modelParent != root.SpanID() || !toolHasParent || toolParent != modelSpan.SpanID() {
		t.Fatalf("parent chain root=%s model-parent=%s/%v tool-parent=%s/%v", root.SpanID(), modelParent, modelHasParent, toolParent, toolHasParent)
	}

	rootAttributes := generatedTraceRecordAttributes(t, root.Record())
	if rootAttributes["defenseclaw.agent.lifecycle.id"] != "lifecycle-001" ||
		rootAttributes["defenseclaw.agent.execution.id"] != "execution-001" ||
		rootAttributes["defenseclaw.agent.phase"] != "model" ||
		rootAttributes["defenseclaw.agent.phase.code"] != float64(3) ||
		rootAttributes["defenseclaw.agent.sequence"] != float64(7) ||
		rootAttributes["defenseclaw.agent.reported_cost.present"] != true ||
		rootAttributes["defenseclaw.agent.reported_cost.usd"] != 0.25 ||
		rootAttributes["defenseclaw.telemetry.input.reported"] != false ||
		rootAttributes["defenseclaw.content.input.state"] != "not_reported" {
		t.Fatalf("root rich/missing-data attributes=%v", rootAttributes)
	}
	if _, fabricated := rootAttributes["gen_ai.input.messages"]; fabricated {
		t.Fatal("missing input content was fabricated")
	}
	modelBody := generatedTraceRecordBody(t, modelSpan.Record())
	if events, ok := modelBody["events"].([]any); !ok || len(events) != 1 {
		t.Fatalf("model events=%v", modelBody["events"])
	}
	if links, ok := modelBody["links"].([]any); !ok || len(links) != 1 {
		t.Fatalf("model links=%v", modelBody["links"])
	}
}

func TestGeneratedRootModelDoesNotFabricateAgentAndAbortReleasesRequestLease(t *testing.T) {
	dependencies := newRuntimeTestDependencies(t)
	pipelines := &generatedTracePipelines{consumers: make(map[uint64]*generatedTraceConsumer)}
	initial := generatedTracePlan(t, dependencies, 90, "always_on", []observability.Bucket{"*"})
	runtime := newGeneratedTraceRuntime(t, dependencies, pipelines, initial)
	base := time.Now().UTC().Add(-time.Second)
	modelInput := generatedModelInput("gpt-5.5", base, base.Add(100*time.Millisecond))
	modelInput.Envelope.Correlation.AgentID = ""
	modelInput.GenAIAgentID = observability.Absent[string]()
	modelInput.GenAIAgentName = observability.Absent[string]()
	modelInput.DefenseClawAgentType = observability.Absent[string]()
	modelInput.DefenseClawAgentRootID = observability.Absent[string]()
	modelInput.DefenseClawAgentLifecycleID = observability.Absent[string]()
	modelInput.DefenseClawAgentExecutionID = observability.Absent[string]()
	modelInput.DefenseClawAgentPhase = observability.Absent[string]()
	modelInput.DefenseClawAgentPhaseCode = observability.Absent[int64]()
	_, model, err := runtime.StartModelTrace(t.Context(), modelInput)
	if err != nil || model == nil {
		t.Fatalf("start root model=%v error=%v", model, err)
	}
	if err := model.End(modelInput); err != nil {
		t.Fatal(err)
	}
	spans := pipelines.consumer(t, 1).snapshot()
	if len(spans) != 1 || spans[0].Record().EventName() != observability.EventName(observability.TelemetryFamilyModelChat) {
		t.Fatalf("root-model spans=%v", spans)
	}
	attributes := generatedTraceRecordAttributes(t, spans[0].Record())
	for _, key := range []string{
		"gen_ai.agent.id", "gen_ai.agent.name", "defenseclaw.agent.type",
		"defenseclaw.agent.root.id", "defenseclaw.agent.lifecycle.id",
		"defenseclaw.agent.execution.id",
	} {
		if _, fabricated := attributes[key]; fabricated {
			t.Fatalf("root model fabricated %s", key)
		}
	}

	agentInput := generatedAgentInput("root", base, base.Add(200*time.Millisecond))
	_, agent, err := runtime.StartAgentTrace(t.Context(), agentInput)
	if err != nil || agent == nil {
		t.Fatalf("start abortable request=%v error=%v", agent, err)
	}
	reloadDone := make(chan struct {
		result runtimegraph.ReloadResult
		err    *runtimegraph.Error
	}, 1)
	candidate := generatedTracePlan(t, dependencies, 30, "always_on", []observability.Bucket{"*"})
	go func() {
		result, reloadErr := runtime.Reload(t.Context(), runtimegraph.ConfigFromPlan(candidate, false))
		reloadDone <- struct {
			result runtimegraph.ReloadResult
			err    *runtimegraph.Error
		}{result: result, err: reloadErr}
	}()
	deadline := time.Now().Add(5 * time.Second)
	for runtime.Active() == nil || runtime.Active().Generation() != 2 {
		if time.Now().After(deadline) {
			t.Fatal("abort test reload did not publish generation two")
		}
		time.Sleep(time.Millisecond)
	}
	select {
	case <-reloadDone:
		t.Fatal("reload returned before request Abort released the lease")
	default:
	}
	agent.Abort()
	reload := <-reloadDone
	if reload.err != nil || reload.result.Status() != runtimegraph.ReloadApplied {
		t.Fatalf("reload after request Abort=%s error=%v", reload.result.Status(), reload.err)
	}
	if pipelines.consumer(t, 1).closed.Load() == 0 {
		t.Fatal("request Abort did not permit generation retirement")
	}
}

func TestGeneratedTraceSessionSupportsRealNestedSubagent(t *testing.T) {
	dependencies := newRuntimeTestDependencies(t)
	pipelines := &generatedTracePipelines{consumers: make(map[uint64]*generatedTraceConsumer)}
	plan := generatedTracePlan(t, dependencies, 90, "always_on", []observability.Bucket{"*"})
	runtime := newGeneratedTraceRuntime(t, dependencies, pipelines, plan)
	base := time.Now().UTC().Add(-time.Second)
	rootInput := generatedAgentInput("root", base, base.Add(500*time.Millisecond))
	_, root, err := runtime.StartAgentTrace(t.Context(), rootInput)
	if err != nil || root == nil {
		t.Fatalf("start root=%v error=%v", root, err)
	}
	childInput := generatedAgentInput("subagent", base.Add(100*time.Millisecond), base.Add(400*time.Millisecond))
	childInput.Envelope.Correlation.AgentID = "agent-child"
	childInput.DefenseClawOperationID = observability.Present("operation-agent-child")
	childInput.GenAIAgentID = observability.Present("agent-child")
	childInput.GenAIAgentName = observability.Present("reviewer")
	childInput.DefenseClawAgentRootID = observability.Present("agent-root")
	childInput.DefenseClawAgentParentID = observability.Present("agent-root")
	childInput.DefenseClawAgentLifecycleID = observability.Present("lifecycle-child")
	childInput.DefenseClawAgentExecutionID = observability.Present("execution-child")
	childInput.DefenseClawAgentDepth = observability.Present[int64](1)
	child, err := root.StartAgent(childInput)
	if err != nil || child == nil || child.TraceID() != root.TraceID() {
		t.Fatalf("start child=%v error=%v", child, err)
	}
	if err := child.End(childInput); err != nil {
		t.Fatal(err)
	}
	if err := root.End(rootInput); err != nil {
		t.Fatal(err)
	}
	spans := pipelines.consumer(t, 1).snapshot()
	if len(spans) != 2 {
		t.Fatalf("agent spans=%d, want 2", len(spans))
	}
	var rootSpan, childSpan telemetry.V8CanonicalEndedSpan
	for _, ended := range spans {
		attributes := generatedTraceRecordAttributes(t, ended.Record())
		if attributes["gen_ai.agent.id"] == "agent-child" {
			childSpan = ended
			if attributes["defenseclaw.agent.root.id"] != "agent-root" ||
				attributes["defenseclaw.agent.parent.id"] != "agent-root" ||
				attributes["defenseclaw.agent.depth"] != float64(1) {
				t.Fatalf("child hierarchy attributes=%v", attributes)
			}
		} else {
			rootSpan = ended
		}
	}
	parent, hasParent := childSpan.ParentSpanID()
	if !rootSpan.SpanID().IsValid() || !childSpan.SpanID().IsValid() ||
		!hasParent || parent != rootSpan.SpanID() {
		t.Fatalf("subagent physical parent=%s/%v root=%s", parent, hasParent, rootSpan.SpanID())
	}
}

func TestGeneratedTraceSessionPinsGenerationAcrossReloadAndRejectsStaleUse(t *testing.T) {
	dependencies := newRuntimeTestDependencies(t)
	pipelines := &generatedTracePipelines{consumers: make(map[uint64]*generatedTraceConsumer)}
	initial := generatedTracePlan(t, dependencies, 90, "always_on", []observability.Bucket{"*"})
	runtime := newGeneratedTraceRuntime(t, dependencies, pipelines, initial)
	base := time.Now().UTC().Add(-time.Second)
	agentInput := generatedAgentInput("root", base, base.Add(900*time.Millisecond))
	_, agent, err := runtime.StartAgentTrace(t.Context(), agentInput)
	if err != nil || agent == nil {
		t.Fatalf("start agent=%v error=%v", agent, err)
	}
	modelInput := generatedModelInput("gpt-5.5", base.Add(100*time.Millisecond), base.Add(700*time.Millisecond))
	model, err := agent.StartModel(modelInput)
	if err != nil || model == nil {
		t.Fatalf("start model=%v error=%v", model, err)
	}

	reloadDone := make(chan struct {
		result runtimegraph.ReloadResult
		err    *runtimegraph.Error
	}, 1)
	candidate := generatedTracePlan(t, dependencies, 30, "always_on", []observability.Bucket{"*"})
	go func() {
		result, reloadErr := runtime.Reload(t.Context(), runtimegraph.ConfigFromPlan(candidate, false))
		reloadDone <- struct {
			result runtimegraph.ReloadResult
			err    *runtimegraph.Error
		}{result: result, err: reloadErr}
	}()
	deadline := time.Now().Add(5 * time.Second)
	for runtime.Active() == nil || runtime.Active().Generation() != 2 {
		if time.Now().After(deadline) {
			t.Fatal("reload did not publish generation two while trace lease remained live")
		}
		time.Sleep(time.Millisecond)
	}
	first := pipelines.consumer(t, 1)
	if first.closed.Load() != 0 {
		t.Fatal("generation one retired while root/model were live")
	}
	select {
	case <-reloadDone:
		t.Fatal("reload returned before the trace hierarchy released its lease")
	default:
	}
	if agent.Generation() != 1 || model.Generation() != 1 {
		t.Fatal("live trace handles changed generation after reload publication")
	}
	if err := model.End(modelInput); err != nil {
		t.Fatal(err)
	}
	if err := agent.End(agentInput); err != nil {
		t.Fatal(err)
	}
	reload := <-reloadDone
	if reload.err != nil || reload.result.Status() != runtimegraph.ReloadApplied {
		t.Fatalf("reload=%s error=%v", reload.result.Status(), reload.err)
	}
	if first.closed.Load() == 0 {
		t.Fatal("generation one was not retired after root End released the lease")
	}
	if _, err := agent.StartModel(modelInput); generatedTraceErrorCode(err) != GeneratedTraceClosed {
		t.Fatalf("stale child start error=%v", err)
	}
	if err := agent.End(agentInput); generatedTraceErrorCode(err) != GeneratedTraceClosed {
		t.Fatalf("double root End error=%v", err)
	}
	_, second, err := runtime.StartAgentTrace(t.Context(), agentInput)
	if err != nil || second == nil || second.Generation() != 2 {
		t.Fatalf("generation-two agent=%v error=%v", second, err)
	}
	second.Abort()
}

func TestGeneratedTraceSessionReleasesLeaseAfterBuildFailureAndSamplingDrop(t *testing.T) {
	dependencies := newRuntimeTestDependencies(t)
	pipelines := &generatedTracePipelines{consumers: make(map[uint64]*generatedTraceConsumer)}
	plan := generatedTracePlan(t, dependencies, 90, "always_on", []observability.Bucket{"*"})
	runtime := newGeneratedTraceRuntime(t, dependencies, pipelines, plan)
	base := time.Now().UTC().Add(-time.Second)
	input := generatedAgentInput("root", base, base.Add(900*time.Millisecond))
	_, agent, err := runtime.StartAgentTrace(t.Context(), input)
	if err != nil || agent == nil {
		t.Fatalf("start agent=%v error=%v", agent, err)
	}
	invalid := input
	invalid.Envelope.Provenance.Producer = ""
	if err := agent.End(invalid); generatedTraceErrorCode(err) != GeneratedTraceBuildRejected {
		t.Fatalf("invalid End error=%v", err)
	}

	candidate := generatedTracePlan(t, dependencies, 30, "always_off", []observability.Bucket{"*"})
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	reload, reloadErr := runtime.Reload(ctx, runtimegraph.ConfigFromPlan(candidate, false))
	if reloadErr != nil || reload.Status() != runtimegraph.ReloadApplied {
		t.Fatalf("reload after failed build=%s error=%v", reload.Status(), reloadErr)
	}
	_, dropped, dropErr := runtime.StartAgentTrace(t.Context(), input)
	if dropErr != nil || dropped != nil {
		t.Fatalf("always-off sampling returned handle=%v error=%v", dropped, dropErr)
	}
	if got := len(pipelines.consumer(t, 2).snapshot()); got != 0 {
		t.Fatalf("sampling drop resurrected %d canonical spans", got)
	}
	third := runtimeTestPlan(t, dependencies.storePath, dependencies.judgePath, 15,
		func(source *config.ObservabilityV8Source) {
			disabled := false
			source.TracePolicy.Sampler = "always_on"
			source.Buckets = map[observability.Bucket]config.ObservabilityV8BucketPolicySource{
				observability.BucketModelIO: {Collect: config.ObservabilityV8CollectSource{Traces: &disabled}},
			}
			source.Destinations = []config.ObservabilityV8DestinationSource{{
				Name: "otlp-all", Kind: config.ObservabilityV8DestinationOTLP,
				Protocol: "http/protobuf", Endpoint: "https://otel.example.test",
				Send: &config.ObservabilityV8SendSource{
					Signals: []observability.Signal{observability.SignalTraces},
					Buckets: []observability.Bucket{"*"},
				},
			}}
		},
	)
	thirdReload, thirdErr := runtime.Reload(ctx, runtimegraph.ConfigFromPlan(third, false))
	if thirdErr != nil || thirdReload.Status() != runtimegraph.ReloadApplied {
		t.Fatalf("reload after sampling drop=%s error=%v", thirdReload.Status(), thirdErr)
	}
	_, thirdAgent, startErr := runtime.StartAgentTrace(t.Context(), input)
	if startErr != nil || thirdAgent == nil {
		t.Fatalf("start collection-limited root=%v error=%v", thirdAgent, startErr)
	}
	modelInput := generatedModelInput("gpt-5.5", base.Add(time.Millisecond), base.Add(2*time.Millisecond))
	model, modelErr := thirdAgent.StartModel(modelInput)
	if modelErr != nil || model != nil {
		t.Fatalf("disabled model bucket returned handle=%v error=%v", model, modelErr)
	}
	thirdAgent.Abort()
}

func TestGeneratedTraceSessionRejectsParentEndWithLiveChildAndReleases(t *testing.T) {
	dependencies := newRuntimeTestDependencies(t)
	pipelines := &generatedTracePipelines{consumers: make(map[uint64]*generatedTraceConsumer)}
	plan := generatedTracePlan(t, dependencies, 90, "always_on", []observability.Bucket{"*"})
	runtime := newGeneratedTraceRuntime(t, dependencies, pipelines, plan)
	base := time.Now().UTC().Add(-time.Second)
	agentInput := generatedAgentInput("root", base, base.Add(900*time.Millisecond))
	_, agent, err := runtime.StartAgentTrace(t.Context(), agentInput)
	if err != nil || agent == nil {
		t.Fatalf("start agent=%v error=%v", agent, err)
	}
	modelInput := generatedModelInput("gpt-5.5", base.Add(time.Millisecond), base.Add(2*time.Millisecond))
	model, err := agent.StartModel(modelInput)
	if err != nil || model == nil {
		t.Fatalf("start model=%v error=%v", model, err)
	}
	if err := agent.End(agentInput); generatedTraceErrorCode(err) != GeneratedTraceChildrenActive {
		t.Fatalf("parent End with live child error=%v", err)
	}
	if err := model.End(modelInput); generatedTraceErrorCode(err) != GeneratedTraceClosed {
		t.Fatalf("aborted child End error=%v", err)
	}
	candidate := generatedTracePlan(t, dependencies, 30, "always_on", []observability.Bucket{"*"})
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	result, reloadErr := runtime.Reload(ctx, runtimegraph.ConfigFromPlan(candidate, false))
	if reloadErr != nil || result.Status() != runtimegraph.ReloadApplied {
		t.Fatalf("reload after active-child failure=%s error=%v", result.Status(), reloadErr)
	}
}

func TestGeneratedTraceSessionInternalPanicAbortsAndReleasesLease(t *testing.T) {
	dependencies := newRuntimeTestDependencies(t)
	pipelines := &generatedTracePipelines{consumers: make(map[uint64]*generatedTraceConsumer)}
	plan := generatedTracePlan(t, dependencies, 90, "always_on", []observability.Bucket{"*"})
	runtime := newGeneratedTraceRuntime(t, dependencies, pipelines, plan)
	base := time.Now().UTC().Add(-time.Second)
	input := generatedAgentInput("root", base, base.Add(500*time.Millisecond))
	_, agent, err := runtime.StartAgentTrace(t.Context(), input)
	if err != nil || agent == nil {
		t.Fatalf("start panic root=%v error=%v", agent, err)
	}
	agent.node.span = &generatedPanickingEndSpan{Span: agent.node.span}
	func() {
		defer func() {
			if recover() == nil {
				t.Fatal("panicking physical End did not propagate")
			}
		}()
		_ = agent.End(input)
	}()
	if agent.session == nil || !agent.session.closed || agent.session.lease != nil {
		t.Fatal("internal panic did not abort the session and release its lease")
	}
	candidate := generatedTracePlan(t, dependencies, 30, "always_on", []observability.Bucket{"*"})
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	result, reloadErr := runtime.Reload(ctx, runtimegraph.ConfigFromPlan(candidate, false))
	if reloadErr != nil || result.Status() != runtimegraph.ReloadApplied {
		t.Fatalf("reload after internal panic=%s error=%v", result.Status(), reloadErr)
	}
}

func generatedTraceErrorCode(err error) GeneratedTraceErrorCode {
	var traceErr *GeneratedTraceError
	if errors.As(err, &traceErr) {
		return traceErr.Code()
	}
	return ""
}

func generatedTraceRecordBody(t *testing.T, record observability.Record) map[string]any {
	t.Helper()
	encoded, err := json.Marshal(record)
	if err != nil {
		t.Fatal(err)
	}
	var wire map[string]any
	if err := json.Unmarshal(encoded, &wire); err != nil {
		t.Fatal(err)
	}
	body, ok := wire["body"].(map[string]any)
	if !ok {
		t.Fatalf("record body=%T", wire["body"])
	}
	return body
}

func generatedTraceRecordAttributes(t *testing.T, record observability.Record) map[string]any {
	t.Helper()
	body := generatedTraceRecordBody(t, record)
	attributes, ok := body["attributes"].(map[string]any)
	if !ok {
		t.Fatalf("record attributes=%T", body["attributes"])
	}
	return attributes
}
