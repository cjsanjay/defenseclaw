// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"context"
	"encoding/json"
	"math"
	"sort"
	"strings"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/audit"
	"github.com/defenseclaw/defenseclaw/internal/observability"
	observabilityruntime "github.com/defenseclaw/defenseclaw/internal/observability/runtime"
)

const proxyV8Producer = "gateway.proxy.chat"

type proxyV8TraceRuntime interface {
	StartAgentTrace(context.Context, observability.SpanAgentInvokeInput) (context.Context, *observabilityruntime.AgentTrace, error)
	StartModelTrace(context.Context, observability.SpanModelChatInput) (context.Context, *observabilityruntime.ModelTrace, error)
}

type proxyV8RequestTrace struct {
	runtime    proxyV8TraceRuntime
	agent      *observabilityruntime.AgentTrace
	agentInput observability.SpanAgentInvokeInput
}

type proxyV8ModelTrace struct {
	model     *observabilityruntime.ModelTrace
	input     observability.SpanModelChatInput
	rootModel bool
}

type proxyV8TraceResult struct {
	Outcome          observability.Outcome
	ErrorType        string
	TechnicalFailure bool
	OutputText       string
	ToolCalls        json.RawMessage
	ResponseModel    string
	ResponseID       string
	FinishReasons    []string
	Usage            *ChatUsage
	ToolCallCount    int
	UpstreamDuration time.Duration
	Streaming        bool
	Cancelled        bool
}

func proxyV8DefaultResult(streaming bool) proxyV8TraceResult {
	return proxyV8TraceResult{
		Outcome: observability.OutcomeFailed, ErrorType: "request_incomplete",
		TechnicalFailure: true, Streaming: streaming,
	}
}

func (p *GuardrailProxy) bindObservabilityV8Trace(runtime proxyV8TraceRuntime) {
	if p == nil {
		return
	}
	p.observabilityV8Mu.Lock()
	p.observabilityV8Trace = runtime
	p.observabilityV8Mu.Unlock()
}

func (p *GuardrailProxy) observabilityV8TraceRuntime() proxyV8TraceRuntime {
	if p == nil {
		return nil
	}
	p.observabilityV8Mu.RLock()
	defer p.observabilityV8Mu.RUnlock()
	return p.observabilityV8Trace
}

func (p *GuardrailProxy) startProxyV8RequestTrace(
	ctx context.Context,
	req *ChatRequest,
	requestHeaderAgent string,
	requestConversation string,
) (context.Context, *proxyV8RequestTrace) {
	runtime := p.observabilityV8TraceRuntime()
	if runtime == nil || ctx == nil || req == nil {
		return ctx, nil
	}
	if SessionIDFromContext(ctx) == "" {
		if conversation := proxyV8StableID(requestConversation); conversation != "" {
			ctx = ContextWithSessionID(ctx, conversation)
		}
	}
	reportedAgentType := p.agentNameForRequest(requestHeaderAgent)
	agentType := strings.TrimSpace(reportedAgentType)
	trace := &proxyV8RequestTrace{runtime: runtime}
	if agentType == "" || agentType != reportedAgentType {
		return ctx, trace
	}
	input := p.proxyV8AgentInput(ctx, req, agentType, time.Now().UTC())
	started, agent, err := runtime.StartAgentTrace(ctx, input)
	if err != nil || agent == nil {
		return ctx, trace
	}
	trace.agent, trace.agentInput = agent, input
	return started, trace
}

func (trace *proxyV8RequestTrace) StartModel(
	ctx context.Context,
	input observability.SpanModelChatInput,
) (context.Context, *proxyV8ModelTrace) {
	if trace == nil || trace.runtime == nil {
		return ctx, nil
	}
	if trace.agent != nil {
		model, err := trace.agent.StartModel(input)
		if err != nil || model == nil {
			return ctx, nil
		}
		return model.Context(), &proxyV8ModelTrace{model: model, input: input}
	}
	started, model, err := trace.runtime.StartModelTrace(ctx, input)
	if err != nil || model == nil {
		return ctx, nil
	}
	return started, &proxyV8ModelTrace{model: model, input: input, rootModel: true}
}

func (trace *proxyV8RequestTrace) Finish(result proxyV8TraceResult) {
	if trace == nil || trace.agent == nil {
		return
	}
	input := trace.agentInput
	applyProxyV8ResultToAgent(&input, result)
	_ = trace.agent.End(input)
}

func (trace *proxyV8RequestTrace) Abort() {
	if trace != nil && trace.agent != nil {
		trace.agent.Abort()
	}
}

func (trace *proxyV8ModelTrace) Finish(result proxyV8TraceResult) {
	if trace == nil || trace.model == nil {
		return
	}
	input := trace.input
	applyProxyV8ResultToModel(&input, result)
	_ = trace.model.End(input)
}

func (trace *proxyV8ModelTrace) Abort() {
	// A child-model abort would abort its still-live agent parent. The request
	// root owns that cleanup path. A root-model fallback has no agent owner and
	// therefore retains its own panic cleanup.
	if trace != nil && trace.model != nil && trace.rootModel {
		trace.model.Abort()
	}
}

func (p *GuardrailProxy) proxyV8AgentInput(
	ctx context.Context,
	req *ChatRequest,
	agentType string,
	start time.Time,
) observability.SpanAgentInvokeInput {
	envelope, facts := p.proxyV8Envelope(ctx, "invoke_agent")
	messages, inputBytes, inputReported := proxyV8InputMessages(req.Messages)
	input := observability.SpanAgentInvokeInput{
		Envelope: envelope, Outcome: observability.OutcomeCompleted, Kind: "INTERNAL",
		StartTimeUnixNano: uint64(start.UnixNano()), Status: observability.NewTraceStatusOK(),
		DefenseClawAgentType: agentType, DefenseClawAgentReportedCostPresent: false,
		DefenseClawTelemetryInputReported:  inputReported,
		DefenseClawContentInputState:       proxyV8ContentState(inputReported),
		DefenseClawTelemetryOutputReported: false,
		DefenseClawContentOutputState:      "not_reported",
		GenAIOperationName:                 observability.Present("invoke_agent"),
		ConditionConnectorKnown:            facts.connectorKnown,
		ConditionOperationTerminal:         true,
	}
	if inputReported {
		input.GenAIInputMessages = observability.Present(messages)
		input.DefenseClawContentInputOriginalBytes = observability.Present(inputBytes)
	}
	applyProxyV8FactsToAgent(&input, facts, agentType)
	return input
}

func (p *GuardrailProxy) proxyV8ModelInput(
	ctx context.Context,
	req *ChatRequest,
	providerName string,
	start time.Time,
) observability.SpanModelChatInput {
	envelope, facts := p.proxyV8Envelope(ctx, "chat")
	messages, inputBytes, inputReported := proxyV8InputMessages(req.Messages)
	input := observability.SpanModelChatInput{
		Envelope: envelope, Outcome: observability.OutcomeCompleted, Kind: "CLIENT",
		StartTimeUnixNano: uint64(start.UnixNano()), Status: observability.NewTraceStatusOK(),
		DefenseClawAgentReportedCostPresent: false,
		DefenseClawTelemetryInputReported:   inputReported,
		DefenseClawContentInputState:        proxyV8ContentState(inputReported),
		DefenseClawTelemetryOutputReported:  false,
		DefenseClawContentOutputState:       "not_reported",
		GenAIOperationName:                  observability.Present("chat"),
		GenAIRequestModel:                   strings.TrimSpace(req.Model),
		DefenseClawModelAttempt:             observability.Present[int64](1),
		DefenseClawModelRetryCount:          observability.Present[int64](0),
		DefenseClawModelStreaming:           observability.Present(req.Stream),
		ConditionConnectorKnown:             facts.connectorKnown,
		ConditionOperationTerminal:          true,
	}
	if providerName = strings.TrimSpace(providerName); providerName != "" {
		input.GenAIProviderName = observability.Present(providerName)
	}
	if req.MaxTokens != nil && *req.MaxTokens > 0 {
		input.GenAIRequestMaxTokens = observability.Present(int64(*req.MaxTokens))
	}
	if req.Temperature != nil {
		input.GenAIRequestTemperature = observability.Present(*req.Temperature)
	}
	if req.TopP != nil {
		input.GenAIRequestTopP = observability.Present(*req.TopP)
	}
	if inputReported {
		input.GenAIInputMessages = observability.Present(messages)
		input.DefenseClawContentInputOriginalBytes = observability.Present(inputBytes)
	}
	applyProxyV8FactsToModel(&input, facts)
	return input
}

type proxyV8Facts struct {
	connectorKnown bool
	connector      string
	runID          string
	requestID      string
	sessionID      string
	turnID         string
	agentID        string
	agentName      string
	agentInstance  string
	policyID       string
	destination    string
}

func (p *GuardrailProxy) proxyV8Envelope(
	ctx context.Context,
	phase string,
) (observability.FamilyEnvelopeInput, proxyV8Facts) {
	auditEnvelope := audit.EnvelopeFromContext(ctx)
	facts := proxyV8Facts{
		connector: proxyV8StableID(firstNonEmpty(auditEnvelope.Connector, p.connectorName())),
		runID:     proxyV8StableID(auditEnvelope.RunID), requestID: proxyV8StableID(firstNonEmpty(auditEnvelope.RequestID, RequestIDFromContext(ctx))),
		sessionID: proxyV8StableID(firstNonEmpty(auditEnvelope.SessionID, SessionIDFromContext(ctx))),
		turnID:    proxyV8StableID(auditEnvelope.TurnID), agentID: proxyV8StableID(firstNonEmpty(auditEnvelope.AgentID, p.agentIDForRequest())),
		agentName: proxyV8StableID(auditEnvelope.AgentName), agentInstance: proxyV8StableID(auditEnvelope.AgentInstanceID),
		policyID:    proxyV8StableID(firstNonEmpty(auditEnvelope.PolicyID, p.defaultPolicyID)),
		destination: proxyV8StableID(auditEnvelope.DestinationApp),
	}
	facts.connectorKnown = facts.connector != "" && facts.connector != "unknown"
	return observability.FamilyEnvelopeInput{
		Source: observability.SourceGateway, Connector: facts.connector,
		Action: "chat.completions", Phase: phase,
		Correlation: observability.Correlation{
			RunID: facts.runID, RequestID: facts.requestID, SessionID: facts.sessionID,
			TurnID: facts.turnID, AgentID: facts.agentID,
			AgentInstanceID: facts.agentInstance, PolicyID: facts.policyID,
		},
		Provenance: observability.FamilyProvenanceInput{Producer: proxyV8Producer},
	}, facts
}

func applyProxyV8FactsToAgent(input *observability.SpanAgentInvokeInput, facts proxyV8Facts, agentType string) {
	input.DefenseClawConnectorSource = proxyV8Optional(facts.connectorKnown, facts.connector)
	input.DefenseClawRunID = proxyV8OptionalID(facts.runID)
	input.DefenseClawRequestID = proxyV8OptionalID(facts.requestID)
	input.DefenseClawTurnID = proxyV8OptionalID(facts.turnID)
	input.DefenseClawPolicyID = proxyV8OptionalID(facts.policyID)
	input.DefenseClawDestinationApp = proxyV8OptionalID(facts.destination)
	input.GenAIConversationID = proxyV8OptionalID(facts.sessionID)
	input.GenAIAgentID = proxyV8OptionalID(facts.agentID)
	input.GenAIAgentName = proxyV8OptionalID(facts.agentName)
	input.DefenseClawAgentInstanceID = proxyV8OptionalID(facts.agentInstance)
	input.DefenseClawAgentRootID = proxyV8OptionalID(facts.agentID)
	input.DefenseClawSessionRootID = proxyV8OptionalID(facts.sessionID)
	if facts.agentID != "" {
		input.DefenseClawAgentLineageProvenance = observability.Present("reported")
		input.DefenseClawAgentDepth = observability.Present[int64](0)
	}
	input.DefenseClawAgentPhase = observability.Present("model")
	input.DefenseClawAgentPhaseCode = observability.Present[int64](3)
	if !input.GenAIAgentName.IsPresent() && observability.IsStableToken(agentType) {
		input.GenAIAgentName = observability.Present(agentType)
	}
}

func applyProxyV8FactsToModel(input *observability.SpanModelChatInput, facts proxyV8Facts) {
	input.DefenseClawConnectorSource = proxyV8Optional(facts.connectorKnown, facts.connector)
	input.DefenseClawRunID = proxyV8OptionalID(facts.runID)
	input.DefenseClawRequestID = proxyV8OptionalID(facts.requestID)
	input.DefenseClawTurnID = proxyV8OptionalID(facts.turnID)
	input.DefenseClawPolicyID = proxyV8OptionalID(facts.policyID)
	input.DefenseClawDestinationApp = proxyV8OptionalID(facts.destination)
	input.GenAIConversationID = proxyV8OptionalID(facts.sessionID)
	input.GenAIAgentID = proxyV8OptionalID(facts.agentID)
	input.GenAIAgentName = proxyV8OptionalID(facts.agentName)
	input.DefenseClawAgentInstanceID = proxyV8OptionalID(facts.agentInstance)
	input.DefenseClawAgentRootID = proxyV8OptionalID(facts.agentID)
	input.DefenseClawSessionRootID = proxyV8OptionalID(facts.sessionID)
	if facts.agentID != "" {
		input.DefenseClawAgentLineageProvenance = observability.Present("reported")
		input.DefenseClawAgentDepth = observability.Present[int64](0)
	}
	input.DefenseClawAgentPhase = observability.Present("model")
	input.DefenseClawAgentPhaseCode = observability.Present[int64](3)
}

func applyProxyV8ResultToAgent(input *observability.SpanAgentInvokeInput, result proxyV8TraceResult) {
	input.Outcome = result.Outcome
	input.EndTimeUnixNano = uint64(time.Now().UTC().UnixNano())
	input.Status = proxyV8Status(result)
	input.ConditionTechnicalFailure = result.TechnicalFailure
	input.ErrorType = proxyV8OptionalID(result.ErrorType)
	output, outputBytes, reported := proxyV8OutputMessages(result.OutputText, result.ToolCalls, result.FinishReasons)
	input.DefenseClawTelemetryOutputReported = reported
	input.DefenseClawContentOutputState = proxyV8ContentState(reported)
	if reported {
		input.GenAIOutputMessages = observability.Present(output)
		input.DefenseClawContentOutputOriginalBytes = observability.Present(outputBytes)
	}
	if result.ResponseModel != "" {
		input.GenAIResponseModel = proxyV8OptionalID(result.ResponseModel)
	}
	input.GenAIResponseID = proxyV8OptionalID(result.ResponseID)
}

func applyProxyV8ResultToModel(input *observability.SpanModelChatInput, result proxyV8TraceResult) {
	input.Outcome = result.Outcome
	input.EndTimeUnixNano = uint64(time.Now().UTC().UnixNano())
	input.Status = proxyV8Status(result)
	input.ConditionTechnicalFailure = result.TechnicalFailure
	input.ErrorType = proxyV8OptionalID(result.ErrorType)
	output, outputBytes, reported := proxyV8OutputMessages(result.OutputText, result.ToolCalls, result.FinishReasons)
	input.DefenseClawTelemetryOutputReported = reported
	input.DefenseClawContentOutputState = proxyV8ContentState(reported)
	if reported {
		input.GenAIOutputMessages = observability.Present(output)
		input.DefenseClawContentOutputOriginalBytes = observability.Present(outputBytes)
	}
	input.GenAIResponseModel = proxyV8OptionalID(result.ResponseModel)
	input.GenAIResponseID = proxyV8OptionalID(result.ResponseID)
	if len(result.FinishReasons) > 0 {
		input.GenAIResponseFinishReasons = observability.Present(append([]string(nil), result.FinishReasons...))
	}
	if result.Usage != nil {
		input.GenAIUsageInputTokens = observability.Present(result.Usage.PromptTokens)
		input.GenAIUsageOutputTokens = observability.Present(result.Usage.CompletionTokens)
		input.DefenseClawTelemetryTokensReported = observability.Present(true)
	} else {
		input.DefenseClawTelemetryTokensReported = observability.Present(false)
	}
	input.DefenseClawModelUpstreamMs = observability.Present(float64(result.UpstreamDuration.Microseconds()) / 1000)
	input.DefenseClawModelStreaming = observability.Present(result.Streaming)
	input.DefenseClawModelCancelled = observability.Present(result.Cancelled)
	input.DefenseClawModelToolCallCount = observability.Present(int64(result.ToolCallCount))
}

func proxyV8InputMessages(messages []ChatMessage) (observability.TelemetryStructuredGenAIInputMessages, int64, bool) {
	items := make([]observability.TelemetryStructuredGenAIChatMessage, 0, len(messages))
	var originalBytes int64
	for _, message := range messages {
		role := strings.TrimSpace(message.Role)
		if !proxyV8MessageRole(role) || message.Content == "" {
			continue
		}
		originalBytes += int64(len(message.Content))
		item := observability.TelemetryStructuredGenAIChatMessage{
			Role: role,
			Parts: observability.TelemetryStructuredGenAIMessageParts{Items: []observability.TelemetryStructuredGenAIMessagePart{
				observability.TelemetryStructuredArmGenAIMessagePartText{Value: observability.TelemetryStructuredGenAITextPart{Content: message.Content}},
			}},
		}
		if observability.IsStableToken(message.Name) {
			item.Name = observability.Present(message.Name)
		}
		items = append(items, item)
	}
	return observability.TelemetryStructuredGenAIInputMessages{Items: items}, originalBytes, len(items) > 0
}

func proxyV8OutputMessages(text string, toolCalls json.RawMessage, finishReasons []string) (observability.TelemetryStructuredGenAIOutputMessages, int64, bool) {
	if len(finishReasons) == 0 || strings.TrimSpace(finishReasons[0]) == "" {
		return observability.TelemetryStructuredGenAIOutputMessages{}, 0, false
	}
	parts := make([]observability.TelemetryStructuredGenAIMessagePart, 0, 1+countToolCalls(toolCalls))
	var originalBytes int64
	if strings.TrimSpace(text) != "" {
		parts = append(parts, observability.TelemetryStructuredArmGenAIMessagePartText{
			Value: observability.TelemetryStructuredGenAITextPart{Content: text},
		})
		originalBytes += int64(len(text))
	}
	var calls []toolCallEntry
	if len(toolCalls) > 0 && json.Unmarshal(toolCalls, &calls) == nil {
		for _, call := range calls {
			name := strings.TrimSpace(call.Function.Name)
			if name == "" || name != call.Function.Name {
				continue
			}
			part := observability.TelemetryStructuredGenAIToolCallRequestPart{Name: name}
			if id := proxyV8StableID(call.ID); id != "" {
				part.ID = observability.Present(id)
			}
			if arguments, ok := proxyV8CanonicalJSON([]byte(call.Function.Arguments)); ok {
				part.Arguments = observability.Present[observability.TelemetryStructuredGenAICanonicalJSON](arguments)
				originalBytes += int64(len(call.Function.Arguments))
			}
			parts = append(parts, observability.TelemetryStructuredArmGenAIMessagePartToolCall{Value: part})
		}
	}
	if len(parts) == 0 {
		return observability.TelemetryStructuredGenAIOutputMessages{}, 0, false
	}
	return observability.TelemetryStructuredGenAIOutputMessages{Items: []observability.TelemetryStructuredGenAIOutputMessage{{
		Role: "assistant", FinishReason: finishReasons[0],
		Parts: observability.TelemetryStructuredGenAIMessageParts{Items: parts},
	}}}, originalBytes, true
}

func proxyV8CanonicalJSON(encoded []byte) (observability.TelemetryStructuredGenAICanonicalJSON, bool) {
	if len(encoded) == 0 || !json.Valid(encoded) {
		return nil, false
	}
	decoder := json.NewDecoder(strings.NewReader(string(encoded)))
	decoder.UseNumber()
	var value any
	if err := decoder.Decode(&value); err != nil {
		return nil, false
	}
	return proxyV8CanonicalJSONValue(value)
}

func proxyV8CanonicalJSONValue(value any) (observability.TelemetryStructuredGenAICanonicalJSON, bool) {
	switch typed := value.(type) {
	case bool:
		return observability.TelemetryStructuredArmGenAICanonicalJSONBoolean{Value: typed}, true
	case string:
		return observability.TelemetryStructuredArmGenAICanonicalJSONString{Value: typed}, true
	case json.Number:
		if integer, err := typed.Int64(); err == nil {
			return observability.TelemetryStructuredArmGenAICanonicalJSONInt64{Value: integer}, true
		}
		finite, err := typed.Float64()
		if err != nil || math.IsInf(finite, 0) || math.IsNaN(finite) {
			return nil, false
		}
		return observability.TelemetryStructuredArmGenAICanonicalJSONFiniteDouble{Value: finite}, true
	case []any:
		items := make([]observability.TelemetryStructuredGenAICanonicalJSON, 0, len(typed))
		for _, item := range typed {
			converted, ok := proxyV8CanonicalJSONValue(item)
			if !ok {
				return nil, false
			}
			items = append(items, converted)
		}
		return observability.TelemetryStructuredArmGenAICanonicalJSONArray{Items: items}, true
	case map[string]any:
		keys := make([]string, 0, len(typed))
		for key := range typed {
			keys = append(keys, key)
		}
		sort.Strings(keys)
		entries := make([]observability.GenAICanonicalJSONEntryMemberInput, 0, len(keys))
		for _, key := range keys {
			converted, ok := proxyV8CanonicalJSONValue(typed[key])
			if !ok {
				return nil, false
			}
			entry, err := observability.NewGenAICanonicalJSONEntryMember(key, converted)
			if err != nil {
				return nil, false
			}
			entries = append(entries, entry)
		}
		return observability.TelemetryStructuredArmGenAICanonicalJSONObject{Entries: entries}, true
	default:
		// The generated canonical JSON vocabulary intentionally has no null
		// arm. Preserve the tool call without arguments rather than inventing
		// a replacement value.
		return nil, false
	}
}

func proxyV8Status(result proxyV8TraceResult) observability.TraceStatusInput {
	if result.TechnicalFailure {
		return observability.NewTraceStatusError(proxyV8OptionalID(result.ErrorType))
	}
	return observability.NewTraceStatusOK()
}

func proxyV8ContentState(reported bool) string {
	if reported {
		return "preserved"
	}
	return "not_reported"
}

func proxyV8MessageRole(role string) bool {
	switch role {
	case "system", "developer", "user", "assistant", "tool":
		return true
	default:
		return false
	}
}

func proxyV8StableID(value string) string {
	if value == "" || strings.TrimSpace(value) != value || !observability.IsStableToken(value) {
		return ""
	}
	return value
}

func proxyV8OptionalID(value string) observability.Optional[string] {
	if value = proxyV8StableID(value); value != "" {
		return observability.Present(value)
	}
	return observability.Absent[string]()
}

func proxyV8Optional(present bool, value string) observability.Optional[string] {
	if present {
		return observability.Present(value)
	}
	return observability.Absent[string]()
}
