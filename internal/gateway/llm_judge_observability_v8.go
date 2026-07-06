// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"context"
	"errors"
	"regexp"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/defenseclaw/defenseclaw/internal/audit"
	"github.com/defenseclaw/defenseclaw/internal/observability"
	observabilityruntime "github.com/defenseclaw/defenseclaw/internal/observability/runtime"
	"github.com/defenseclaw/defenseclaw/internal/telemetry"
	"go.opentelemetry.io/otel/trace"
)

const judgeV8Producer = "gateway.llm_judge"

var judgeV8IdentifierPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:/-]*$`)

type judgeTraceV8Runtime interface {
	StartJudgeTrace(context.Context, observability.SpanGuardrailJudgeInput) (context.Context, *observabilityruntime.JudgeTrace, error)
}

type judgeTraceFailure string

const (
	judgeTraceFailureNone          judgeTraceFailure = ""
	judgeTraceFailureProvider      judgeTraceFailure = "judge_provider_error"
	judgeTraceFailureEmptyResponse judgeTraceFailure = "judge_empty_response"
	judgeTraceFailureParse         judgeTraceFailure = "judge_parse_error"
)

type judgeTraceOperation struct {
	generated *observabilityruntime.JudgeTrace
	input     observability.SpanGuardrailJudgeInput
	legacy    trace.Span
	provider  *telemetry.Provider
	model     string
	v8        bool
}

// SetTelemetryProvider installs the metric provider and the v7-only legacy
// judge span provider for this judge instance. Generated v8 tracing is selected
// independently by bindJudgeTraceV8; metrics remain exactly-once in both modes.
func (j *LLMJudge) SetTelemetryProvider(provider *telemetry.Provider) {
	if j == nil {
		return
	}
	j.telemetryMu.Lock()
	j.telemetry = provider
	j.telemetryMu.Unlock()
}

func (j *LLMJudge) bindJudgeTraceV8(runtime judgeTraceV8Runtime) {
	if j == nil {
		return
	}
	j.telemetryMu.Lock()
	j.traceV8 = runtime
	j.traceV8Authoritative = true
	j.telemetryMu.Unlock()
}

func (j *LLMJudge) judgeTelemetrySnapshot() (*telemetry.Provider, judgeTraceV8Runtime, bool) {
	if j == nil {
		return nil, nil, false
	}
	j.telemetryMu.RLock()
	provider, runtime, authoritative := j.telemetry, j.traceV8, j.traceV8Authoritative
	j.telemetryMu.RUnlock()
	if provider == nil {
		provider = judgeTelemetry()
	}
	return provider, runtime, authoritative
}

func (j *LLMJudge) startJudgeTrace(
	ctx context.Context,
	kind, direction string,
	maxTokens int,
	messages []ChatMessage,
	started time.Time,
) (context.Context, *judgeTraceOperation, *telemetry.Provider) {
	provider, runtime, v8Authoritative := j.judgeTelemetrySnapshot()
	operation := &judgeTraceOperation{provider: provider, model: j.model}
	if !v8Authoritative {
		if provider != nil {
			startedContext, span := provider.StartJudgeSpan(ctx, judgeGenAISystem(j.model), j.model, maxTokens, kind)
			operation.legacy = span
			return startedContext, operation, provider
		}
		return ctx, operation, provider
	}

	operation.v8 = true
	if runtime == nil {
		return ctx, operation, provider
	}
	input := j.judgeTraceInput(ctx, kind, direction, maxTokens, messages, started)
	operation.input = input
	startedContext, generated, err := runtime.StartJudgeTrace(ctx, input)
	if err != nil {
		return ctx, operation, provider
	}
	if generated == nil {
		return startedContext, operation, provider
	}
	operation.generated = generated
	return startedContext, operation, provider
}

func (j *LLMJudge) judgeTraceInput(
	ctx context.Context,
	kind string,
	direction string,
	maxTokens int,
	messages []ChatMessage,
	started time.Time,
) observability.SpanGuardrailJudgeInput {
	envelope := audit.EnvelopeFromContext(ctx)
	connector := proxyV8StableID(envelope.Connector)
	inputMessages, inputBytes, inputState, inputEvents := judgeV8InputMessages(messages, started)
	input := observability.SpanGuardrailJudgeInput{
		Envelope: observability.FamilyEnvelopeInput{
			Source: observability.SourceGateway, Connector: connector, Action: "judge", Phase: "judge",
			Correlation: observability.Correlation{
				RunID: proxyV8StableID(envelope.RunID), RequestID: proxyV8StableID(envelope.RequestID),
				SessionID: proxyV8StableID(envelope.SessionID), TurnID: proxyV8StableID(envelope.TurnID),
				AgentID: proxyV8StableID(envelope.AgentID), AgentInstanceID: proxyV8StableID(envelope.AgentInstanceID),
				PolicyID: proxyV8StableID(envelope.PolicyID),
			},
			Provenance: observability.FamilyProvenanceInput{Producer: judgeV8Producer},
		},
		Outcome: observability.OutcomeFailed, Kind: "CLIENT", StartTimeUnixNano: uint64(started.UnixNano()),
		Status: observability.NewTraceStatusOK(), Events: inputEvents,
		DefenseClawJudgeKind:               kind,
		DefenseClawConnectorSource:         proxyV8Optional(connector != "", connector),
		DefenseClawRunID:                   proxyV8OptionalID(envelope.RunID),
		DefenseClawPolicyID:                proxyV8OptionalID(envelope.PolicyID),
		GenAIConversationID:                proxyV8OptionalID(envelope.SessionID),
		GenAIAgentID:                       proxyV8OptionalID(envelope.AgentID),
		GenAIAgentName:                     proxyV8OptionalID(envelope.AgentName),
		DefenseClawAgentInstanceID:         proxyV8OptionalID(envelope.AgentInstanceID),
		DefenseClawGuardrailPhase:          observability.Present("judge"),
		DefenseClawGuardrailDirection:      judgeV8Direction(direction),
		DefenseClawGuardrailCacheHit:       observability.Present(false),
		DefenseClawGuardrailAttempt:        observability.Present[int64](1),
		GenAIOperationName:                 observability.Present("chat"),
		GenAIRequestModel:                  j.model,
		DefenseClawModelAttempt:            observability.Present[int64](1),
		DefenseClawModelRetryCount:         observability.Present[int64](0),
		DefenseClawModelStreaming:          observability.Present(false),
		DefenseClawModelCancelled:          observability.Present(false),
		DefenseClawTelemetryTokensReported: observability.Present(false),
		DefenseClawTelemetryInputReported:  len(inputMessages.Items) > 0,
		DefenseClawContentInputState:       inputState,
		DefenseClawTelemetryOutputReported: false,
		DefenseClawContentOutputState:      "not_reported",
		ConditionConnectorKnown:            connector != "",
		ConditionOperationTerminal:         true,
	}
	providerName := strings.TrimSpace(j.providerName)
	if providerName == "" {
		providerName = judgeGenAISystem(j.model)
		if providerName == "unknown" {
			providerName = ""
		}
	}
	if providerName != "" && len(providerName) <= 4096 && utf8.ValidString(providerName) {
		input.GenAIProviderName = observability.Present(providerName)
	}
	if maxTokens >= 0 {
		input.GenAIRequestMaxTokens = observability.Present(int64(maxTokens))
	}
	if len(inputMessages.Items) > 0 {
		input.GenAIInputMessages = observability.Present(inputMessages)
		input.DefenseClawContentInputOriginalBytes = observability.Present(inputBytes)
	}
	return input
}

func (operation *judgeTraceOperation) End(
	response *ChatResponse,
	rawResponse string,
	verdict *ScanVerdict,
	failure judgeTraceFailure,
	providerErr error,
	latencyMs int64,
) error {
	if operation == nil {
		return nil
	}
	responseModel := ""
	promptTokens, completionTokens := 0, 0
	if response != nil {
		responseModel = response.Model
		if response.Usage != nil {
			promptTokens = int(response.Usage.PromptTokens)
			completionTokens = int(response.Usage.CompletionTokens)
		}
	}
	action := "error"
	if verdict != nil {
		action = verdict.Action
	}
	if !operation.v8 {
		if operation.legacy != nil {
			// The legacy SDK-only path remains byte-for-byte isolated to v7.
			// It intentionally retains its historical response-model fallback.
			legacyResponseModel := responseModel
			if legacyResponseModel == "" || failure == judgeTraceFailureProvider || failure == judgeTraceFailureEmptyResponse {
				legacyResponseModel = operation.model
			}
			legacyErr := providerErr
			if failure == judgeTraceFailureParse {
				legacyErr = errors.New("parse-failed")
			}
			if operation.provider != nil {
				operation.provider.EndJudgeSpan(operation.legacy, legacyResponseModel, promptTokens, completionTokens, latencyMs, action, false, legacyErr)
			} else {
				operation.legacy.End()
			}
		}
		return nil
	}
	if operation.generated == nil {
		return nil
	}

	input := operation.input
	endedAt := time.Now().UTC()
	input.EndTimeUnixNano = uint64(endedAt.UnixNano())
	input.DefenseClawGuardrailLatencyMs = observability.Present(float64(latencyMs))
	input.DefenseClawModelUpstreamMs = observability.Present(float64(latencyMs))
	if action != "" {
		input.DefenseClawGuardrailRawAction = observability.Present(action)
		input.DefenseClawGuardrailEffectiveAction = observability.Present(action)
		if judgeV8Decision(action) {
			input.DefenseClawGuardrailDecision = observability.Present(action)
		}
	}
	if verdict != nil {
		input.DefenseClawGuardrailFindingCount = observability.Present(int64(len(verdict.Findings)))
		if normalized := observability.NormalizeSeverity(verdict.Severity); normalized.Present && normalized.Valid {
			input.DefenseClawSecuritySeverity = observability.Present(string(normalized.Severity))
		}
	}
	if len(responseModel) <= 256 && judgeV8IdentifierPattern.MatchString(responseModel) {
		input.GenAIResponseModel = observability.Present(responseModel)
	}
	if response != nil {
		if responseID := proxyV8StableID(response.ID); responseID != "" {
			input.GenAIResponseID = observability.Present(responseID)
			input.DefenseClawModelResponseID = observability.Present(responseID)
		}
		if response.Usage != nil {
			input.GenAIUsageInputTokens = observability.Present(int64(promptTokens))
			input.GenAIUsageOutputTokens = observability.Present(int64(completionTokens))
			input.DefenseClawTelemetryTokensReported = observability.Present(true)
		}
		if reasons := judgeV8FinishReasons(response); len(reasons) > 0 {
			input.GenAIResponseFinishReasons = observability.Present(reasons)
			if output, outputBytes, state, events, reported := judgeV8OutputMessages(rawResponse, reasons[0], endedAt); reported {
				input.GenAIOutputMessages = observability.Present(output)
				input.DefenseClawTelemetryOutputReported = true
				input.DefenseClawContentOutputState = state
				input.DefenseClawContentOutputOriginalBytes = observability.Present(outputBytes)
				input.Events = append(input.Events, events...)
			}
		}
	}

	input.Outcome, input.Status, input.ErrorType, input.ConditionTechnicalFailure = judgeV8Terminal(failure, providerErr, action)
	if errors.Is(providerErr, context.Canceled) {
		input.DefenseClawModelCancelled = observability.Present(true)
	}
	if errors.Is(providerErr, context.DeadlineExceeded) {
		input.DefenseClawModelTimeoutClass = observability.Present("deadline")
	}
	if providerErr != nil {
		if reason := truncateToRuneBoundary(strings.ToValidUTF8(providerErr.Error(), "\uFFFD"), 4096); reason != "" {
			input.DefenseClawGuardrailReason = observability.Present(reason)
		}
	}
	return operation.generated.End(input)
}

func (operation *judgeTraceOperation) Abort() {
	if operation != nil && operation.generated != nil {
		operation.generated.Abort()
	}
}

func judgeV8Terminal(
	failure judgeTraceFailure,
	providerErr error,
	action string,
) (observability.Outcome, observability.TraceStatusInput, observability.Optional[string], bool) {
	if failure == judgeTraceFailureNone && providerErr == nil {
		if action == "block" || action == "deny" {
			return observability.OutcomeBlocked, observability.NewTraceStatusOK(), observability.Absent[string](), false
		}
		return observability.OutcomeAllowed, observability.NewTraceStatusOK(), observability.Absent[string](), false
	}
	errorType := string(failure)
	outcome := observability.OutcomeFailed
	if errors.Is(providerErr, context.Canceled) {
		errorType, outcome = "judge_cancelled", observability.OutcomeCancelled
	} else if errors.Is(providerErr, context.DeadlineExceeded) {
		errorType, outcome = "judge_timeout", observability.OutcomeTimedOut
	} else if errorType == "" {
		errorType = "judge_provider_error"
	}
	typed := observability.Present(errorType)
	return outcome, observability.NewTraceStatusError(typed), typed, true
}

func judgeV8Direction(direction string) observability.Optional[string] {
	switch strings.ToLower(strings.TrimSpace(direction)) {
	case "prompt", "input":
		return observability.Present("input")
	case "completion", "output", "tool_result":
		return observability.Present("output")
	case "tool", "tool_call":
		return observability.Present("tool")
	default:
		return observability.Absent[string]()
	}
}

func judgeV8Decision(action string) bool {
	switch action {
	case "allow", "block", "deny", "review", "redact":
		return true
	default:
		return false
	}
}

func judgeV8InputMessages(
	messages []ChatMessage,
	eventTime time.Time,
) (observability.TelemetryStructuredGenAIInputMessages, int64, string, []observability.TraceEventInput) {
	items := make([]observability.TelemetryStructuredGenAIChatMessage, 0, len(messages))
	var originalBytes int64
	truncated := false
	for _, message := range messages {
		role := strings.TrimSpace(message.Role)
		if !proxyV8MessageRole(role) || message.Content == "" {
			continue
		}
		originalBytes += int64(len(message.Content))
		validContent := strings.ToValidUTF8(message.Content, "\uFFFD")
		content := truncateToRuneBoundary(validContent, 4096)
		truncated = truncated || content != message.Content
		items = append(items, observability.TelemetryStructuredGenAIChatMessage{
			Role: role,
			Parts: observability.TelemetryStructuredGenAIMessageParts{Items: []observability.TelemetryStructuredGenAIMessagePart{
				observability.TelemetryStructuredArmGenAIMessagePartText{Value: observability.TelemetryStructuredGenAITextPart{Content: content}},
			}},
		})
	}
	state := "preserved"
	if len(items) == 0 {
		state = "not_reported"
	}
	var events []observability.TraceEventInput
	if truncated {
		state = "truncated"
		if event, err := observability.NewSpanGuardrailJudgeContentTruncatedEvent(observability.SpanGuardrailJudgeContentTruncatedEventInput{
			TimeUnixNano:      uint64(eventTime.UnixNano()),
			DefenseClawBucket: observability.Present(string(observability.BucketGuardrailEvaluation)),
		}); err == nil {
			events = append(events, event)
		}
	}
	return observability.TelemetryStructuredGenAIInputMessages{Items: items}, originalBytes, state, events
}

func judgeV8OutputMessages(
	content, finishReason string,
	eventTime time.Time,
) (observability.TelemetryStructuredGenAIOutputMessages, int64, string, []observability.TraceEventInput, bool) {
	if content == "" || strings.TrimSpace(finishReason) == "" {
		return observability.TelemetryStructuredGenAIOutputMessages{}, 0, "not_reported", nil, false
	}
	originalBytes := int64(len(content))
	validContent := strings.ToValidUTF8(content, "\uFFFD")
	bounded := truncateToRuneBoundary(validContent, 4096)
	state := "preserved"
	var events []observability.TraceEventInput
	if bounded != content {
		state = "truncated"
		if event, err := observability.NewSpanGuardrailJudgeContentTruncatedEvent(observability.SpanGuardrailJudgeContentTruncatedEventInput{
			TimeUnixNano:      uint64(eventTime.UnixNano()),
			DefenseClawBucket: observability.Present(string(observability.BucketGuardrailEvaluation)),
		}); err == nil {
			events = append(events, event)
		}
	}
	output := observability.TelemetryStructuredGenAIOutputMessages{Items: []observability.TelemetryStructuredGenAIOutputMessage{{
		Role: "assistant", FinishReason: finishReason,
		Parts: observability.TelemetryStructuredGenAIMessageParts{Items: []observability.TelemetryStructuredGenAIMessagePart{
			observability.TelemetryStructuredArmGenAIMessagePartText{Value: observability.TelemetryStructuredGenAITextPart{Content: bounded}},
		}},
	}}}
	return output, originalBytes, state, events, true
}

func judgeV8FinishReasons(response *ChatResponse) []string {
	if response == nil || len(response.Choices) == 0 || response.Choices[0].FinishReason == nil {
		return nil
	}
	reason := *response.Choices[0].FinishReason
	if reason == "" || strings.TrimSpace(reason) != reason || len(reason) > 4096 || !utf8.ValidString(reason) {
		return nil
	}
	return []string{reason}
}
