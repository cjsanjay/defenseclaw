// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"context"
	"math"
	"regexp"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/defenseclaw/defenseclaw/internal/gatewaylog"
	"github.com/defenseclaw/defenseclaw/internal/observability"
	"github.com/defenseclaw/defenseclaw/internal/observability/router"
	observabilityruntime "github.com/defenseclaw/defenseclaw/internal/observability/runtime"
	"github.com/defenseclaw/defenseclaw/internal/telemetry"
	"github.com/defenseclaw/defenseclaw/internal/version"
	"github.com/google/uuid"
	"go.opentelemetry.io/otel/trace"
)

type hookLifecycleEmission uint8

const (
	hookLifecycleLegacy hookLifecycleEmission = iota
	hookLifecycleV8Dropped
	hookLifecycleV8Persisted
	hookLifecycleV8Failed
)

var hookV8IdentifierPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:/-]*$`)

// emitHookLifecycleEvent is the durable hook-log ownership boundary. A bound
// v8 runtime owns collection and persistence decisions and therefore never
// falls back to the legacy gateway writer: doing so after a drop or local
// failure would make collection policy ambiguous and can duplicate a record.
// Other hook records (prompt, response, tool invocation, and decision) retain
// their existing fanout until their own producer cutovers.
func (a *APIServer) emitHookLifecycleEvent(ctx context.Context, meta llmEventMeta) hookLifecycleEmission {
	emitter := a.observabilityV8RuntimeEmitter()
	if emitter == nil {
		emitLegacyHookLifecycleEvent(ctx, meta)
		return hookLifecycleLegacy
	}
	if ctx == nil || strings.TrimSpace(meta.Source) == "" || strings.TrimSpace(meta.SessionID) == "" {
		return hookLifecycleV8Failed
	}
	if !hookLifecycleV8Representable(meta) {
		emitLegacyHookLifecycleEvent(ctx, meta)
		return hookLifecycleLegacy
	}

	eventName, bucket := hookLifecycleV8Identity(meta.LifecycleEvent)
	producerKey := observability.ProducerKey(gatewaylog.EventLifecycle)
	if bucket == observability.BucketToolActivity {
		producerKey = observability.ProducerKey(gatewaylog.EventToolInvocation)
	}
	classification := observability.ClassificationContext{
		Bucket: bucket, EventName: eventName, RawSeverity: "INFO",
	}
	metadata, err := router.NewClassifiedLogMetadata(
		observability.ProducerGatewayEvent,
		producerKey,
		classification,
		observability.SourceConnector,
		meta.Source,
		producerKey,
	)
	if err != nil {
		emitLegacyHookLifecycleEvent(ctx, meta)
		return hookLifecycleLegacy
	}

	outcome, emitErr := emitter.Emit(ctx, metadata, func(
		snapshot observabilityruntime.EmitContext,
		admission router.Admission,
	) (observability.Record, error) {
		if admission != router.AdmissionOrdinary || snapshot.Generation() > math.MaxInt64 {
			return observability.Record{}, &sidecarObservabilityError{code: sidecarObservabilityBuildFailed}
		}
		builder, buildErr := observability.NewFamilyBuilder(
			observability.ClockFunc(func() time.Time { return time.Now().UTC() }),
			observability.OccurrenceIDGeneratorFunc(func() (string, error) { return uuid.NewString(), nil }),
		)
		if buildErr != nil {
			return observability.Record{}, &sidecarObservabilityError{code: sidecarObservabilityBuildFailed}
		}
		return buildHookLifecycleV8Record(ctx, builder, snapshot, meta)
	})
	if emitErr != nil {
		return hookLifecycleV8Failed
	}
	switch outcome.Admission() {
	case router.AdmissionDrop:
		if !outcome.LocalPersisted() {
			return hookLifecycleV8Dropped
		}
	case router.AdmissionOrdinary:
		if outcome.LocalPersisted() {
			return hookLifecycleV8Persisted
		}
	}
	return hookLifecycleV8Failed
}

func hookLifecycleV8Identity(event string) (observability.EventName, observability.Bucket) {
	switch event {
	case observability.TelemetryEventSessionStart,
		observability.TelemetryEventSessionEnd,
		observability.TelemetryEventSubagentStart,
		observability.TelemetryEventSubagentStop,
		observability.TelemetryEventTurnStart,
		observability.TelemetryEventTurnEnd,
		observability.TelemetryEventCompactStart,
		observability.TelemetryEventCompactEnd:
		return observability.EventName(event), observability.BucketAgentLifecycle
	case observability.TelemetryEventToolStart, observability.TelemetryEventToolEnd:
		return observability.EventName(event), observability.BucketToolActivity
	default:
		return observability.EventName(observability.TelemetryEventEvent), observability.BucketAgentLifecycle
	}
}

func hookLifecycleV8Representable(meta llmEventMeta) bool {
	if !observability.IsStableToken(meta.Source) || meta.AgentDepth < 0 || meta.AgentDepth > 64 {
		return false
	}
	if meta.ReportedCost && !hookV8OptionalReportedCost(meta).IsPresent() {
		return false
	}
	if meta.LifecycleEvent == observability.TelemetryEventToolStart ||
		meta.LifecycleEvent == observability.TelemetryEventToolEnd {
		return hookV8OptionalIdentifier(meta.SessionID).IsPresent()
	}
	for _, value := range []string{
		meta.SessionID, meta.AgentID, meta.RootAgentID, meta.RootSessionID,
		meta.LifecycleID, meta.ExecutionID,
	} {
		if !hookV8OptionalIdentifier(value).IsPresent() {
			return false
		}
	}
	return meta.LifecycleEvent != "" && len(meta.LifecycleEvent) <= 4096 &&
		meta.LifecycleState != "" && len(meta.LifecycleState) <= 4096
}

func buildHookLifecycleV8Record(
	ctx context.Context,
	builder *observability.FamilyBuilder,
	snapshot observabilityruntime.EmitContext,
	meta llmEventMeta,
) (observability.Record, error) {
	correlation := observability.Correlation{
		RunID: meta.RunID, RequestID: meta.RequestID, SessionID: meta.SessionID,
		TurnID: meta.TurnID, AgentID: meta.AgentID, PolicyID: meta.PolicyID,
		ToolInvocationID: meta.ToolID, ConnectorID: meta.Source,
	}
	if spanContext := trace.SpanContextFromContext(ctx); spanContext.IsValid() {
		correlation.TraceID = spanContext.TraceID().String()
		correlation.SpanID = spanContext.SpanID().String()
	}
	producerAction := string(gatewaylog.EventLifecycle)
	if meta.LifecycleEvent == observability.TelemetryEventToolStart ||
		meta.LifecycleEvent == observability.TelemetryEventToolEnd {
		producerAction = string(gatewaylog.EventToolInvocation)
	}
	envelope := observability.FamilyEnvelopeInput{
		Source:      observability.SourceConnector,
		Connector:   meta.Source,
		Action:      producerAction,
		Phase:       meta.Phase,
		Correlation: correlation,
		Provenance: observability.FamilyProvenanceInput{
			Producer: "defenseclaw", BinaryVersion: version.Current().BinaryVersion,
			ConfigGeneration: int64(snapshot.Generation()), ConfigDigest: snapshot.Digest(),
		},
	}
	if meta.LifecycleEvent == observability.TelemetryEventToolStart ||
		meta.LifecycleEvent == observability.TelemetryEventToolEnd {
		return buildHookToolLifecycleV8Record(builder, envelope, meta)
	}

	base := observability.LogCompatSessionStartInput{
		Envelope: envelope, Severity: observability.Present(observability.SeverityInfo),
		LogLevel: observability.Present(observability.LogLevelInfo), Outcome: hookLifecycleV8Outcome(meta),
		GenAIConversationID: meta.SessionID, GenAIAgentID: meta.AgentID,
		GenAIAgentName:                      hookV8OptionalIdentifier(meta.AgentName),
		DefenseClawAgentType:                hookV8OptionalText(meta.AgentType, 4096),
		DefenseClawAgentRootID:              meta.RootAgentID,
		DefenseClawAgentParentID:            hookV8OptionalIdentifier(meta.ParentAgentID),
		DefenseClawAgentLineageProvenance:   hookV8OptionalLineageProvenance(meta.LineageProvenance),
		DefenseClawSessionRootID:            meta.RootSessionID,
		DefenseClawSessionParentID:          hookV8OptionalIdentifier(meta.ParentSessionID),
		DefenseClawAgentLifecycleID:         meta.LifecycleID,
		DefenseClawAgentExecutionID:         meta.ExecutionID,
		DefenseClawAgentDepth:               int64(meta.AgentDepth),
		DefenseClawAgentLifecycleEvent:      meta.LifecycleEvent,
		DefenseClawAgentLifecycleState:      meta.LifecycleState,
		DefenseClawAgentPhase:               hookV8OptionalPhase(meta.Phase),
		DefenseClawAgentPhasePrevious:       hookV8OptionalPhase(meta.PreviousPhase),
		DefenseClawAgentPhaseCode:           hookV8OptionalPhaseCode(meta.Phase),
		DefenseClawAgentSequence:            hookV8OptionalPositiveInt64(meta.Sequence),
		DefenseClawSessionSource:            hookV8OptionalSessionSource(meta.SessionSource),
		DefenseClawSessionResumed:           hookV8OptionalSessionResumed(meta),
		DefenseClawRequestID:                hookV8OptionalIdentifier(meta.RequestID),
		DefenseClawTurnID:                   hookV8OptionalIdentifier(meta.TurnID),
		DefenseClawOperationID:              hookV8OptionalIdentifier(meta.OperationID),
		DefenseClawRunID:                    hookV8OptionalIdentifier(meta.RunID),
		UserID:                              hookV8OptionalIdentifier(meta.UserID),
		DefenseClawUserName:                 hookV8OptionalIdentifier(meta.UserName),
		DefenseClawPolicyID:                 hookV8OptionalIdentifier(meta.PolicyID),
		DefenseClawDestinationApp:           hookV8OptionalIdentifier(meta.DestinationApp),
		GenAIProviderName:                   hookV8OptionalText(meta.Provider, 4096),
		GenAIRequestModel:                   hookV8OptionalIdentifier(meta.Model),
		GenAIResponseID:                     hookV8OptionalIdentifier(meta.ResponseID),
		GenAIToolName:                       hookV8OptionalIdentifier(meta.ToolName),
		GenAIToolCallID:                     hookV8OptionalIdentifier(meta.ToolID),
		DefenseClawAgentReportedCostPresent: meta.ReportedCost,
		DefenseClawAgentReportedCostUsd:     hookV8OptionalReportedCost(meta),
	}

	switch meta.LifecycleEvent {
	case observability.TelemetryEventSessionStart:
		return builder.BuildLogCompatSessionStart(base)
	case observability.TelemetryEventSessionEnd:
		return builder.BuildLogCompatSessionEnd(observability.LogCompatSessionEndInput(base))
	case observability.TelemetryEventSubagentStart:
		return builder.BuildLogCompatSubagentStart(observability.LogCompatSubagentStartInput(base))
	case observability.TelemetryEventSubagentStop:
		return builder.BuildLogCompatSubagentStop(observability.LogCompatSubagentStopInput(base))
	case observability.TelemetryEventTurnStart:
		return builder.BuildLogCompatTurnStart(observability.LogCompatTurnStartInput(base))
	case observability.TelemetryEventTurnEnd:
		return builder.BuildLogCompatTurnEnd(observability.LogCompatTurnEndInput(base))
	case observability.TelemetryEventCompactStart:
		return builder.BuildLogCompatCompactStart(observability.LogCompatCompactStartInput(base))
	case observability.TelemetryEventCompactEnd:
		return builder.BuildLogCompatCompactEnd(observability.LogCompatCompactEndInput(base))
	default:
		return builder.BuildLogCompatEvent(hookLifecycleV8EventInput(base))
	}
}

func hookLifecycleV8EventInput(base observability.LogCompatSessionStartInput) observability.LogCompatEventInput {
	return observability.LogCompatEventInput{
		Envelope: base.Envelope, Severity: base.Severity, LogLevel: base.LogLevel,
		GenAIConversationID: base.GenAIConversationID, GenAIAgentID: base.GenAIAgentID,
		GenAIAgentName: base.GenAIAgentName, DefenseClawAgentType: base.DefenseClawAgentType,
		DefenseClawAgentInstanceID:        base.DefenseClawAgentInstanceID,
		DefenseClawAgentRootID:            base.DefenseClawAgentRootID,
		DefenseClawAgentParentID:          base.DefenseClawAgentParentID,
		DefenseClawAgentLineageProvenance: base.DefenseClawAgentLineageProvenance,
		DefenseClawSessionRootID:          base.DefenseClawSessionRootID,
		DefenseClawSessionParentID:        base.DefenseClawSessionParentID,
		DefenseClawAgentLifecycleID:       base.DefenseClawAgentLifecycleID,
		DefenseClawAgentExecutionID:       base.DefenseClawAgentExecutionID,
		DefenseClawAgentDepth:             base.DefenseClawAgentDepth,
		DefenseClawAgentLifecycleEvent:    base.DefenseClawAgentLifecycleEvent,
		DefenseClawAgentLifecycleState:    base.DefenseClawAgentLifecycleState,
		DefenseClawAgentPhase:             base.DefenseClawAgentPhase,
		DefenseClawAgentPhasePrevious:     base.DefenseClawAgentPhasePrevious,
		DefenseClawAgentPhaseCode:         base.DefenseClawAgentPhaseCode,
		DefenseClawAgentSequence:          base.DefenseClawAgentSequence,
		DefenseClawSessionSource:          base.DefenseClawSessionSource,
		DefenseClawSessionResumed:         base.DefenseClawSessionResumed,
		DefenseClawRequestID:              base.DefenseClawRequestID,
		DefenseClawTurnID:                 base.DefenseClawTurnID,
		DefenseClawOperationID:            base.DefenseClawOperationID,
		DefenseClawRunID:                  base.DefenseClawRunID,
		UserID:                            base.UserID, DefenseClawUserName: base.DefenseClawUserName,
		DefenseClawPolicyID:       base.DefenseClawPolicyID,
		DefenseClawPolicyVersion:  base.DefenseClawPolicyVersion,
		DefenseClawDestinationApp: base.DefenseClawDestinationApp,
		GenAIProviderName:         base.GenAIProviderName, GenAIRequestModel: base.GenAIRequestModel,
		GenAIResponseModel: base.GenAIResponseModel, GenAIResponseID: base.GenAIResponseID,
		DefenseClawModelRequestID:  base.DefenseClawModelRequestID,
		DefenseClawModelResponseID: base.DefenseClawModelResponseID,
		DefenseClawToolID:          base.DefenseClawToolID, GenAIToolName: base.GenAIToolName,
		GenAIToolType: base.GenAIToolType, GenAIToolCallID: base.GenAIToolCallID,
		DefenseClawToolProvider:             base.DefenseClawToolProvider,
		DefenseClawToolSkillKey:             base.DefenseClawToolSkillKey,
		DefenseClawAgentReportedCostPresent: base.DefenseClawAgentReportedCostPresent,
		DefenseClawAgentReportedCostUsd:     base.DefenseClawAgentReportedCostUsd,
	}
}

func buildHookToolLifecycleV8Record(
	builder *observability.FamilyBuilder,
	envelope observability.FamilyEnvelopeInput,
	meta llmEventMeta,
) (observability.Record, error) {
	base := observability.LogCompatToolStartInput{
		Envelope: envelope, Severity: observability.Present(observability.SeverityInfo),
		LogLevel: observability.Present(observability.LogLevelInfo), Outcome: hookLifecycleV8Outcome(meta),
		DefenseClawRequestID:               hookV8OptionalIdentifier(meta.RequestID),
		DefenseClawTurnID:                  hookV8OptionalIdentifier(meta.TurnID),
		DefenseClawOperationID:             hookV8OptionalIdentifier(meta.OperationID),
		DefenseClawRunID:                   hookV8OptionalIdentifier(meta.RunID),
		UserID:                             hookV8OptionalIdentifier(meta.UserID),
		DefenseClawUserName:                hookV8OptionalIdentifier(meta.UserName),
		DefenseClawPolicyID:                hookV8OptionalIdentifier(meta.PolicyID),
		DefenseClawDestinationApp:          hookV8OptionalIdentifier(meta.DestinationApp),
		GenAIConversationID:                hookV8OptionalIdentifier(meta.SessionID),
		GenAIAgentID:                       hookV8OptionalIdentifier(meta.AgentID),
		GenAIAgentName:                     hookV8OptionalIdentifier(meta.AgentName),
		DefenseClawAgentType:               hookV8OptionalText(meta.AgentType, 4096),
		DefenseClawAgentRootID:             hookV8OptionalIdentifier(meta.RootAgentID),
		DefenseClawAgentParentID:           hookV8OptionalIdentifier(meta.ParentAgentID),
		DefenseClawAgentLineageProvenance:  hookV8OptionalLineageProvenance(meta.LineageProvenance),
		DefenseClawSessionRootID:           hookV8OptionalIdentifier(meta.RootSessionID),
		DefenseClawSessionParentID:         hookV8OptionalIdentifier(meta.ParentSessionID),
		DefenseClawAgentLifecycleID:        hookV8OptionalIdentifier(meta.LifecycleID),
		DefenseClawAgentExecutionID:        hookV8OptionalIdentifier(meta.ExecutionID),
		DefenseClawAgentDepth:              observability.Present(int64(meta.AgentDepth)),
		DefenseClawAgentLifecycleEvent:     hookV8OptionalText(meta.LifecycleEvent, 4096),
		DefenseClawAgentLifecycleState:     hookV8OptionalText(meta.LifecycleState, 4096),
		DefenseClawAgentPhase:              hookV8OptionalPhase(meta.Phase),
		DefenseClawAgentPhasePrevious:      hookV8OptionalPhase(meta.PreviousPhase),
		DefenseClawAgentPhaseCode:          hookV8OptionalPhaseCode(meta.Phase),
		DefenseClawAgentSequence:           hookV8OptionalPositiveInt64(meta.Sequence),
		DefenseClawSessionSource:           hookV8OptionalSessionSource(meta.SessionSource),
		DefenseClawSessionResumed:          hookV8OptionalSessionResumed(meta),
		GenAIToolName:                      hookV8OptionalIdentifier(meta.ToolName),
		GenAIToolCallID:                    hookV8OptionalIdentifier(meta.ToolID),
		DefenseClawTelemetryInputReported:  false,
		DefenseClawTelemetryOutputReported: false,
	}
	if meta.LifecycleEvent == observability.TelemetryEventToolEnd {
		return builder.BuildLogCompatToolEnd(observability.LogCompatToolEndInput(base))
	}
	return builder.BuildLogCompatToolStart(base)
}

func hookLifecycleV8Outcome(meta llmEventMeta) observability.Outcome {
	switch meta.LifecycleOutcome {
	case "attempted":
		return observability.OutcomeAttempted
	case "blocked":
		return observability.OutcomeBlocked
	case "cancelled":
		return observability.OutcomeCancelled
	case "completed":
		return observability.OutcomeCompleted
	case "denied":
		return observability.OutcomeDenied
	case "failed":
		return observability.OutcomeFailed
	case "no_change":
		return observability.OutcomeNoChange
	case "partial":
		return observability.OutcomePartial
	case "rejected":
		return observability.OutcomeRejected
	case "skipped":
		return observability.OutcomeSkipped
	case "terminated":
		return observability.OutcomeTerminated
	case "timed_out":
		return observability.OutcomeTimedOut
	}
	switch meta.LifecycleEvent {
	case observability.TelemetryEventSessionStart,
		observability.TelemetryEventSubagentStart,
		observability.TelemetryEventTurnStart,
		observability.TelemetryEventCompactStart,
		observability.TelemetryEventToolStart:
		return observability.OutcomeAttempted
	}
	switch meta.LifecycleState {
	case "failed":
		return observability.OutcomeFailed
	case "interrupted", "cancelled", "canceled":
		return observability.OutcomeCancelled
	default:
		return observability.OutcomeCompleted
	}
}

func hookV8OptionalIdentifier(value string) observability.Optional[string] {
	value = strings.TrimSpace(value)
	if value == "" || len(value) > 256 || !hookV8IdentifierPattern.MatchString(value) {
		return observability.Absent[string]()
	}
	return observability.Present(value)
}

func hookV8OptionalText(value string, maxBytes int) observability.Optional[string] {
	value = strings.TrimSpace(value)
	if value == "" || len(value) > maxBytes || !utf8.ValidString(value) {
		return observability.Absent[string]()
	}
	return observability.Present(value)
}

func hookV8OptionalLineageProvenance(value string) observability.Optional[string] {
	if value == "reported" || value == "inferred" {
		return observability.Present(value)
	}
	return observability.Absent[string]()
}

func hookV8OptionalPhase(value string) observability.Optional[string] {
	switch value {
	case "session", "planning", "model", "tool", "approval", "waiting", "responding",
		"maintenance", "completed", "failed", "interrupted", "observed":
		return observability.Present(value)
	default:
		return observability.Absent[string]()
	}
}

func hookV8OptionalPhaseCode(phase string) observability.Optional[int64] {
	if !hookV8OptionalPhase(phase).IsPresent() {
		return observability.Absent[int64]()
	}
	return observability.Present(int64(telemetry.AgentPhaseCode(phase)))
}

func hookV8OptionalPositiveInt64(value int64) observability.Optional[int64] {
	if value <= 0 {
		return observability.Absent[int64]()
	}
	return observability.Present(value)
}

func hookV8OptionalSessionSource(value string) observability.Optional[string] {
	switch value {
	case "startup", "resume", "clear", "compact":
		return observability.Present(value)
	default:
		return observability.Absent[string]()
	}
}

func hookV8OptionalSessionResumed(meta llmEventMeta) observability.Optional[bool] {
	if strings.TrimSpace(meta.SessionSource) == "" {
		return observability.Absent[bool]()
	}
	return observability.Present(meta.SessionResumed)
}

func hookV8OptionalReportedCost(meta llmEventMeta) observability.Optional[float64] {
	if !meta.ReportedCost || math.IsNaN(meta.ReportedCostUSD) || math.IsInf(meta.ReportedCostUSD, 0) || meta.ReportedCostUSD < 0 {
		return observability.Absent[float64]()
	}
	return observability.Present(meta.ReportedCostUSD)
}
