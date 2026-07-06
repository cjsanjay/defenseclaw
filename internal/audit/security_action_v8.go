// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
// SPDX-License-Identifier: Apache-2.0

package audit

import (
	"context"
	"fmt"
	"math"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/defenseclaw/defenseclaw/internal/gatewaylog"
	"github.com/defenseclaw/defenseclaw/internal/observability"
	"github.com/defenseclaw/defenseclaw/internal/observability/router"
)

// JudgeCompletionInput contains only facts present on the completed judge call.
// It deliberately has no finding fields: a judge result is an evaluation, not
// evidence that a separately identified security finding was persisted.
type JudgeCompletionInput struct {
	Kind         string
	Action       string
	LatencyMS    int64
	InputBytes   int64
	FailureClass gatewaylog.JudgeFailureClass
	ErrorSummary string
	ParseError   string
}

// EnforcementQuarantineAppliedInput describes one successful quarantine state
// change. EnforcementID is a domain ID and must be distinct from Event.ID, the
// canonical record occurrence ID.
type EnforcementQuarantineAppliedInput struct {
	EnforcementID   string
	RequestedAction string
	EffectiveAction string
	Initiator       string
	PreviousState   string
	ResultingState  string
}

// LogJudgeCompletion preserves the legacy Event view while routing a bound-v8
// occurrence through the generated guardrail.judge.completed family.
func (l *Logger) LogJudgeCompletion(
	ctx context.Context,
	event Event,
	input JudgeCompletionInput,
) error {
	if Action(event.Action) != ActionLLMJudgeResponse {
		return fmt.Errorf("audit: judge completion requires action %q", ActionLLMJudgeResponse)
	}
	if l.runtimeV8Snapshot() == nil {
		applyEnvelope(&event, EnvelopeFromContext(ctx))
		return l.logEventWithV8(ctx, event, nil)
	}
	if err := validateJudgeCompletionInput(input); err != nil {
		return err
	}
	applyEnvelope(&event, EnvelopeFromContext(ctx))
	return l.logEventWithV8(ctx, event, func(ctx context.Context, stamped Event) (auditV8Disposition, error) {
		return l.emitJudgeCompletionV8(ctx, stamped, input)
	})
}

// LogEnforcementQuarantineApplied preserves the legacy Event view while
// routing a bound-v8 occurrence through enforcement.quarantine.applied.
func (l *Logger) LogEnforcementQuarantineApplied(
	ctx context.Context,
	event Event,
	input EnforcementQuarantineAppliedInput,
) error {
	if Action(event.Action) != ActionQuarantine {
		return fmt.Errorf("audit: quarantine completion requires action %q", ActionQuarantine)
	}
	if l.runtimeV8Snapshot() == nil {
		applyEnvelope(&event, EnvelopeFromContext(ctx))
		return l.logEventWithV8(ctx, event, nil)
	}
	if err := validateEnforcementQuarantineInput(event, input); err != nil {
		return err
	}
	applyEnvelope(&event, EnvelopeFromContext(ctx))
	return l.logEventWithV8(ctx, event, func(ctx context.Context, stamped Event) (auditV8Disposition, error) {
		return l.emitEnforcementQuarantineV8(ctx, stamped, input)
	})
}

func (l *Logger) emitJudgeCompletionV8(
	ctx context.Context,
	event Event,
	input JudgeCompletionInput,
) (auditV8Disposition, error) {
	emitter := l.runtimeV8Snapshot()
	if emitter == nil {
		return auditV8Unhandled, nil
	}
	outcome, judgeOutcome, _ := judgeCompletionOutcome(input.Action)
	classification := observability.ClassificationContext{
		EventName:   observability.EventName(observability.TelemetryEventGuardrailJudgeCompleted),
		RawSeverity: event.Severity,
	}
	metadata, err := router.NewClassifiedLogMetadata(
		observability.ProducerAuditAction, observability.ProducerKey(event.Action), classification,
		observability.SourceGuardrail, event.Connector, observability.ProducerKey(event.Action),
	)
	if err != nil {
		return auditV8Persisted, fmt.Errorf("audit: classify judge completion: %w", err)
	}
	correlation := controlPlaneV8Correlation(event)
	correlation.ToolInvocationID = event.ToolID
	result, err := emitter.EmitRuntimeV8(
		contextWithLegacyEventProjection(ctx, event), metadata,
		func(snapshot RuntimeV8BuildContext, admission router.Admission) (observability.Record, error) {
			if admission != router.AdmissionOrdinary {
				return observability.Record{}, fmt.Errorf("audit: judge completion requires ordinary admission")
			}
			builder, envelope, severity, logLevel, buildErr := runtimeV8FamilyBuildState(
				event, snapshot, observability.SourceGuardrail, "judge", correlation,
			)
			if buildErr != nil {
				return observability.Record{}, buildErr
			}
			parseError := observability.Absent[string]()
			if input.ParseError != "" {
				parseError = observability.Present(input.ParseError)
			}
			errorSummary := observability.Absent[string]()
			if input.ErrorSummary != "" {
				errorSummary = observability.Present(input.ErrorSummary)
			}
			record, buildErr := builder.BuildLogGuardrailJudgeCompleted(observability.LogGuardrailJudgeCompletedInput{
				Envelope: envelope, Severity: severity, LogLevel: logLevel, Outcome: judgeOutcome,
				DefenseClawPolicyID:  optionalControlPlaneV8Identifier(event.PolicyID),
				DefenseClawJudgeKind: input.Kind, DefenseClawJudgeAction: outcome,
				DefenseClawJudgeLatencyMs: input.LatencyMS, DefenseClawJudgeInputBytes: input.InputBytes,
				DefenseClawJudgeParseError: parseError, DefenseClawJudgeErrorSummary: errorSummary,
				ConditionJudgeOutputParseFailed: input.FailureClass == gatewaylog.JudgeFailureOutputParse,
			})
			return verifyRuntimeV8Record(record, buildErr, event, false)
		},
	)
	if err != nil {
		return auditV8Persisted, fmt.Errorf("audit: emit judge completion: %w", err)
	}
	return runtimeV8Disposition(result, false)
}

func (l *Logger) emitEnforcementQuarantineV8(
	ctx context.Context,
	event Event,
	input EnforcementQuarantineAppliedInput,
) (auditV8Disposition, error) {
	emitter := l.runtimeV8Snapshot()
	if emitter == nil {
		return auditV8Unhandled, nil
	}
	classification := observability.ClassificationContext{
		EventName:   observability.EventName(observability.TelemetryEventEnforcementQuarantineApplied),
		RawSeverity: event.Severity,
		MandatoryFacts: observability.MandatoryFacts{
			EnforcementStateChange: true,
		},
		StateChanged: true,
	}
	metadata, err := router.NewClassifiedLogMetadata(
		observability.ProducerAuditAction, observability.ProducerKey(event.Action), classification,
		observability.SourceWatcher, event.Connector, observability.ProducerKey(event.Action),
	)
	if err != nil {
		return auditV8Persisted, fmt.Errorf("audit: classify quarantine completion: %w", err)
	}
	correlation := controlPlaneV8Correlation(event)
	correlation.EnforcementActionID = input.EnforcementID
	result, err := emitter.EmitRuntimeV8(
		contextWithLegacyEventProjection(ctx, event), metadata,
		func(snapshot RuntimeV8BuildContext, admission router.Admission) (observability.Record, error) {
			if admission == router.AdmissionFloor {
				return buildRuntimeV8FloorRecord(
					event, snapshot, classification, observability.SourceWatcher, "apply",
					observability.OutcomeQuarantined, correlation,
				)
			}
			if admission != router.AdmissionOrdinary {
				return observability.Record{}, fmt.Errorf("audit: quarantine completion has no admitted path")
			}
			builder, envelope, severity, logLevel, buildErr := runtimeV8FamilyBuildState(
				event, snapshot, observability.SourceWatcher, "apply", correlation,
			)
			if buildErr != nil {
				return observability.Record{}, buildErr
			}
			record, buildErr := builder.BuildLogEnforcementQuarantineApplied(observability.LogEnforcementQuarantineAppliedInput{
				Envelope: envelope, Severity: severity, LogLevel: logLevel,
				Outcome:                               observability.OutcomeQuarantined,
				DefenseClawPolicyID:                   optionalControlPlaneV8Identifier(event.PolicyID),
				DefenseClawEnforcementID:              input.EnforcementID,
				DefenseClawEnforcementRequestedAction: optionalRuntimeV8Text(input.RequestedAction),
				DefenseClawEnforcementEffectiveAction: input.EffectiveAction,
				DefenseClawEnforcementInitiator:       optionalControlPlaneV8Identifier(input.Initiator),
				DefenseClawEnforcementPreviousState:   optionalRuntimeV8Text(input.PreviousState),
				DefenseClawEnforcementResultingState:  optionalRuntimeV8Text(input.ResultingState),
				MandatoryEnforcementStateChange:       true,
			})
			return verifyRuntimeV8Record(record, buildErr, event, true)
		},
	)
	if err != nil {
		return auditV8Persisted, fmt.Errorf("audit: emit quarantine completion: %w", err)
	}
	return runtimeV8Disposition(result, true)
}

func runtimeV8FamilyBuildState(
	event Event,
	snapshot RuntimeV8BuildContext,
	source observability.Source,
	phase string,
	correlation observability.Correlation,
) (*observability.FamilyBuilder, observability.FamilyEnvelopeInput, observability.Optional[observability.Severity], observability.Optional[observability.LogLevel], error) {
	if event.ID == "" || event.Timestamp.IsZero() || event.BinaryVersion == "" ||
		snapshot.ConfigGeneration > math.MaxInt64 || !observability.IsStableToken(snapshot.ConfigDigest) {
		return nil, observability.FamilyEnvelopeInput{}, observability.Absent[observability.Severity](), observability.Absent[observability.LogLevel](), fmt.Errorf("audit: invalid v8 family build context")
	}
	normalized := observability.NormalizeSeverity(event.Severity)
	if !normalized.Valid {
		return nil, observability.FamilyEnvelopeInput{}, observability.Absent[observability.Severity](), observability.Absent[observability.LogLevel](), fmt.Errorf("audit: invalid v8 family severity")
	}
	severity := observability.Absent[observability.Severity]()
	logLevel := observability.Absent[observability.LogLevel]()
	if normalized.Present {
		severity = observability.Present(normalized.Severity)
	}
	if normalized.LogLevel != "" {
		logLevel = observability.Present(normalized.LogLevel)
	}
	builder, err := observability.NewFamilyBuilder(
		observability.ClockFunc(func() time.Time { return event.Timestamp.UTC() }),
		observability.OccurrenceIDGeneratorFunc(func() (string, error) { return event.ID, nil }),
	)
	if err != nil {
		return nil, observability.FamilyEnvelopeInput{}, severity, logLevel, err
	}
	return builder, observability.FamilyEnvelopeInput{
		ObservedAt: observability.Present(event.Timestamp.UTC()), Source: source,
		Connector: event.Connector, Action: event.Action, Phase: phase, Correlation: correlation,
		Provenance: observability.FamilyProvenanceInput{
			Producer: "audit_logger", BinaryVersion: event.BinaryVersion,
			ConfigGeneration: int64(snapshot.ConfigGeneration), ConfigDigest: snapshot.ConfigDigest,
		},
	}, severity, logLevel, nil
}

func buildRuntimeV8FloorRecord(
	event Event,
	snapshot RuntimeV8BuildContext,
	classification observability.ClassificationContext,
	source observability.Source,
	phase string,
	outcome observability.Outcome,
	correlation observability.Correlation,
) (observability.Record, error) {
	if event.ID == "" || event.Timestamp.IsZero() || event.BinaryVersion == "" ||
		snapshot.ConfigGeneration > math.MaxInt64 || !observability.IsStableToken(snapshot.ConfigDigest) {
		return observability.Record{}, fmt.Errorf("audit: invalid v8 floor build context")
	}
	builder, err := observability.NewRecordBuilder(
		observability.ClockFunc(func() time.Time { return event.Timestamp.UTC() }),
		observability.OccurrenceIDGeneratorFunc(func() (string, error) { return event.ID, nil }),
	)
	if err != nil {
		return observability.Record{}, err
	}
	return builder.BuildMandatoryFloorLog(observability.MandatoryFloorLogInput{
		ProducerKind: observability.ProducerAuditAction, ProducerKey: observability.ProducerKey(event.Action),
		ClassificationContext: classification, ObservedAt: timePointer(event.Timestamp.UTC()),
		Source: source, Connector: event.Connector, Action: event.Action, Phase: phase,
		Outcome: outcome, Correlation: correlation,
		Provenance: observability.Provenance{
			Producer: "audit_logger", BinaryVersion: event.BinaryVersion,
			RegistrySchemaVersion: observability.CurrentRecordSchemaVersion,
			ConfigGeneration:      int64(snapshot.ConfigGeneration), ConfigDigest: snapshot.ConfigDigest,
		},
	})
}

func verifyRuntimeV8Record(
	record observability.Record,
	err error,
	event Event,
	mandatory bool,
) (observability.Record, error) {
	if err != nil {
		return observability.Record{}, err
	}
	if record.RecordID() != event.ID || !record.Timestamp().Equal(event.Timestamp.UTC()) ||
		record.IsFloorOnly() || record.Mandatory() != mandatory {
		return observability.Record{}, fmt.Errorf("audit: generated v8 record violated its identity contract")
	}
	return record, nil
}

func validateJudgeCompletionInput(input JudgeCompletionInput) error {
	if strings.TrimSpace(input.Kind) == "" || len(input.Kind) > 4096 || !utf8.ValidString(input.Kind) {
		return fmt.Errorf("audit: judge kind is required")
	}
	action, _, ok := judgeCompletionOutcome(input.Action)
	if !ok {
		return fmt.Errorf("audit: judge action must be allow, block, or error")
	}
	if input.LatencyMS < 0 || input.InputBytes < 0 {
		return fmt.Errorf("audit: judge measurements must not be negative")
	}
	if len(input.ErrorSummary) > 65536 || !utf8.ValidString(input.ErrorSummary) {
		return fmt.Errorf("audit: judge error summary is invalid")
	}
	if len(input.ParseError) > 65536 || !utf8.ValidString(input.ParseError) {
		return fmt.Errorf("audit: judge parse error is invalid")
	}
	if action != "error" {
		if input.FailureClass != "" || input.ErrorSummary != "" || input.ParseError != "" {
			return fmt.Errorf("audit: successful judge result must not carry failure metadata")
		}
		return nil
	}
	if !input.FailureClass.Valid() {
		return fmt.Errorf("audit: judge error failure class is invalid")
	}
	if strings.TrimSpace(input.ErrorSummary) == "" {
		return fmt.Errorf("audit: judge error summary is required")
	}
	if input.FailureClass == gatewaylog.JudgeFailureOutputParse {
		if strings.TrimSpace(input.ParseError) == "" {
			return fmt.Errorf("audit: output-parse judge failure requires parse error")
		}
	} else if input.ParseError != "" {
		return fmt.Errorf("audit: parse error is forbidden for non-parse judge failure")
	}
	return nil
}

func validateEnforcementQuarantineInput(event Event, input EnforcementQuarantineAppliedInput) error {
	if !runtimeV8Identifier(input.EnforcementID) || input.EnforcementID == event.ID {
		return fmt.Errorf("audit: quarantine enforcement id is required and distinct from record id")
	}
	if strings.TrimSpace(input.EffectiveAction) == "" || len(input.EffectiveAction) > 4096 ||
		!utf8.ValidString(input.EffectiveAction) {
		return fmt.Errorf("audit: quarantine effective action is required")
	}
	return nil
}

func judgeCompletionOutcome(action string) (string, observability.Outcome, bool) {
	switch strings.ToLower(strings.TrimSpace(action)) {
	case "allow":
		return "allow", observability.OutcomeAllowed, true
	case "block":
		return "block", observability.OutcomeBlocked, true
	case "error":
		return "error", observability.OutcomeFailed, true
	default:
		return "", "", false
	}
}

func runtimeV8Identifier(value string) bool {
	value = strings.TrimSpace(value)
	return value != "" && len(value) <= 256 && utf8.ValidString(value) &&
		controlPlaneV8PrincipalPattern.MatchString(value)
}

func optionalRuntimeV8Text(value string) observability.Optional[string] {
	if value == "" {
		return observability.Absent[string]()
	}
	return observability.Present(value)
}
