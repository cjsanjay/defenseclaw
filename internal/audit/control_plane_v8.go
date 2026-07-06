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
	"regexp"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/defenseclaw/defenseclaw/internal/observability"
	"github.com/defenseclaw/defenseclaw/internal/observability/router"
)

// ControlPlaneV8BuildContext is the exact graph generation pinned by the
// unified runtime for one emission. The runtime adapter must populate it from
// runtime.EmitContext; legacy version.ContentHash is not a graph digest.
type ControlPlaneV8BuildContext struct {
	ConfigGeneration uint64
	ConfigDigest     string
}

// ControlPlaneV8Builder is lazy: collection is evaluated before the generated
// family builder runs. AdmissionFloor selects the authenticated minimal floor
// record and never constructs the ordinary family body.
type ControlPlaneV8Builder func(
	ControlPlaneV8BuildContext,
	router.Admission,
) (observability.Record, error)

// ControlPlaneV8Emitter is the audit-owned, cycle-free runtime seam. A runtime
// adapter calls runtime.Emit with metadata and translates its pinned
// EmitContext into ControlPlaneV8BuildContext. The returned bool is true only
// when the canonical local SQLite projection committed successfully.
type ControlPlaneV8Emitter interface {
	EmitControlPlaneV8(
		context.Context,
		router.Metadata,
		ControlPlaneV8Builder,
	) (localPersisted bool, err error)
}

type controlPlaneV8Family uint8

var controlPlaneV8PrincipalPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:/-]*$`)

const (
	controlPlaneV8FamilyNone controlPlaneV8Family = iota
	controlPlaneV8FamilyConfigApplied
	controlPlaneV8FamilyPolicyUpdated
	controlPlaneV8FamilyAuthenticationFailed
)

// emitControlPlaneV8 sends one selected v7 Event through the canonical runtime.
// A true handled result means the runtime owns SQLite persistence, so the
// caller must not invoke Store.LogEvent for the same occurrence.
func (l *Logger) emitControlPlaneV8(ctx context.Context, event Event) (handled bool, err error) {
	family := controlPlaneV8FamilyForAction(event.Action)
	if family == controlPlaneV8FamilyNone {
		return false, nil
	}
	emitter := l.controlPlaneV8Snapshot()
	if emitter == nil {
		return false, nil
	}
	if ctx == nil {
		ctx = context.Background()
	}

	normalized := observability.NormalizeSeverity(event.Severity)
	if !normalized.Valid || !normalized.Present {
		return true, fmt.Errorf("audit: v8 control-plane severity %q is not canonical", event.Severity)
	}
	source := controlPlaneV8Source(event)
	classification := controlPlaneV8Classification(family, event.Severity)
	metadata, err := router.NewClassifiedLogMetadata(
		observability.ProducerAuditAction,
		observability.ProducerKey(event.Action),
		classification,
		source,
		event.Connector,
		observability.ProducerKey(event.Action),
	)
	if err != nil {
		return true, fmt.Errorf("audit: classify v8 control-plane action %q: %w", event.Action, err)
	}

	build := func(snapshot ControlPlaneV8BuildContext, admission router.Admission) (observability.Record, error) {
		return buildControlPlaneV8Record(event, family, source, classification, normalized, snapshot, admission)
	}
	localPersisted, err := emitter.EmitControlPlaneV8(
		contextWithLegacyEventProjection(ctx, event), metadata, build,
	)
	if err != nil {
		return true, fmt.Errorf("audit: emit v8 control-plane action %q: %w", event.Action, err)
	}
	if !localPersisted {
		return true, fmt.Errorf("audit: v8 control-plane action %q was not persisted locally", event.Action)
	}
	return true, nil
}

func buildControlPlaneV8Record(
	event Event,
	family controlPlaneV8Family,
	source observability.Source,
	classification observability.ClassificationContext,
	normalized observability.SeverityNormalization,
	snapshot ControlPlaneV8BuildContext,
	admission router.Admission,
) (observability.Record, error) {
	if event.ID == "" || event.Timestamp.IsZero() || event.BinaryVersion == "" ||
		snapshot.ConfigGeneration > math.MaxInt64 || !observability.IsStableToken(snapshot.ConfigDigest) {
		return observability.Record{}, fmt.Errorf("audit: invalid v8 control-plane build context")
	}
	clock := observability.ClockFunc(func() time.Time { return event.Timestamp.UTC() })
	ids := observability.OccurrenceIDGeneratorFunc(func() (string, error) { return event.ID, nil })
	correlation := controlPlaneV8Correlation(event)
	provenance := observability.FamilyProvenanceInput{
		Producer:         "audit_logger",
		BinaryVersion:    event.BinaryVersion,
		ConfigGeneration: int64(snapshot.ConfigGeneration),
		ConfigDigest:     snapshot.ConfigDigest,
	}
	if admission == router.AdmissionFloor {
		builder, err := observability.NewRecordBuilder(clock, ids)
		if err != nil {
			return observability.Record{}, err
		}
		return builder.BuildMandatoryFloorLog(observability.MandatoryFloorLogInput{
			ProducerKind:          observability.ProducerAuditAction,
			ProducerKey:           observability.ProducerKey(event.Action),
			ClassificationContext: classification,
			ObservedAt:            timePointer(event.Timestamp.UTC()),
			Source:                source,
			Connector:             event.Connector,
			Action:                event.Action,
			Phase:                 controlPlaneV8Phase(family),
			Outcome:               controlPlaneV8Outcome(family),
			Correlation:           correlation,
			Provenance: observability.Provenance{
				Producer:              provenance.Producer,
				BinaryVersion:         provenance.BinaryVersion,
				RegistrySchemaVersion: observability.CurrentRecordSchemaVersion,
				ConfigGeneration:      provenance.ConfigGeneration,
				ConfigDigest:          provenance.ConfigDigest,
			},
		})
	}
	if admission != router.AdmissionOrdinary {
		return observability.Record{}, fmt.Errorf("audit: v8 control-plane record has no admitted path")
	}

	builder, err := observability.NewFamilyBuilder(clock, ids)
	if err != nil {
		return observability.Record{}, err
	}
	severity := observability.Present(normalized.Severity)
	logLevel := observability.Absent[observability.LogLevel]()
	if normalized.LogLevel != "" {
		logLevel = observability.Present(normalized.LogLevel)
	}
	envelope := observability.FamilyEnvelopeInput{
		ObservedAt:  observability.Present(event.Timestamp.UTC()),
		Source:      source,
		Connector:   event.Connector,
		Action:      event.Action,
		Phase:       controlPlaneV8Phase(family),
		Correlation: correlation,
		Provenance:  provenance,
	}
	principal, principalKnown := controlPlaneV8Principal(event.Actor)

	var record observability.Record
	switch family {
	case controlPlaneV8FamilyConfigApplied:
		record, err = builder.BuildLogConfigChangeApplied(observability.LogConfigChangeAppliedInput{
			Envelope: envelope, Severity: severity, LogLevel: logLevel,
			Outcome: observability.OutcomeApplied, DefenseClawAdminOperation: event.Action,
			DefenseClawAdminPrincipalRef: principal, ConditionAdminPrincipalKnown: principalKnown,
			MandatoryControlPlaneMutation: true,
		})
	case controlPlaneV8FamilyPolicyUpdated:
		record, err = builder.BuildLogPolicyUpdated(observability.LogPolicyUpdatedInput{
			Envelope: envelope, Severity: severity, LogLevel: logLevel,
			Outcome: observability.OutcomeApplied, DefenseClawAdminOperation: event.Action,
			DefenseClawAdminPrincipalRef: principal, ConditionAdminPrincipalKnown: principalKnown,
			MandatoryControlPlaneMutation: true,
		})
	case controlPlaneV8FamilyAuthenticationFailed:
		record, err = builder.BuildLogAuthenticationFailed(observability.LogAuthenticationFailedInput{
			Envelope: envelope, Severity: severity, LogLevel: logLevel,
			Outcome: observability.OutcomeRejected, DefenseClawAdminOperation: event.Action,
			DefenseClawAdminPrincipalRef: principal, ConditionAdminPrincipalKnown: principalKnown,
			MandatoryProtectedBoundaryAuthFailure: true,
		})
	default:
		return observability.Record{}, fmt.Errorf("audit: unsupported v8 control-plane family")
	}
	if err != nil {
		return observability.Record{}, err
	}
	if !record.Mandatory() || record.IsFloorOnly() || record.RecordID() != event.ID ||
		!record.Timestamp().Equal(event.Timestamp.UTC()) {
		return observability.Record{}, fmt.Errorf("audit: generated v8 control-plane record violated its identity contract")
	}
	return record, nil
}

func controlPlaneV8FamilyForAction(action string) controlPlaneV8Family {
	switch Action(action) {
	case ActionConfigUpdate, ActionAPIConfigPatch, ActionGuardrailConfigReload:
		return controlPlaneV8FamilyConfigApplied
	case ActionPolicyUpdate, ActionPolicyReload:
		return controlPlaneV8FamilyPolicyUpdated
	case ActionAPIAuthFailure:
		return controlPlaneV8FamilyAuthenticationFailed
	default:
		return controlPlaneV8FamilyNone
	}
}

func controlPlaneV8Classification(family controlPlaneV8Family, severity string) observability.ClassificationContext {
	context := observability.ClassificationContext{RawSeverity: severity}
	switch family {
	case controlPlaneV8FamilyConfigApplied:
		context.EventName = observability.EventName(observability.TelemetryEventConfigChangeApplied)
		context.MandatoryFacts.ControlPlaneMutation = true
	case controlPlaneV8FamilyPolicyUpdated:
		context.EventName = observability.EventName(observability.TelemetryEventPolicyUpdated)
		context.MandatoryFacts.ControlPlaneMutation = true
	case controlPlaneV8FamilyAuthenticationFailed:
		context.EventName = observability.EventName(observability.TelemetryEventAuthenticationFailed)
		context.MandatoryFacts.ProtectedBoundaryAuthFailure = true
	}
	return context
}

func controlPlaneV8Phase(family controlPlaneV8Family) string {
	if family == controlPlaneV8FamilyAuthenticationFailed {
		return "authentication"
	}
	return "apply"
}

func controlPlaneV8Outcome(family controlPlaneV8Family) observability.Outcome {
	if family == controlPlaneV8FamilyAuthenticationFailed {
		return observability.OutcomeRejected
	}
	return observability.OutcomeApplied
}

func controlPlaneV8Source(event Event) observability.Source {
	action := Action(event.Action)
	if action == ActionAPIAuthFailure || action == ActionAPIConfigPatch {
		return observability.SourceOperatorAPI
	}
	actor := strings.ToLower(strings.TrimSpace(event.Actor))
	switch {
	case strings.HasPrefix(actor, "cli:") || actor == "cli":
		return observability.SourceCLI
	case actor == "watcher":
		return observability.SourceWatcher
	case event.RequestID != "":
		return observability.SourceOperatorAPI
	case actor != "" && actor != "system" && actor != "defenseclaw":
		return observability.SourceOperator
	default:
		return observability.SourceSystem
	}
}

func controlPlaneV8Correlation(event Event) observability.Correlation {
	return observability.Correlation{
		RunID:             event.RunID,
		RequestID:         event.RequestID,
		SessionID:         event.SessionID,
		TurnID:            event.TurnID,
		TraceID:           event.TraceID,
		AgentID:           event.AgentID,
		AgentInstanceID:   event.AgentInstanceID,
		PolicyID:          event.PolicyID,
		ConnectorID:       event.Connector,
		SidecarInstanceID: event.SidecarInstanceID,
	}
}

func controlPlaneV8Principal(actor string) (observability.Optional[string], bool) {
	actor = strings.TrimSpace(actor)
	if actor == "" || len(actor) > 256 || !utf8.ValidString(actor) ||
		!controlPlaneV8PrincipalPattern.MatchString(actor) {
		return observability.Absent[string](), false
	}
	return observability.Present(actor), true
}

func timePointer(value time.Time) *time.Time { return &value }
