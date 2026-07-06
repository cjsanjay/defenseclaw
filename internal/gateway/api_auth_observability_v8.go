// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"context"
	"math"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/audit"
	"github.com/defenseclaw/defenseclaw/internal/gatewaylog"
	"github.com/defenseclaw/defenseclaw/internal/observability"
	"github.com/defenseclaw/defenseclaw/internal/observability/router"
	observabilityruntime "github.com/defenseclaw/defenseclaw/internal/observability/runtime"
	"github.com/defenseclaw/defenseclaw/internal/version"
	"github.com/google/uuid"
)

// emitAPIAuthenticationFailureV8 returns true as soon as the canonical runtime
// owns this occurrence. Ownership is deliberately independent of the eventual
// build or persistence result: callers must never fall back to a second legacy
// event after selecting a runtime generation.
func (a *APIServer) emitAPIAuthenticationFailureV8(ctx context.Context, reason string) bool {
	if a == nil {
		return false
	}
	emitter := a.observabilityV8RuntimeEmitter()
	if emitter == nil {
		return false
	}
	if ctx == nil {
		ctx = context.Background()
	}

	producerKey := observability.ProducerKey(audit.ActionAPIAuthFailure)
	classification := observability.ClassificationContext{
		EventName:   observability.EventName(observability.TelemetryEventAuthenticationFailed),
		RawSeverity: "WARN",
		MandatoryFacts: observability.MandatoryFacts{
			ProtectedBoundaryAuthFailure: true,
		},
	}
	metadata, err := router.NewClassifiedLogMetadata(
		observability.ProducerAuditAction,
		producerKey,
		classification,
		observability.SourceOperatorAPI,
		"",
		producerKey,
	)
	if err != nil {
		return true
	}

	// metricReason is supplied only by fixed middleware branches. Still use an
	// explicit allowlist so a future caller cannot turn this metadata field into
	// an error, path, header, token, address, or user-agent exfiltration channel.
	canonicalReason := apiAuthenticationFailureReason(reason)
	_, _ = emitter.Emit(ctx, metadata, func(
		snapshot observabilityruntime.EmitContext,
		admission router.Admission,
	) (observability.Record, error) {
		if snapshot.Generation() > math.MaxInt64 || !observability.IsStableToken(snapshot.Digest()) {
			return observability.Record{}, &apiAuthenticationV8Error{}
		}
		provenance := observability.Provenance{
			Producer:              "gateway_api",
			BinaryVersion:         version.Current().BinaryVersion,
			RegistrySchemaVersion: observability.CurrentRecordSchemaVersion,
			ConfigGeneration:      int64(snapshot.Generation()),
			ConfigDigest:          snapshot.Digest(),
		}
		correlation := apiAuthenticationFailureCorrelation(ctx)
		clock := observability.ClockFunc(func() time.Time { return time.Now().UTC() })
		ids := observability.OccurrenceIDGeneratorFunc(func() (string, error) {
			return uuid.NewString(), nil
		})

		if admission == router.AdmissionFloor {
			builder, buildErr := observability.NewRecordBuilder(clock, ids)
			if buildErr != nil {
				return observability.Record{}, &apiAuthenticationV8Error{}
			}
			return builder.BuildMandatoryFloorLog(observability.MandatoryFloorLogInput{
				ProducerKind:          observability.ProducerAuditAction,
				ProducerKey:           producerKey,
				ClassificationContext: classification,
				Source:                observability.SourceOperatorAPI,
				Action:                string(audit.ActionAPIAuthFailure),
				Phase:                 "authentication",
				Outcome:               observability.OutcomeRejected,
				Correlation:           correlation,
				Provenance:            provenance,
			})
		}
		if admission != router.AdmissionOrdinary {
			return observability.Record{}, &apiAuthenticationV8Error{}
		}

		builder, buildErr := observability.NewFamilyBuilder(clock, ids)
		if buildErr != nil {
			return observability.Record{}, &apiAuthenticationV8Error{}
		}
		reasonValue := observability.Absent[string]()
		if canonicalReason != "" {
			reasonValue = observability.Present(canonicalReason)
		}
		return builder.BuildLogAuthenticationFailed(observability.LogAuthenticationFailedInput{
			Envelope: observability.FamilyEnvelopeInput{
				Source:      observability.SourceOperatorAPI,
				Action:      string(audit.ActionAPIAuthFailure),
				Phase:       "authentication",
				Correlation: correlation,
				Provenance: observability.FamilyProvenanceInput{
					Producer:         provenance.Producer,
					BinaryVersion:    provenance.BinaryVersion,
					ConfigGeneration: provenance.ConfigGeneration,
					ConfigDigest:     provenance.ConfigDigest,
				},
			},
			Severity:                              observability.Present(observability.SeverityMedium),
			LogLevel:                              observability.Present(observability.LogLevelWarn),
			Outcome:                               observability.OutcomeRejected,
			DefenseClawAdminOperation:             string(audit.ActionAPIAuthFailure),
			DefenseClawAdminReason:                reasonValue,
			ConditionAdminPrincipalKnown:          false,
			MandatoryProtectedBoundaryAuthFailure: true,
		})
	})
	return true
}

// apiAuthenticationV8Error intentionally carries no wrapped error or request
// data. The runtime health channel reports canonical pipeline failures without
// making authentication input part of an error string.
type apiAuthenticationV8Error struct{}

func (*apiAuthenticationV8Error) Error() string {
	return "canonical API authentication failure emission failed"
}

func apiAuthenticationFailureReason(reason string) string {
	switch reason {
	case "no_token_configured",
		"missing_token",
		"invalid_token",
		"sec_fetch_site_rejected",
		"origin_blocked",
		"bad_content_type",
		"csrf_mismatch_options",
		"csrf_mismatch":
		return reason
	default:
		return ""
	}
}

func apiAuthenticationFailureCorrelation(ctx context.Context) observability.Correlation {
	// Authentication has not succeeded, so no caller-supplied agent, session,
	// connector, user, tool, or destination identity is trusted here.
	return observability.Correlation{
		RunID:             gatewaylog.ProcessRunID(),
		RequestID:         RequestIDFromContext(ctx),
		SidecarInstanceID: gatewaylog.SidecarInstanceID(),
	}
}
