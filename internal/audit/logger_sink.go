// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package audit

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"math"
	"net/http"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/defenseclaw/defenseclaw/internal/gatewaylog"
	"github.com/defenseclaw/defenseclaw/internal/observability"
	"github.com/defenseclaw/defenseclaw/internal/version"
)

func (l *Logger) sinkDeliveryHook(ctx context.Context, kind, sinkName string, err error, latencyMs float64) {
	if l == nil || l.store == nil {
		return
	}
	binding := l.runtimeV8BindingSnapshot()
	if !binding.authoritative {
		l.sinkDeliveryHookLegacy(ctx, kind, sinkName, err, latencyMs)
		return
	}
	prov := version.Current()
	now := time.Now().UTC()
	retryCount := 0
	safeKind := safeSinkHealthDimension(kind)
	safeName := safeSinkHealthDimension(sinkName)
	if err != nil {
		failure := classifySinkFailure(err)
		if binding.authoritative {
			_ = l.recordSinkMetricV8(ctx, binding, sinkMetricV8Input{
				kind: sinkMetricV8BatchDropped, valueInt: 1,
				sinkKind: safeKind, sinkName: safeName,
				statusCode: int64(failure.statusCode), retryCount: int64(retryCount),
				action: string(ActionSinkFailure), timestamp: now,
			})
			_ = l.recordSinkMetricV8(ctx, binding, sinkMetricV8Input{
				kind: sinkMetricV8Failure, valueInt: 1,
				sinkKind: safeKind, sinkName: safeName, reason: failure.metricReason,
				action: string(ActionSinkFailure), timestamp: now,
			})
		}
		_ = l.store.InsertSinkHealth(SinkHealthInput{
			Timestamp:     now,
			SinkName:      safeName,
			SinkKind:      safeKind,
			Outcome:       "failed",
			StatusCode:    failure.statusCode,
			LatencyMs:     stableSinkLatencyMS(latencyMs),
			BatchSize:     1,
			Error:         fmt.Sprintf("retry_count=%d failure_code=%s", retryCount, failure.errorCode),
			SchemaVersion: prov.SchemaVersion,
			ContentHash:   prov.ContentHash,
			Generation:    prov.Generation,
			BinaryVersion: prov.BinaryVersion,
		})
		if binding.authoritative {
			_ = l.emitSinkHealthV8(ctx, binding, sinkHealthV8Occurrence{
				family: failure.family, action: ActionSinkFailure, phase: "delivery",
				outcome: failure.outcome, severity: "HIGH", subsystem: safeName,
				healthState: "failed", errorCode: observability.Present(failure.errorCode),
				protectedBoundaryAuthFailure: failure.family == sinkHealthV8AuthenticationFailed ||
					failure.family == sinkHealthV8AuthorizationDenied,
				timestamp: now,
			})
		}
		return
	}
	if binding.authoritative {
		_ = l.recordSinkMetricV8(ctx, binding, sinkMetricV8Input{
			kind: sinkMetricV8BatchDelivered, valueInt: 1,
			sinkKind: safeKind, sinkName: safeName,
			statusCode: http.StatusOK, retryCount: int64(retryCount),
			action: "", timestamp: now,
		})
		if validSinkLatencyMS(latencyMs) {
			_ = l.recordSinkMetricV8(ctx, binding, sinkMetricV8Input{
				kind: sinkMetricV8DeliveryLatency, valueFloat: latencyMs,
				sinkKind: safeKind, sinkName: safeName,
				statusCode: http.StatusOK, retryCount: int64(retryCount),
				action: "", timestamp: now,
			})
		}
	}
	_ = l.store.InsertSinkHealth(SinkHealthInput{
		Timestamp:     now,
		SinkName:      safeName,
		SinkKind:      safeKind,
		Outcome:       "delivered",
		StatusCode:    http.StatusOK,
		LatencyMs:     stableSinkLatencyMS(latencyMs),
		BatchSize:     1,
		SchemaVersion: prov.SchemaVersion,
		ContentHash:   prov.ContentHash,
		Generation:    prov.Generation,
		BinaryVersion: prov.BinaryVersion,
	})
}

// sinkDeliveryHookLegacy is the exact v7 delivery path. Keep its configured
// sink labels, latency conversion, stored diagnostic, and gateway/audit shape
// unchanged; the v8 path above is selected before any of these values are
// normalized or bounded.
func (l *Logger) sinkDeliveryHookLegacy(
	ctx context.Context,
	kind, sinkName string,
	err error,
	latencyMs float64,
) {
	_, tel, _ := l.snapshot()
	prov := version.Current()
	now := time.Now().UTC()
	retryCount := 0
	if err != nil {
		statusCode := extractHTTPStatus(err)
		reason := sinkFailureReason(err)
		if tel != nil {
			tel.RecordSinkBatchFailed(ctx, sinkName, kind, statusCode, retryCount)
			tel.RecordSinkFailure(kind, sinkName, reason)
		}
		_ = l.store.InsertSinkHealth(SinkHealthInput{
			Timestamp:     now,
			SinkName:      sinkName,
			SinkKind:      kind,
			Outcome:       "failed",
			StatusCode:    statusCode,
			LatencyMs:     int64(latencyMs),
			BatchSize:     1,
			Error:         fmt.Sprintf("retry_count=%d | %v", retryCount, err),
			SchemaVersion: prov.SchemaVersion,
			ContentHash:   prov.ContentHash,
			Generation:    prov.Generation,
			BinaryVersion: prov.BinaryVersion,
		})
		l.emitSinkFailureAuditAndGateway(ctx, sinkName, kind, classifySinkFailureCode(err), err)
		return
	}
	if tel != nil {
		sc := http.StatusOK
		tel.RecordSinkBatchDelivered(ctx, sinkName, kind, sc, retryCount, latencyMs)
	}
	_ = l.store.InsertSinkHealth(SinkHealthInput{
		Timestamp:     now,
		SinkName:      sinkName,
		SinkKind:      kind,
		Outcome:       "delivered",
		StatusCode:    http.StatusOK,
		LatencyMs:     int64(latencyMs),
		BatchSize:     1,
		SchemaVersion: prov.SchemaVersion,
		ContentHash:   prov.ContentHash,
		Generation:    prov.Generation,
		BinaryVersion: prov.BinaryVersion,
	})
}

type sinkFailureClassification struct {
	family       sinkHealthV8Family
	outcome      observability.Outcome
	metricReason string
	errorCode    string
	statusCode   int
	gatewayCode  gatewaylog.ErrorCode
}

func classifySinkFailure(err error) sinkFailureClassification {
	statusCode := extractHTTPStatus(err)
	classification := sinkFailureClassification{
		family: sinkHealthV8ExportFailed, outcome: observability.OutcomeFailed,
		metricReason: "delivery_error", errorCode: "delivery_failed",
		statusCode: statusCode, gatewayCode: gatewaylog.ErrCodeSinkDeliveryFailed,
	}
	switch {
	case statusCode == http.StatusUnauthorized:
		classification.family = sinkHealthV8AuthenticationFailed
		classification.metricReason = "authentication_failed"
		classification.errorCode = "authentication_failed"
	case statusCode == http.StatusForbidden:
		classification.family = sinkHealthV8AuthorizationDenied
		classification.outcome = observability.OutcomeDenied
		classification.metricReason = "authorization_denied"
		classification.errorCode = "authorization_denied"
	case errors.Is(err, context.Canceled):
		classification.outcome = observability.OutcomeCancelled
		classification.metricReason = "cancelled"
		classification.errorCode = "delivery_cancelled"
	case errors.Is(err, context.DeadlineExceeded) || containsSinkError(err, "timeout", "deadline"):
		classification.outcome = observability.OutcomeTimedOut
		classification.metricReason = "timeout"
		classification.errorCode = "delivery_timeout"
	case containsSinkError(err, "backlog", "dropping", "queue full", "cap "):
		classification.family = sinkHealthV8QueueFull
		classification.outcome = observability.OutcomeRejected
		classification.metricReason = "queue_full"
		classification.errorCode = "queue_full"
		classification.gatewayCode = gatewaylog.ErrCodeSinkQueueFull
	case containsSinkError(err, "encode", "marshal", "serialize"):
		classification.metricReason = "serialize_error"
		classification.errorCode = "serialization_failed"
	case statusCode != 0:
		classification.metricReason = "http_error"
		classification.errorCode = "http_delivery_failed"
	}
	return classification
}

func containsSinkError(err error, values ...string) bool {
	if err == nil {
		return false
	}
	message := strings.ToLower(err.Error())
	for _, value := range values {
		if strings.Contains(message, value) {
			return true
		}
	}
	return false
}

func safeSinkHealthDimension(value string) string {
	value = strings.TrimSpace(value)
	if observability.IsStableToken(value) {
		return value
	}
	// A configured display name remains distinguishable after normalization,
	// while values shaped like endpoints are represented only by a stable digest
	// so health telemetry never promotes an endpoint into a label or subsystem.
	if value != "" && len(value) <= observability.MaxStableTokenBytes &&
		!strings.Contains(strings.ToLower(value), "://") {
		var normalized strings.Builder
		previousSeparator := false
		for _, character := range strings.ToLower(value) {
			allowed := character >= 'a' && character <= 'z' ||
				character >= '0' && character <= '9' || character == '.' ||
				character == '_' || character == '-'
			if allowed {
				normalized.WriteRune(character)
				previousSeparator = false
				continue
			}
			if normalized.Len() > 0 && !previousSeparator {
				normalized.WriteByte('-')
				previousSeparator = true
			}
		}
		candidate := strings.Trim(normalized.String(), "-._")
		if observability.IsStableToken(candidate) {
			return candidate
		}
	}
	digest := sha256.Sum256([]byte(value))
	return "sink-" + hex.EncodeToString(digest[:8])
}

func validSinkLatencyMS(value float64) bool {
	return value >= 0 && !math.IsNaN(value) && !math.IsInf(value, 0) && value <= math.MaxInt64
}

func stableSinkLatencyMS(value float64) int64 {
	if !validSinkLatencyMS(value) {
		return 0
	}
	return int64(value)
}

func classifySinkFailureCode(err error) gatewaylog.ErrorCode {
	if err == nil {
		return ""
	}
	s := err.Error()
	if strings.Contains(s, "backlog") || strings.Contains(s, "dropping") || strings.Contains(s, "cap ") {
		return gatewaylog.ErrCodeSinkQueueFull
	}
	return gatewaylog.ErrCodeSinkDeliveryFailed
}

func extractHTTPStatus(err error) int {
	if err == nil {
		return 0
	}
	s := err.Error()
	// "HEC returned 503" / "returned 503"
	for _, prefix := range []string{"returned ", "HTTP ", "status "} {
		if i := strings.Index(s, prefix); i >= 0 {
			var code int
			if n, _ := fmt.Sscanf(s[i+len(prefix):], "%d", &code); n == 1 && code >= 100 && code < 600 {
				return code
			}
		}
	}
	return 0
}

func sinkFailureReason(err error) string {
	if err == nil {
		return "unknown"
	}
	s := err.Error()
	switch {
	case strings.Contains(s, "timeout") || strings.Contains(s, "deadline"):
		return "timeout"
	case strings.Contains(s, "backlog") || strings.Contains(s, "dropping"):
		return "queue_full"
	case strings.Contains(s, "encode") || strings.Contains(s, "marshal"):
		return "serialize_error"
	default:
		return "http_error"
	}
}

func (l *Logger) emitSinkFailureAuditAndGateway(
	ctx context.Context,
	sinkName, kind string,
	code gatewaylog.ErrorCode,
	err error,
) {
	_, otel, emitter := l.snapshot()
	ev := gatewaylog.Event{
		Timestamp: time.Now().UTC(),
		EventType: gatewaylog.EventError,
		Severity:  gatewaylog.SeverityHigh,
		RunID:     currentRunID(),
		Error: &gatewaylog.ErrorPayload{
			Subsystem: string(gatewaylog.SubsystemSink),
			Code:      string(code),
			Message:   fmt.Sprintf("audit sink %q (%s) delivery failed", sinkName, kind),
			Cause:     err.Error(),
		},
	}
	stampGatewayEnvelope(&ev)
	if otel != nil {
		otel.RecordGatewayEvent(ev)
	}
	l.emitGatewaySnapshot(emitter, ev)

	ae := Event{
		ID:        uuid.New().String(),
		Timestamp: time.Now().UTC(),
		Action:    string(ActionSinkFailure),
		Target:    sinkName,
		Actor:     "defenseclaw",
		Details:   fmt.Sprintf(`{"sink_kind":%q,"sink":%q,"code":%q}`, kind, sinkName, code),
		Severity:  "HIGH",
		RunID:     currentRunID(),
	}
	ae = sanitizeEvent(ae)
	if err := l.store.LogEvent(ae); err != nil {
		if otel != nil {
			otel.RecordAuditDBError(ctx, "insert_sink_failure_audit")
		}
		return
	}
	if otel != nil {
		otel.RecordAuditEvent(ctx, ae.Action, ae.Severity)
	}
	l.emitStructuredSnapshot(emitter, ae)
}

func (l *Logger) onCircuitTripActivity(kind, sinkName string) {
	if l == nil {
		return
	}
	binding := l.runtimeV8BindingSnapshot()
	if binding.authoritative {
		now := time.Now().UTC()
		_ = l.recordSinkMetricV8(context.Background(), binding, sinkMetricV8Input{
			kind: sinkMetricV8CircuitState, valueInt: 1,
			sinkKind: safeSinkHealthDimension(kind), sinkName: safeSinkHealthDimension(sinkName),
			action: string(ActionSinkFailure), timestamp: now,
		})
		_ = l.emitSinkHealthV8(context.Background(), binding, sinkHealthV8Occurrence{
			family: sinkHealthV8ExportFailed, action: ActionSinkFailure, phase: "circuit",
			outcome: observability.OutcomeFailed, severity: "HIGH",
			subsystem: safeSinkHealthDimension(sinkName), healthState: "failed",
			errorCode: observability.Present("circuit_open"), durableHealthTransition: true,
			timestamp: now,
		})
		return
	}
	_ = l.LogActivity(ActivityInput{
		Actor:          "defenseclaw",
		Action:         ActionSinkFailure,
		TargetType:     "sink",
		TargetID:       sinkName,
		Reason:         "consecutive forward failures reached threshold",
		Before:         map[string]any{"circuit": "closed", "sink_kind": kind},
		After:          map[string]any{"circuit": "open", "sink_kind": kind},
		Severity:       "HIGH",
		SkipSinkFanout: true,
	})
}

func (l *Logger) onCircuitRecoverActivity(kind, sinkName string) {
	if l == nil {
		return
	}
	binding := l.runtimeV8BindingSnapshot()
	if binding.authoritative {
		now := time.Now().UTC()
		_ = l.recordSinkMetricV8(context.Background(), binding, sinkMetricV8Input{
			kind: sinkMetricV8CircuitState, valueInt: 0,
			sinkKind: safeSinkHealthDimension(kind), sinkName: safeSinkHealthDimension(sinkName),
			action: string(ActionSinkRestored), timestamp: now,
		})
		_ = l.emitSinkHealthV8(context.Background(), binding, sinkHealthV8Occurrence{
			family: sinkHealthV8Restored, action: ActionSinkRestored, phase: "circuit",
			outcome: observability.OutcomeCompleted, severity: "INFO",
			subsystem: safeSinkHealthDimension(sinkName), healthState: "restored",
			errorCode: observability.Absent[string](), durableHealthTransition: true,
			timestamp: now,
		})
		return
	}
	_ = l.LogActivity(ActivityInput{
		Actor:          "defenseclaw",
		Action:         ActionSinkRestored,
		TargetType:     "sink",
		TargetID:       sinkName,
		Reason:         "sink delivery succeeded after open circuit",
		Before:         map[string]any{"circuit": "open", "sink_kind": kind},
		After:          map[string]any{"circuit": "closed", "sink_kind": kind},
		Severity:       "INFO",
		SkipSinkFanout: true,
	})
}
