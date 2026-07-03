// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"context"
	"encoding/json"
	"fmt"
	"math"
	"net/http"
	"strings"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/audit"
	"github.com/defenseclaw/defenseclaw/internal/gatewaylog"
	"github.com/defenseclaw/defenseclaw/internal/observability"
	"github.com/defenseclaw/defenseclaw/internal/observability/pipeline"
	"github.com/defenseclaw/defenseclaw/internal/observability/router"
	observabilityruntime "github.com/defenseclaw/defenseclaw/internal/observability/runtime"
	"github.com/defenseclaw/defenseclaw/internal/version"
	"github.com/google/uuid"
	"go.opentelemetry.io/otel/trace"
)

// isDefenseClawSelfExport recognizes only the markers emitted by DefenseClaw's
// own v8 OTLP exporters. Such a batch is acknowledged and dropped without
// producing another ingest record; emitting a rejection would itself be routed
// back to the same destination and recreate the loop.
func isDefenseClawSelfExport(body []byte, signal otelIngestSignal) bool {
	switch signal {
	case otelSignalLogs:
		var envelope struct {
			ResourceLogs []struct {
				ScopeLogs []struct {
					LogRecords []struct {
						Attributes []otlpAttribute `json:"attributes"`
					} `json:"logRecords"`
				} `json:"scopeLogs"`
			} `json:"resourceLogs"`
		}
		if json.Unmarshal(body, &envelope) != nil {
			return false
		}
		total, self := 0, 0
		for _, resource := range envelope.ResourceLogs {
			for _, scope := range resource.ScopeLogs {
				for _, record := range scope.LogRecords {
					total++
					attributes := otlpAttributesToMap(record.Attributes)
					bucket := observability.Bucket(otlpString(attributes, "defenseclaw.bucket"))
					eventName := observability.EventName(otlpString(attributes, "defenseclaw.event.name"))
					if otlpString(attributes, "defenseclaw.record.id") != "" &&
						observability.IsBucket(bucket) &&
						otlpString(attributes, "defenseclaw.signal") == string(observability.SignalLogs) &&
						observability.IsRegisteredEventNameForSignal(observability.SignalLogs, eventName) {
						self++
					}
				}
			}
		}
		return total > 0 && self == total
	case otelSignalTraces:
		var envelope struct {
			ResourceSpans []struct {
				Resource struct {
					Attributes []otlpAttribute `json:"attributes"`
				} `json:"resource"`
				ScopeSpans []struct {
					Spans []struct {
						Attributes []otlpAttribute `json:"attributes"`
					} `json:"spans"`
				} `json:"scopeSpans"`
			} `json:"resourceSpans"`
		}
		if json.Unmarshal(body, &envelope) != nil {
			return false
		}
		total, self := 0, 0
		for _, resource := range envelope.ResourceSpans {
			resourceAttributes := otlpAttributesToMap(resource.Resource.Attributes)
			ownedResource := otlpString(resourceAttributes, "defenseclaw.instance.id") != ""
			for _, scope := range resource.ScopeSpans {
				for _, span := range scope.Spans {
					total++
					attributes := otlpAttributesToMap(span.Attributes)
					bucket := observability.Bucket(otlpString(attributes, "defenseclaw.bucket"))
					_, hasGeneration := attributes["defenseclaw.config.generation"]
					if ownedResource && observability.IsBucket(bucket) && hasGeneration {
						self++
					}
				}
			}
		}
		return total > 0 && self == total
	case otelSignalMetrics:
		var envelope struct {
			ResourceMetrics []struct {
				Resource struct {
					Attributes []otlpAttribute `json:"attributes"`
				} `json:"resource"`
				ScopeMetrics []struct {
					Metrics []struct {
						Name string `json:"name"`
					} `json:"metrics"`
				} `json:"scopeMetrics"`
			} `json:"resourceMetrics"`
		}
		if json.Unmarshal(body, &envelope) != nil {
			return false
		}
		total, self := 0, 0
		for _, resource := range envelope.ResourceMetrics {
			resourceAttributes := otlpAttributesToMap(resource.Resource.Attributes)
			ownedResource := otlpString(resourceAttributes, "defenseclaw.instance.id") != ""
			for _, scope := range resource.ScopeMetrics {
				for _, metric := range scope.Metrics {
					total++
					if ownedResource && strings.HasPrefix(metric.Name, "defenseclaw.") &&
						observability.IsRegisteredEventNameForSignal(
							observability.SignalMetrics, observability.EventName(metric.Name),
						) {
						self++
					}
				}
			}
		}
		return total > 0 && self == total
	}
	return false
}

type otlpIngestV8ErrorCode string

const (
	otlpIngestV8InvalidMetadata otlpIngestV8ErrorCode = "invalid_metadata"
	otlpIngestV8InvalidGraph    otlpIngestV8ErrorCode = "invalid_graph"
	otlpIngestV8BuildFailed     otlpIngestV8ErrorCode = "record_build_failed"
	otlpIngestV8EmitFailed      otlpIngestV8ErrorCode = "emit_failed"
)

// otlpIngestV8Error is deliberately bounded and content-free. Decode errors,
// payload bytes, configured endpoints, and storage errors never cross this
// receiver boundary.
type otlpIngestV8Error struct{ code otlpIngestV8ErrorCode }

func (err *otlpIngestV8Error) Error() string {
	if err == nil {
		return "canonical OTLP ingest failed"
	}
	return "canonical OTLP ingest failed: " + string(err.code)
}

type otlpIngestV8Event struct {
	producerKey     observability.ProducerKey
	eventName       observability.EventName
	rawSeverity     string
	mandatoryFacts  observability.MandatoryFacts
	phase           string
	outcome         observability.Outcome
	signal          otelIngestSignal
	connector       string
	payloadFormat   string
	reasonClass     string
	records         int64
	resources       int64
	wireBytes       int64
	normalizedBytes int64
	latency         time.Duration
	correlation     observability.Correlation
}

func (a *APIServer) bindOTLPObservabilityRuntime(emitter sidecarRuntimeEmitter) {
	// Deliberately package-private during P3: the receiver summary is canonical,
	// but token/duration metric derivation still belongs to the legacy provider.
	// Sidecar production wiring remains disabled until those metrics bind to the
	// same v8 graph, otherwise activating this seam would silently break the
	// PR412 local-observability dashboards.
	if a == nil {
		return
	}
	a.observabilityV8 = emitter
}

func (a *APIServer) hasOTLPObservabilityRuntime() bool {
	return a != nil && a.observabilityV8 != nil
}

func otlpIngestProducerKey(signal otelIngestSignal) observability.ProducerKey {
	switch signal {
	case otelSignalLogs:
		return observability.ProducerKey(audit.ActionOTelIngestLogs)
	case otelSignalMetrics:
		return observability.ProducerKey(audit.ActionOTelIngestMetrics)
	case otelSignalTraces:
		return observability.ProducerKey(audit.ActionOTelIngestTraces)
	default:
		return observability.ProducerKey(audit.ActionOTelIngestMalformed)
	}
}

func otlpIngestCorrelation(ctx context.Context, connector string) observability.Correlation {
	identity := AgentIdentityFromContext(ctx)
	traceID := TraceIDFromContext(ctx)
	spanID := ""
	if span := trace.SpanFromContext(ctx); span != nil && span.SpanContext().IsValid() {
		if traceID == "" {
			traceID = span.SpanContext().TraceID().String()
		}
		spanID = span.SpanContext().SpanID().String()
	}
	return observability.Correlation{
		RunID:             gatewaylog.ProcessRunID(),
		RequestID:         RequestIDFromContext(ctx),
		SessionID:         SessionIDFromContext(ctx),
		TraceID:           traceID,
		SpanID:            spanID,
		AgentID:           identity.AgentID,
		AgentInstanceID:   identity.AgentInstanceID,
		ConnectorID:       connector,
		SidecarInstanceID: gatewaylog.SidecarInstanceID(),
	}
}

func (a *APIServer) emitOTLPIngestV8(
	ctx context.Context,
	event otlpIngestV8Event,
) (pipeline.LocalLogOutcome, error) {
	if a == nil || a.observabilityV8 == nil || ctx == nil {
		return pipeline.LocalLogOutcome{}, &otlpIngestV8Error{code: otlpIngestV8InvalidGraph}
	}
	classification := observability.ClassificationContext{
		EventName:      event.eventName,
		RawSeverity:    event.rawSeverity,
		MandatoryFacts: event.mandatoryFacts,
	}
	metadata, err := router.NewClassifiedLogMetadata(
		observability.ProducerAuditAction,
		event.producerKey,
		classification,
		observability.SourceOTelReceiver,
		event.connector,
		event.producerKey,
	)
	if err != nil {
		return pipeline.LocalLogOutcome{}, &otlpIngestV8Error{code: otlpIngestV8InvalidMetadata}
	}

	outcome, emitErr := a.observabilityV8.Emit(ctx, metadata, func(
		snapshot observabilityruntime.EmitContext,
		admission router.Admission,
	) (observability.Record, error) {
		if snapshot.Generation() > math.MaxInt64 {
			return observability.Record{}, &otlpIngestV8Error{code: otlpIngestV8BuildFailed}
		}
		builder, buildErr := observability.NewRecordBuilder(
			observability.ClockFunc(func() time.Time { return time.Now().UTC() }),
			observability.OccurrenceIDGeneratorFunc(func() (string, error) { return uuid.NewString(), nil }),
		)
		if buildErr != nil {
			return observability.Record{}, &otlpIngestV8Error{code: otlpIngestV8BuildFailed}
		}
		provenance := observability.Provenance{
			Producer:              "defenseclaw",
			BinaryVersion:         version.Current().BinaryVersion,
			RegistrySchemaVersion: observability.CurrentRecordSchemaVersion,
			ConfigGeneration:      int64(snapshot.Generation()),
			ConfigDigest:          snapshot.Digest(),
		}
		if admission == router.AdmissionFloor {
			return builder.BuildMandatoryFloorLog(observability.MandatoryFloorLogInput{
				ProducerKind:          observability.ProducerAuditAction,
				ProducerKey:           event.producerKey,
				ClassificationContext: classification,
				Source:                observability.SourceOTelReceiver,
				Connector:             event.connector,
				Action:                string(event.producerKey),
				Phase:                 event.phase,
				Outcome:               event.outcome,
				Correlation:           event.correlation,
				Provenance:            provenance,
			})
		}
		if admission != router.AdmissionOrdinary {
			return observability.Record{}, &otlpIngestV8Error{code: otlpIngestV8BuildFailed}
		}
		body := map[string]any{
			"protocol":                "otlp_http",
			"protocol_schema_version": "otlp_v1",
			"signal":                  string(event.signal),
			"source_connector":        event.connector,
			"payload_format":          event.payloadFormat,
			"normalization_result":    "normalized",
			"record_count":            event.records,
			"resource_count":          event.resources,
			"wire_bytes":              event.wireBytes,
			"normalized_bytes":        event.normalizedBytes,
			"latency_ms":              event.latency.Milliseconds(),
		}
		fieldClasses := map[string]observability.FieldClass{}
		for key := range body {
			fieldClasses["/"+key] = observability.FieldClassMetadata
		}
		if event.reasonClass != "" {
			body["normalization_result"] = "rejected"
			body["rejection_reason_class"] = event.reasonClass
			fieldClasses["/rejection_reason_class"] = observability.FieldClassMetadata
		}
		return builder.BuildClassifiedLog(observability.ClassifiedLogInput{
			ProducerKind:          observability.ProducerAuditAction,
			ProducerKey:           event.producerKey,
			ClassificationContext: classification,
			Source:                observability.SourceOTelReceiver,
			Connector:             event.connector,
			Action:                string(event.producerKey),
			Phase:                 event.phase,
			Outcome:               event.outcome,
			Correlation:           event.correlation,
			Provenance:            provenance,
			Body:                  body,
			FieldClasses:          fieldClasses,
		})
	})
	if emitErr != nil {
		return pipeline.LocalLogOutcome{}, &otlpIngestV8Error{code: otlpIngestV8EmitFailed}
	}
	return outcome, nil
}

func (a *APIServer) emitOTLPBatchAcceptedV8(
	ctx context.Context,
	signal otelIngestSignal,
	connector string,
	payloadFormat string,
	stats otelIngestStats,
	wireBytes int64,
	normalizedBytes int64,
	started time.Time,
) (pipeline.LocalLogOutcome, error) {
	return a.emitOTLPIngestV8(ctx, otlpIngestV8Event{
		producerKey:     otlpIngestProducerKey(signal),
		eventName:       "telemetry.batch.accepted",
		rawSeverity:     "INFO",
		phase:           "admission",
		outcome:         observability.OutcomeCompleted,
		signal:          signal,
		connector:       connector,
		payloadFormat:   payloadFormat,
		records:         stats.Records,
		resources:       stats.Resources,
		wireBytes:       wireBytes,
		normalizedBytes: normalizedBytes,
		latency:         time.Since(started),
		correlation:     otlpIngestCorrelation(ctx, connector),
	})
}

func (a *APIServer) emitOTLPBatchRejectedV8(
	ctx context.Context,
	signal otelIngestSignal,
	connector string,
	payloadFormat string,
	reasonClass string,
	wireBytes int64,
	started time.Time,
) {
	if !a.hasOTLPObservabilityRuntime() {
		return
	}
	_, err := a.emitOTLPIngestV8(ctx, otlpIngestV8Event{
		producerKey: observability.ProducerKey(audit.ActionOTelIngestMalformed),
		eventName:   "telemetry.batch.rejected",
		rawSeverity: "WARN",
		mandatoryFacts: observability.MandatoryFacts{
			SchemaValidationFailure: true,
		},
		phase:         "normalization",
		outcome:       observability.OutcomeRejected,
		signal:        signal,
		connector:     connector,
		payloadFormat: payloadFormat,
		reasonClass:   reasonClass,
		wireBytes:     wireBytes,
		latency:       time.Since(started),
		correlation:   otlpIngestCorrelation(ctx, connector),
	})
	if err != nil {
		fmt.Fprintln(otelIngestLogSink(), "[otel-ingest] canonical rejection persistence failed")
	}
}

func otlpSignalFromRequestPath(path string) (otelIngestSignal, bool) {
	switch {
	case path == "/v1/logs" || strings.HasSuffix(path, "/v1/logs"):
		return otelSignalLogs, true
	case path == "/v1/metrics" || strings.HasSuffix(path, "/v1/metrics"):
		return otelSignalMetrics, true
	case path == "/v1/traces" || strings.HasSuffix(path, "/v1/traces"):
		return otelSignalTraces, true
	default:
		return "", false
	}
}

func otlpAuthFailureConnector(r *http.Request) string {
	if r == nil {
		return "unknown"
	}
	if _, source, ok := parseOTLPPathToken(r.URL.Path); ok {
		return normalizeConnectorTelemetrySource(source)
	}
	// The source header is unauthenticated on this path and therefore cannot be
	// used as canonical provenance.
	return "unknown"
}

func (a *APIServer) emitOTLPAuthenticationFailureV8(
	ctx context.Context,
	r *http.Request,
	reasonClass string,
) {
	if !a.hasOTLPObservabilityRuntime() || r == nil {
		return
	}
	signal, ok := otlpSignalFromRequestPath(r.URL.Path)
	if !ok {
		return
	}
	connector := otlpAuthFailureConnector(r)
	_, err := a.emitOTLPIngestV8(ctx, otlpIngestV8Event{
		producerKey: observability.ProducerKey(audit.ActionOTelIngestMalformed),
		eventName:   "telemetry.authentication.failed",
		rawSeverity: "WARN",
		mandatoryFacts: observability.MandatoryFacts{
			ProtectedBoundaryAuthFailure: true,
		},
		phase:         "authentication",
		outcome:       observability.OutcomeRejected,
		signal:        signal,
		connector:     connector,
		payloadFormat: "unknown",
		reasonClass:   reasonClass,
		correlation:   otlpIngestCorrelation(ctx, connector),
	})
	if err != nil {
		fmt.Fprintln(otelIngestLogSink(), "[otel-ingest] canonical authentication failure persistence failed")
	}
}
