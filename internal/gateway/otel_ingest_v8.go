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
	"github.com/defenseclaw/defenseclaw/internal/telemetry"
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
				Resource struct {
					Attributes []otlpAttribute `json:"attributes"`
				} `json:"resource"`
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
			resourceAttributes := otlpAttributesToMap(resource.Resource.Attributes)
			ownedResource := otlpString(resourceAttributes, "defenseclaw.instance.id") != ""
			for _, scope := range resource.ScopeLogs {
				for _, record := range scope.LogRecords {
					total++
					attributes := otlpAttributesToMap(record.Attributes)
					bucket := observability.Bucket(otlpString(attributes, "defenseclaw.bucket"))
					eventName := observability.EventName(otlpString(attributes, "defenseclaw.event.name"))
					if ownedResource && otlpString(attributes, "defenseclaw.record.id") != "" &&
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
					family := observability.EventName(otlpString(attributes, "defenseclaw.span.family"))
					_, hasGeneration := attributes["defenseclaw.config.generation"]
					if ownedResource && observability.IsBucket(bucket) && hasGeneration &&
						observability.IsRegisteredEventNameForSignal(observability.SignalTraces, family) {
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

// otlpGeneratedMetricRuntime is deliberately narrower than the log emitter.
// A receiver binding is not considered metric-capable merely because it can
// persist logs: derived ingest and GenAI metrics must remain pinned to the
// same generation-owned Runtime that performs collection gating and
// destination projection.
type otlpGeneratedMetricRuntime interface {
	RecordGeneratedMetric(
		context.Context,
		observability.EventName,
		observabilityruntime.GeneratedMetricBuilder,
	) (telemetry.V8MetricRecordResult, error)
}

func (a *APIServer) bindOTLPObservabilityRuntime(emitter sidecarRuntimeEmitter) {
	// Deliberately package-private: production binds the process-owned Runtime,
	// while focused tests may bind a minimal log emitter. Derived metrics require
	// the additional otlpGeneratedMetricRuntime capability and never fall back
	// to the legacy process provider when it is absent.
	if a == nil {
		return
	}
	a.observabilityV8Mu.Lock()
	a.observabilityV8 = emitter
	a.observabilityV8Mu.Unlock()
}

func (a *APIServer) hasOTLPObservabilityRuntime() bool {
	return a != nil && a.observabilityV8RuntimeEmitter() != nil
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
	if a == nil || ctx == nil {
		return pipeline.LocalLogOutcome{}, &otlpIngestV8Error{code: otlpIngestV8InvalidGraph}
	}
	emitter := a.observabilityV8RuntimeEmitter()
	if emitter == nil {
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

	outcome, emitErr := emitter.Emit(ctx, metadata, func(
		snapshot observabilityruntime.EmitContext,
		admission router.Admission,
	) (observability.Record, error) {
		if snapshot.Generation() > math.MaxInt64 {
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
			builder, buildErr := observability.NewRecordBuilder(
				observability.ClockFunc(func() time.Time { return time.Now().UTC() }),
				observability.OccurrenceIDGeneratorFunc(func() (string, error) { return uuid.NewString(), nil }),
			)
			if buildErr != nil {
				return observability.Record{}, &otlpIngestV8Error{code: otlpIngestV8BuildFailed}
			}
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
		familyBuilder, buildErr := observability.NewFamilyBuilder(
			observability.ClockFunc(func() time.Time { return time.Now().UTC() }),
			observability.OccurrenceIDGeneratorFunc(func() (string, error) { return uuid.NewString(), nil }),
		)
		if buildErr != nil {
			return observability.Record{}, &otlpIngestV8Error{code: otlpIngestV8BuildFailed}
		}
		envelope := observability.FamilyEnvelopeInput{
			Source: observability.SourceOTelReceiver, Connector: event.connector,
			Action: string(event.producerKey), Phase: event.phase,
			Correlation: event.correlation,
			Provenance: observability.FamilyProvenanceInput{
				Producer: "defenseclaw", BinaryVersion: version.Current().BinaryVersion,
				ConfigGeneration: int64(snapshot.Generation()), ConfigDigest: snapshot.Digest(),
			},
		}
		return buildOTLPIngestGeneratedLog(familyBuilder, envelope, event)
	})
	if emitErr != nil {
		return pipeline.LocalLogOutcome{}, &otlpIngestV8Error{code: otlpIngestV8EmitFailed}
	}
	return outcome, nil
}

func buildOTLPIngestGeneratedLog(
	builder *observability.FamilyBuilder,
	envelope observability.FamilyEnvelopeInput,
	event otlpIngestV8Event,
) (observability.Record, error) {
	if builder == nil || event.records < 0 || event.resources < 0 || event.wireBytes < 0 ||
		event.normalizedBytes < 0 {
		return observability.Record{}, &otlpIngestV8Error{code: otlpIngestV8BuildFailed}
	}
	latencyMillis := event.latency.Milliseconds()
	if latencyMillis < 0 {
		latencyMillis = 0
	}
	payloadFormat := observability.Absent[string]()
	if event.payloadFormat == "json" || event.payloadFormat == "protobuf" {
		payloadFormat = observability.Present(event.payloadFormat)
	}
	resourceCount := observability.Absent[int64]()
	wireBytes := observability.Absent[int64]()
	normalizedBytes := observability.Absent[int64]()
	if event.reasonClass == "" {
		resourceCount = observability.Present(event.resources)
		wireBytes = observability.Present(event.wireBytes)
		normalizedBytes = observability.Present(event.normalizedBytes)
	} else if event.wireBytes > 0 {
		// A rejected body has a measured wire size only after ReadAll
		// completed. Resource and normalized sizes do not exist until strict
		// decoding succeeds and must not be fabricated as zero.
		wireBytes = observability.Present(event.wireBytes)
	}
	latency := observability.Present(latencyMillis)
	reasonClass := observability.Absent[string]()
	if event.reasonClass != "" {
		reasonClass = observability.Present(event.reasonClass)
	}
	severity := observability.Present(observability.SeverityInfo)
	logLevel := observability.Present(observability.LogLevelInfo)
	if event.eventName == observability.EventName(observability.TelemetryEventTelemetryBatchRejected) ||
		event.eventName == observability.EventName(observability.TelemetryEventTelemetryAuthenticationFailed) {
		severity = observability.Present(observability.SeverityMedium)
		logLevel = observability.Present(observability.LogLevelWarn)
	}
	switch event.eventName {
	case observability.EventName(observability.TelemetryEventTelemetryBatchAccepted):
		return builder.BuildLogTelemetryBatchAccepted(observability.LogTelemetryBatchAcceptedInput{
			Envelope: envelope, Severity: severity, LogLevel: logLevel, Outcome: event.outcome,
			DefenseClawTelemetrySignal: string(event.signal), DefenseClawTelemetryRecordCount: event.records,
			DefenseClawTelemetryByteCount: event.wireBytes, DefenseClawTelemetryPayloadFormat: payloadFormat,
			DefenseClawTelemetryResourceCount: resourceCount, DefenseClawTelemetryWireBytes: wireBytes,
			DefenseClawTelemetryNormalizedBytes: normalizedBytes, DefenseClawTelemetryLatencyMs: latency,
		})
	case observability.EventName(observability.TelemetryEventTelemetryBatchRejected):
		return builder.BuildLogTelemetryBatchRejected(observability.LogTelemetryBatchRejectedInput{
			Envelope: envelope, Severity: severity, LogLevel: logLevel, Outcome: event.outcome,
			DefenseClawTelemetrySignal: string(event.signal), DefenseClawTelemetryRecordCount: event.records,
			DefenseClawTelemetryByteCount: event.wireBytes, DefenseClawTelemetryPayloadFormat: payloadFormat,
			DefenseClawTelemetryResourceCount: resourceCount, DefenseClawTelemetryWireBytes: wireBytes,
			DefenseClawTelemetryNormalizedBytes: normalizedBytes, DefenseClawTelemetryLatencyMs: latency,
			DefenseClawTelemetryRejectionReasonClass: reasonClass,
			MandatorySchemaValidationFailure:         event.mandatoryFacts.SchemaValidationFailure,
		})
	case observability.EventName(observability.TelemetryEventTelemetryAuthenticationFailed):
		return builder.BuildLogTelemetryAuthenticationFailed(observability.LogTelemetryAuthenticationFailedInput{
			Envelope: envelope, Severity: severity, LogLevel: logLevel, Outcome: event.outcome,
			DefenseClawTelemetrySignal: string(event.signal), DefenseClawTelemetryRecordCount: event.records,
			DefenseClawTelemetryByteCount: event.wireBytes, DefenseClawTelemetryPayloadFormat: payloadFormat,
			DefenseClawTelemetryResourceCount: resourceCount, DefenseClawTelemetryWireBytes: wireBytes,
			DefenseClawTelemetryNormalizedBytes: normalizedBytes, DefenseClawTelemetryLatencyMs: latency,
			DefenseClawTelemetryRejectionReasonClass: reasonClass,
			MandatoryProtectedBoundaryAuthFailure:    event.mandatoryFacts.ProtectedBoundaryAuthFailure,
		})
	default:
		return observability.Record{}, &otlpIngestV8Error{code: otlpIngestV8BuildFailed}
	}
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
	a.recordOTLPBatchMetricsV8(ctx, signal, connector, "malformed", 0, wireBytes)
}

type otlpIngestV8MetricSummary struct {
	recorded    int
	unsupported int
	failed      int
}

func (summary *otlpIngestV8MetricSummary) add(other otlpIngestV8MetricSummary) {
	if summary == nil {
		return
	}
	summary.recorded += other.recorded
	summary.unsupported += other.unsupported
	summary.failed += other.failed
}

type otlpGeneratedMetricBuild func(
	*observability.FamilyBuilder,
	observability.FamilyEnvelopeInput,
) (observability.Record, error)

func (a *APIServer) recordOTLPGeneratedMetricV8(
	ctx context.Context,
	family observability.EventName,
	connector string,
	build otlpGeneratedMetricBuild,
) error {
	runtime, ok := a.observabilityV8RuntimeEmitter().(otlpGeneratedMetricRuntime)
	if !ok || runtime == nil || ctx == nil || build == nil {
		return &otlpIngestV8Error{code: otlpIngestV8InvalidGraph}
	}
	_, err := runtime.RecordGeneratedMetric(ctx, family, func(
		snapshot observabilityruntime.EmitContext,
	) (observability.Record, error) {
		if snapshot.Generation() > math.MaxInt64 {
			return observability.Record{}, &otlpIngestV8Error{code: otlpIngestV8BuildFailed}
		}
		builder, builderErr := observability.NewFamilyBuilder(
			observability.ClockFunc(func() time.Time { return time.Now().UTC() }),
			observability.OccurrenceIDGeneratorFunc(func() (string, error) { return uuid.NewString(), nil }),
		)
		if builderErr != nil {
			return observability.Record{}, &otlpIngestV8Error{code: otlpIngestV8BuildFailed}
		}
		envelope := observability.FamilyEnvelopeInput{
			Source: observability.SourceOTelReceiver, Connector: connector,
			Action: string(family), Phase: "admission",
			Correlation: otlpIngestCorrelation(ctx, connector),
			Provenance: observability.FamilyProvenanceInput{
				Producer: "defenseclaw", BinaryVersion: version.Current().BinaryVersion,
				ConfigGeneration: int64(snapshot.Generation()), ConfigDigest: snapshot.Digest(),
			},
		}
		return build(builder, envelope)
	})
	return err
}

func (a *APIServer) recordOTLPBatchMetricsV8(
	ctx context.Context,
	signal otelIngestSignal,
	connector string,
	result string,
	records int64,
	wireBytes int64,
) otlpIngestV8MetricSummary {
	summary := otlpIngestV8MetricSummary{}
	if !a.hasOTLPObservabilityRuntime() || records < 0 || wireBytes < 0 {
		return summary
	}
	metricSource := observability.Present(connector)
	metricSignal := observability.Present(string(signal))
	record := func(family observability.EventName, build otlpGeneratedMetricBuild) {
		if err := a.recordOTLPGeneratedMetricV8(ctx, family, connector, build); err != nil {
			summary.failed++
			return
		}
		summary.recorded++
	}
	record(observability.EventName(observability.TelemetryInstrumentDefenseClawOTelIngestRequests), func(
		builder *observability.FamilyBuilder, envelope observability.FamilyEnvelopeInput,
	) (observability.Record, error) {
		return builder.BuildMetricDefenseClawOTelIngestRequests(observability.MetricDefenseClawOTelIngestRequestsInput{
			Envelope: envelope, Value: 1, DefenseClawConnectorSource: metricSource,
			DefenseClawMetricResult: observability.Present(result), DefenseClawTelemetrySignal: metricSignal,
			DefenseClawMetricSource: metricSource,
		})
	})
	if result == "malformed" {
		record(observability.EventName(observability.TelemetryInstrumentDefenseClawOTelIngestMalformed), func(
			builder *observability.FamilyBuilder, envelope observability.FamilyEnvelopeInput,
		) (observability.Record, error) {
			return builder.BuildMetricDefenseClawOTelIngestMalformed(observability.MetricDefenseClawOTelIngestMalformedInput{
				Envelope: envelope, Value: 1, DefenseClawConnectorSource: metricSource,
				DefenseClawTelemetrySignal: metricSignal, DefenseClawMetricSource: metricSource,
			})
		})
	}
	if records > 0 {
		record(observability.EventName(observability.TelemetryInstrumentDefenseClawOTelIngestRecords), func(
			builder *observability.FamilyBuilder, envelope observability.FamilyEnvelopeInput,
		) (observability.Record, error) {
			return builder.BuildMetricDefenseClawOTelIngestRecords(observability.MetricDefenseClawOTelIngestRecordsInput{
				Envelope: envelope, Value: records, DefenseClawConnectorSource: metricSource,
				DefenseClawTelemetrySignal: metricSignal, DefenseClawMetricSource: metricSource,
			})
		})
	}
	if wireBytes > 0 {
		record(observability.EventName(observability.TelemetryInstrumentDefenseClawOTelIngestBytes), func(
			builder *observability.FamilyBuilder, envelope observability.FamilyEnvelopeInput,
		) (observability.Record, error) {
			return builder.BuildMetricDefenseClawOTelIngestBytes(observability.MetricDefenseClawOTelIngestBytesInput{
				Envelope: envelope, Value: wireBytes, DefenseClawConnectorSource: metricSource,
				DefenseClawTelemetrySignal: metricSignal, DefenseClawMetricSource: metricSource,
			})
		})
	}
	record(observability.EventName(observability.TelemetryInstrumentDefenseClawOTelIngestLastSeenTs), func(
		builder *observability.FamilyBuilder, envelope observability.FamilyEnvelopeInput,
	) (observability.Record, error) {
		return builder.BuildMetricDefenseClawOTelIngestLastSeenTs(observability.MetricDefenseClawOTelIngestLastSeenTsInput{
			Envelope: envelope, Value: float64(time.Now().Unix()), DefenseClawConnectorSource: metricSource,
			DefenseClawTelemetrySignal: metricSignal, DefenseClawMetricSource: metricSource,
		})
	})
	if summary.failed > 0 {
		fmt.Fprintln(otelIngestLogSink(), "[otel-ingest] canonical ingest metric delivery incomplete")
	}
	return summary
}

func (a *APIServer) recordOTLPGenAIMetricsV8(
	ctx context.Context,
	body []byte,
	signal otelIngestSignal,
	connector string,
	sessionID string,
) otlpIngestV8MetricSummary {
	summary := otlpIngestV8MetricSummary{}
	for _, candidate := range extractOTLPTokenUsage(body, signal, connector) {
		if candidate.cumulative {
			var ok bool
			candidate, ok = a.deltaOTLPCumulativeTokenUsage(candidate)
			if !ok {
				continue
			}
		}
		resolvedSessionID := firstNonEmpty(candidate.sessionID, sessionID, SessionIDFromContext(ctx))
		agentName := candidate.agentName
		agentID := SharedAgentRegistry().AgentID()
		if snapshot, ok := a.hookLifecycleSnapshot(connector, resolvedSessionID, ""); ok {
			agentName = firstNonEmpty(snapshot.AgentName, agentName)
			agentID = firstNonEmpty(snapshot.AgentID, agentID)
		}
		metricSummary := a.recordOTLPTokenMetricV8(ctx, connector, candidate, agentName, agentID, resolvedSessionID)
		summary.add(metricSummary)
		if signal == otelSignalLogs {
			a.rememberOTLPHookLLMTokenUsage(connector, resolvedSessionID, candidate)
		}
	}
	for _, duration := range extractOTLPOperationDurations(body, signal, connector) {
		summary.add(a.recordOTLPDurationMetricV8(
			ctx, connector, duration, SharedAgentRegistry().AgentID(),
		))
	}
	if summary.unsupported > 0 {
		fmt.Fprintln(otelIngestLogSink(), "[otel-ingest] canonical derived metric fact unsupported")
	}
	if summary.failed > 0 {
		fmt.Fprintln(otelIngestLogSink(), "[otel-ingest] canonical derived metric delivery incomplete")
	}
	return summary
}

func (a *APIServer) recordOTLPTokenMetricV8(
	ctx context.Context,
	connector string,
	usage otelTokenUsage,
	agentName string,
	agentID string,
	sessionID string,
) otlpIngestV8MetricSummary {
	if usage.tokens <= 0 {
		return otlpIngestV8MetricSummary{}
	}
	switch usage.tokenType {
	case "input", "output", "cacheRead", "cacheCreation":
		// Exact source-backed values registered by the generated schema. The
		// cache categories intentionally remain distinct from input tokens for
		// PR #412 query and provider-cost fidelity.
	default:
		return otlpIngestV8MetricSummary{unsupported: 1}
	}
	operation := canonicalOTLPOperation(usage.operationName)
	if operation == "" {
		return otlpIngestV8MetricSummary{unsupported: 1}
	}
	err := a.recordOTLPGeneratedMetricV8(
		ctx,
		observability.EventName(observability.TelemetryInstrumentGenAIClientTokenUsage),
		connector,
		func(builder *observability.FamilyBuilder, envelope observability.FamilyEnvelopeInput) (observability.Record, error) {
			return builder.BuildMetricGenAIClientTokenUsage(observability.MetricGenAIClientTokenUsageInput{
				Envelope: envelope, Value: float64(usage.tokens),
				GenAIAgentID:        optionalOTLPMetricIdentifier(agentID),
				GenAIAgentName:      optionalOTLPMetricIdentifier(agentName),
				GenAIConversationID: optionalOTLPMetricIdentifier(sessionID),
				GenAIOperationName:  observability.Present(operation),
				GenAIProviderName:   observability.Present(telemetry.NormalizeGenAIProviderLabel(usage.providerName)),
				GenAIRequestModel:   observability.Present(telemetry.NormalizeModelLabel(usage.model)),
				GenAITokenType:      observability.Present(usage.tokenType),
			})
		},
	)
	if err != nil {
		return otlpIngestV8MetricSummary{failed: 1}
	}
	return otlpIngestV8MetricSummary{recorded: 1}
}

func (a *APIServer) recordOTLPDurationMetricV8(
	ctx context.Context,
	connector string,
	duration otelLLMDuration,
	agentID string,
) otlpIngestV8MetricSummary {
	if duration.durationSeconds <= 0 || math.IsNaN(duration.durationSeconds) || math.IsInf(duration.durationSeconds, 0) {
		return otlpIngestV8MetricSummary{}
	}
	operation := canonicalOTLPOperation(duration.operationName)
	if operation == "" {
		return otlpIngestV8MetricSummary{unsupported: 1}
	}
	err := a.recordOTLPGeneratedMetricV8(
		ctx,
		observability.EventName(observability.TelemetryInstrumentGenAIClientOperationDuration),
		connector,
		func(builder *observability.FamilyBuilder, envelope observability.FamilyEnvelopeInput) (observability.Record, error) {
			return builder.BuildMetricGenAIClientOperationDuration(observability.MetricGenAIClientOperationDurationInput{
				Envelope: envelope, Value: duration.durationSeconds,
				GenAIAgentID:       optionalOTLPMetricIdentifier(agentID),
				GenAIAgentName:     optionalOTLPMetricIdentifier(duration.agentName),
				GenAIOperationName: observability.Present(operation),
				GenAIProviderName:  observability.Present(telemetry.NormalizeGenAIProviderLabel(duration.providerName)),
				GenAIRequestModel:  observability.Present(telemetry.NormalizeModelLabel(duration.model)),
			})
		},
	)
	if err != nil {
		return otlpIngestV8MetricSummary{failed: 1}
	}
	return otlpIngestV8MetricSummary{recorded: 1}
}

func canonicalOTLPOperation(value string) string {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "chat", "completion", "completions", "responses", "response", "generate", "generation", "chat.completions":
		return "chat"
	case "embedding", "embeddings", "embed":
		return "embeddings"
	case "tool", "tool-call", "tool_call", "tool-result", "tool_result", "execute-tool", "execute_tool":
		return "execute_tool"
	case "create_agent", "create_memory", "create_memory_store", "delete_memory", "delete_memory_store",
		"generate_content", "invoke_agent", "invoke_workflow", "plan", "retrieval", "search_memory",
		"text_completion", "update_memory", "upsert_memory":
		return strings.ToLower(strings.TrimSpace(value))
	default:
		return ""
	}
}

func optionalOTLPMetricIdentifier(value string) observability.Optional[string] {
	value = strings.TrimSpace(value)
	if len(value) == 0 || len(value) > 256 || !isOTLPMetricIdentifierByte(value[0], true) {
		return observability.Absent[string]()
	}
	for index := 1; index < len(value); index++ {
		if !isOTLPMetricIdentifierByte(value[index], false) {
			return observability.Absent[string]()
		}
	}
	return observability.Present(value)
}

func isOTLPMetricIdentifierByte(value byte, first bool) bool {
	alphanumeric := value >= 'A' && value <= 'Z' || value >= 'a' && value <= 'z' || value >= '0' && value <= '9'
	if first {
		return alphanumeric
	}
	return alphanumeric || value == '.' || value == '_' || value == ':' || value == '/' || value == '-'
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
