// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// SPDX-License-Identifier: Apache-2.0

package audit

import (
	"context"
	"fmt"
	"math"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/observability"
	"github.com/defenseclaw/defenseclaw/internal/observability/router"
	"github.com/defenseclaw/defenseclaw/internal/version"
	"github.com/google/uuid"
)

// RuntimeV8GeneratedMetric is an opaque, audit-owned generated metric
// operation. Its fields are private so callers cannot substitute a handwritten
// family identity or builder. The runtime adapter still validates the returned
// record against the generated registry before recording it.
type RuntimeV8GeneratedMetric struct {
	family observability.EventName
	build  RuntimeV8MetricBuilder
}

// RuntimeV8MetricBuilder receives only the immutable generation/digest pair.
// It cannot access the runtime graph or telemetry provider.
type RuntimeV8MetricBuilder func(RuntimeV8BuildContext) (observability.Record, error)

// Family exposes the exact generated identity to the cycle-breaking runtime
// adapter. A zero value is invalid and is rejected by Build.
func (metric RuntimeV8GeneratedMetric) Family() observability.EventName { return metric.family }

// Build invokes the sealed generated-family callback.
func (metric RuntimeV8GeneratedMetric) Build(
	snapshot RuntimeV8BuildContext,
) (observability.Record, error) {
	if metric.family == "" || metric.build == nil {
		return observability.Record{}, fmt.Errorf("audit: generated metric operation is unavailable")
	}
	record, err := metric.build(snapshot)
	if err != nil {
		return observability.Record{}, err
	}
	if record.Signal() != observability.SignalMetrics || record.EventName() != metric.family {
		return observability.Record{}, fmt.Errorf("audit: generated metric identity mismatch")
	}
	return record, nil
}

// RuntimeV8MetricEmitter is the narrow optional metric capability implemented
// by the owned v8 runtime. It accepts only the opaque generated operation above;
// audit producers never receive a graph, provider, meter, or free-form metric
// recording API.
type RuntimeV8MetricEmitter interface {
	RecordRuntimeV8GeneratedMetric(context.Context, RuntimeV8GeneratedMetric) error
}

type sinkHealthV8Family uint8

const (
	sinkHealthV8Invalid sinkHealthV8Family = iota
	sinkHealthV8AuthenticationFailed
	sinkHealthV8AuthorizationDenied
	sinkHealthV8ExportFailed
	sinkHealthV8QueueFull
	sinkHealthV8Restored
)

type sinkHealthV8Occurrence struct {
	family                       sinkHealthV8Family
	action                       Action
	phase                        string
	outcome                      observability.Outcome
	severity                     string
	subsystem                    string
	healthState                  string
	errorCode                    observability.Optional[string]
	durableHealthTransition      bool
	protectedBoundaryAuthFailure bool
	timestamp                    time.Time
}

func (occurrence sinkHealthV8Occurrence) mandatory() bool {
	return occurrence.durableHealthTransition || occurrence.protectedBoundaryAuthFailure
}

func (occurrence sinkHealthV8Occurrence) eventName() observability.EventName {
	switch occurrence.family {
	case sinkHealthV8AuthenticationFailed:
		return observability.EventName(observability.TelemetryEventDestinationAuthenticationFailed)
	case sinkHealthV8AuthorizationDenied:
		return observability.EventName(observability.TelemetryEventDestinationAuthorizationDenied)
	case sinkHealthV8ExportFailed:
		return observability.EventName(observability.TelemetryEventDestinationExportFailed)
	case sinkHealthV8QueueFull:
		return observability.EventName(observability.TelemetryEventDestinationQueueFull)
	case sinkHealthV8Restored:
		return observability.EventName(observability.TelemetryEventSubsystemRestored)
	default:
		return ""
	}
}

// emitSinkHealthV8 emits exactly one generated platform-health log through the
// binding captured at the beginning of the sink occurrence. authoritative=true
// always suppresses legacy fallback, including a detached/unavailable runtime.
func (l *Logger) emitSinkHealthV8(
	ctx context.Context,
	binding runtimeV8Binding,
	occurrence sinkHealthV8Occurrence,
) error {
	if !binding.authoritative {
		return fmt.Errorf("audit: v8 sink health is not authoritative")
	}
	if binding.emitter == nil {
		return fmt.Errorf("audit: v8 sink health runtime is unavailable")
	}
	if ctx == nil {
		ctx = context.Background()
	}
	if occurrence.timestamp.IsZero() {
		occurrence.timestamp = time.Now().UTC()
	}
	eventName := occurrence.eventName()
	if eventName == "" || !observability.IsStableToken(occurrence.phase) ||
		!observability.IsStableToken(occurrence.subsystem) {
		return fmt.Errorf("audit: v8 sink health occurrence is invalid")
	}
	classification := observability.ClassificationContext{
		Bucket:      observability.BucketPlatformHealth,
		EventName:   eventName,
		RawSeverity: occurrence.severity,
		MandatoryFacts: observability.MandatoryFacts{
			DurableHealthTransition:      occurrence.durableHealthTransition,
			ProtectedBoundaryAuthFailure: occurrence.protectedBoundaryAuthFailure,
		},
	}
	metadata, err := router.NewClassifiedLogMetadata(
		observability.ProducerAuditAction,
		observability.ProducerKey(occurrence.action),
		classification,
		observability.SourceSystem,
		"",
		observability.ProducerKey(occurrence.action),
	)
	if err != nil {
		return fmt.Errorf("audit: classify v8 sink health: %w", err)
	}

	event := Event{
		Timestamp: occurrence.timestamp.UTC(), Action: string(occurrence.action),
		Target: occurrence.subsystem, Actor: "defenseclaw", Severity: occurrence.severity,
		RunID: currentRunID(), SidecarInstanceID: ProcessAgentInstanceID(),
	}
	stampAuditEventEnvelope(&event)
	result, err := binding.emitter.EmitRuntimeV8(ctx, metadata, func(
		snapshot RuntimeV8BuildContext,
		admission router.Admission,
	) (observability.Record, error) {
		if admission == router.AdmissionFloor {
			return buildRuntimeV8FloorRecord(
				event, snapshot, classification, observability.SourceSystem,
				occurrence.phase, occurrence.outcome, controlPlaneV8Correlation(event),
			)
		}
		if admission != router.AdmissionOrdinary {
			return observability.Record{}, fmt.Errorf("audit: v8 sink health has no admitted build path")
		}
		builder, envelope, severity, logLevel, buildErr := runtimeV8FamilyBuildState(
			event, snapshot, observability.SourceSystem, occurrence.phase,
			controlPlaneV8Correlation(event),
		)
		if buildErr != nil {
			return observability.Record{}, buildErr
		}
		record, buildErr := buildSinkHealthV8Family(
			builder, envelope, severity, logLevel, occurrence,
		)
		return verifyRuntimeV8Record(record, buildErr, event, occurrence.mandatory())
	})
	if err != nil {
		return fmt.Errorf("audit: emit v8 sink health: %w", err)
	}
	_, err = runtimeV8Disposition(result, occurrence.mandatory())
	return err
}

func buildSinkHealthV8Family(
	builder *observability.FamilyBuilder,
	envelope observability.FamilyEnvelopeInput,
	severity observability.Optional[observability.Severity],
	logLevel observability.Optional[observability.LogLevel],
	occurrence sinkHealthV8Occurrence,
) (observability.Record, error) {
	subsystem := occurrence.subsystem
	switch occurrence.family {
	case sinkHealthV8AuthenticationFailed:
		return builder.BuildLogDestinationAuthenticationFailed(
			observability.LogDestinationAuthenticationFailedInput{
				Envelope: envelope, Severity: severity, LogLevel: logLevel,
				Outcome: occurrence.outcome, DefenseClawHealthSubsystem: subsystem,
				DefenseClawHealthState:                occurrence.healthState,
				DefenseClawSchemaErrorCode:            occurrence.errorCode,
				MandatoryProtectedBoundaryAuthFailure: occurrence.protectedBoundaryAuthFailure,
			},
		)
	case sinkHealthV8AuthorizationDenied:
		return builder.BuildLogDestinationAuthorizationDenied(
			observability.LogDestinationAuthorizationDeniedInput{
				Envelope: envelope, Severity: severity, LogLevel: logLevel,
				Outcome: occurrence.outcome, DefenseClawHealthSubsystem: subsystem,
				DefenseClawHealthState:                occurrence.healthState,
				DefenseClawSchemaErrorCode:            occurrence.errorCode,
				MandatoryProtectedBoundaryAuthFailure: occurrence.protectedBoundaryAuthFailure,
			},
		)
	case sinkHealthV8ExportFailed:
		return builder.BuildLogDestinationExportFailed(observability.LogDestinationExportFailedInput{
			Envelope: envelope, Severity: severity, LogLevel: logLevel,
			Outcome: occurrence.outcome, DefenseClawHealthSubsystem: subsystem,
			DefenseClawHealthState:           occurrence.healthState,
			DefenseClawSchemaErrorCode:       occurrence.errorCode,
			MandatoryDurableHealthTransition: occurrence.durableHealthTransition,
		})
	case sinkHealthV8QueueFull:
		return builder.BuildLogDestinationQueueFull(observability.LogDestinationQueueFullInput{
			Envelope: envelope, Severity: severity, LogLevel: logLevel,
			Outcome: occurrence.outcome, DefenseClawHealthSubsystem: subsystem,
			DefenseClawHealthState:           occurrence.healthState,
			DefenseClawSchemaErrorCode:       occurrence.errorCode,
			MandatoryDurableHealthTransition: occurrence.durableHealthTransition,
		})
	case sinkHealthV8Restored:
		return builder.BuildLogSubsystemRestored(observability.LogSubsystemRestoredInput{
			Envelope: envelope, Severity: severity, LogLevel: logLevel,
			Outcome: occurrence.outcome, DefenseClawHealthSubsystem: subsystem,
			DefenseClawHealthState:           occurrence.healthState,
			DefenseClawSchemaErrorCode:       occurrence.errorCode,
			MandatoryDurableHealthTransition: occurrence.durableHealthTransition,
		})
	default:
		return observability.Record{}, fmt.Errorf("audit: unsupported v8 sink health family")
	}
}

type sinkMetricV8Kind uint8

const (
	sinkMetricV8Invalid sinkMetricV8Kind = iota
	sinkMetricV8BatchDelivered
	sinkMetricV8BatchDropped
	sinkMetricV8DeliveryLatency
	sinkMetricV8Failure
	sinkMetricV8CircuitState
)

type sinkMetricV8Input struct {
	kind       sinkMetricV8Kind
	valueInt   int64
	valueFloat float64
	sinkKind   string
	sinkName   string
	reason     string
	statusCode int64
	retryCount int64
	action     string
	timestamp  time.Time
}

func newSinkRuntimeV8GeneratedMetric(input sinkMetricV8Input) (RuntimeV8GeneratedMetric, error) {
	family := sinkMetricV8Family(input.kind)
	if family == "" || input.valueInt < 0 || input.valueFloat < 0 ||
		input.statusCode < 0 || input.statusCode > 999 || input.retryCount < 0 {
		return RuntimeV8GeneratedMetric{}, fmt.Errorf("audit: invalid generated sink metric input")
	}
	return RuntimeV8GeneratedMetric{
		family: family,
		build: func(snapshot RuntimeV8BuildContext) (observability.Record, error) {
			return buildSinkRuntimeV8GeneratedMetric(snapshot, input)
		},
	}, nil
}

func sinkMetricV8Family(kind sinkMetricV8Kind) observability.EventName {
	switch kind {
	case sinkMetricV8BatchDelivered:
		return observability.EventName(observability.TelemetryInstrumentDefenseClawAuditSinkBatchesDelivered)
	case sinkMetricV8BatchDropped:
		return observability.EventName(observability.TelemetryInstrumentDefenseClawAuditSinkBatchesDropped)
	case sinkMetricV8DeliveryLatency:
		return observability.EventName(observability.TelemetryInstrumentDefenseClawAuditSinkDeliveryLatency)
	case sinkMetricV8Failure:
		return observability.EventName(observability.TelemetryInstrumentDefenseClawAuditSinkFailures)
	case sinkMetricV8CircuitState:
		return observability.EventName(observability.TelemetryInstrumentDefenseClawAuditSinkCircuitState)
	default:
		return ""
	}
}

func buildSinkRuntimeV8GeneratedMetric(
	snapshot RuntimeV8BuildContext,
	input sinkMetricV8Input,
) (observability.Record, error) {
	if snapshot.ConfigGeneration > math.MaxInt64 ||
		!observability.IsStableToken(snapshot.ConfigDigest) || input.timestamp.IsZero() {
		return observability.Record{}, fmt.Errorf("audit: invalid v8 sink metric build context")
	}
	builder, err := observability.NewFamilyBuilder(
		observability.ClockFunc(func() time.Time { return input.timestamp.UTC() }),
		observability.OccurrenceIDGeneratorFunc(func() (string, error) {
			return uuid.NewString(), nil
		}),
	)
	if err != nil {
		return observability.Record{}, err
	}
	envelope := observability.FamilyEnvelopeInput{
		ObservedAt: observability.Present(input.timestamp.UTC()),
		Source:     observability.SourceSystem, Action: input.action, Phase: "delivery",
		Correlation: observability.Correlation{
			RunID: currentRunID(), SidecarInstanceID: ProcessAgentInstanceID(),
		},
		Provenance: observability.FamilyProvenanceInput{
			Producer: "audit_logger", BinaryVersion: version.Current().BinaryVersion,
			ConfigGeneration: int64(snapshot.ConfigGeneration), ConfigDigest: snapshot.ConfigDigest,
		},
	}
	sinkKind := optionalSinkMetricDimension(input.sinkKind)
	sinkName := optionalSinkMetricDimension(input.sinkName)
	retryCount := observability.Present(input.retryCount)
	statusCode := observability.Present(input.statusCode)
	switch input.kind {
	case sinkMetricV8BatchDelivered:
		return builder.BuildMetricDefenseClawAuditSinkBatchesDelivered(
			observability.MetricDefenseClawAuditSinkBatchesDeliveredInput{
				Envelope: envelope, Value: input.valueInt,
				DefenseClawMetricKind: sinkKind, DefenseClawMetricSink: sinkName,
				DefenseClawMetricRetryCount: retryCount,
				DefenseClawMetricStatusCode: statusCode,
			},
		)
	case sinkMetricV8BatchDropped:
		return builder.BuildMetricDefenseClawAuditSinkBatchesDropped(
			observability.MetricDefenseClawAuditSinkBatchesDroppedInput{
				Envelope: envelope, Value: input.valueInt,
				DefenseClawMetricKind: sinkKind, DefenseClawMetricSink: sinkName,
				DefenseClawMetricRetryCount: retryCount,
				DefenseClawMetricStatusCode: statusCode,
			},
		)
	case sinkMetricV8DeliveryLatency:
		return builder.BuildMetricDefenseClawAuditSinkDeliveryLatency(
			observability.MetricDefenseClawAuditSinkDeliveryLatencyInput{
				Envelope: envelope, Value: input.valueFloat,
				DefenseClawMetricKind: sinkKind, DefenseClawMetricSink: sinkName,
				DefenseClawMetricRetryCount: retryCount,
				DefenseClawMetricStatusCode: statusCode,
			},
		)
	case sinkMetricV8Failure:
		return builder.BuildMetricDefenseClawAuditSinkFailures(
			observability.MetricDefenseClawAuditSinkFailuresInput{
				Envelope: envelope, Value: input.valueInt,
				DefenseClawMetricSinkKind: sinkKind, DefenseClawMetricSinkName: sinkName,
				DefenseClawMetricSinkReason: optionalSinkMetricDimension(input.reason),
			},
		)
	case sinkMetricV8CircuitState:
		return builder.BuildMetricDefenseClawAuditSinkCircuitState(
			observability.MetricDefenseClawAuditSinkCircuitStateInput{
				Envelope: envelope, Value: input.valueInt,
				DefenseClawMetricSinkKind: sinkKind, DefenseClawMetricSinkName: sinkName,
			},
		)
	default:
		return observability.Record{}, fmt.Errorf("audit: unsupported v8 sink metric family")
	}
}

func optionalSinkMetricDimension(value string) observability.Optional[string] {
	if !observability.IsStableToken(value) {
		return observability.Absent[string]()
	}
	return observability.Present(value)
}

func (l *Logger) recordSinkMetricV8(
	ctx context.Context,
	binding runtimeV8Binding,
	input sinkMetricV8Input,
) error {
	if !binding.authoritative {
		return fmt.Errorf("audit: v8 sink metrics are not authoritative")
	}
	if binding.metricEmitter == nil {
		return fmt.Errorf("audit: v8 sink metric runtime is unavailable")
	}
	if ctx == nil {
		ctx = context.Background()
	}
	metric, err := newSinkRuntimeV8GeneratedMetric(input)
	if err != nil {
		return err
	}
	return binding.metricEmitter.RecordRuntimeV8GeneratedMetric(ctx, metric)
}
