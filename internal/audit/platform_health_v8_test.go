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
	"errors"
	"fmt"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/gatewaylog"
	"github.com/defenseclaw/defenseclaw/internal/observability"
	"github.com/defenseclaw/defenseclaw/internal/observability/router"
	"github.com/defenseclaw/defenseclaw/internal/telemetry"
	sdkmetric "go.opentelemetry.io/otel/sdk/metric"
	"go.opentelemetry.io/otel/sdk/metric/metricdata"
)

type sinkHealthTestRuntime struct {
	logs *testRuntimeV8Emitter

	mu      sync.Mutex
	metrics []observability.Record
	err     error
}

type sinkLegacyCapture struct {
	mu       sync.Mutex
	audits   []Event
	gateways []gatewaylog.Event
}

type rejectingSinkHealthRuntime struct {
	logCalls    int
	metricCalls int
}

type evaluatingSinkHealthRuntime struct {
	base      *sinkHealthTestRuntime
	evaluator *router.Evaluator

	mu         sync.Mutex
	deliveries [][]router.Delivery
}

func (runtime *evaluatingSinkHealthRuntime) EmitRuntimeV8(
	ctx context.Context,
	metadata router.Metadata,
	builder RuntimeV8Builder,
) (RuntimeV8EmitOutcome, error) {
	result, err := runtime.evaluator.Evaluate(metadata, func(admission router.Admission) (observability.Record, error) {
		return builder(RuntimeV8BuildContext{
			ConfigGeneration: 23, ConfigDigest: testEventHistoryGraphDigest,
		}, admission)
	})
	if err != nil {
		return RuntimeV8EmitOutcome{}, err
	}
	runtime.mu.Lock()
	runtime.deliveries = append(runtime.deliveries, result.Deliveries())
	runtime.mu.Unlock()
	if result.Admission() == router.AdmissionDrop {
		return RuntimeV8EmitOutcome{Admission: router.AdmissionDrop}, nil
	}
	record, ok := result.Record()
	if !ok {
		return RuntimeV8EmitOutcome{}, errors.New("test evaluator admitted no record")
	}
	projection, _, err := testEventHistoryProjectionEngine.Project(record, runtime.base.logs.profile)
	if err != nil {
		return RuntimeV8EmitOutcome{}, err
	}
	if err := runtime.base.logs.writer.AppendContext(ctx, record, projection); err != nil {
		return RuntimeV8EmitOutcome{}, err
	}
	runtime.base.logs.mu.Lock()
	runtime.base.logs.metadata = append(runtime.base.logs.metadata, metadata)
	runtime.base.logs.records = append(runtime.base.logs.records, record.Clone())
	runtime.base.logs.mu.Unlock()
	return RuntimeV8EmitOutcome{Admission: result.Admission(), LocalPersisted: true}, nil
}

func (runtime *evaluatingSinkHealthRuntime) RecordRuntimeV8GeneratedMetric(
	ctx context.Context,
	metric RuntimeV8GeneratedMetric,
) error {
	return runtime.base.RecordRuntimeV8GeneratedMetric(ctx, metric)
}

func (runtime *evaluatingSinkHealthRuntime) deliverySnapshot() [][]router.Delivery {
	runtime.mu.Lock()
	defer runtime.mu.Unlock()
	result := make([][]router.Delivery, len(runtime.deliveries))
	for index := range runtime.deliveries {
		result[index] = append([]router.Delivery(nil), runtime.deliveries[index]...)
	}
	return result
}

func (runtime *rejectingSinkHealthRuntime) EmitRuntimeV8(
	context.Context,
	router.Metadata,
	RuntimeV8Builder,
) (RuntimeV8EmitOutcome, error) {
	runtime.logCalls++
	return RuntimeV8EmitOutcome{}, errors.New("private runtime failure")
}

func (runtime *rejectingSinkHealthRuntime) RecordRuntimeV8GeneratedMetric(
	context.Context,
	RuntimeV8GeneratedMetric,
) error {
	runtime.metricCalls++
	return errors.New("private metric failure")
}

func (capture *sinkLegacyCapture) EmitAudit(event Event) {
	capture.mu.Lock()
	capture.audits = append(capture.audits, event)
	capture.mu.Unlock()
}

func (capture *sinkLegacyCapture) EmitGatewayEvent(event gatewaylog.Event) {
	capture.mu.Lock()
	capture.gateways = append(capture.gateways, event)
	capture.mu.Unlock()
}

func (capture *sinkLegacyCapture) snapshot() ([]Event, []gatewaylog.Event) {
	capture.mu.Lock()
	defer capture.mu.Unlock()
	return append([]Event(nil), capture.audits...), append([]gatewaylog.Event(nil), capture.gateways...)
}

func newSinkHealthTestRuntime(
	t *testing.T,
	logger *Logger,
	admission router.Admission,
) *sinkHealthTestRuntime {
	t.Helper()
	return &sinkHealthTestRuntime{
		logs: newTestRuntimeV8Emitter(t, logger.store, admission),
	}
}

func (runtime *sinkHealthTestRuntime) EmitRuntimeV8(
	ctx context.Context,
	metadata router.Metadata,
	builder RuntimeV8Builder,
) (RuntimeV8EmitOutcome, error) {
	return runtime.logs.EmitRuntimeV8(ctx, metadata, builder)
}

func (runtime *sinkHealthTestRuntime) RecordRuntimeV8GeneratedMetric(
	_ context.Context,
	metric RuntimeV8GeneratedMetric,
) error {
	if runtime.err != nil {
		return runtime.err
	}
	record, err := metric.Build(RuntimeV8BuildContext{
		ConfigGeneration: 23,
		ConfigDigest:     testEventHistoryGraphDigest,
	})
	if err != nil {
		return err
	}
	runtime.mu.Lock()
	runtime.metrics = append(runtime.metrics, record.Clone())
	runtime.mu.Unlock()
	return nil
}

func (runtime *sinkHealthTestRuntime) snapshot() ([]observability.Record, []observability.Record) {
	_, logs := runtime.logs.snapshot()
	runtime.mu.Lock()
	defer runtime.mu.Unlock()
	metrics := make([]observability.Record, len(runtime.metrics))
	for index := range runtime.metrics {
		metrics[index] = runtime.metrics[index].Clone()
	}
	return logs, metrics
}

func TestClassifySinkFailureUsesClosedBoundedVocabulary(t *testing.T) {
	tests := []struct {
		name       string
		err        error
		family     sinkHealthV8Family
		outcome    observability.Outcome
		reason     string
		errorCode  string
		statusCode int
		gateway    gatewaylog.ErrorCode
	}{
		{name: "authentication", err: errors.New("endpoint secret returned 401 token=private"), family: sinkHealthV8AuthenticationFailed, outcome: observability.OutcomeFailed, reason: "authentication_failed", errorCode: "authentication_failed", statusCode: 401, gateway: gatewaylog.ErrCodeSinkDeliveryFailed},
		{name: "authorization", err: errors.New("HTTP 403 payload=private"), family: sinkHealthV8AuthorizationDenied, outcome: observability.OutcomeDenied, reason: "authorization_denied", errorCode: "authorization_denied", statusCode: 403, gateway: gatewaylog.ErrCodeSinkDeliveryFailed},
		{name: "cancelled", err: fmt.Errorf("wrapped: %w", context.Canceled), family: sinkHealthV8ExportFailed, outcome: observability.OutcomeCancelled, reason: "cancelled", errorCode: "delivery_cancelled", gateway: gatewaylog.ErrCodeSinkDeliveryFailed},
		{name: "timeout", err: fmt.Errorf("wrapped: %w", context.DeadlineExceeded), family: sinkHealthV8ExportFailed, outcome: observability.OutcomeTimedOut, reason: "timeout", errorCode: "delivery_timeout", gateway: gatewaylog.ErrCodeSinkDeliveryFailed},
		{name: "queue", err: errors.New("private payload dropping because backlog cap reached"), family: sinkHealthV8QueueFull, outcome: observability.OutcomeRejected, reason: "queue_full", errorCode: "queue_full", gateway: gatewaylog.ErrCodeSinkQueueFull},
		{name: "serialization", err: errors.New("marshal failed: private payload"), family: sinkHealthV8ExportFailed, outcome: observability.OutcomeFailed, reason: "serialize_error", errorCode: "serialization_failed", gateway: gatewaylog.ErrCodeSinkDeliveryFailed},
		{name: "http", err: errors.New("returned 503 endpoint=https://private.example token=secret"), family: sinkHealthV8ExportFailed, outcome: observability.OutcomeFailed, reason: "http_error", errorCode: "http_delivery_failed", statusCode: 503, gateway: gatewaylog.ErrCodeSinkDeliveryFailed},
		{name: "generic", err: errors.New("opaque private failure"), family: sinkHealthV8ExportFailed, outcome: observability.OutcomeFailed, reason: "delivery_error", errorCode: "delivery_failed", gateway: gatewaylog.ErrCodeSinkDeliveryFailed},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got := classifySinkFailure(test.err)
			if got.family != test.family || got.outcome != test.outcome ||
				got.metricReason != test.reason || got.errorCode != test.errorCode ||
				got.statusCode != test.statusCode || got.gatewayCode != test.gateway {
				t.Fatalf("classification = %#v", got)
			}
			encoded := fmt.Sprintf("%s %s %s", got.metricReason, got.errorCode, got.gatewayCode)
			for _, private := range []string{"private", "secret", "https://"} {
				if strings.Contains(encoded, private) {
					t.Fatalf("classification leaked %q: %s", private, encoded)
				}
			}
		})
	}
}

func TestSafeSinkHealthDimensionPreservesNamesAndHashesEndpoints(t *testing.T) {
	if got := safeSinkHealthDimension("primary"); got != "primary" {
		t.Fatalf("stable name = %q", got)
	}
	if got := safeSinkHealthDimension("SOC Primary"); got != "soc-primary" {
		t.Fatalf("display name = %q", got)
	}
	first := safeSinkHealthDimension("https://collector-a.example/v1")
	second := safeSinkHealthDimension("HTTPS://collector-b.example/v1")
	if first == second || !observability.IsStableToken(first) || !observability.IsStableToken(second) ||
		strings.Contains(first, "collector") || strings.Contains(second, "collector") {
		t.Fatalf("endpoint identities = %q, %q", first, second)
	}
}

func TestSinkDeliveryHookV8UsesExactGeneratedFamiliesAndNoLegacyFanout(t *testing.T) {
	tests := []struct {
		name      string
		err       error
		eventName observability.EventName
		outcome   observability.Outcome
		code      string
		status    int64
		mandatory bool
	}{
		{name: "authentication", err: errors.New("returned 401 token=private"), eventName: observability.EventName(observability.TelemetryEventDestinationAuthenticationFailed), outcome: observability.OutcomeFailed, code: "authentication_failed", status: 401, mandatory: true},
		{name: "authorization", err: errors.New("HTTP 403 body=private"), eventName: observability.EventName(observability.TelemetryEventDestinationAuthorizationDenied), outcome: observability.OutcomeDenied, code: "authorization_denied", status: 403, mandatory: true},
		{name: "queue full", err: errors.New("backlog dropping private payload"), eventName: observability.EventName(observability.TelemetryEventDestinationQueueFull), outcome: observability.OutcomeRejected, code: "queue_full"},
		{name: "timeout", err: context.DeadlineExceeded, eventName: observability.EventName(observability.TelemetryEventDestinationExportFailed), outcome: observability.OutcomeTimedOut, code: "delivery_timeout"},
		{name: "delivery failure", err: errors.New("endpoint=https://private.invalid token=secret"), eventName: observability.EventName(observability.TelemetryEventDestinationExportFailed), outcome: observability.OutcomeFailed, code: "delivery_failed"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			logger := newTestLogger(t)
			runtime := newSinkHealthTestRuntime(t, logger, router.AdmissionOrdinary)
			logger.SetRuntimeV8Emitter(runtime)
			legacy := &countingRuntimeOwnedLegacyEmitter{}
			logger.SetStructuredEmitter(legacy)
			legacySink := installCaptureSink(t, logger)

			logger.sinkDeliveryHook(t.Context(), "splunk_hec", "primary", test.err, 12.75)

			logs, metrics := runtime.snapshot()
			if len(logs) != 1 {
				t.Fatalf("generated logs = %d, want 1", len(logs))
			}
			assertSinkHealthLog(t, logs[0], test.eventName, test.outcome, test.code, test.mandatory)
			assertMetricFamilies(t, metrics,
				observability.EventName(observability.TelemetryInstrumentDefenseClawAuditSinkBatchesDropped),
				observability.EventName(observability.TelemetryInstrumentDefenseClawAuditSinkFailures),
			)
			assertSinkBatchMetricLabels(t, metrics[0], "splunk_hec", "primary", test.status, 0)
			if audits, gateways := legacy.counts(); audits != 0 || gateways != 0 || len(legacySink.snapshot()) != 0 {
				t.Fatalf("legacy fanout audits=%d gateways=%d sink=%d", audits, gateways, len(legacySink.snapshot()))
			}
			assertOnlyStableSinkHealthFailure(t, logger, test.code)
		})
	}
}

func TestSinkDeliveryHookV8SuccessPreservesDashboardLabelsExactlyOnce(t *testing.T) {
	logger := newTestLogger(t)
	runtime := newSinkHealthTestRuntime(t, logger, router.AdmissionOrdinary)
	logger.SetRuntimeV8Emitter(runtime)
	legacy := &countingRuntimeOwnedLegacyEmitter{}
	logger.SetStructuredEmitter(legacy)

	logger.sinkDeliveryHook(t.Context(), "splunk_hec", "primary", nil, 4.5)

	logs, metrics := runtime.snapshot()
	if len(logs) != 0 {
		t.Fatalf("success logs = %d, want 0", len(logs))
	}
	assertMetricFamilies(t, metrics,
		observability.EventName(observability.TelemetryInstrumentDefenseClawAuditSinkBatchesDelivered),
		observability.EventName(observability.TelemetryInstrumentDefenseClawAuditSinkDeliveryLatency),
	)
	for _, record := range metrics {
		assertSinkBatchMetricLabels(t, record, "splunk_hec", "primary", 200, 0)
	}
	if audits, gateways := legacy.counts(); audits != 0 || gateways != 0 {
		t.Fatalf("legacy fanout audits=%d gateways=%d", audits, gateways)
	}
}

func TestSinkCircuitV8TransitionsAreMandatoryAndDistinct(t *testing.T) {
	logger := newTestLogger(t)
	runtime := newSinkHealthTestRuntime(t, logger, router.AdmissionOrdinary)
	logger.SetRuntimeV8Emitter(runtime)
	legacy := &countingRuntimeOwnedLegacyEmitter{}
	logger.SetStructuredEmitter(legacy)
	legacySink := installCaptureSink(t, logger)

	logger.onCircuitTripActivity("splunk_hec", "primary")
	logger.onCircuitRecoverActivity("splunk_hec", "primary")

	logs, metrics := runtime.snapshot()
	if len(logs) != 2 {
		t.Fatalf("transition logs = %d, want 2", len(logs))
	}
	assertSinkHealthLog(t, logs[0],
		observability.EventName(observability.TelemetryEventDestinationExportFailed),
		observability.OutcomeFailed, "circuit_open", true,
	)
	assertSinkHealthLog(t, logs[1],
		observability.EventName(observability.TelemetryEventSubsystemRestored),
		observability.OutcomeCompleted, "", true,
	)
	assertMetricFamilies(t, metrics,
		observability.EventName(observability.TelemetryInstrumentDefenseClawAuditSinkCircuitState),
		observability.EventName(observability.TelemetryInstrumentDefenseClawAuditSinkCircuitState),
	)
	if value := fmt.Sprint(metricValue(t, metrics[0])); value != "1" {
		t.Fatalf("open circuit value = %#v", value)
	}
	if value := fmt.Sprint(metricValue(t, metrics[1])); value != "0" {
		t.Fatalf("closed circuit value = %#v", value)
	}
	if audits, gateways := legacy.counts(); audits != 0 || gateways != 0 || len(legacySink.snapshot()) != 0 {
		t.Fatalf("legacy transition fanout audits=%d gateways=%d sink=%d", audits, gateways, len(legacySink.snapshot()))
	}
}

func TestSinkDestinationAuthFailureUsesDisabledCollectionSQLiteFloorOnly(t *testing.T) {
	falseValue, trueValue := false, true
	plan, err := config.CompileObservabilityV8(&config.ObservabilityV8Source{
		Buckets: map[observability.Bucket]config.ObservabilityV8BucketPolicySource{
			observability.BucketPlatformHealth: {
				Collect: config.ObservabilityV8CollectSource{
					Logs: &falseValue, Metrics: &trueValue,
				},
			},
		},
		Destinations: []config.ObservabilityV8DestinationSource{
			{Name: "remote-logs", Kind: config.ObservabilityV8DestinationConsole},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	evaluator, err := router.New(plan)
	if err != nil {
		t.Fatal(err)
	}

	for _, test := range []struct {
		name      string
		err       error
		eventName observability.EventName
		outcome   observability.Outcome
	}{
		{name: "401 authentication", err: errors.New("returned 401 Authorization=private-token"), eventName: observability.EventName(observability.TelemetryEventDestinationAuthenticationFailed), outcome: observability.OutcomeFailed},
		{name: "403 authorization", err: errors.New("HTTP 403 endpoint=https://private.example payload=secret"), eventName: observability.EventName(observability.TelemetryEventDestinationAuthorizationDenied), outcome: observability.OutcomeDenied},
	} {
		t.Run(test.name, func(t *testing.T) {
			logger := newTestLogger(t)
			base := newSinkHealthTestRuntime(t, logger, router.AdmissionOrdinary)
			runtime := &evaluatingSinkHealthRuntime{base: base, evaluator: evaluator}
			legacy := &countingRuntimeOwnedLegacyEmitter{}
			logger.SetStructuredEmitter(legacy)
			legacySink := installCaptureSink(t, logger)
			logger.SetRuntimeV8Emitter(runtime)

			logger.sinkDeliveryHook(t.Context(), "splunk_hec", "primary", test.err, 1)

			logs, metrics := base.snapshot()
			if len(logs) != 1 || len(metrics) != 2 {
				t.Fatalf("floor logs/metrics = %d/%d", len(logs), len(metrics))
			}
			record := logs[0]
			if record.EventName() != test.eventName || record.Outcome() != test.outcome ||
				!record.Mandatory() || !record.IsFloorOnly() {
				t.Fatalf("floor record = %#v", record)
			}
			body, present := record.Body()
			if !present || string(body.Bytes()) != `{"detail_state":"omitted","floor_only":true}` {
				t.Fatalf("floor body = %q, present=%t", body.Bytes(), present)
			}
			if want := map[string]observability.FieldClass{
				"/detail_state": observability.FieldClassMetadata,
				"/floor_only":   observability.FieldClassMetadata,
			}; !reflect.DeepEqual(record.FieldClasses(), want) {
				t.Fatalf("floor classes = %#v, want %#v", record.FieldClasses(), want)
			}
			deliveries := runtime.deliverySnapshot()
			if len(deliveries) != 1 || len(deliveries[0]) != 1 ||
				deliveries[0][0].DestinationName != config.ObservabilityV8LocalDestinationName ||
				!deliveries[0][0].MandatoryFloor {
				t.Fatalf("floor deliveries = %#v", deliveries)
			}
			encoded, err := record.Bytes()
			if err != nil {
				t.Fatal(err)
			}
			for _, forbidden := range []string{
				"private-token", "private.example", "payload", "secret",
				"authentication_failed", "authorization_denied",
			} {
				if strings.Contains(string(encoded), forbidden) {
					t.Fatalf("floor record leaked %q: %s", forbidden, encoded)
				}
			}
			if audits, gateways := legacy.counts(); audits != 0 || gateways != 0 || len(legacySink.snapshot()) != 0 {
				t.Fatalf("floor used legacy fanout audits=%d gateways=%d sink=%d",
					audits, gateways, len(legacySink.snapshot()))
			}
			events, err := logger.store.ListEvents(10)
			if err != nil {
				t.Fatal(err)
			}
			if len(events) != 1 || events[0].Details != string(test.eventName) || events[0].Target != "" ||
				!reflect.DeepEqual(events[0].Structured, map[string]any{
					"detail_state": "omitted",
					"floor_only":   true,
				}) {
				t.Fatalf("floor SQLite row retained ordinary content: %#v", events)
			}
		})
	}
}

func TestSinkHealthV8ReloadAndDetachNeverResurrectLegacy(t *testing.T) {
	logger := newTestLogger(t)
	first := newSinkHealthTestRuntime(t, logger, router.AdmissionOrdinary)
	second := newSinkHealthTestRuntime(t, logger, router.AdmissionOrdinary)
	legacy := &countingRuntimeOwnedLegacyEmitter{}
	logger.SetStructuredEmitter(legacy)
	legacySink := installCaptureSink(t, logger)

	logger.SetRuntimeV8Emitter(first)
	logger.sinkDeliveryHook(t.Context(), "splunk_hec", "primary", nil, 1)
	logger.SetRuntimeV8Emitter(second)
	logger.sinkDeliveryHook(t.Context(), "splunk_hec", "primary", errors.New("returned 503 private endpoint"), 2)

	firstLogs, firstMetrics := first.snapshot()
	secondLogs, secondMetrics := second.snapshot()
	if len(firstLogs) != 0 || len(firstMetrics) != 2 || len(secondLogs) != 1 || len(secondMetrics) != 2 {
		t.Fatalf("reload routing first=%d/%d second=%d/%d",
			len(firstLogs), len(firstMetrics), len(secondLogs), len(secondMetrics))
	}

	logger.SetRuntimeV8Emitter(nil)
	logger.sinkDeliveryHook(t.Context(), "splunk_hec", "primary", errors.New("token=private returned 401"), 3)
	logger.onCircuitTripActivity("splunk_hec", "primary")
	logger.onCircuitRecoverActivity("splunk_hec", "primary")

	afterLogs, afterMetrics := second.snapshot()
	if len(afterLogs) != len(secondLogs) || len(afterMetrics) != len(secondMetrics) {
		t.Fatalf("detached runtime received work logs=%d metrics=%d", len(afterLogs), len(afterMetrics))
	}
	if audits, gateways := legacy.counts(); audits != 0 || gateways != 0 || len(legacySink.snapshot()) != 0 {
		t.Fatalf("detach resurrected legacy fanout audits=%d gateways=%d sink=%d",
			audits, gateways, len(legacySink.snapshot()))
	}
}

func TestSinkHealthV8ConcurrentReloadDetachNeverUsesLegacy(t *testing.T) {
	logger := newTestLogger(t)
	first := newSinkHealthTestRuntime(t, logger, router.AdmissionOrdinary)
	second := newSinkHealthTestRuntime(t, logger, router.AdmissionOrdinary)
	legacy := &countingRuntimeOwnedLegacyEmitter{}
	logger.SetStructuredEmitter(legacy)
	legacySink := installCaptureSink(t, logger)
	logger.SetRuntimeV8Emitter(first)

	var group sync.WaitGroup
	group.Add(3)
	go func() {
		defer group.Done()
		for index := 0; index < 32; index++ {
			switch index % 3 {
			case 0:
				logger.SetRuntimeV8Emitter(first)
			case 1:
				logger.SetRuntimeV8Emitter(second)
			default:
				logger.SetRuntimeV8Emitter(nil)
			}
		}
	}()
	for worker := 0; worker < 2; worker++ {
		go func() {
			defer group.Done()
			for index := 0; index < 32; index++ {
				if index%2 == 0 {
					logger.sinkDeliveryHook(t.Context(), "splunk_hec", "primary", nil, float64(index))
					continue
				}
				logger.sinkDeliveryHook(t.Context(), "splunk_hec", "primary", errors.New("delivery failed"), float64(index))
			}
		}()
	}
	group.Wait()

	if audits, gateways := legacy.counts(); audits != 0 || gateways != 0 || len(legacySink.snapshot()) != 0 {
		t.Fatalf("concurrent reload resurrected legacy fanout audits=%d gateways=%d sink=%d",
			audits, gateways, len(legacySink.snapshot()))
	}
}

func TestSinkHealthV8RuntimeFailureNeverFallsBackToLegacy(t *testing.T) {
	logger := newTestLogger(t)
	runtime := &rejectingSinkHealthRuntime{}
	legacy := &countingRuntimeOwnedLegacyEmitter{}
	logger.SetStructuredEmitter(legacy)
	legacySink := installCaptureSink(t, logger)
	logger.SetRuntimeV8Emitter(runtime)

	logger.sinkDeliveryHook(t.Context(), "splunk_hec", "primary", errors.New("delivery failed"), 1)

	if runtime.logCalls != 1 || runtime.metricCalls != 2 {
		t.Fatalf("v8 calls logs=%d metrics=%d", runtime.logCalls, runtime.metricCalls)
	}
	if audits, gateways := legacy.counts(); audits != 0 || gateways != 0 || len(legacySink.snapshot()) != 0 {
		t.Fatalf("runtime failure fell back audits=%d gateways=%d sink=%d",
			audits, gateways, len(legacySink.snapshot()))
	}
	events, err := logger.store.ListEvents(10)
	if err != nil {
		t.Fatal(err)
	}
	if len(events) != 0 {
		t.Fatalf("runtime failure wrote legacy audit rows: %#v", events)
	}
}

func TestSinkDeliveryHookTrueV7PreservesLegacyFactsByteForByte(t *testing.T) {
	logger := newTestLogger(t)
	reader := sdkmetric.NewManualReader()
	provider, err := telemetry.NewProviderForTest(reader)
	if err != nil {
		t.Fatal(err)
	}
	logger.SetOTelProvider(provider)
	legacy := &sinkLegacyCapture{}
	logger.SetStructuredEmitter(legacy)

	const kind = "Splunk HEC"
	const sinkName = "https://private.example/sink"
	legacyErr := errors.New("returned 503 endpoint=https://private.invalid Authorization=secret")
	logger.sinkDeliveryHook(t.Context(), kind, sinkName, legacyErr, 8.25)

	var resourceMetrics metricdata.ResourceMetrics
	if err := reader.Collect(t.Context(), &resourceMetrics); err != nil {
		t.Fatal(err)
	}
	if got := metricPointCount(resourceMetrics, "defenseclaw.audit.sink.batches.dropped"); got != 1 {
		t.Fatalf("legacy dropped metric points = %d, want 1", got)
	}
	if got := metricPointCount(resourceMetrics, "defenseclaw.audit.sink.failures"); got != 1 {
		t.Fatalf("legacy failure metric points = %d, want 1", got)
	}
	assertLegacyMetricLabels(t, resourceMetrics, "defenseclaw.audit.sink.batches.dropped", map[string]any{
		"kind": kind, "sink": sinkName, "status_code": int64(503), "retry_count": int64(0),
	})
	assertLegacyMetricLabels(t, resourceMetrics, "defenseclaw.audit.sink.failures", map[string]any{
		"sink.kind": kind, "sink.name": sinkName, "sink.reason": "http_error",
	})
	audits, gateways := legacy.snapshot()
	if len(audits) != 1 || len(gateways) != 1 {
		t.Fatalf("true v7 fanout audits=%d gateways=%d", len(audits), len(gateways))
	}
	if gateways[0].Error == nil || gateways[0].Error.Cause != legacyErr.Error() ||
		gateways[0].Error.Message != fmt.Sprintf("audit sink %q (%s) delivery failed", sinkName, kind) {
		t.Fatalf("legacy gateway error = %#v", gateways[0].Error)
	}
	row := logger.store.db.QueryRow(`SELECT sink_name, sink_kind, status_code, latency_ms, error
		FROM sink_health ORDER BY id DESC LIMIT 1`)
	var gotName, gotKind, gotError string
	var gotStatus, gotLatency int64
	if err := row.Scan(&gotName, &gotKind, &gotStatus, &gotLatency, &gotError); err != nil {
		t.Fatal(err)
	}
	if gotName != sinkName || gotKind != kind || gotStatus != 503 || gotLatency != 8 ||
		gotError != "retry_count=0 | "+legacyErr.Error() {
		t.Fatalf("legacy sink health = %q %q %d %d %q", gotName, gotKind, gotStatus, gotLatency, gotError)
	}
	events, err := logger.store.ListEvents(10)
	if err != nil {
		t.Fatal(err)
	}
	if len(events) != 1 || events[0].Target != sinkName ||
		!strings.HasPrefix(events[0].Details, "<redacted len=") {
		t.Fatalf("v7 audit failure details = %#v", events)
	}
}

func TestRuntimeV8GeneratedMetricRejectsZeroAndIdentityMismatch(t *testing.T) {
	if _, err := (RuntimeV8GeneratedMetric{}).Build(RuntimeV8BuildContext{}); err == nil {
		t.Fatal("zero generated metric operation was accepted")
	}
	metric := RuntimeV8GeneratedMetric{
		family: observability.EventName(observability.TelemetryInstrumentDefenseClawAuditSinkFailures),
		build: func(RuntimeV8BuildContext) (observability.Record, error) {
			valid, err := newSinkRuntimeV8GeneratedMetric(sinkMetricV8Input{
				kind: sinkMetricV8CircuitState, valueInt: 1,
				sinkKind: "splunk_hec", sinkName: "primary",
				action:    string(ActionSinkFailure),
				timestamp: time.Date(2026, 7, 6, 12, 0, 0, 0, time.UTC),
			})
			if err != nil {
				return observability.Record{}, err
			}
			return valid.Build(RuntimeV8BuildContext{
				ConfigGeneration: 23, ConfigDigest: testEventHistoryGraphDigest,
			})
		},
	}
	if _, err := metric.Build(RuntimeV8BuildContext{}); err == nil || !strings.Contains(err.Error(), "identity mismatch") {
		t.Fatalf("identity mismatch error = %v", err)
	}
}

func assertSinkHealthLog(
	t *testing.T,
	record observability.Record,
	eventName observability.EventName,
	outcome observability.Outcome,
	errorCode string,
	mandatory bool,
) {
	t.Helper()
	severity, hasSeverity := record.Severity()
	if record.Identity() != (observability.EventIdentity{
		Bucket: observability.BucketPlatformHealth, Signal: observability.SignalLogs, Name: eventName,
	}) || record.Outcome() != outcome || record.Mandatory() != mandatory || record.IsFloorOnly() ||
		!hasSeverity || (severity != observability.SeverityHigh && severity != observability.SeverityInfo) ||
		!record.SchemaDerivedFieldClasses() {
		t.Fatalf("sink health envelope = %#v", record)
	}
	bodyValue, present := record.Body()
	if !present {
		t.Fatal("sink health body is absent")
	}
	body, err := bodyValue.Object()
	if err != nil {
		t.Fatal(err)
	}
	if body["defenseclaw.health.subsystem"] != "primary" {
		t.Fatalf("sink health body = %#v", body)
	}
	gotCode, hasCode := body["defenseclaw.schema.error_code"]
	if errorCode == "" {
		if hasCode {
			t.Fatalf("unexpected error code %#v", gotCode)
		}
	} else if gotCode != errorCode {
		t.Fatalf("error code = %#v, want %q", gotCode, errorCode)
	}
}

func assertMetricFamilies(
	t *testing.T,
	records []observability.Record,
	want ...observability.EventName,
) {
	t.Helper()
	got := make([]observability.EventName, len(records))
	for index, record := range records {
		if record.Bucket() != observability.BucketPlatformHealth ||
			record.Signal() != observability.SignalMetrics || record.Mandatory() {
			t.Fatalf("metric envelope = %#v", record)
		}
		got[index] = record.EventName()
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("metric families = %v, want %v", got, want)
	}
}

func assertSinkBatchMetricLabels(
	t *testing.T,
	record observability.Record,
	kind, sink string,
	statusCode, retryCount int64,
) {
	t.Helper()
	instrument, present := record.InstrumentData()
	if !present {
		t.Fatal("metric instrument data is absent")
	}
	data, err := instrument.Object()
	if err != nil {
		t.Fatal(err)
	}
	attributes, ok := data["attributes"].(map[string]any)
	if !ok {
		t.Fatalf("metric attributes = %#v", data["attributes"])
	}
	want := map[string]string{
		"defenseclaw.metric.kind": kind, "defenseclaw.metric.sink": sink,
		"defenseclaw.metric.status_code": fmt.Sprint(statusCode),
		"defenseclaw.metric.retry_count": fmt.Sprint(retryCount),
	}
	got := make(map[string]string, len(attributes))
	for key, value := range attributes {
		got[key] = fmt.Sprint(value)
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("metric attributes = %#v, want %#v", got, want)
	}
}

func metricValue(t *testing.T, record observability.Record) any {
	t.Helper()
	instrument, present := record.InstrumentData()
	if !present {
		t.Fatal("metric instrument data is absent")
	}
	data, err := instrument.Object()
	if err != nil {
		t.Fatal(err)
	}
	return data["value"]
}

func assertOnlyStableSinkHealthFailure(t *testing.T, logger *Logger, wantCode string) {
	t.Helper()
	row := logger.store.db.QueryRow(`SELECT error FROM sink_health ORDER BY id DESC LIMIT 1`)
	var detail string
	if err := row.Scan(&detail); err != nil {
		t.Fatal(err)
	}
	if detail != "retry_count=0 failure_code="+wantCode {
		t.Fatalf("sink health detail = %q", detail)
	}
	for _, private := range []string{"private", "secret", "https://", "token", "Authorization"} {
		if strings.Contains(detail, private) {
			t.Fatalf("sink health detail leaked %q: %q", private, detail)
		}
	}
}

func metricPointCount(resource metricdata.ResourceMetrics, name string) int {
	for _, scope := range resource.ScopeMetrics {
		for _, metric := range scope.Metrics {
			if metric.Name != name {
				continue
			}
			switch data := metric.Data.(type) {
			case metricdata.Sum[int64]:
				return len(data.DataPoints)
			case metricdata.Histogram[float64]:
				return len(data.DataPoints)
			}
		}
	}
	return 0
}

func assertLegacyMetricLabels(
	t *testing.T,
	resource metricdata.ResourceMetrics,
	name string,
	want map[string]any,
) {
	t.Helper()
	for _, scope := range resource.ScopeMetrics {
		for _, metric := range scope.Metrics {
			if metric.Name != name {
				continue
			}
			sum, ok := metric.Data.(metricdata.Sum[int64])
			if !ok || len(sum.DataPoints) != 1 {
				t.Fatalf("legacy metric %s = %T %#v", name, metric.Data, metric.Data)
			}
			got := make(map[string]any)
			for _, attribute := range sum.DataPoints[0].Attributes.ToSlice() {
				got[string(attribute.Key)] = attribute.Value.AsInterface()
			}
			if !reflect.DeepEqual(got, want) {
				t.Fatalf("legacy metric %s labels = %#v, want %#v", name, got, want)
			}
			return
		}
	}
	t.Fatalf("legacy metric %s is absent", name)
}
