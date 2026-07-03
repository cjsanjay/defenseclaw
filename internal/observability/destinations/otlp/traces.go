// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// SPDX-License-Identifier: Apache-2.0

package otlp

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"sync"

	"github.com/defenseclaw/defenseclaw/internal/observability"
	"go.opentelemetry.io/otel/attribute"
	tracegrpc "go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracegrpc"
	tracehttp "go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracehttp"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	"google.golang.org/grpc"
)

// NewSpanExporter returns a single generation-owned exporter with guarded
// dialing. It applies no bucket/vendor filter; the complete routed general OTLP
// span graph reaches this exporter unchanged.
func (factory *Factory) NewSpanExporter(ctx context.Context) (*SpanExporter, error) {
	if ctx == nil {
		return nil, newError(ErrorInvalidConfig, nil)
	}
	config, err := factory.claim(observability.SignalTraces)
	if err != nil {
		return nil, err
	}
	if config.protocol == ProtocolHTTP {
		initialRetry, maximumRetry := retryBounds(config.timeout)
		client, transport := newHTTPClient(config)
		exporter, buildErr := tracehttp.New(ctx,
			tracehttp.WithEndpointURL(signalURL(config)),
			tracehttp.WithURLPath(config.path),
			tracehttp.WithHeaders(cloneHeaders(config.headers)),
			tracehttp.WithTimeout(config.timeout),
			tracehttp.WithCompression(tracehttp.NoCompression),
			tracehttp.WithRetry(tracehttp.RetryConfig{
				Enabled: true, InitialInterval: initialRetry,
				MaxInterval: maximumRetry, MaxElapsedTime: config.timeout,
			}),
			tracehttp.WithHTTPClient(client),
		)
		if buildErr != nil {
			closeHTTPTransport(transport)
			return nil, newError(ErrorInitialization, buildErr)
		}
		return &SpanExporter{
			inner: exporter, httpTransport: transport, maxBytes: factory.config.Batch.MaxExportBatchBytes,
			config: config, destination: factory.config.Destination,
		}, nil
	}
	connection, err := newGRPCConnection(config)
	if err != nil {
		return nil, err
	}
	initialRetry, maximumRetry := retryBounds(config.timeout)
	exporter, buildErr := tracegrpc.New(ctx,
		tracegrpc.WithGRPCConn(connection),
		tracegrpc.WithHeaders(cloneHeaders(config.headers)),
		tracegrpc.WithTimeout(config.timeout),
		tracegrpc.WithRetry(tracegrpc.RetryConfig{
			Enabled: true, InitialInterval: initialRetry,
			MaxInterval: maximumRetry, MaxElapsedTime: config.timeout,
		}),
	)
	if buildErr != nil {
		_ = connection.Close()
		return nil, newError(ErrorInitialization, buildErr)
	}
	return &SpanExporter{
		inner: exporter, connection: connection, maxBytes: factory.config.Batch.MaxExportBatchBytes,
		config: config, destination: factory.config.Destination,
	}, nil
}

// NewBatchSpanProcessor is the uncoupled telemetry-provider integration seam.
// Calling it is the explicit point at which the SDK batch worker is started.
func (factory *Factory) NewBatchSpanProcessor(ctx context.Context) (sdktrace.SpanProcessor, error) {
	exporter, err := factory.NewSpanExporter(ctx)
	if err != nil {
		return nil, err
	}
	batch := factory.config.Batch
	if batch.MaxQueueSize <= 0 || batch.MaxExportBatchSize <= 0 ||
		batch.MaxExportBatchSize > batch.MaxQueueSize || batch.ScheduledDelay <= 0 {
		cleanup, cancel := cleanupContext(ctx, factory.config.Timeout)
		_ = exporter.Shutdown(cleanup)
		cancel()
		return nil, newError(ErrorInvalidConfig, nil)
	}
	return newBoundedSpanProcessor(exporter, batch), nil
}

// SpanFilter is evaluated against an immutable ended span before it enters a
// destination queue. False and panics fail closed without retaining the span.
type SpanFilter func(sdktrace.ReadOnlySpan) bool

// NewFilteredBatchSpanProcessor creates one destination-owned processor whose
// route predicate runs before queue count/byte charging.
func (factory *Factory) NewFilteredBatchSpanProcessor(ctx context.Context, filter SpanFilter) (sdktrace.SpanProcessor, error) {
	if filter == nil {
		return nil, newError(ErrorInvalidConfig, nil)
	}
	processor, err := factory.NewBatchSpanProcessor(ctx)
	if err != nil {
		return nil, err
	}
	return &filteredSpanProcessor{inner: processor, filter: filter}, nil
}

type filteredSpanProcessor struct {
	inner  sdktrace.SpanProcessor
	filter SpanFilter
}

func (processor *filteredSpanProcessor) OnStart(ctx context.Context, span sdktrace.ReadWriteSpan) {
	// The bounded processor currently owns no start-time state, but delegate to
	// preserve the SpanProcessor contract if that implementation evolves.
	processor.inner.OnStart(ctx, span)
}

func (processor *filteredSpanProcessor) OnEnd(span sdktrace.ReadOnlySpan) {
	allowed := false
	func() {
		defer func() { _ = recover() }()
		allowed = processor.filter(span)
	}()
	if allowed {
		processor.inner.OnEnd(span)
	}
}

func (processor *filteredSpanProcessor) ForceFlush(ctx context.Context) error {
	return processor.inner.ForceFlush(ctx)
}

func (processor *filteredSpanProcessor) Shutdown(ctx context.Context) error {
	return processor.inner.Shutdown(ctx)
}

type SpanExporter struct {
	inner         sdktrace.SpanExporter
	connection    *grpc.ClientConn
	httpTransport *http.Transport
	config        signalConfig
	destination   string
	maxBytes      int
	counters      mutableCounters
	mu            sync.RWMutex
	closed        bool
}

func (exporter *SpanExporter) ExportSpans(ctx context.Context, spans []sdktrace.ReadOnlySpan) error {
	if exporter == nil || ctx == nil {
		return newError(ErrorExport, nil)
	}
	exporter.mu.RLock()
	closed := exporter.closed
	defer exporter.mu.RUnlock()
	if closed {
		return newError(ErrorExport, nil)
	}
	spans = canarySpansForOTLPDestination(spans, exporter.destination)
	regular, canaries := partitionOTLPCanarySpans(spans)
	var exportErrors []error
	if len(regular) > 0 {
		if err := exporter.exportBatch(ctx, regular, ""); err != nil {
			exportErrors = append(exportErrors, err)
		}
	}
	for _, canary := range canaries {
		traceID := completeOTLPCanaryTrace(canary)
		if err := exporter.exportBatch(ctx, canary, traceID); err != nil {
			exportErrors = append(exportErrors, err)
		}
	}
	return errors.Join(exportErrors...)
}

func completeOTLPCanaryTrace(spans []sdktrace.ReadOnlySpan) string {
	if len(spans) != 2 {
		return ""
	}
	traceID := spans[0].SpanContext().TraceID()
	if !traceID.IsValid() || spans[1].SpanContext().TraceID() != traceID {
		return ""
	}
	operations := make(map[string]struct{}, 2)
	for _, span := range spans {
		if !isOTLPCanarySpan(span) {
			return ""
		}
		for _, item := range span.Attributes() {
			if string(item.Key) == "gen_ai.operation.name" && item.Value.Type() == attribute.STRING {
				operations[item.Value.AsString()] = struct{}{}
			}
		}
	}
	if _, ok := operations["invoke_agent"]; !ok {
		return ""
	}
	if _, ok := operations["chat"]; !ok {
		return ""
	}
	return traceID.String()
}

func (exporter *SpanExporter) exportBatch(ctx context.Context, spans []sdktrace.ReadOnlySpan, canaryTraceID string) error {
	total := 0
	for _, span := range spans {
		bound, ok := conservativeSpanBytes(span)
		if !ok || bound > exporter.maxBytes-total {
			exporter.counters.rejectedOversize.Add(uint64(len(spans)))
			observe(exporter.config.observer, SignalEvent{Signal: observability.SignalTraces, Outcome: SignalOutcomeRejectedOversize, Count: uint64(len(spans))})
			return newError(ErrorExport, nil)
		}
		total += bound
	}
	exporter.counters.accepted.Add(uint64(len(spans)))
	dialSequence := exporter.config.tracker.snapshot()
	attemptContext, attempts := withAttemptCounter(ctx)
	err := exporter.inner.ExportSpans(attemptContext, spans)
	recordRetryAttempts(&exporter.counters, exporter.config.observer, observability.SignalTraces, uint64(len(spans)), attempts.Load())
	if err != nil {
		exporter.counters.failed.Add(uint64(len(spans)))
		observe(exporter.config.observer, SignalEvent{Signal: observability.SignalTraces, Outcome: SignalOutcomeExportFailed, Count: uint64(len(spans))})
		if exporter.config.tracker.unsafeSince(dialSequence) {
			return newError(ErrorUnsafeEndpoint, err)
		}
		return newError(ErrorExport, err)
	}
	exporter.counters.exported.Add(uint64(len(spans)))
	observe(exporter.config.observer, SignalEvent{Signal: observability.SignalTraces, Outcome: SignalOutcomeExported, Count: uint64(len(spans))})
	if canaryTraceID != "" {
		observeCanaryAcknowledgement(exporter.config.canary, CanaryAcknowledgement{
			Destination: exporter.destination, TraceID: canaryTraceID,
		})
	}
	return nil
}

func canarySpansForOTLPDestination(spans []sdktrace.ReadOnlySpan, destination string) []sdktrace.ReadOnlySpan {
	filtered := make([]sdktrace.ReadOnlySpan, 0, len(spans))
	for _, span := range spans {
		target := otlpCanaryDestination(span)
		if span != nil && (target == "" || target == destination) {
			filtered = append(filtered, span)
		}
	}
	return filtered
}

func partitionOTLPCanarySpans(spans []sdktrace.ReadOnlySpan) ([]sdktrace.ReadOnlySpan, [][]sdktrace.ReadOnlySpan) {
	regular := make([]sdktrace.ReadOnlySpan, 0, len(spans))
	byTrace := make(map[string][]sdktrace.ReadOnlySpan)
	order := make([]string, 0)
	for _, span := range spans {
		if !isOTLPCanarySpan(span) {
			regular = append(regular, span)
			continue
		}
		traceID := span.SpanContext().TraceID().String()
		if _, exists := byTrace[traceID]; !exists {
			order = append(order, traceID)
		}
		byTrace[traceID] = append(byTrace[traceID], span)
	}
	canaries := make([][]sdktrace.ReadOnlySpan, 0, len(order))
	for _, traceID := range order {
		canaries = append(canaries, byTrace[traceID])
	}
	return regular, canaries
}

func isOTLPCanarySpan(span sdktrace.ReadOnlySpan) bool {
	if span == nil {
		return false
	}
	for _, item := range span.Attributes() {
		if string(item.Key) == "defenseclaw.telemetry.canary" && item.Value.Type() == attribute.BOOL {
			return item.Value.AsBool()
		}
	}
	return false
}

func otlpCanaryDestination(span sdktrace.ReadOnlySpan) string {
	if !isOTLPCanarySpan(span) {
		return ""
	}
	for _, item := range span.Attributes() {
		if string(item.Key) == "defenseclaw.telemetry.canary.destination" && item.Value.Type() == attribute.STRING {
			return strings.TrimSpace(item.Value.AsString())
		}
	}
	return ""
}

func observeCanaryAcknowledgement(observer CanaryAcknowledgementObserver, event CanaryAcknowledgement) {
	if observer == nil || event.Destination == "" || event.TraceID == "" {
		return
	}
	defer func() { _ = recover() }()
	observer.ObserveOTLPCanaryAcknowledgement(event)
}

func (exporter *SpanExporter) Shutdown(ctx context.Context) error {
	if exporter == nil {
		return nil
	}
	if ctx == nil {
		return newError(ErrorShutdown, nil)
	}
	exporter.mu.Lock()
	if exporter.closed {
		exporter.mu.Unlock()
		return nil
	}
	exporter.closed = true
	exporter.mu.Unlock()
	err := exporter.inner.Shutdown(ctx)
	closeHTTPTransport(exporter.httpTransport)
	if exporter.connection != nil {
		if closeErr := exporter.connection.Close(); err == nil {
			err = closeErr
		}
	}
	if err != nil {
		return newError(ErrorShutdown, err)
	}
	return nil
}

func (exporter *SpanExporter) Counters() ExportCounters {
	if exporter == nil {
		return ExportCounters{}
	}
	return exporter.counters.snapshot()
}
