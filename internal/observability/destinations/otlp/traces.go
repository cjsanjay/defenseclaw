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
	"net/http"
	"sync"

	"github.com/defenseclaw/defenseclaw/internal/observability"
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
		return &SpanExporter{inner: exporter, httpTransport: transport, maxBytes: factory.config.Batch.MaxExportBatchBytes, config: config}, nil
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
	return &SpanExporter{inner: exporter, connection: connection, maxBytes: factory.config.Batch.MaxExportBatchBytes, config: config}, nil
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

type SpanExporter struct {
	inner         sdktrace.SpanExporter
	connection    *grpc.ClientConn
	httpTransport *http.Transport
	config        signalConfig
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
	return nil
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
