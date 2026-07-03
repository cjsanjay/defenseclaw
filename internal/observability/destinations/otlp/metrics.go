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
	"sync"

	"github.com/defenseclaw/defenseclaw/internal/observability"
	metricgrpc "go.opentelemetry.io/otel/exporters/otlp/otlpmetric/otlpmetricgrpc"
	metrichttp "go.opentelemetry.io/otel/exporters/otlp/otlpmetric/otlpmetrichttp"
	sdkmetric "go.opentelemetry.io/otel/sdk/metric"
	"go.opentelemetry.io/otel/sdk/metric/metricdata"
	"google.golang.org/grpc"
)

func (factory *Factory) NewMetricExporter(ctx context.Context) (*MetricExporter, error) {
	if ctx == nil {
		return nil, newError(ErrorInvalidConfig, nil)
	}
	config, err := factory.claim(observability.SignalMetrics)
	if err != nil {
		return nil, err
	}
	if config.protocol == ProtocolHTTP {
		initialRetry, maximumRetry := retryBounds(config.timeout)
		client, transport := newHTTPClient(config)
		exporter, buildErr := metrichttp.New(ctx,
			metrichttp.WithEndpointURL(signalURL(config)),
			metrichttp.WithURLPath(config.path),
			metrichttp.WithHeaders(cloneHeaders(config.headers)),
			metrichttp.WithTimeout(config.timeout),
			metrichttp.WithCompression(metrichttp.NoCompression),
			metrichttp.WithRetry(metrichttp.RetryConfig{
				Enabled: true, InitialInterval: initialRetry,
				MaxInterval: maximumRetry, MaxElapsedTime: config.timeout,
			}),
			metrichttp.WithHTTPClient(client),
			metrichttp.WithTemporalitySelector(config.temporality),
			metrichttp.WithAggregationSelector(config.aggregation),
		)
		if buildErr != nil {
			closeHTTPTransport(transport)
			return nil, newError(ErrorInitialization, buildErr)
		}
		return &MetricExporter{inner: exporter, httpTransport: transport, maxBytes: factory.config.Batch.MaxExportBatchBytes, config: config}, nil
	}
	connection, err := newGRPCConnection(config)
	if err != nil {
		return nil, err
	}
	initialRetry, maximumRetry := retryBounds(config.timeout)
	exporter, buildErr := metricgrpc.New(ctx,
		metricgrpc.WithGRPCConn(connection),
		metricgrpc.WithHeaders(cloneHeaders(config.headers)),
		metricgrpc.WithTimeout(config.timeout),
		metricgrpc.WithRetry(metricgrpc.RetryConfig{
			Enabled: true, InitialInterval: initialRetry,
			MaxInterval: maximumRetry, MaxElapsedTime: config.timeout,
		}),
		metricgrpc.WithTemporalitySelector(config.temporality),
		metricgrpc.WithAggregationSelector(config.aggregation),
	)
	if buildErr != nil {
		_ = connection.Close()
		return nil, newError(ErrorInitialization, buildErr)
	}
	return &MetricExporter{inner: exporter, connection: connection, maxBytes: factory.config.Batch.MaxExportBatchBytes, config: config}, nil
}

// MetricReader owns one independently shutdown periodic metric pipeline. Its
// SDKReader is registered with a MeterProvider without any package-global
// mutation; ForceFlush and Shutdown remain destination-local. Metric retry and
// backpressure stay in the SDK exporter/reader contract instead of adding a
// second DefenseClaw queue; MetricExporter still exposes final failure and
// per-item retry counts through its content-free counters and observer.
type MetricReader struct {
	reader *sdkmetric.PeriodicReader
	mu     sync.RWMutex
	closed bool
}

func (factory *Factory) NewPeriodicMetricReader(ctx context.Context) (*MetricReader, error) {
	exporter, err := factory.NewMetricExporter(ctx)
	if err != nil {
		return nil, err
	}
	interval := factory.config.Batch.ExportInterval
	if interval <= 0 {
		cleanup, cancel := cleanupContext(ctx, factory.config.Timeout)
		_ = exporter.Shutdown(cleanup)
		cancel()
		return nil, newError(ErrorInvalidConfig, nil)
	}
	return &MetricReader{reader: sdkmetric.NewPeriodicReader(exporter, sdkmetric.WithInterval(interval))}, nil
}

func (reader *MetricReader) SDKReader() sdkmetric.Reader {
	if reader == nil {
		return nil
	}
	return reader.reader
}

func (reader *MetricReader) ForceFlush(ctx context.Context) error {
	if reader == nil || reader.reader == nil {
		return nil
	}
	if ctx == nil {
		return newError(ErrorFlush, nil)
	}
	reader.mu.RLock()
	defer reader.mu.RUnlock()
	if reader.closed {
		return newError(ErrorFlush, nil)
	}
	if err := reader.reader.ForceFlush(ctx); err != nil {
		return newError(ErrorFlush, err)
	}
	return nil
}

func (reader *MetricReader) Shutdown(ctx context.Context) error {
	if reader == nil || reader.reader == nil {
		return nil
	}
	if ctx == nil {
		return newError(ErrorShutdown, nil)
	}
	reader.mu.Lock()
	defer reader.mu.Unlock()
	if reader.closed {
		return nil
	}
	reader.closed = true
	if err := reader.reader.Shutdown(ctx); err != nil && !errors.Is(err, sdkmetric.ErrReaderShutdown) {
		return newError(ErrorShutdown, err)
	}
	return nil
}

type MetricExporter struct {
	inner         sdkmetric.Exporter
	connection    *grpc.ClientConn
	httpTransport *http.Transport
	config        signalConfig
	maxBytes      int
	counters      mutableCounters
	mu            sync.RWMutex
	closed        bool
}

func (exporter *MetricExporter) Temporality(kind sdkmetric.InstrumentKind) metricdata.Temporality {
	return exporter.inner.Temporality(kind)
}

func (exporter *MetricExporter) Aggregation(kind sdkmetric.InstrumentKind) sdkmetric.Aggregation {
	return exporter.inner.Aggregation(kind)
}

// Export preflights a strict conservative protobuf bound before invoking the
// SDK exporter, so an oversized collection is rejected before the SDK allocates
// its OTLP request. A ResourceMetrics collection is intentionally not split:
// partitioning cumulative/delta streams outside the SDK reader can change
// temporality and reset semantics. Counters and the observer expose that
// bounded rejection to destination health without retaining metric content.
func (exporter *MetricExporter) Export(ctx context.Context, metrics *metricdata.ResourceMetrics) error {
	if exporter == nil || ctx == nil {
		return newError(ErrorExport, nil)
	}
	exporter.mu.RLock()
	closed := exporter.closed
	defer exporter.mu.RUnlock()
	if closed {
		return newError(ErrorExport, nil)
	}
	count := metricCount(metrics)
	bound, ok := conservativeMetricBytes(metrics)
	if !ok || bound > exporter.maxBytes {
		exporter.counters.rejectedOversize.Add(count)
		observe(exporter.config.observer, SignalEvent{Signal: observability.SignalMetrics, Outcome: SignalOutcomeRejectedOversize, Count: count})
		return newError(ErrorExport, nil)
	}
	exporter.counters.accepted.Add(count)
	dialSequence := exporter.config.tracker.snapshot()
	attemptContext, attempts := withAttemptCounter(ctx)
	err := exporter.inner.Export(attemptContext, metrics)
	recordRetryAttempts(&exporter.counters, exporter.config.observer, observability.SignalMetrics, count, attempts.Load())
	if err != nil {
		exporter.counters.failed.Add(count)
		observe(exporter.config.observer, SignalEvent{Signal: observability.SignalMetrics, Outcome: SignalOutcomeExportFailed, Count: count})
		if exporter.config.tracker.unsafeSince(dialSequence) {
			return newError(ErrorUnsafeEndpoint, err)
		}
		return newError(ErrorExport, err)
	}
	exporter.counters.exported.Add(count)
	observe(exporter.config.observer, SignalEvent{Signal: observability.SignalMetrics, Outcome: SignalOutcomeExported, Count: count})
	return nil
}

func (exporter *MetricExporter) ForceFlush(ctx context.Context) error {
	if exporter == nil || ctx == nil {
		return newError(ErrorFlush, nil)
	}
	exporter.mu.RLock()
	defer exporter.mu.RUnlock()
	if exporter.closed {
		return newError(ErrorFlush, nil)
	}
	if err := exporter.inner.ForceFlush(ctx); err != nil {
		return newError(ErrorFlush, err)
	}
	return nil
}

func (exporter *MetricExporter) Shutdown(ctx context.Context) error {
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

func (exporter *MetricExporter) Counters() ExportCounters {
	if exporter == nil {
		return ExportCounters{}
	}
	return exporter.counters.snapshot()
}

func metricCount(metrics *metricdata.ResourceMetrics) uint64 {
	if metrics == nil {
		return 1
	}
	var count uint64
	for _, scope := range metrics.ScopeMetrics {
		count += uint64(len(scope.Metrics))
	}
	if count == 0 {
		return 1
	}
	return count
}
