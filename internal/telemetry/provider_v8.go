// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// SPDX-License-Identifier: Apache-2.0

package telemetry

import (
	"context"
	"errors"
	"fmt"
	"math"
	"os"
	"reflect"
	"runtime"
	"runtime/debug"
	"sort"
	"strconv"
	"strings"
	"sync/atomic"
	"time"
	"unicode/utf8"

	"github.com/google/uuid"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	logNoop "go.opentelemetry.io/otel/log/noop"
	"go.opentelemetry.io/otel/metric"
	metricNoop "go.opentelemetry.io/otel/metric/noop"
	sdkmetric "go.opentelemetry.io/otel/sdk/metric"
	"go.opentelemetry.io/otel/sdk/metric/exemplar"
	"go.opentelemetry.io/otel/sdk/metric/metricdata"
	"go.opentelemetry.io/otel/sdk/resource"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	"go.opentelemetry.io/otel/trace"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/observability"
	"github.com/defenseclaw/defenseclaw/internal/observability/runtimegraph"
)

// V8ProviderComponentName is the stable runtime-graph lookup key for the
// generation-owned OTel provider.
const V8ProviderComponentName = "otel-provider"

const (
	v8CanaryOperationAttribute = "defenseclaw.telemetry.canary.operation"
	v8CanaryOperationValue     = "runtime-pipeline-test"
)

// V8SpanProcessorFactory creates processors owned by exactly one graph
// generation. A factory is used instead of accepting reusable processor
// instances so reload cannot accidentally share queues across generations.
type V8SpanProcessorFactory func(generation uint64) (sdktrace.SpanProcessor, error)

// V8MetricReaderSpec is the complete process-wide policy handed to every
// independently prepared reader. The default compiled plan yields 60-second
// delta collection and an explicit per-instrument cardinality ceiling.
type V8MetricReaderSpec struct {
	ExportInterval   time.Duration
	ExportTimeout    time.Duration
	Temporality      metricdata.Temporality
	CardinalityLimit int
}

// V8MetricReaderFactory creates one reader owned by exactly one graph
// generation. Multiple factories allow later OTLP destinations to own
// independent readers without sharing providers or mutating OTel globals.
type V8MetricReaderFactory func(generation uint64, spec V8MetricReaderSpec) (sdkmetric.Reader, error)

// V8GenerationPipelines is one detached set of signal pipelines prepared from
// the exact immutable plan being installed. The provider takes ownership of
// every returned non-nil processor and reader, including defensive cleanup of
// a returned partial set when the factory reports failure. A factory must still
// release any allocated child that it does not include in the returned set.
type V8GenerationPipelines struct {
	SpanProcessors []sdktrace.SpanProcessor
	MetricReaders  []sdkmetric.Reader
	// CanaryAcknowledged queries only the exact candidate generation's
	// destination acknowledgement registry. It must be nonblocking, panic-safe
	// at the provider boundary, and return false after its processors retire.
	CanaryAcknowledged func(destination, traceID string) bool
}

// V8GenerationPipelineFactory is the production destination-assembly seam.
// Unlike the lower-level test factories above, it receives the exact plan and
// context for this candidate generation, allowing reload to prepare independent
// OTLP/Prometheus processors and readers without ambient state or reusable
// queues.
type V8GenerationPipelineFactory func(
	context.Context,
	*config.ObservabilityV8Plan,
	uint64,
	V8MetricReaderSpec,
) (V8GenerationPipelines, error)

// SamplingDecisionDebug is the bounded, content-free sampler decision exposed
// to tests and diagnostics. Reason and Decision belong to closed vocabularies;
// names, identifiers, attributes, and trace IDs are never included.
type SamplingDecisionDebug struct {
	Reason   string
	Decision string
}

// V8ProviderOptions contains process inputs that do not belong in config.yaml.
// It deliberately has no destination or transport fields: delivery is owned by
// the graph's destination components, not by this provider substrate.
type V8ProviderOptions struct {
	Version               string
	Environment           string
	ServiceInstanceID     string
	DefenseClawInstanceID string
	TenantID              string
	WorkspaceID           string
	DeploymentMode        string
	ConnectorMode         string
	DiscoverySource       string
	DeviceKeyFile         string
	SpanProcessorFactory  V8SpanProcessorFactory
	MetricReaderFactories []V8MetricReaderFactory
	GenerationPipelines   V8GenerationPipelineFactory
	// PrepareCleanupTimeout bounds defensive cleanup when a later reader or
	// runtimegraph acquisition rejects an otherwise prepared candidate.
	// Zero uses the reviewed five-second default.
	PrepareCleanupTimeout time.Duration
	// SamplingObserver runs synchronously on the span-start path. It MUST be
	// nonblocking. Panics are contained and cannot affect sampling decisions.
	SamplingObserver func(SamplingDecisionDebug)
}

// V8ProviderErrorCode is a closed, content-free provider failure identity.
type V8ProviderErrorCode string

const (
	V8ProviderErrorInitialization          V8ProviderErrorCode = "initialization_failed"
	V8ProviderErrorProcessorInitialization V8ProviderErrorCode = "processor_initialization_failed"
	V8ProviderErrorReaderInitialization    V8ProviderErrorCode = "reader_initialization_failed"
	V8ProviderErrorPipelineInitialization  V8ProviderErrorCode = "signal_pipeline_initialization_failed"
	V8ProviderErrorFlush                   V8ProviderErrorCode = "flush_failed"
	V8ProviderErrorShutdown                V8ProviderErrorCode = "shutdown_failed"
)

// V8ProviderError never retains backend diagnostics. It preserves only the
// standard context cancellation identity when a backend reports cancellation.
type V8ProviderError struct {
	code  V8ProviderErrorCode
	cause error
}

func (err *V8ProviderError) Error() string {
	if err == nil {
		return "telemetry: v8 provider operation failed"
	}
	return "telemetry: v8 provider operation failed: " + string(err.code)
}

func (err *V8ProviderError) Code() V8ProviderErrorCode {
	if err == nil {
		return ""
	}
	return err.code
}

func (err *V8ProviderError) Unwrap() error {
	if err == nil {
		return nil
	}
	return err.cause
}

func newV8ProviderError(code V8ProviderErrorCode, backend error) *V8ProviderError {
	return &V8ProviderError{code: code, cause: v8ContextCause(backend)}
}

func v8ContextCause(err error) error {
	switch {
	case errors.Is(err, context.Canceled):
		return context.Canceled
	case errors.Is(err, context.DeadlineExceeded):
		return context.DeadlineExceeded
	default:
		return nil
	}
}

type v8ProviderState struct {
	active     atomic.Bool
	generation uint64
	planDigest string
	collect    map[observability.Bucket]bool
	metrics    map[observability.Bucket]bool
	metricSpec V8MetricReaderSpec
	limits     config.ObservabilityV8TraceLimitsSource
	debug      *v8SamplingDebug
	canaryAck  func(destination, traceID string) bool
}

// MetricBucketEnabled is the collection-before-construction predicate for
// v8 instruments. Legacy providers preserve their process-wide behavior.
func (p *Provider) MetricBucketEnabled(bucket observability.Bucket) bool {
	if p == nil || !p.Enabled() || p.metrics == nil {
		return false
	}
	if p.v8 == nil {
		return p.meterProvider != nil
	}
	return observability.IsBucket(bucket) && p.v8.metrics[bucket]
}

// MeterForBucket returns the generation-owned meter only for a collected
// bucket. Producers can therefore avoid constructing expensive attributes.
func (p *Provider) MeterForBucket(bucket observability.Bucket) metric.Meter {
	if !p.MetricBucketEnabled(bucket) {
		return metricNoop.NewMeterProvider().Meter("defenseclaw")
	}
	if bounded, ok := p.meter.(*v8MetricMeter); ok {
		return bounded.forBucket(bucket)
	}
	return p.meter
}

func (p *Provider) V8MetricPolicy() (V8MetricReaderSpec, bool) {
	if p == nil || p.v8 == nil || len(p.v8.metrics) == 0 {
		return V8MetricReaderSpec{}, false
	}
	return p.v8.metricSpec, true
}

// TraceLimits returns the effective complete v8 limits. The OTel SDK enforces
// the native span/event/link limits; projection-specific byte/message limits
// are retained here for producer adapters that enforce them before export.
func (p *Provider) TraceLimits() config.ObservabilityV8TraceLimitsSource {
	if p == nil || p.v8 == nil {
		return config.ObservabilityV8TraceLimitsSource{}
	}
	return p.v8.limits
}

// V8PlanBinding identifies the immutable plan generation captured by this
// provider. It lets graph adapters reject cross-generation wiring without
// exposing or mutating the plan itself.
func (p *Provider) V8PlanBinding() (digest string, generation uint64, ok bool) {
	if p == nil || p.v8 == nil {
		return "", 0, false
	}
	return p.v8.planDigest, p.v8.generation, true
}

// TraceBucketEnabled is the collection-before-construction predicate. For a
// v8 provider it consults the immutable plan captured by this graph generation.
// Legacy providers retain their previous process-wide traces-enabled behavior.
func (p *Provider) TraceBucketEnabled(bucket observability.Bucket) bool {
	if p == nil || !p.TracesEnabled() {
		return false
	}
	if p.v8 == nil {
		return true
	}
	return observability.IsBucket(bucket) && p.v8.collect[bucket]
}

// TracerForBucket is the migration seam for producers that create their own
// spans. A disabled collection bucket receives a no-op tracer before it can
// construct names, attributes, events, or content.
func (p *Provider) TracerForBucket(bucket observability.Bucket) trace.Tracer {
	if !p.TraceBucketEnabled(bucket) {
		return noopTracer()
	}
	return p.Tracer()
}

// TraceExportEligible is the hard boundary between sampling and future route
// evaluation. Routes may narrow this result but cannot resurrect a span that
// collection or sampling already dropped.
func (p *Provider) TraceExportEligible(bucket observability.Bucket, spanContext trace.SpanContext) bool {
	return p.TraceBucketEnabled(bucket) && spanContext.IsValid() && spanContext.IsSampled()
}

// SamplingDebugSnapshot reports only fixed-vocabulary aggregate counts.
func (p *Provider) SamplingDebugSnapshot() []SamplingDebugCount {
	if p == nil || p.v8 == nil || p.v8.debug == nil {
		return nil
	}
	return p.v8.debug.snapshot()
}

// SamplingDebugCount is one stable aggregate sampler counter.
type SamplingDebugCount struct {
	Reason   string
	Decision string
	Count    uint64
}

func noopTracer() trace.Tracer {
	return trace.NewNoopTracerProvider().Tracer("defenseclaw")
}

func (p *Provider) v8StartAttributes(bucket observability.Bucket) []attribute.KeyValue {
	if p == nil || p.v8 == nil {
		return nil
	}
	return []attribute.KeyValue{
		attribute.String("defenseclaw.bucket", string(bucket)),
		attribute.Int64("defenseclaw.config.generation", int64(p.v8.generation)),
	}
}

// NewProviderV8Inactive builds a plan-bound provider without publishing it or
// mutating OTel package globals. The runtime graph activates it only after the
// complete candidate graph has been atomically published.
func NewProviderV8Inactive(
	ctx context.Context,
	plan *config.ObservabilityV8Plan,
	generation uint64,
	options V8ProviderOptions,
) (*Provider, error) {
	if ctx == nil || plan == nil || generation == 0 {
		return nil, errors.New("telemetry: invalid v8 provider input")
	}
	if err := ctx.Err(); err != nil {
		return nil, newV8ProviderError(V8ProviderErrorInitialization, err)
	}
	snapshot := plan.Snapshot()
	if snapshot.BucketCatalogVersion != observability.CurrentBucketCatalogVersion {
		return nil, fmt.Errorf("telemetry: unsupported bucket catalog version %d", snapshot.BucketCatalogVersion)
	}
	traceCollect := make(map[observability.Bucket]bool, len(snapshot.Buckets))
	metricCollect := make(map[observability.Bucket]bool, len(snapshot.Buckets))
	for _, bucket := range snapshot.Buckets {
		if bucket.Collect.Traces {
			traceCollect[bucket.Bucket] = true
		}
		if bucket.Collect.Metrics {
			metricCollect[bucket.Bucket] = true
		}
	}
	metricSpec := v8MetricReaderSpec(snapshot.MetricPolicy)

	debug := newV8SamplingDebug(options.SamplingObserver)
	sampler, err := newV8Sampler(snapshot.TracePolicy.Sampler, snapshot.TracePolicy.SamplerArg, debug)
	if err != nil {
		return nil, err
	}

	res := buildV8Resource(snapshot, options)
	limits := snapshot.TracePolicy.Limits
	preparedProcessors := make([]sdktrace.SpanProcessor, 0, 1)
	preparedReaders := make([]sdkmetric.Reader, 0, len(options.MetricReaderFactories))
	pipelines := V8GenerationPipelines{}
	cleanupPrepared := func() {
		v8BoundedPrepareCleanup(options.PrepareCleanupTimeout, func(cleanupContext context.Context) {
			for index := len(preparedReaders) - 1; index >= 0; index-- {
				if preparedReaders[index] != nil {
					_ = preparedReaders[index].Shutdown(cleanupContext)
				}
			}
		})
		v8BoundedPrepareCleanup(options.PrepareCleanupTimeout, func(cleanupContext context.Context) {
			for index := len(preparedProcessors) - 1; index >= 0; index-- {
				if preparedProcessors[index] != nil {
					_ = preparedProcessors[index].Shutdown(cleanupContext)
				}
			}
		})
	}
	if options.GenerationPipelines != nil && (len(traceCollect) > 0 || len(metricCollect) > 0) {
		var pipelineErr error
		pipelines, pipelineErr = callV8GenerationPipelineFactory(
			options.GenerationPipelines, ctx, plan, generation, metricSpec,
		)
		preparedProcessors = append(preparedProcessors, pipelines.SpanProcessors...)
		preparedReaders = append(preparedReaders, pipelines.MetricReaders...)
		if pipelineErr != nil || !validV8GenerationPipelines(pipelines, len(traceCollect) > 0, len(metricCollect) > 0) {
			cleanupPrepared()
			return nil, newV8ProviderError(V8ProviderErrorPipelineInitialization, pipelineErr)
		}
		if err := ctx.Err(); err != nil {
			cleanupPrepared()
			return nil, newV8ProviderError(V8ProviderErrorPipelineInitialization, err)
		}
	}
	if options.SpanProcessorFactory != nil {
		processor, processorErr := callV8SpanProcessorFactory(options.SpanProcessorFactory, generation)
		if processorErr != nil || processor == nil {
			cleanupPrepared()
			return nil, newV8ProviderError(V8ProviderErrorProcessorInitialization, processorErr)
		}
		preparedProcessors = append(preparedProcessors, processor)
	}
	traceOptions := []sdktrace.TracerProviderOption{
		sdktrace.WithResource(res),
		sdktrace.WithSampler(sampler),
		sdktrace.WithSpanLimits(sdktrace.SpanLimits{
			AttributeValueLengthLimit:   limits.MaxAttributeValueBytes,
			AttributeCountLimit:         limits.MaxAttributesPerSpan,
			EventCountLimit:             limits.MaxEventsPerSpan,
			LinkCountLimit:              limits.MaxLinksPerSpan,
			AttributePerEventCountLimit: limits.MaxAttributesPerEvent,
			AttributePerLinkCountLimit:  limits.MaxAttributesPerEvent,
		}),
	}
	for _, processor := range preparedProcessors {
		traceOptions = append(traceOptions, sdktrace.WithSpanProcessor(processor))
	}

	tracerProvider := sdktrace.NewTracerProvider(traceOptions...)
	version := strings.TrimSpace(options.Version)
	tracerOptions := make([]trace.TracerOption, 0, 1)
	if version != "" {
		tracerOptions = append(tracerOptions, trace.WithInstrumentationVersion(version))
	}
	boundedTracerProvider := &v8ByteBoundedTracerProvider{
		TracerProvider: tracerProvider, maxBytes: limits.MaxAttributeValueBytes,
		maxStacktraceBytes: limits.MaxStacktraceBytes,
	}
	tracer := boundedTracerProvider.Tracer("defenseclaw", tracerOptions...)
	logger := logNoop.NewLoggerProvider().Logger("defenseclaw")
	meter := metricNoop.NewMeterProvider().Meter("defenseclaw")
	var meterProvider *sdkmetric.MeterProvider
	var metrics *metricsSet
	if len(metricCollect) > 0 {
		meterOptions := []sdkmetric.Option{
			sdkmetric.WithResource(res),
			sdkmetric.WithCardinalityLimit(v8MetricCardinalityLimit),
			sdkmetric.WithExemplarFilter(exemplar.AlwaysOffFilter),
		}
		for _, reader := range preparedReaders {
			meterOptions = append(meterOptions, sdkmetric.WithReader(reader))
		}
		cleanupReaders := func() {
			v8BoundedPrepareCleanup(options.PrepareCleanupTimeout, func(cleanupContext context.Context) {
				for index := len(preparedReaders) - 1; index >= 0; index-- {
					_ = preparedReaders[index].Shutdown(cleanupContext)
				}
			})
		}
		for _, readerFactory := range options.MetricReaderFactories {
			if readerFactory == nil {
				cleanupReaders()
				v8BoundedPrepareCleanup(options.PrepareCleanupTimeout, func(cleanupContext context.Context) {
					_ = tracerProvider.Shutdown(cleanupContext)
				})
				return nil, newV8ProviderError(V8ProviderErrorReaderInitialization, nil)
			}
			reader, readerErr := callV8MetricReaderFactory(readerFactory, generation, metricSpec)
			if readerErr != nil || reader == nil {
				cleanupReaders()
				v8BoundedPrepareCleanup(options.PrepareCleanupTimeout, func(cleanupContext context.Context) {
					_ = tracerProvider.Shutdown(cleanupContext)
				})
				return nil, newV8ProviderError(V8ProviderErrorReaderInitialization, readerErr)
			}
			preparedReaders = append(preparedReaders, reader)
			meterOptions = append(meterOptions, sdkmetric.WithReader(reader))
		}
		meterProvider = sdkmetric.NewMeterProvider(meterOptions...)
		boundedMeter := newV8MetricMeter(meterProvider.Meter("defenseclaw"), metricCollect)
		meter = boundedMeter
		var metricsErr error
		metrics, metricsErr = newMetricsSet(boundedMeter)
		if metricsErr != nil {
			v8BoundedPrepareCleanup(options.PrepareCleanupTimeout, func(cleanupContext context.Context) {
				_ = meterProvider.Shutdown(cleanupContext)
			})
			v8BoundedPrepareCleanup(options.PrepareCleanupTimeout, func(cleanupContext context.Context) {
				_ = tracerProvider.Shutdown(cleanupContext)
			})
			return nil, fmt.Errorf("telemetry: register v8 metrics: %w", metricsErr)
		}
	}
	return &Provider{
		res: res, tracerProvider: tracerProvider, tracer: tracer, meterProvider: meterProvider,
		logger: logger, meter: meter, metrics: metrics, enabled: true,
		v8: &v8ProviderState{
			generation: generation, planDigest: plan.Digest(), collect: traceCollect,
			metrics: metricCollect, metricSpec: metricSpec, limits: limits, debug: debug,
			canaryAck: pipelines.CanaryAcknowledged,
		},
	}, nil
}

func callV8GenerationPipelineFactory(
	factory V8GenerationPipelineFactory,
	ctx context.Context,
	plan *config.ObservabilityV8Plan,
	generation uint64,
	spec V8MetricReaderSpec,
) (pipelines V8GenerationPipelines, err error) {
	defer func() {
		if recover() != nil {
			pipelines = V8GenerationPipelines{}
			err = newV8ProviderError(V8ProviderErrorPipelineInitialization, nil)
		}
	}()
	return factory(ctx, plan, generation, spec)
}

func callV8SpanProcessorFactory(
	factory V8SpanProcessorFactory,
	generation uint64,
) (processor sdktrace.SpanProcessor, err error) {
	defer func() {
		if recover() != nil {
			processor = nil
			err = newV8ProviderError(V8ProviderErrorProcessorInitialization, nil)
		}
	}()
	return factory(generation)
}

func callV8MetricReaderFactory(
	factory V8MetricReaderFactory,
	generation uint64,
	spec V8MetricReaderSpec,
) (reader sdkmetric.Reader, err error) {
	defer func() {
		if recover() != nil {
			reader = nil
			err = newV8ProviderError(V8ProviderErrorReaderInitialization, nil)
		}
	}()
	return factory(generation, spec)
}

func validV8GenerationPipelines(
	pipelines V8GenerationPipelines,
	tracesCollected bool,
	metricsCollected bool,
) bool {
	if !tracesCollected && len(pipelines.SpanProcessors) != 0 {
		return false
	}
	if pipelines.CanaryAcknowledged != nil && (!tracesCollected || len(pipelines.SpanProcessors) == 0) {
		return false
	}
	if !metricsCollected && len(pipelines.MetricReaders) != 0 {
		return false
	}
	for _, processor := range pipelines.SpanProcessors {
		if processor == nil || reflect.ValueOf(processor).Kind() == reflect.Pointer && reflect.ValueOf(processor).IsNil() {
			return false
		}
	}
	for _, reader := range pipelines.MetricReaders {
		if reader == nil || reflect.ValueOf(reader).Kind() == reflect.Pointer && reflect.ValueOf(reader).IsNil() {
			return false
		}
	}
	return true
}

const v8DefaultPrepareCleanupTimeout = 5 * time.Second

func v8BoundedPrepareCleanup(timeout time.Duration, cleanup func(context.Context)) {
	if cleanup == nil {
		return
	}
	if timeout <= 0 {
		timeout = v8DefaultPrepareCleanupTimeout
	}
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	done := make(chan struct{})
	go func() {
		defer close(done)
		defer func() { _ = recover() }()
		cleanup(ctx)
	}()
	select {
	case <-done:
	case <-ctx.Done():
	}
}

func v8MetricReaderSpec(policy config.ObservabilityV8EffectiveMetricPolicy) V8MetricReaderSpec {
	temporality := metricdata.DeltaTemporality
	if policy.Temporality == "cumulative" {
		temporality = metricdata.CumulativeTemporality
	}
	return V8MetricReaderSpec{
		ExportInterval: time.Duration(policy.ExportIntervalSeconds) * time.Second,
		ExportTimeout:  30 * time.Second, Temporality: temporality,
		CardinalityLimit: v8MetricCardinalityLimit,
	}
}

// NewV8PeriodicMetricReader builds a reader with no environment-derived
// interval, timeout, temporality, or cardinality behavior.
func NewV8PeriodicMetricReader(exporter sdkmetric.Exporter, spec V8MetricReaderSpec) (*sdkmetric.PeriodicReader, error) {
	if exporter == nil || spec.ExportInterval <= 0 || spec.ExportTimeout <= 0 || spec.CardinalityLimit <= 0 ||
		(spec.Temporality != metricdata.DeltaTemporality && spec.Temporality != metricdata.CumulativeTemporality) {
		return nil, errors.New("telemetry: invalid v8 metric reader input")
	}
	for _, kind := range []sdkmetric.InstrumentKind{
		sdkmetric.InstrumentKindCounter, sdkmetric.InstrumentKindUpDownCounter,
		sdkmetric.InstrumentKindHistogram, sdkmetric.InstrumentKindGauge,
		sdkmetric.InstrumentKindObservableCounter, sdkmetric.InstrumentKindObservableUpDownCounter,
		sdkmetric.InstrumentKindObservableGauge,
	} {
		if exporter.Temporality(kind) != spec.Temporality {
			return nil, errors.New("telemetry: metric exporter temporality conflicts with the v8 plan")
		}
	}
	return sdkmetric.NewPeriodicReader(
		exporter,
		sdkmetric.WithInterval(spec.ExportInterval),
		sdkmetric.WithTimeout(spec.ExportTimeout),
		sdkmetric.WithCardinalityLimitSelector(func(sdkmetric.InstrumentKind) (int, bool) {
			return spec.CardinalityLimit, false
		}),
	), nil
}

func buildV8Resource(snapshot config.ObservabilityV8EffectivePlan, options V8ProviderOptions) *resource.Resource {
	hostname, _ := os.Hostname()
	instanceID := strings.TrimSpace(options.ServiceInstanceID)
	if instanceID == "" {
		instanceID = uuid.NewString()
	}
	defenseClawInstanceID := strings.TrimSpace(options.DefenseClawInstanceID)
	if defenseClawInstanceID == "" {
		defenseClawInstanceID = instanceID
	}
	values := map[string]string{
		"service.name":            "defenseclaw",
		"service.version":         strings.TrimSpace(options.Version),
		"service.namespace":       "defenseclaw",
		"service.instance.id":     instanceID,
		"host.name":               hostname,
		"host.arch":               runtime.GOARCH,
		"os.type":                 runtime.GOOS,
		"defenseclaw.instance.id": defenseClawInstanceID,
	}
	for key, value := range snapshot.ResourceAttributes {
		if v8AlwaysProcessOwnedResourceKeys[key] {
			continue
		}
		values[key] = value
	}
	setTrusted := func(key, value string) {
		if value = strings.TrimSpace(value); value != "" {
			values[key] = value
		}
	}
	setTrusted("tenant.id", options.TenantID)
	setTrusted("workspace.id", options.WorkspaceID)
	setTrusted("deployment.mode", options.DeploymentMode)
	setTrusted("defenseclaw.claw.mode", options.ConnectorMode)
	setTrusted("discovery.source", options.DiscoverySource)
	if environment := strings.TrimSpace(options.Environment); environment != "" {
		values["deployment.environment.name"] = environment
		values["deployment.environment"] = environment
	}
	if fingerprint := deviceFingerprint(strings.TrimSpace(options.DeviceKeyFile)); fingerprint != "" {
		values["defenseclaw.device.id"] = fingerprint
	}
	keys := make([]string, 0, len(values))
	for key := range values {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	attrs := make([]attribute.KeyValue, 0, len(keys))
	for _, key := range keys {
		if values[key] != "" {
			attrs = append(attrs, attribute.String(key, values[key]))
		}
	}
	return resource.NewWithAttributes("", attrs...)
}

var v8AlwaysProcessOwnedResourceKeys = map[string]bool{
	"service.version": true, "service.namespace": true, "service.instance.id": true,
	"host.name": true, "host.arch": true, "os.type": true,
	"defenseclaw.instance.id": true,
	"deployment.mode":         true, "defenseclaw.claw.mode": true,
	"defenseclaw.claw.home_dir": true, "discovery.source": true,
	"defenseclaw.device.id": true,
}

// V8ProviderFactory owns the process-stable service.instance.id while each
// Prepare call creates a fresh generation-owned SDK provider and processor.
type V8ProviderFactory struct {
	options V8ProviderOptions
}

func NewV8ProviderFactory(options V8ProviderOptions) *V8ProviderFactory {
	if strings.TrimSpace(options.ServiceInstanceID) == "" {
		options.ServiceInstanceID = uuid.NewString()
	}
	options.MetricReaderFactories = append([]V8MetricReaderFactory(nil), options.MetricReaderFactories...)
	return &V8ProviderFactory{options: options}
}

func (*V8ProviderFactory) Name() string { return V8ProviderComponentName }

func (factory *V8ProviderFactory) Prepare(
	ctx context.Context,
	input runtimegraph.BuildInput,
	acquisitions *runtimegraph.Acquisitions,
) (runtimegraph.Component, error) {
	if factory == nil {
		return nil, errors.New("telemetry: nil v8 provider factory")
	}
	provider, err := NewProviderV8Inactive(ctx, input.Config.Plan, input.Generation, factory.options)
	if err != nil {
		return nil, err
	}
	if err := acquisitions.Register("otel-sdk-provider", provider.Shutdown); err != nil {
		v8BoundedPrepareCleanup(factory.options.PrepareCleanupTimeout, func(cleanupContext context.Context) {
			_ = provider.Shutdown(cleanupContext)
		})
		return nil, err
	}
	return &V8ProviderComponent{provider: provider}, nil
}

// V8ProviderComponent is a graph-generation handle. Provider is available only
// while this component accepts intake.
type V8ProviderComponent struct {
	provider *Provider
	closed   atomic.Bool
}

func (component *V8ProviderComponent) Activate() {
	if component == nil || component.provider == nil || component.closed.Load() {
		return
	}
	component.provider.v8.active.Store(true)
}

func (component *V8ProviderComponent) Provider() (*Provider, bool) {
	if component == nil || component.provider == nil || component.closed.Load() || !component.provider.Enabled() {
		return nil, false
	}
	return component.provider, true
}

func (component *V8ProviderComponent) StopIntake(context.Context) error {
	if component != nil && component.provider != nil && component.provider.v8 != nil {
		component.provider.v8.active.Store(false)
	}
	return nil
}

func (component *V8ProviderComponent) Drain(ctx context.Context) error {
	if component == nil || component.provider == nil {
		return nil
	}
	if component.provider.tracerProvider != nil {
		if err := component.provider.tracerProvider.ForceFlush(ctx); err != nil {
			return newV8ProviderError(V8ProviderErrorFlush, err)
		}
	}
	if component.provider.meterProvider != nil {
		if err := component.provider.meterProvider.ForceFlush(ctx); err != nil {
			return newV8ProviderError(V8ProviderErrorFlush, err)
		}
	}
	return nil
}

func (component *V8ProviderComponent) Close(context.Context) error {
	if component != nil {
		component.closed.Store(true)
	}
	return nil
}

// V8ProviderFromLease binds a producer to exactly one active graph generation.
func V8ProviderFromLease(lease *runtimegraph.Lease) (*Provider, bool) {
	if lease == nil {
		return nil, false
	}
	value, ok := lease.Component(V8ProviderComponentName)
	if !ok {
		return nil, false
	}
	component, ok := value.(*V8ProviderComponent)
	if !ok {
		return nil, false
	}
	return component.Provider()
}

const (
	v8SamplingReasonAlwaysOn        = "always_on"
	v8SamplingReasonAlwaysOff       = "always_off"
	v8SamplingReasonTraceIDRatio    = "trace_id_ratio"
	v8SamplingReasonParentSampled   = "parent_sampled"
	v8SamplingReasonParentUnsampled = "parent_unsampled"
	v8SamplingReasonTargetedCanary  = "targeted_canary"
	v8SamplingDecisionSampled       = "sampled"
	v8SamplingDecisionUnsampled     = "unsampled"
)

type v8SamplingDebug struct {
	observer func(SamplingDecisionDebug)
	counts   [12]atomic.Uint64
}

func newV8SamplingDebug(observer func(SamplingDecisionDebug)) *v8SamplingDebug {
	return &v8SamplingDebug{observer: observer}
}

var v8SamplingReasons = [...]string{
	v8SamplingReasonAlwaysOn,
	v8SamplingReasonAlwaysOff,
	v8SamplingReasonTraceIDRatio,
	v8SamplingReasonParentSampled,
	v8SamplingReasonParentUnsampled,
	v8SamplingReasonTargetedCanary,
}

func (debug *v8SamplingDebug) record(reason string, decision sdktrace.SamplingDecision) {
	if debug == nil {
		return
	}
	reasonIndex := -1
	for index, candidate := range v8SamplingReasons {
		if candidate == reason {
			reasonIndex = index
			break
		}
	}
	if reasonIndex < 0 {
		return
	}
	decisionName := v8SamplingDecisionUnsampled
	decisionIndex := 0
	if decision == sdktrace.RecordAndSample {
		decisionName = v8SamplingDecisionSampled
		decisionIndex = 1
	}
	debug.counts[reasonIndex*2+decisionIndex].Add(1)
	if debug.observer != nil {
		func() {
			defer func() { _ = recover() }()
			debug.observer(SamplingDecisionDebug{Reason: reason, Decision: decisionName})
		}()
	}
}

func (debug *v8SamplingDebug) snapshot() []SamplingDebugCount {
	result := make([]SamplingDebugCount, 0, len(debug.counts))
	for reasonIndex, reason := range v8SamplingReasons {
		for decisionIndex, decision := range [...]string{v8SamplingDecisionUnsampled, v8SamplingDecisionSampled} {
			count := debug.counts[reasonIndex*2+decisionIndex].Load()
			if count > 0 {
				result = append(result, SamplingDebugCount{Reason: reason, Decision: decision, Count: count})
			}
		}
	}
	return result
}

type v8Sampler struct {
	name   string
	ratio  sdktrace.Sampler
	debug  *v8SamplingDebug
	parent bool
	root   string
}

func newV8Sampler(name, argument string, debug *v8SamplingDebug) (sdktrace.Sampler, error) {
	sampler := &v8Sampler{name: name, debug: debug}
	switch name {
	case "always_on", "always_off":
		sampler.root = name
	case "parentbased_always_on":
		sampler.parent, sampler.root = true, "always_on"
	case "parentbased_always_off":
		sampler.parent, sampler.root = true, "always_off"
	case "traceidratio", "parentbased_traceidratio":
		ratio, err := strconv.ParseFloat(argument, 64)
		if err != nil || math.IsNaN(ratio) || math.IsInf(ratio, 0) || ratio < 0 || ratio > 1 {
			return nil, errors.New("telemetry: trace sampler ratio must be from 0 through 1")
		}
		sampler.root = "traceidratio"
		sampler.parent = name == "parentbased_traceidratio"
		sampler.ratio = sdktrace.TraceIDRatioBased(ratio)
	default:
		return nil, fmt.Errorf("telemetry: unsupported trace sampler %q", name)
	}
	if argument != "" && sampler.root != "traceidratio" {
		return nil, fmt.Errorf("telemetry: sampler argument is not valid with %q", name)
	}
	if sampler.root == "traceidratio" && argument == "" {
		return nil, fmt.Errorf("telemetry: sampler argument is required with %q", name)
	}
	return sampler, nil
}

func (sampler *v8Sampler) ShouldSample(parameters sdktrace.SamplingParameters) sdktrace.SamplingResult {
	if v8TargetedCanary(parameters) {
		return sampler.result(parameters.ParentContext, v8SamplingReasonTargetedCanary, sdktrace.RecordAndSample)
	}
	parent := trace.SpanContextFromContext(parameters.ParentContext)
	if sampler.parent && parent.IsValid() {
		if parent.IsSampled() {
			return sampler.result(parameters.ParentContext, v8SamplingReasonParentSampled, sdktrace.RecordAndSample)
		}
		return sampler.result(parameters.ParentContext, v8SamplingReasonParentUnsampled, sdktrace.Drop)
	}
	switch sampler.root {
	case "always_on":
		return sampler.result(parameters.ParentContext, v8SamplingReasonAlwaysOn, sdktrace.RecordAndSample)
	case "always_off":
		return sampler.result(parameters.ParentContext, v8SamplingReasonAlwaysOff, sdktrace.Drop)
	case "traceidratio":
		result := sampler.ratio.ShouldSample(parameters)
		sampler.debug.record(v8SamplingReasonTraceIDRatio, result.Decision)
		return result
	default:
		return sampler.result(parameters.ParentContext, v8SamplingReasonAlwaysOff, sdktrace.Drop)
	}
}

func (sampler *v8Sampler) result(parentContext context.Context, reason string, decision sdktrace.SamplingDecision) sdktrace.SamplingResult {
	result := sdktrace.SamplingResult{Decision: decision}
	if parent := trace.SpanContextFromContext(parentContext); parent.IsValid() {
		result.Tracestate = parent.TraceState()
	}
	sampler.debug.record(reason, decision)
	return result
}

func (sampler *v8Sampler) Description() string { return "DefenseClawV8/" + sampler.name }

func v8TargetedCanary(parameters sdktrace.SamplingParameters) bool {
	if parameters.Name != "invoke_agent defenseclaw" && parameters.Name != "chat gpt-4o-mini" {
		return false
	}
	var destination, bucket, operation string
	var canary bool
	for _, item := range parameters.Attributes {
		switch string(item.Key) {
		case telemetryCanaryAttribute:
			canary = item.Value.AsBool()
		case telemetryCanaryDestinationAttribute:
			destination = item.Value.AsString()
		case "defenseclaw.bucket":
			bucket = item.Value.AsString()
		case v8CanaryOperationAttribute:
			operation = item.Value.AsString()
		}
	}
	return canary && strings.TrimSpace(destination) != "" &&
		bucket == string(observability.BucketDiagnostic) && operation == v8CanaryOperationValue
}

type v8ByteBoundedTracer struct {
	trace.Tracer
	maxBytes           int
	maxStacktraceBytes int
	provider           trace.TracerProvider
}

type v8ByteBoundedTracerProvider struct {
	trace.TracerProvider
	maxBytes           int
	maxStacktraceBytes int
}

func (provider *v8ByteBoundedTracerProvider) Tracer(name string, options ...trace.TracerOption) trace.Tracer {
	return &v8ByteBoundedTracer{
		Tracer: provider.TracerProvider.Tracer(name, options...), maxBytes: provider.maxBytes,
		maxStacktraceBytes: provider.maxStacktraceBytes, provider: provider,
	}
}

func (tracer *v8ByteBoundedTracer) Start(
	ctx context.Context,
	name string,
	options ...trace.SpanStartOption,
) (context.Context, trace.Span) {
	config := trace.NewSpanStartConfig(options...)
	boundedOptions := []trace.SpanStartOption{
		trace.WithSpanKind(config.SpanKind()),
		trace.WithAttributes(v8BoundAttributes(config.Attributes(), tracer.maxBytes)...),
		trace.WithLinks(v8BoundAPILinks(config.Links(), tracer.maxBytes)...),
	}
	if !config.Timestamp().IsZero() {
		boundedOptions = append(boundedOptions, trace.WithTimestamp(config.Timestamp()))
	}
	if config.NewRoot() {
		boundedOptions = append(boundedOptions, trace.WithNewRoot())
	}
	startedContext, span := tracer.Tracer.Start(
		ctx, v8BoundUTF8(name, tracer.maxBytes), boundedOptions...,
	)
	boundedSpan := &v8ByteBoundedSpan{
		Span: span, maxBytes: tracer.maxBytes, maxStacktraceBytes: tracer.maxStacktraceBytes, provider: tracer.provider,
	}
	return trace.ContextWithSpan(startedContext, boundedSpan), boundedSpan
}

type v8ByteBoundedSpan struct {
	trace.Span
	maxBytes           int
	maxStacktraceBytes int
	provider           trace.TracerProvider
}

func (span *v8ByteBoundedSpan) TracerProvider() trace.TracerProvider {
	if span.provider != nil {
		return span.provider
	}
	return span.Span.TracerProvider()
}

func (span *v8ByteBoundedSpan) SetAttributes(values ...attribute.KeyValue) {
	span.Span.SetAttributes(v8BoundAttributes(values, span.maxBytes)...)
}

func (span *v8ByteBoundedSpan) SetName(name string) {
	span.Span.SetName(v8BoundUTF8(name, span.maxBytes))
}

func (span *v8ByteBoundedSpan) SetStatus(code codes.Code, description string) {
	span.Span.SetStatus(code, v8BoundUTF8(description, span.maxBytes))
}

func (span *v8ByteBoundedSpan) AddEvent(name string, options ...trace.EventOption) {
	config := trace.NewEventConfig(options...)
	attrs := v8BoundAttributes(config.Attributes(), span.maxBytes)
	if config.StackTrace() {
		limit := span.maxStacktraceBytes
		if span.maxBytes >= 0 && (limit < 0 || span.maxBytes < limit) {
			limit = span.maxBytes
		}
		attrs = append(attrs, attribute.String("exception.stacktrace", v8BoundUTF8(string(debug.Stack()), limit)))
	}
	bounded := []trace.EventOption{
		trace.WithAttributes(attrs...),
	}
	if !config.Timestamp().IsZero() {
		bounded = append(bounded, trace.WithTimestamp(config.Timestamp()))
	}
	span.Span.AddEvent(v8BoundUTF8(name, span.maxBytes), bounded...)
}

func (span *v8ByteBoundedSpan) AddLink(link trace.Link) {
	link.Attributes = v8BoundAttributes(link.Attributes, span.maxBytes)
	span.Span.AddLink(link)
}

func (span *v8ByteBoundedSpan) RecordError(err error, options ...trace.EventOption) {
	if err == nil {
		return
	}
	config := trace.NewEventConfig(options...)
	attrs := v8BoundAttributes(config.Attributes(), span.maxBytes)
	filtered := attrs[:0]
	for _, item := range attrs {
		switch string(item.Key) {
		case "exception.type", "exception.message", "exception.stacktrace":
			continue
		default:
			filtered = append(filtered, item)
		}
	}
	attrs = append(filtered,
		attribute.String("exception.type", v8BoundUTF8(v8ErrorType(err), span.maxBytes)),
		attribute.String("exception.message", v8BoundUTF8(err.Error(), span.maxBytes)),
	)
	if config.StackTrace() {
		limit := span.maxStacktraceBytes
		if span.maxBytes >= 0 && (limit < 0 || span.maxBytes < limit) {
			limit = span.maxBytes
		}
		attrs = append(attrs, attribute.String("exception.stacktrace", v8BoundUTF8(string(debug.Stack()), limit)))
	}
	bounded := []trace.EventOption{
		trace.WithAttributes(attrs...),
	}
	if !config.Timestamp().IsZero() {
		bounded = append(bounded, trace.WithTimestamp(config.Timestamp()))
	}
	span.Span.AddEvent("exception", bounded...)
}

func v8ErrorType(err error) string {
	typeOf := reflect.TypeOf(err)
	if typeOf == nil {
		return ""
	}
	if typeOf.PkgPath() == "" && typeOf.Name() == "" {
		return typeOf.String()
	}
	return typeOf.PkgPath() + "." + typeOf.Name()
}

func v8BoundAPILinks(links []trace.Link, maxBytes int) []trace.Link {
	result := append([]trace.Link(nil), links...)
	for index := range result {
		result[index].Attributes = v8BoundAttributes(result[index].Attributes, maxBytes)
	}
	return result
}

func v8BoundAttributes(values []attribute.KeyValue, maxBytes int) []attribute.KeyValue {
	result := append([]attribute.KeyValue(nil), values...)
	for index, value := range result {
		switch value.Value.Type() {
		case attribute.STRING:
			result[index].Value = attribute.StringValue(v8BoundUTF8(value.Value.AsString(), maxBytes))
		case attribute.STRINGSLICE:
			strings := value.Value.AsStringSlice()
			bounded := make([]string, len(strings))
			for stringIndex, item := range strings {
				bounded[stringIndex] = v8BoundUTF8(item, maxBytes)
			}
			result[index].Value = attribute.StringSliceValue(bounded)
		}
	}
	return result
}

func v8BoundUTF8(value string, maxBytes int) string {
	value = strings.ToValidUTF8(value, "\uFFFD")
	if maxBytes < 0 || len(value) <= maxBytes {
		return value
	}
	end := maxBytes
	for end > 0 && !utf8.RuneStart(value[end]) {
		end--
	}
	return value[:end]
}
