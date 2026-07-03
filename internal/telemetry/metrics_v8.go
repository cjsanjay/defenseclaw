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
	"sort"
	"strings"
	"unicode/utf8"

	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/metric"
	metricEmbedded "go.opentelemetry.io/otel/metric/embedded"
	metricNoop "go.opentelemetry.io/otel/metric/noop"

	"github.com/defenseclaw/defenseclaw/internal/observability"
)

const (
	v8MetricMaxAttributes       = 32
	v8MetricMaxAttributeBytes   = 256
	v8MetricMaxSliceElements    = 16
	v8MetricCardinalityLimit    = 2_048
	v8MetricOverflowLabel       = "other"
	v8MetricInvalidUnicodeLabel = "invalid"
)

// V8MetricDefinition binds each compatibility instrument to exactly one
// primary-domain bucket. Instrument name, unit, kind, description, and explicit
// histogram boundaries remain owned by newMetricsSet and the checked-in OTel
// metrics schema; this catalog supplies the v8 collection boundary only.
type V8MetricDefinition struct {
	Name   string
	Bucket observability.Bucket
}

// V8MetricCatalog returns the deterministic 131-instrument compatibility
// inventory. The returned slice is detached from runtime state.
func V8MetricCatalog() []V8MetricDefinition {
	result := make([]V8MetricDefinition, 0, len(v8MetricBucketByName))
	for name, bucket := range v8MetricBucketByName {
		result = append(result, V8MetricDefinition{Name: name, Bucket: bucket})
	}
	sort.Slice(result, func(left, right int) bool { return result[left].Name < result[right].Name })
	return result
}

var v8MetricBucketByName = map[string]observability.Bucket{
	"defenseclaw.activity.diff_entries":             observability.BucketComplianceActivity,
	"defenseclaw.activity.total":                    observability.BucketComplianceActivity,
	"defenseclaw.admission.decisions":               observability.BucketGuardrailEvaluation,
	"defenseclaw.agent.discovery.duration":          observability.BucketAgentLifecycle,
	"defenseclaw.agent.discovery.errors":            observability.BucketAgentLifecycle,
	"defenseclaw.agent.discovery.installed":         observability.BucketAgentLifecycle,
	"defenseclaw.agent.discovery.runs":              observability.BucketAgentLifecycle,
	"defenseclaw.agent.discovery.signals":           observability.BucketAgentLifecycle,
	"defenseclaw.agent.last_seen":                   observability.BucketAgentLifecycle,
	"defenseclaw.agent.lifecycle.transitions":       observability.BucketAgentLifecycle,
	"defenseclaw.agent.phase.current":               observability.BucketAgentLifecycle,
	"defenseclaw.agent.phase.transitions":           observability.BucketAgentLifecycle,
	"defenseclaw.agent.reported_cost":               observability.BucketAgentLifecycle,
	"defenseclaw.agent.token.usage":                 observability.BucketAgentLifecycle,
	"defenseclaw.ai.components.installs":            observability.BucketAIDiscovery,
	"defenseclaw.ai.components.observations":        observability.BucketAIDiscovery,
	"defenseclaw.ai.components.workspaces":          observability.BucketAIDiscovery,
	"defenseclaw.ai.confidence.identity_score":      observability.BucketAIDiscovery,
	"defenseclaw.ai.confidence.presence_score":      observability.BucketAIDiscovery,
	"defenseclaw.ai.discovery.active_signals":       observability.BucketAIDiscovery,
	"defenseclaw.ai.discovery.dedupe_suppressed":    observability.BucketAIDiscovery,
	"defenseclaw.ai.discovery.duration":             observability.BucketAIDiscovery,
	"defenseclaw.ai.discovery.errors":               observability.BucketAIDiscovery,
	"defenseclaw.ai.discovery.files_scanned":        observability.BucketAIDiscovery,
	"defenseclaw.ai.discovery.gone_signals":         observability.BucketAIDiscovery,
	"defenseclaw.ai.discovery.new_signals":          observability.BucketAIDiscovery,
	"defenseclaw.ai.discovery.runs":                 observability.BucketAIDiscovery,
	"defenseclaw.ai.discovery.signals":              observability.BucketAIDiscovery,
	"defenseclaw.alert.count":                       observability.BucketSecurityFinding,
	"defenseclaw.approval.count":                    observability.BucketEnforcementAction,
	"defenseclaw.audit.db.errors":                   observability.BucketPlatformHealth,
	"defenseclaw.audit.events.total":                observability.BucketComplianceActivity,
	"defenseclaw.audit.sink.batches.delivered":      observability.BucketPlatformHealth,
	"defenseclaw.audit.sink.batches.dropped":        observability.BucketPlatformHealth,
	"defenseclaw.audit.sink.circuit.state":          observability.BucketPlatformHealth,
	"defenseclaw.audit.sink.delivery.latency":       observability.BucketPlatformHealth,
	"defenseclaw.audit.sink.failures":               observability.BucketPlatformHealth,
	"defenseclaw.audit.sink.queue.depth":            observability.BucketPlatformHealth,
	"defenseclaw.cisco.errors":                      observability.BucketGuardrailEvaluation,
	"defenseclaw.cisco_inspect.latency":             observability.BucketGuardrailEvaluation,
	"defenseclaw.codex.notify":                      observability.BucketAgentLifecycle,
	"defenseclaw.codex.notify.malformed":            observability.BucketAgentLifecycle,
	"defenseclaw.config.load.errors":                observability.BucketComplianceActivity,
	"defenseclaw.connector.hook.invocations":        observability.BucketAgentLifecycle,
	"defenseclaw.connector.hook.latency":            observability.BucketAgentLifecycle,
	"defenseclaw.connector.hook.outcome":            observability.BucketAgentLifecycle,
	"defenseclaw.connector.hook.tokens":             observability.BucketAgentLifecycle,
	"defenseclaw.connector.hook.unified_dispatch":   observability.BucketAgentLifecycle,
	"defenseclaw.egress.events":                     observability.BucketNetworkEgress,
	"defenseclaw.gateway.errors":                    observability.BucketDiagnostic,
	"defenseclaw.gateway.events.emitted":            observability.BucketDiagnostic,
	"defenseclaw.gateway.forwarded_headers":         observability.BucketToolActivity,
	"defenseclaw.gateway.judge.errors":              observability.BucketGuardrailEvaluation,
	"defenseclaw.gateway.judge.invocations":         observability.BucketGuardrailEvaluation,
	"defenseclaw.gateway.judge.latency":             observability.BucketGuardrailEvaluation,
	"defenseclaw.gateway.verdicts":                  observability.BucketEnforcementAction,
	"defenseclaw.guardrail.cache.hits":              observability.BucketGuardrailEvaluation,
	"defenseclaw.guardrail.cache.misses":            observability.BucketGuardrailEvaluation,
	"defenseclaw.guardrail.evaluations":             observability.BucketGuardrailEvaluation,
	"defenseclaw.guardrail.judge.latency":           observability.BucketGuardrailEvaluation,
	"defenseclaw.guardrail.latency":                 observability.BucketGuardrailEvaluation,
	"defenseclaw.http.auth.failures":                observability.BucketPlatformHealth,
	"defenseclaw.http.rate_limit.breaches":          observability.BucketPlatformHealth,
	"defenseclaw.http.request.count":                observability.BucketPlatformHealth,
	"defenseclaw.http.request.duration":             observability.BucketPlatformHealth,
	"defenseclaw.inspect.evaluations":               observability.BucketGuardrailEvaluation,
	"defenseclaw.inspect.latency":                   observability.BucketGuardrailEvaluation,
	"defenseclaw.judge.persist.batch_size":          observability.BucketPlatformHealth,
	"defenseclaw.judge.persist.drops":               observability.BucketPlatformHealth,
	"defenseclaw.judge.persist.queue_depth":         observability.BucketPlatformHealth,
	"defenseclaw.judge.semaphore.depth":             observability.BucketPlatformHealth,
	"defenseclaw.judge.semaphore.drops":             observability.BucketPlatformHealth,
	"defenseclaw.llm_bridge.latency":                observability.BucketModelIO,
	"defenseclaw.openshell.exit":                    observability.BucketToolActivity,
	"defenseclaw.otel.ingest.bytes":                 observability.BucketTelemetryIngest,
	"defenseclaw.otel.ingest.last_seen_ts":          observability.BucketTelemetryIngest,
	"defenseclaw.otel.ingest.malformed":             observability.BucketTelemetryIngest,
	"defenseclaw.otel.ingest.records":               observability.BucketTelemetryIngest,
	"defenseclaw.otel.ingest.requests":              observability.BucketTelemetryIngest,
	"defenseclaw.panics.total":                      observability.BucketPlatformHealth,
	"defenseclaw.policy.evaluations":                observability.BucketGuardrailEvaluation,
	"defenseclaw.policy.latency":                    observability.BucketGuardrailEvaluation,
	"defenseclaw.policy.reloads":                    observability.BucketComplianceActivity,
	"defenseclaw.process.uptime_seconds":            observability.BucketPlatformHealth,
	"defenseclaw.provenance.bumps":                  observability.BucketDiagnostic,
	"defenseclaw.quarantine.actions":                observability.BucketEnforcementAction,
	"defenseclaw.queue.depth":                       observability.BucketPlatformHealth,
	"defenseclaw.queue.drops":                       observability.BucketPlatformHealth,
	"defenseclaw.redaction.applied":                 observability.BucketDiagnostic,
	"defenseclaw.runtime.fd.in_use":                 observability.BucketPlatformHealth,
	"defenseclaw.runtime.gc.pause":                  observability.BucketPlatformHealth,
	"defenseclaw.runtime.goroutines":                observability.BucketPlatformHealth,
	"defenseclaw.runtime.heap.alloc":                observability.BucketPlatformHealth,
	"defenseclaw.runtime.heap.objects":              observability.BucketPlatformHealth,
	"defenseclaw.scan.count":                        observability.BucketAssetScan,
	"defenseclaw.scan.duration":                     observability.BucketAssetScan,
	"defenseclaw.scan.errors":                       observability.BucketAssetScan,
	"defenseclaw.scan.findings":                     observability.BucketSecurityFinding,
	"defenseclaw.scan.findings.by_rule":             observability.BucketSecurityFinding,
	"defenseclaw.scan.findings.gauge":               observability.BucketSecurityFinding,
	"defenseclaw.scanner.queue.depth":               observability.BucketAssetScan,
	"defenseclaw.schema.violations":                 observability.BucketDiagnostic,
	"defenseclaw.slo.block.latency":                 observability.BucketPlatformHealth,
	"defenseclaw.slo.tui.refresh":                   observability.BucketDiagnostic,
	"defenseclaw.sqlite.busy_retries":               observability.BucketPlatformHealth,
	"defenseclaw.sqlite.checkpoint.duration":        observability.BucketPlatformHealth,
	"defenseclaw.sqlite.db.bytes":                   observability.BucketPlatformHealth,
	"defenseclaw.sqlite.freelist_count":             observability.BucketPlatformHealth,
	"defenseclaw.sqlite.page_count":                 observability.BucketPlatformHealth,
	"defenseclaw.sqlite.wal.bytes":                  observability.BucketPlatformHealth,
	"defenseclaw.stream.bytes_sent":                 observability.BucketModelIO,
	"defenseclaw.stream.duration_ms":                observability.BucketModelIO,
	"defenseclaw.stream.lifecycle":                  observability.BucketModelIO,
	"defenseclaw.telemetry.destination.spans":       observability.BucketPlatformHealth,
	"defenseclaw.telemetry.destination.exports":     observability.BucketPlatformHealth,
	"defenseclaw.telemetry.exporter.errors":         observability.BucketPlatformHealth,
	"defenseclaw.telemetry.exporter.last_export_ts": observability.BucketPlatformHealth,
	"defenseclaw.tool.calls":                        observability.BucketToolActivity,
	"defenseclaw.tool.duration":                     observability.BucketToolActivity,
	"defenseclaw.tool.errors":                       observability.BucketToolActivity,
	"defenseclaw.tui.filter.applied":                observability.BucketDiagnostic,
	"defenseclaw.watcher.errors":                    observability.BucketAssetLifecycle,
	"defenseclaw.watcher.events":                    observability.BucketAssetLifecycle,
	"defenseclaw.watcher.restarts":                  observability.BucketAssetLifecycle,
	"defenseclaw.webhook.circuit_breaker":           observability.BucketNetworkEgress,
	"defenseclaw.webhook.cooldown.suppressed":       observability.BucketNetworkEgress,
	"defenseclaw.webhook.dispatches":                observability.BucketNetworkEgress,
	"defenseclaw.webhook.failures":                  observability.BucketNetworkEgress,
	"defenseclaw.webhook.latency":                   observability.BucketNetworkEgress,
	"gen_ai.client.operation.duration":              observability.BucketModelIO,
	"gen_ai.client.token.usage":                     observability.BucketModelIO,
}

// v8MetricAllowedAttributeKeys is the closed compatibility label vocabulary.
// It is intentionally global because many aliases share dimensions; per-family
// registration remains the source contract and unknown keys fail closed here.
var v8MetricAllowedAttributeKeys = map[attribute.Key]struct{}{
	"action": {}, "actor": {}, "ai.product": {}, "ai.vendor": {},
	"alert.severity": {}, "alert.source": {}, "alert.type": {}, "auto": {},
	"branch": {}, "cache": {}, "cache_hit": {}, "capacity": {}, "client.kind": {},
	"code": {}, "command": {}, "confidence": {}, "connector": {}, "dangerous": {},
	"decision": {}, "defenseclaw.agent.depth": {}, "defenseclaw.agent.execution.id": {},
	"defenseclaw.agent.lifecycle.event": {}, "defenseclaw.agent.lifecycle.id": {},
	"defenseclaw.agent.lifecycle.state": {}, "defenseclaw.agent.parent.id": {},
	"defenseclaw.agent.phase.from": {}, "defenseclaw.agent.phase.to": {},
	"defenseclaw.agent.root.id": {}, "defenseclaw.session.root.id": {},
	"destination": {}, "detector": {}, "ecosystem": {}, "error_type": {},
	"event_type": {}, "exit_code": {}, "exporter": {}, "field": {}, "filter_type": {},
	"framework": {}, "gen_ai.agent.id": {}, "gen_ai.agent.name": {},
	"gen_ai.agent.type": {}, "gen_ai.conversation.id": {}, "gen_ai.operation.name": {},
	"gen_ai.provider.name": {}, "gen_ai.request.model": {}, "gen_ai.token.type": {},
	"gen_ai.tool.name": {}, "guardrail.action_taken": {}, "guardrail.connector": {},
	"guardrail.scanner": {}, "has_binary": {}, "has_config": {}, "http.method": {},
	"http.route": {}, "http.status_code": {}, "identity_band": {}, "installed": {},
	"judge.kind": {}, "kind": {}, "model": {}, "name": {}, "operation": {},
	"outcome": {}, "panel": {}, "path": {}, "policy.domain": {}, "policy.status": {},
	"policy.verdict": {}, "presence_band": {}, "privacy_mode": {}, "probe_status": {},
	"quarantine.op": {}, "quarantine.result": {}, "queue": {}, "reason": {},
	"result": {}, "retry_count": {}, "rule_id": {}, "scanner": {}, "severity": {},
	"signal": {}, "signal.category": {}, "sink": {}, "sink.kind": {}, "sink.name": {},
	"sink.reason": {}, "source": {}, "state": {}, "status": {}, "status_code": {},
	"subsystem": {}, "target_type": {}, "tool": {}, "tool.provider": {},
	"transition": {}, "ttl_bucket": {}, "type": {}, "verdict": {}, "webhook.kind": {},
	"webhook.target_hash": {}, "would_block": {},
}

// V8MetricAllowedAttributeKeys returns the deterministic compatibility label
// vocabulary used by the metric construction boundary. Destination adapters
// use this detached snapshot to fail closed without maintaining a second label
// catalog.
func V8MetricAllowedAttributeKeys() []string {
	result := make([]string, 0, len(v8MetricAllowedAttributeKeys))
	for key := range v8MetricAllowedAttributeKeys {
		result = append(result, string(key))
	}
	sort.Strings(result)
	return result
}

// v8MetricMeter lets the existing metricsSet constructor remain the single
// source of names, units, descriptions, and histogram boundaries. Enabled
// bucket instruments reach the graph-owned SDK Meter; disabled bucket fields
// receive no-op handles and never register an SDK instrument.
type v8MetricMeter struct {
	metricEmbedded.Meter
	real           metric.Meter
	noop           metric.Meter
	enabled        map[observability.Bucket]bool
	selectedBucket observability.Bucket
}

func newV8MetricMeter(real metric.Meter, enabled map[observability.Bucket]bool) *v8MetricMeter {
	return &v8MetricMeter{
		real: real, noop: metricNoop.NewMeterProvider().Meter("defenseclaw"), enabled: enabled,
	}
}

func (meter *v8MetricMeter) forBucket(bucket observability.Bucket) *v8MetricMeter {
	return &v8MetricMeter{
		real: meter.real, noop: meter.noop, enabled: meter.enabled, selectedBucket: bucket,
	}
}

func (meter *v8MetricMeter) selected(name string) (bool, error) {
	bucket, ok := v8MetricBucketByName[name]
	if !ok {
		return false, errors.New("telemetry: metric is absent from the v8 catalog")
	}
	if meter.selectedBucket != "" && bucket != meter.selectedBucket {
		return false, errors.New("telemetry: metric belongs to a different v8 bucket")
	}
	return meter.enabled[bucket], nil
}

func (meter *v8MetricMeter) Int64Counter(name string, options ...metric.Int64CounterOption) (metric.Int64Counter, error) {
	selected, err := meter.selected(name)
	if err != nil {
		return nil, err
	}
	if !selected {
		return meter.noop.Int64Counter(name, options...)
	}
	instrument, err := meter.real.Int64Counter(name, options...)
	return v8Int64Counter{Int64Counter: instrument}, err
}

func (meter *v8MetricMeter) Int64UpDownCounter(name string, options ...metric.Int64UpDownCounterOption) (metric.Int64UpDownCounter, error) {
	selected, err := meter.selected(name)
	if err != nil {
		return nil, err
	}
	if !selected {
		return meter.noop.Int64UpDownCounter(name, options...)
	}
	instrument, err := meter.real.Int64UpDownCounter(name, options...)
	return v8Int64UpDownCounter{Int64UpDownCounter: instrument}, err
}

func (meter *v8MetricMeter) Int64Histogram(name string, options ...metric.Int64HistogramOption) (metric.Int64Histogram, error) {
	selected, err := meter.selected(name)
	if err != nil {
		return nil, err
	}
	if !selected {
		return meter.noop.Int64Histogram(name, options...)
	}
	instrument, err := meter.real.Int64Histogram(name, options...)
	return v8Int64Histogram{Int64Histogram: instrument}, err
}

func (meter *v8MetricMeter) Int64Gauge(name string, options ...metric.Int64GaugeOption) (metric.Int64Gauge, error) {
	selected, err := meter.selected(name)
	if err != nil {
		return nil, err
	}
	if !selected {
		return meter.noop.Int64Gauge(name, options...)
	}
	instrument, err := meter.real.Int64Gauge(name, options...)
	return v8Int64Gauge{Int64Gauge: instrument}, err
}

func (meter *v8MetricMeter) Float64Histogram(name string, options ...metric.Float64HistogramOption) (metric.Float64Histogram, error) {
	selected, err := meter.selected(name)
	if err != nil {
		return nil, err
	}
	if !selected {
		return meter.noop.Float64Histogram(name, options...)
	}
	instrument, err := meter.real.Float64Histogram(name, options...)
	return v8Float64Histogram{Float64Histogram: instrument}, err
}

func (meter *v8MetricMeter) Float64Gauge(name string, options ...metric.Float64GaugeOption) (metric.Float64Gauge, error) {
	selected, err := meter.selected(name)
	if err != nil {
		return nil, err
	}
	if !selected {
		return meter.noop.Float64Gauge(name, options...)
	}
	instrument, err := meter.real.Float64Gauge(name, options...)
	return v8Float64Gauge{Float64Gauge: instrument}, err
}

func (meter *v8MetricMeter) Float64Counter(name string, options ...metric.Float64CounterOption) (metric.Float64Counter, error) {
	selected, err := meter.selected(name)
	if err != nil {
		return nil, err
	}
	if !selected {
		return meter.noop.Float64Counter(name, options...)
	}
	instrument, err := meter.real.Float64Counter(name, options...)
	return v8Float64Counter{Float64Counter: instrument}, err
}

func (meter *v8MetricMeter) Float64UpDownCounter(name string, options ...metric.Float64UpDownCounterOption) (metric.Float64UpDownCounter, error) {
	selected, err := meter.selected(name)
	if err != nil {
		return nil, err
	}
	if !selected {
		return meter.noop.Float64UpDownCounter(name, options...)
	}
	instrument, err := meter.real.Float64UpDownCounter(name, options...)
	return v8Float64UpDownCounter{Float64UpDownCounter: instrument}, err
}

func (*v8MetricMeter) Int64ObservableCounter(string, ...metric.Int64ObservableCounterOption) (metric.Int64ObservableCounter, error) {
	return nil, errors.New("telemetry: observable metrics are absent from the v8 catalog")
}

func (*v8MetricMeter) Int64ObservableUpDownCounter(string, ...metric.Int64ObservableUpDownCounterOption) (metric.Int64ObservableUpDownCounter, error) {
	return nil, errors.New("telemetry: observable metrics are absent from the v8 catalog")
}

func (*v8MetricMeter) Int64ObservableGauge(string, ...metric.Int64ObservableGaugeOption) (metric.Int64ObservableGauge, error) {
	return nil, errors.New("telemetry: observable metrics are absent from the v8 catalog")
}

func (*v8MetricMeter) Float64ObservableCounter(string, ...metric.Float64ObservableCounterOption) (metric.Float64ObservableCounter, error) {
	return nil, errors.New("telemetry: observable metrics are absent from the v8 catalog")
}

func (*v8MetricMeter) Float64ObservableUpDownCounter(string, ...metric.Float64ObservableUpDownCounterOption) (metric.Float64ObservableUpDownCounter, error) {
	return nil, errors.New("telemetry: observable metrics are absent from the v8 catalog")
}

func (*v8MetricMeter) Float64ObservableGauge(string, ...metric.Float64ObservableGaugeOption) (metric.Float64ObservableGauge, error) {
	return nil, errors.New("telemetry: observable metrics are absent from the v8 catalog")
}

func (*v8MetricMeter) RegisterCallback(metric.Callback, ...metric.Observable) (metric.Registration, error) {
	return nil, errors.New("telemetry: observable metrics are absent from the v8 catalog")
}

type v8Int64Counter struct{ metric.Int64Counter }

func (instrument v8Int64Counter) Add(ctx context.Context, value int64, options ...metric.AddOption) {
	instrument.Int64Counter.Add(ctx, value, metric.WithAttributeSet(v8BoundMetricAttributes(metric.NewAddConfig(options).Attributes())))
}

type v8Int64UpDownCounter struct{ metric.Int64UpDownCounter }

func (instrument v8Int64UpDownCounter) Add(ctx context.Context, value int64, options ...metric.AddOption) {
	instrument.Int64UpDownCounter.Add(ctx, value, metric.WithAttributeSet(v8BoundMetricAttributes(metric.NewAddConfig(options).Attributes())))
}

type v8Int64Histogram struct{ metric.Int64Histogram }

func (instrument v8Int64Histogram) Record(ctx context.Context, value int64, options ...metric.RecordOption) {
	instrument.Int64Histogram.Record(ctx, value, metric.WithAttributeSet(v8BoundMetricAttributes(metric.NewRecordConfig(options).Attributes())))
}

type v8Int64Gauge struct{ metric.Int64Gauge }

func (instrument v8Int64Gauge) Record(ctx context.Context, value int64, options ...metric.RecordOption) {
	instrument.Int64Gauge.Record(ctx, value, metric.WithAttributeSet(v8BoundMetricAttributes(metric.NewRecordConfig(options).Attributes())))
}

type v8Float64Histogram struct{ metric.Float64Histogram }

func (instrument v8Float64Histogram) Record(ctx context.Context, value float64, options ...metric.RecordOption) {
	instrument.Float64Histogram.Record(ctx, value, metric.WithAttributeSet(v8BoundMetricAttributes(metric.NewRecordConfig(options).Attributes())))
}

type v8Float64Gauge struct{ metric.Float64Gauge }

func (instrument v8Float64Gauge) Record(ctx context.Context, value float64, options ...metric.RecordOption) {
	instrument.Float64Gauge.Record(ctx, value, metric.WithAttributeSet(v8BoundMetricAttributes(metric.NewRecordConfig(options).Attributes())))
}

type v8Float64Counter struct{ metric.Float64Counter }

func (instrument v8Float64Counter) Add(ctx context.Context, value float64, options ...metric.AddOption) {
	instrument.Float64Counter.Add(ctx, value, metric.WithAttributeSet(v8BoundMetricAttributes(metric.NewAddConfig(options).Attributes())))
}

type v8Float64UpDownCounter struct{ metric.Float64UpDownCounter }

func (instrument v8Float64UpDownCounter) Add(ctx context.Context, value float64, options ...metric.AddOption) {
	instrument.Float64UpDownCounter.Add(ctx, value, metric.WithAttributeSet(v8BoundMetricAttributes(metric.NewAddConfig(options).Attributes())))
}

func v8BoundMetricAttributes(source attribute.Set) attribute.Set {
	values := make([]attribute.KeyValue, 0, min(source.Len(), v8MetricMaxAttributes))
	iterator := source.Iter()
	for iterator.Next() && len(values) < v8MetricMaxAttributes {
		item := iterator.Attribute()
		if _, allowed := v8MetricAllowedAttributeKeys[item.Key]; !allowed {
			continue
		}
		values = append(values, v8BoundMetricAttribute(item))
	}
	return attribute.NewSet(values...)
}

func v8BoundMetricAttribute(item attribute.KeyValue) attribute.KeyValue {
	key := string(item.Key)
	switch item.Value.Type() {
	case attribute.STRING:
		return attribute.String(key, v8BoundMetricLabel(item.Value.AsString()))
	case attribute.STRINGSLICE:
		source := item.Value.AsStringSlice()
		if len(source) > v8MetricMaxSliceElements {
			source = source[:v8MetricMaxSliceElements]
		}
		bounded := make([]string, len(source))
		for index, value := range source {
			bounded[index] = v8BoundMetricLabel(value)
		}
		return attribute.StringSlice(key, bounded)
	case attribute.BOOLSLICE:
		values := item.Value.AsBoolSlice()
		if len(values) > v8MetricMaxSliceElements {
			values = values[:v8MetricMaxSliceElements]
		}
		return attribute.BoolSlice(key, append([]bool(nil), values...))
	case attribute.INT64SLICE:
		values := item.Value.AsInt64Slice()
		if len(values) > v8MetricMaxSliceElements {
			values = values[:v8MetricMaxSliceElements]
		}
		return attribute.Int64Slice(key, append([]int64(nil), values...))
	case attribute.FLOAT64SLICE:
		values := item.Value.AsFloat64Slice()
		if len(values) > v8MetricMaxSliceElements {
			values = values[:v8MetricMaxSliceElements]
		}
		return attribute.Float64Slice(key, append([]float64(nil), values...))
	case attribute.BOOL:
		return attribute.Bool(key, item.Value.AsBool())
	case attribute.INT64:
		return attribute.Int64(key, item.Value.AsInt64())
	case attribute.FLOAT64:
		return attribute.Float64(key, item.Value.AsFloat64())
	default:
		return attribute.String(key, v8MetricInvalidUnicodeLabel)
	}
}

func v8BoundMetricLabel(value string) string {
	if !utf8.ValidString(value) {
		return v8MetricInvalidUnicodeLabel
	}
	if len(value) > v8MetricMaxAttributeBytes {
		return v8MetricOverflowLabel
	}
	return strings.Clone(value)
}

var _ metric.Meter = (*v8MetricMeter)(nil)
var _ metric.Int64Counter = v8Int64Counter{}
var _ metric.Int64UpDownCounter = v8Int64UpDownCounter{}
var _ metric.Int64Histogram = v8Int64Histogram{}
var _ metric.Int64Gauge = v8Int64Gauge{}
var _ metric.Float64Histogram = v8Float64Histogram{}
var _ metric.Float64Gauge = v8Float64Gauge{}
var _ metric.Float64Counter = v8Float64Counter{}
var _ metric.Float64UpDownCounter = v8Float64UpDownCounter{}
