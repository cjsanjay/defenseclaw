// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// SPDX-License-Identifier: Apache-2.0

package runtime

import (
	"context"

	"github.com/defenseclaw/defenseclaw/internal/observability"
	"github.com/defenseclaw/defenseclaw/internal/telemetry"
)

// GeneratedMetricErrorCode is a fixed, content-free recording failure.
type GeneratedMetricErrorCode string

const (
	GeneratedMetricInvalidInput  GeneratedMetricErrorCode = "invalid_input"
	GeneratedMetricUnavailable   GeneratedMetricErrorCode = "unavailable"
	GeneratedMetricBuildRejected GeneratedMetricErrorCode = "build_rejected"
	GeneratedMetricRecordFailed  GeneratedMetricErrorCode = "record_failed"
)

type GeneratedMetricError struct{ code GeneratedMetricErrorCode }

func (err *GeneratedMetricError) Error() string {
	if err == nil {
		return "generated metric operation failed"
	}
	return "generated metric operation failed: " + string(err.code)
}

func (err *GeneratedMetricError) Code() GeneratedMetricErrorCode {
	if err == nil {
		return ""
	}
	return err.code
}

// GeneratedMetricBuilder runs only after the exact family bucket is collected.
// The supplied graph snapshot must be used for generated provenance.
type GeneratedMetricBuilder func(EmitContext) (observability.Record, error)

// RecordGeneratedMetric holds one runtimegraph lease across collection gating,
// generated construction, projection, and synchronous destination handoff.
// A disabled family returns an empty result without invoking builder.
func (runtime *Runtime) RecordGeneratedMetric(
	ctx context.Context,
	family observability.EventName,
	builder GeneratedMetricBuilder,
) (telemetry.V8MetricRecordResult, error) {
	if runtime == nil || runtime.manager == nil || ctx == nil || family == "" || builder == nil {
		return telemetry.V8MetricRecordResult{}, &GeneratedMetricError{code: GeneratedMetricInvalidInput}
	}
	lease, err := runtime.manager.Acquire(ctx)
	if err != nil {
		return telemetry.V8MetricRecordResult{}, err
	}
	defer lease.Release()
	graph := lease.Graph()
	provider, ok := telemetry.V8ProviderFromLease(lease)
	if graph == nil || !ok {
		return telemetry.V8MetricRecordResult{}, &GeneratedMetricError{code: GeneratedMetricUnavailable}
	}
	digest, generation, bound := provider.V8PlanBinding()
	if !bound || digest == "" || digest != graph.Digest() || generation != graph.Generation() {
		return telemetry.V8MetricRecordResult{}, &GeneratedMetricError{code: GeneratedMetricUnavailable}
	}
	// This check deliberately precedes the producer callback so disabled
	// collection cannot construct labels, records, or expensive measurements.
	if !provider.MetricFamilyEnabled(family) {
		return telemetry.V8MetricRecordResult{}, nil
	}
	snapshot := EmitContext{plan: graph.Plan(), digest: digest, generation: generation}
	record, buildErr := builder(snapshot)
	if buildErr != nil {
		return telemetry.V8MetricRecordResult{}, &GeneratedMetricError{code: GeneratedMetricBuildRejected}
	}
	provenance := record.Provenance()
	if record.Signal() != observability.SignalMetrics || record.EventName() != family ||
		provenance.ConfigGeneration < 0 || uint64(provenance.ConfigGeneration) != generation ||
		provenance.ConfigDigest != digest {
		return telemetry.V8MetricRecordResult{}, &GeneratedMetricError{code: GeneratedMetricBuildRejected}
	}
	result, recordErr := provider.RecordGeneratedMetric(ctx, record)
	if recordErr != nil {
		return result, &GeneratedMetricError{code: GeneratedMetricRecordFailed}
	}
	return result, nil
}

var _ error = (*GeneratedMetricError)(nil)
