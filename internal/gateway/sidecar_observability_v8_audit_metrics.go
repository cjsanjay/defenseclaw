// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"context"

	"github.com/defenseclaw/defenseclaw/internal/audit"
	"github.com/defenseclaw/defenseclaw/internal/observability"
	observabilityruntime "github.com/defenseclaw/defenseclaw/internal/observability/runtime"
)

// RecordRuntimeV8GeneratedMetric adapts audit's opaque generated-metric
// capability to the runtime without exposing the graph or telemetry provider
// across the package boundary. Runtime validates the family identity and exact
// generation/digest again before recording.
func (owner *sidecarOwnedObservabilityV8Runtime) RecordRuntimeV8GeneratedMetric(
	ctx context.Context,
	metric audit.RuntimeV8GeneratedMetric,
) error {
	_, err := owner.RecordGeneratedMetric(
		ctx,
		metric.Family(),
		func(snapshot observabilityruntime.EmitContext) (observability.Record, error) {
			return metric.Build(audit.RuntimeV8BuildContext{
				ConfigGeneration: snapshot.Generation(),
				ConfigDigest:     snapshot.Digest(),
			})
		},
	)
	return err
}

var _ audit.RuntimeV8MetricEmitter = (*sidecarOwnedObservabilityV8Runtime)(nil)
