// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// SPDX-License-Identifier: Apache-2.0

package inventory

import (
	"context"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/telemetry"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/trace"
)

// AIDiscoveryV8ScanStart contains only facts known before a real scan starts.
// The gateway adapter translates it to the generated family vocabulary; this
// package never owns routing, resource, sampling, or provenance.
type AIDiscoveryV8ScanStart struct {
	ScanID      string
	Source      string
	PrivacyMode string
	StartedAt   time.Time
}

// AIDiscoveryV8DetectorStart contains the source-backed identity and start
// time of one detector actually invoked by the scan.
type AIDiscoveryV8DetectorStart struct {
	ScanID    string
	Detector  string
	StartedAt time.Time
}

// AIDiscoveryV8DetectorResult is the bounded terminal observation for one
// detector. Failed is deliberately separate from an error value so arbitrary
// detector diagnostics never cross the telemetry adapter boundary.
type AIDiscoveryV8DetectorResult struct {
	EndedAt      time.Time
	DurationMs   int64
	SignalsTotal int64
	FilesScanned int64
	Failed       bool
	legacyError  error
}

// AIDiscoveryV8ComponentObservation is the source-backed component rollup used
// by the generated confidence-change log and the existing dashboard metrics.
// ComponentID is a deterministic digest of the exact normalized grouping key;
// it does not invent an external asset identity.
type AIDiscoveryV8ComponentObservation struct {
	ComponentID        string
	ComponentType      string
	HasLifecycleChange bool
	Metrics            telemetry.AIComponentConfidenceAttrs
}

type AIDiscoveryV8DetectorTrace interface {
	End(AIDiscoveryV8DetectorResult) error
	Abort()
}

// AIDiscoveryV8ScanTrace is the inventory-facing capability for one generated
// scan root. A nil child is normal collection/sampling admission.
type AIDiscoveryV8ScanTrace interface {
	StartDetector(AIDiscoveryV8DetectorStart) (AIDiscoveryV8DetectorTrace, error)
	End(AIDiscoveryReport) error
	Abort()
}

// AIDiscoveryObservabilityV8 is implemented by the gateway's process-owned v8
// runtime adapter. EmitReport owns generated log/metric construction and must
// never fall back to legacy OTel after accepting an occurrence.
type AIDiscoveryObservabilityV8 interface {
	StartScan(context.Context, AIDiscoveryV8ScanStart) (context.Context, AIDiscoveryV8ScanTrace, error)
	EmitReport(context.Context, AIDiscoveryReport, []AIDiscoveryV8ComponentObservation) error
}

// BindObservabilityV8 publishes or detaches the process-owned adapter. Config
// version, not adapter presence, decides authority, so a v8 detach/build/drop
// can never resurrect the legacy direct OTel path.
func (s *ContinuousDiscoveryService) BindObservabilityV8(observer AIDiscoveryObservabilityV8) {
	if s == nil {
		return
	}
	s.observabilityV8Mu.Lock()
	s.observabilityV8 = observer
	s.observabilityV8Mu.Unlock()
}

func (s *ContinuousDiscoveryService) observabilityV8Snapshot() (AIDiscoveryObservabilityV8, bool) {
	if s == nil {
		return nil, false
	}
	s.observabilityV8Mu.RLock()
	observer := s.observabilityV8
	s.observabilityV8Mu.RUnlock()
	return observer, s.opts.ConfigVersion == 8
}

type aiDiscoveryScanObservation struct {
	v8        bool
	generated AIDiscoveryV8ScanTrace
	legacy    trace.Span
}

func (s *ContinuousDiscoveryService) startScanObservation(
	ctx context.Context,
	start AIDiscoveryV8ScanStart,
) (context.Context, *aiDiscoveryScanObservation) {
	observer, authoritative := s.observabilityV8Snapshot()
	observation := &aiDiscoveryScanObservation{v8: authoritative}
	if authoritative {
		if observer == nil {
			return ctx, observation
		}
		startedContext, generated, err := observer.StartScan(ctx, start)
		if err != nil {
			return ctx, observation
		}
		observation.generated = generated
		return startedContext, observation
	}

	startedContext, span := s.otel.Tracer().Start(ctx, "defenseclaw.ai.discovery",
		trace.WithAttributes(
			attribute.String("defenseclaw.ai.discovery.scan_id", start.ScanID),
			attribute.String("defenseclaw.ai.discovery.source", start.Source),
			attribute.String("defenseclaw.ai.discovery.privacy_mode", start.PrivacyMode),
		),
	)
	s.otel.SetSpanResourceContext(span)
	observation.legacy = span
	return startedContext, observation
}

func (observation *aiDiscoveryScanObservation) startDetector(
	ctx context.Context,
	s *ContinuousDiscoveryService,
	start AIDiscoveryV8DetectorStart,
) *aiDiscoveryDetectorObservation {
	detector := &aiDiscoveryDetectorObservation{v8: observation != nil && observation.v8}
	if observation == nil {
		return detector
	}
	if observation.v8 {
		if observation.generated == nil {
			return detector
		}
		generated, err := observation.generated.StartDetector(start)
		if err == nil {
			detector.generated = generated
		}
		return detector
	}
	_, child := s.otel.Tracer().Start(ctx, "defenseclaw.ai.discovery.detector",
		trace.WithAttributes(attribute.String("defenseclaw.ai.discovery.detector", start.Detector)),
	)
	s.otel.SetSpanResourceContext(child)
	detector.legacy = child
	return detector
}

type aiDiscoveryDetectorObservation struct {
	v8        bool
	generated AIDiscoveryV8DetectorTrace
	legacy    trace.Span
}

func (observation *aiDiscoveryDetectorObservation) end(result AIDiscoveryV8DetectorResult) {
	if observation == nil {
		return
	}
	if observation.v8 {
		if observation.generated != nil {
			_ = observation.generated.End(result)
		}
		return
	}
	if observation.legacy == nil {
		return
	}
	observation.legacy.SetAttributes(attribute.Int64("defenseclaw.ai.discovery.signals", result.SignalsTotal))
	if result.FilesScanned > 0 {
		observation.legacy.SetAttributes(attribute.Int64("defenseclaw.ai.discovery.files_scanned", result.FilesScanned))
	}
	if result.Failed {
		if result.legacyError != nil {
			observation.legacy.RecordError(result.legacyError)
			observation.legacy.SetStatus(codes.Error, result.legacyError.Error())
		} else {
			observation.legacy.SetStatus(codes.Error, "detector_error")
		}
	}
	observation.legacy.End()
	observation.legacy = nil
}

func (observation *aiDiscoveryScanObservation) end(report AIDiscoveryReport) {
	if observation == nil {
		return
	}
	if observation.v8 {
		if observation.generated != nil {
			_ = observation.generated.End(report)
		}
		return
	}
	if observation.legacy == nil {
		return
	}
	if report.Summary.Errors > 0 {
		observation.legacy.SetStatus(codes.Error, "one or more detectors failed")
	}
	observation.legacy.SetAttributes(
		attribute.Int("defenseclaw.ai.discovery.signals", report.Summary.TotalSignals),
		attribute.Int("defenseclaw.ai.discovery.active_signals", report.Summary.ActiveSignals),
		attribute.Int("defenseclaw.ai.discovery.files_scanned", report.Summary.FilesScanned),
	)
	observation.legacy.End()
	observation.legacy = nil
}

func (observation *aiDiscoveryScanObservation) abort() {
	if observation == nil {
		return
	}
	if observation.v8 {
		if observation.generated != nil {
			observation.generated.Abort()
		}
		return
	}
	if observation.legacy != nil {
		observation.legacy.End()
	}
}
