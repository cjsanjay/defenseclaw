// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"context"
	"math"
	"sync/atomic"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/audit"
	"github.com/defenseclaw/defenseclaw/internal/gatewaylog"
	"github.com/defenseclaw/defenseclaw/internal/observability"
	"github.com/defenseclaw/defenseclaw/internal/observability/pipeline"
	"github.com/defenseclaw/defenseclaw/internal/observability/router"
	observabilityruntime "github.com/defenseclaw/defenseclaw/internal/observability/runtime"
	"github.com/defenseclaw/defenseclaw/internal/version"
	"github.com/google/uuid"
)

const sidecarLifecycleStopPersistTimeout = 5 * time.Second

type sidecarRuntimeEmitter interface {
	Emit(
		context.Context,
		router.Metadata,
		observabilityruntime.EmitBuilder,
	) (pipeline.LocalLogOutcome, error)
}

type sidecarRuntimeLocalOnlyEmitter interface {
	EmitLocalOnly(
		context.Context,
		router.Metadata,
		observabilityruntime.EmitBuilder,
	) (pipeline.LocalLogOutcome, error)
}

// sidecarRuntimeCanaryEmitter is intentionally separate from
// sidecarRuntimeEmitter. Log-only test doubles and integrations do not need to
// implement the trace diagnostic, while the real v8 Runtime exposes both on
// the same generation-owned object.
type sidecarRuntimeCanaryEmitter interface {
	EmitTraceCanary(
		context.Context,
		string,
	) (observabilityruntime.TraceCanaryResult, error)
}

type sidecarObservabilityErrorCode string

const (
	sidecarObservabilityInvalidBinding sidecarObservabilityErrorCode = "invalid_binding"
	sidecarObservabilityAlreadyBound   sidecarObservabilityErrorCode = "already_bound"
	sidecarObservabilityRunStarted     sidecarObservabilityErrorCode = "run_started"
	sidecarObservabilityBuildFailed    sidecarObservabilityErrorCode = "record_build_failed"
	sidecarObservabilityEmitFailed     sidecarObservabilityErrorCode = "emit_failed"
	sidecarObservabilityAmbiguous      sidecarObservabilityErrorCode = "ambiguous_outcome"
)

// sidecarObservabilityError is deliberately bounded and content-free. In
// particular, it never retains the SQLite, redaction, or producer error that
// caused a canonical lifecycle write to fail.
type sidecarObservabilityError struct{ code sidecarObservabilityErrorCode }

func (err *sidecarObservabilityError) Error() string {
	if err == nil {
		return "sidecar observability lifecycle failed"
	}
	return "sidecar observability lifecycle failed: " + string(err.code)
}

func (err *sidecarObservabilityError) Code() sidecarObservabilityErrorCode {
	if err == nil {
		return ""
	}
	return err.code
}

// BindObservabilityRuntime opts this Sidecar into the canonical v8 SQLite
// lifecycle path. It must be called exactly once before Run. The Runtime and
// its stores remain owned by the caller.
func (s *Sidecar) BindObservabilityRuntime(runtime *observabilityruntime.Runtime) error {
	if runtime == nil {
		return &sidecarObservabilityError{code: sidecarObservabilityInvalidBinding}
	}
	return s.bindObservabilityRuntime(runtime)
}

func (s *Sidecar) bindObservabilityRuntime(emitter sidecarRuntimeEmitter) error {
	if s == nil || emitter == nil {
		return &sidecarObservabilityError{code: sidecarObservabilityInvalidBinding}
	}
	s.observabilityV8Mu.Lock()
	defer s.observabilityV8Mu.Unlock()
	if s.observabilityV8Run {
		return &sidecarObservabilityError{code: sidecarObservabilityRunStarted}
	}
	if s.observabilityV8 != nil {
		return &sidecarObservabilityError{code: sidecarObservabilityAlreadyBound}
	}
	s.observabilityV8 = emitter
	s.observabilityV8Trace, _ = emitter.(proxyV8TraceRuntime)
	traceRuntime := s.observabilityV8Trace
	if proxy := s.proxySnapshot(); proxy != nil {
		proxy.bindObservabilityV8Trace(traceRuntime)
	}
	return nil
}

func (s *Sidecar) beginObservabilityV8Run() error {
	if s == nil {
		return &sidecarObservabilityError{code: sidecarObservabilityInvalidBinding}
	}
	s.observabilityV8Mu.Lock()
	defer s.observabilityV8Mu.Unlock()
	if s.observabilityV8Run {
		return &sidecarObservabilityError{code: sidecarObservabilityRunStarted}
	}
	// A validated v8 process must have completed mandatory runtime assembly
	// before any subsystem starts serving. v7 and test configurations preserve
	// the exact unbound legacy behavior.
	if cfg := s.currentConfig(); cfg != nil && cfg.ConfigVersion == 8 && s.observabilityV8 == nil {
		return &sidecarObservabilityError{code: sidecarObservabilityInvalidBinding}
	}
	s.observabilityV8Run = true
	return nil
}

func (s *Sidecar) observabilityV8Emitter() sidecarRuntimeEmitter {
	if s == nil {
		return nil
	}
	s.observabilityV8Mu.Lock()
	defer s.observabilityV8Mu.Unlock()
	return s.observabilityV8
}

func (s *Sidecar) observabilityV8CanaryEmitter() sidecarRuntimeCanaryEmitter {
	emitter := s.observabilityV8Emitter()
	if emitter == nil {
		return nil
	}
	canary, _ := emitter.(sidecarRuntimeCanaryEmitter)
	return canary
}

func (s *Sidecar) observabilityV8LocalOnlyEmitter() sidecarRuntimeLocalOnlyEmitter {
	emitter := s.observabilityV8Emitter()
	if emitter == nil {
		return nil
	}
	localOnly, _ := emitter.(sidecarRuntimeLocalOnlyEmitter)
	return localOnly
}

func (a *APIServer) bindTelemetryCanaryRuntime(emitter sidecarRuntimeCanaryEmitter) {
	if a == nil {
		return
	}
	a.observabilityV8Canary = emitter
}

func (a *APIServer) bindLocalOnlyObservabilityRuntime(emitter sidecarRuntimeLocalOnlyEmitter) {
	if a == nil {
		return
	}
	a.observabilityV8LocalOnly = emitter
}

func (s *Sidecar) recordSidecarLifecycle(ctx context.Context, action audit.Action) error {
	emitter := s.observabilityV8Emitter()
	if emitter == nil {
		details := "starting all subsystems"
		if action == audit.ActionSidecarStop {
			details = "all subsystems stopped"
		}
		// This is the exact legacy SQLite/OTel/sink path. Once Runtime is
		// bound, no error or collection decision is allowed to fall back here.
		_ = s.logLegacySidecarLifecycle(action, details)
		return nil
	}

	transition, outcome, phase := "start", observability.OutcomeAttempted, "startup"
	message := "starting all subsystems"
	if action == audit.ActionSidecarStop {
		transition, outcome, phase = "stop", observability.OutcomeCompleted, "shutdown"
		message = "all subsystems stopped"
		// Run's lifecycle context is canceled before shutdown. Preserve all
		// correlation values while giving mandatory local persistence a fresh,
		// bounded cancellation budget.
		withoutCancellation := context.WithoutCancel(ctx)
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(withoutCancellation, sidecarLifecycleStopPersistTimeout)
		defer cancel()
	} else if action != audit.ActionSidecarStart {
		return &sidecarObservabilityError{code: sidecarObservabilityBuildFailed}
	}

	classification := observability.ClassificationContext{RawSeverity: "INFO"}
	metadata, err := router.NewClassifiedLogMetadata(
		observability.ProducerAuditAction,
		observability.ProducerKey(action),
		classification,
		observability.SourceGateway,
		"",
		observability.ProducerKey(action),
	)
	if err != nil {
		return &sidecarObservabilityError{code: sidecarObservabilityBuildFailed}
	}
	var builds atomic.Int32
	result, emitErr := emitter.Emit(ctx, metadata, func(
		snapshot observabilityruntime.EmitContext,
		admission router.Admission,
	) (observability.Record, error) {
		builds.Add(1)
		if snapshot.Generation() > math.MaxInt64 {
			return observability.Record{}, &sidecarObservabilityError{code: sidecarObservabilityBuildFailed}
		}
		builder, buildErr := observability.NewRecordBuilder(
			observability.ClockFunc(func() time.Time { return time.Now().UTC() }),
			observability.OccurrenceIDGeneratorFunc(func() (string, error) { return uuid.NewString(), nil }),
		)
		if buildErr != nil {
			return observability.Record{}, &sidecarObservabilityError{code: sidecarObservabilityBuildFailed}
		}
		return builder.BuildClassifiedLog(observability.ClassifiedLogInput{
			ProducerKind:          observability.ProducerAuditAction,
			ProducerKey:           observability.ProducerKey(action),
			ClassificationContext: classification,
			Source:                observability.SourceGateway,
			Action:                string(action),
			Phase:                 phase,
			Outcome:               outcome,
			Correlation: observability.Correlation{
				RunID:             gatewaylog.ProcessRunID(),
				SidecarInstanceID: gatewaylog.SidecarInstanceID(),
			},
			Provenance: observability.Provenance{
				Producer: "defenseclaw", BinaryVersion: version.Current().BinaryVersion,
				RegistrySchemaVersion: observability.CurrentRecordSchemaVersion,
				ConfigGeneration:      int64(snapshot.Generation()),
				ConfigDigest:          snapshot.Digest(),
			},
			Body: map[string]any{
				"component":  "sidecar",
				"message":    message,
				"transition": transition,
			},
			FieldClasses: map[string]observability.FieldClass{
				"/component":  observability.FieldClassMetadata,
				"/message":    observability.FieldClassContent,
				"/transition": observability.FieldClassMetadata,
			},
		})
	})
	if emitErr != nil {
		return &sidecarObservabilityError{code: sidecarObservabilityEmitFailed}
	}
	switch result.Admission() {
	case router.AdmissionDrop:
		if result.LocalPersisted() || builds.Load() != 0 {
			return &sidecarObservabilityError{code: sidecarObservabilityAmbiguous}
		}
		return nil
	case router.AdmissionOrdinary:
		if !result.LocalPersisted() || builds.Load() != 1 {
			return &sidecarObservabilityError{code: sidecarObservabilityAmbiguous}
		}
		return nil
	default:
		return &sidecarObservabilityError{code: sidecarObservabilityAmbiguous}
	}
}

var _ sidecarRuntimeEmitter = (*observabilityruntime.Runtime)(nil)
var _ sidecarRuntimeCanaryEmitter = (*observabilityruntime.Runtime)(nil)
var _ sidecarRuntimeLocalOnlyEmitter = (*observabilityruntime.Runtime)(nil)
