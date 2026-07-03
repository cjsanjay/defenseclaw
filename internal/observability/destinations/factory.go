// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// SPDX-License-Identifier: Apache-2.0

// Package destinations assembles generation-owned observability-v8 log
// adapters from one detached compiled destination. It performs no routing,
// worker activation, or exporter-environment discovery.
package destinations

import (
	"context"
	"errors"
	"io"
	"path/filepath"
	"reflect"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/netguard"
	"github.com/defenseclaw/defenseclaw/internal/observability"
	"github.com/defenseclaw/defenseclaw/internal/observability/delivery"
	"github.com/defenseclaw/defenseclaw/internal/observability/destinations/local"
	"github.com/defenseclaw/defenseclaw/internal/observability/destinations/push"
	observabilityruntime "github.com/defenseclaw/defenseclaw/internal/observability/runtime"
)

const (
	maxQueueItems     = 65_536
	minQueueBytes     = 4_198_400
	maxQueueBytes     = 256 * 1024 * 1024
	maxBatchItems     = 8_192
	minBatchBytes     = 4_263_936
	maxBatchBytes     = 64 * 1024 * 1024
	maxBatchDelayMS   = 600_000
	maxHeaderBytes    = 16_384
	maxSecretBytes    = 64 * 1024
	maxCABundleBytes  = 4 * 1024 * 1024
	maxWireValueBytes = 512
)

var secretReferencePattern = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]{0,255}$`)

type ErrorCode string

const (
	ErrorInvalidDependencies ErrorCode = "invalid_dependencies"
	ErrorInvalidDestination  ErrorCode = "invalid_destination"
	ErrorUnsupportedKind     ErrorCode = "unsupported_kind"
	ErrorSecretUnavailable   ErrorCode = "secret_unavailable"
	ErrorCALoadFailed        ErrorCode = "ca_load_failed"
	ErrorAdapterPrepare      ErrorCode = "adapter_prepare_failed"
)

// Error is safe for mandatory health reporting. It never includes a
// destination name, path, endpoint, secret reference, secret value, or wrapped
// dependency error.
type Error struct{ code ErrorCode }

func (err *Error) Error() string {
	if err == nil {
		return "observability destination preparation failed"
	}
	return "observability destination preparation failed: " + string(err.code)
}

func (err *Error) Code() ErrorCode {
	if err == nil {
		return ""
	}
	return err.code
}

func IsError(err error, code ErrorCode) bool {
	var target *Error
	return errors.As(err, &target) && target.code == code
}

func newError(code ErrorCode) error { return &Error{code: code} }

type ConsoleStream string

const (
	ConsoleStdout ConsoleStream = "stdout"
	ConsoleStderr ConsoleStream = "stderr"
)

// CAFileLoader reads an already trust-checked configured CA path. The factory
// copies and bounds returned bytes before passing them to a push adapter.
type CAFileLoader interface {
	LoadObservabilityCA(context.Context, string) ([]byte, error)
}

type CAFileLoaderFunc func(context.Context, string) ([]byte, error)

func (function CAFileLoaderFunc) LoadObservabilityCA(ctx context.Context, path string) ([]byte, error) {
	return function(ctx, path)
}

// Options are process-stable dependencies. Secret values and CA bytes are not
// resolved until PrepareDestination, so a new generation observes legitimate
// rotation without the factory caching prior material.
type Options struct {
	ConsoleStream ConsoleStream
	Stdout        io.Writer
	Stderr        io.Writer
	Secrets       config.ObservabilityV8SecretResolver
	CALoader      CAFileLoader
	Resolver      netguard.V8Resolver
	Dialer        netguard.V8Dialer
	Warnings      push.WarningObserver
}

// Factory owns no generation resource. Every successful preparation returns a
// distinct adapter and retryable, idempotent cleanup closure.
type Factory struct {
	console  io.Writer
	secrets  config.ObservabilityV8SecretResolver
	caLoader CAFileLoader
	resolver netguard.V8Resolver
	dialer   netguard.V8Dialer
	warnings push.WarningObserver
}

var _ observabilityruntime.DestinationAdapterFactory = (*Factory)(nil)

func NewFactory(options Options) (*Factory, error) {
	var console io.Writer
	switch options.ConsoleStream {
	case ConsoleStdout:
		console = options.Stdout
	case ConsoleStderr:
		console = options.Stderr
	default:
		return nil, newError(ErrorInvalidDependencies)
	}
	if nilInterface(console) || nilInterface(options.Secrets) || nilInterface(options.CALoader) ||
		nilInterface(options.Resolver) || nilInterface(options.Dialer) || nilInterface(options.Warnings) {
		return nil, newError(ErrorInvalidDependencies)
	}
	return &Factory{
		console: console, secrets: options.Secrets, caLoader: options.CALoader,
		resolver: options.Resolver, dialer: options.Dialer, warnings: options.Warnings,
	}, nil
}

func (factory *Factory) PrepareDestination(
	ctx context.Context,
	destination config.ObservabilityV8EffectiveDestination,
) (delivery.Adapter, observabilityruntime.DestinationAdapterCleanup, error) {
	cleanup := noopCleanup()
	if factory == nil || ctx == nil || nilInterface(factory.console) || nilInterface(factory.secrets) ||
		nilInterface(factory.caLoader) || nilInterface(factory.resolver) || nilInterface(factory.dialer) ||
		nilInterface(factory.warnings) {
		return nil, cleanup, newError(ErrorInvalidDependencies)
	}
	if err := ctx.Err(); err != nil {
		return nil, cleanup, err
	}
	if !factoryOwns(destination.Kind) {
		return nil, cleanup, newError(ErrorUnsupportedKind)
	}
	if !validCompiledDestination(destination) {
		return nil, cleanup, newError(ErrorInvalidDestination)
	}

	switch destination.Kind {
	case config.ObservabilityV8DestinationJSONL:
		rotation := destination.Transport.Rotation
		adapter, err := local.NewJSONL(local.JSONLConfig{
			Path: destination.Transport.Path, MaxSizeMB: rotation.MaxSizeMB,
			MaxBackups: rotation.MaxBackups, MaxAgeDays: rotation.MaxAgeDays,
			Compress: rotation.Compress,
		})
		if err != nil {
			return nil, cleanup, newError(ErrorAdapterPrepare)
		}
		cleanup = retryableCleanup(adapter.Close)
		if err := ctx.Err(); err != nil {
			return nil, cleanup, err
		}
		return adapter, cleanup, nil
	case config.ObservabilityV8DestinationConsole:
		adapter, err := local.NewConsole(factory.console)
		if err != nil {
			return nil, cleanup, newError(ErrorAdapterPrepare)
		}
		cleanup = retryableCleanup(adapter.Close)
		if err := ctx.Err(); err != nil {
			return nil, cleanup, err
		}
		return adapter, cleanup, nil
	case config.ObservabilityV8DestinationSplunkHEC:
		return factory.prepareSplunk(ctx, destination, cleanup)
	case config.ObservabilityV8DestinationHTTPJSONL:
		return factory.prepareHTTPJSONL(ctx, destination, cleanup)
	default:
		return nil, cleanup, newError(ErrorUnsupportedKind)
	}
}

func (factory *Factory) prepareSplunk(
	ctx context.Context,
	destination config.ObservabilityV8EffectiveDestination,
	noResource observabilityruntime.DestinationAdapterCleanup,
) (delivery.Adapter, observabilityruntime.DestinationAdapterCleanup, error) {
	token, ok := factory.resolveToken(destination.Transport.TokenEnv)
	if !ok {
		return nil, noResource, newError(ErrorSecretUnavailable)
	}
	tlsOptions, err := factory.loadTLS(ctx, destination.Transport.TLS)
	if err != nil {
		return nil, noResource, err
	}
	overrides := make(map[string]string, len(destination.Transport.SourceTypeOverrides))
	for key, value := range destination.Transport.SourceTypeOverrides {
		overrides[string(key)] = value
	}
	network := destination.Transport.NetworkSafety
	adapter, prepareErr := newSplunkSafely(ctx, push.SplunkHECConfig{
		Destination: destination.Name, Endpoint: destination.Transport.Endpoint,
		Token: token, Index: destination.Transport.Index, Source: destination.Transport.Source,
		SourceType: destination.Transport.SourceType, SourceTypeOverrides: overrides,
		TLS: tlsOptions,
		Network: push.NetworkOptions{
			AllowPrivateNetworks: network.AllowPrivateNetworks,
			AllowCGNAT:           network.AllowCGNAT,
			Resolver:             factory.resolver, Dialer: factory.dialer,
		},
		Observer: factory.warnings,
	})
	if prepareErr != nil {
		return nil, noResource, newError(ErrorAdapterPrepare)
	}
	cleanup := retryableCleanup(func(context.Context) error {
		adapter.CloseIdleConnections()
		return nil
	})
	if err := ctx.Err(); err != nil {
		return nil, cleanup, err
	}
	return adapter, cleanup, nil
}

func (factory *Factory) prepareHTTPJSONL(
	ctx context.Context,
	destination config.ObservabilityV8EffectiveDestination,
	noResource observabilityruntime.DestinationAdapterCleanup,
) (delivery.Adapter, observabilityruntime.DestinationAdapterCleanup, error) {
	headers, err := factory.resolveHeaders(destination.Transport.Headers)
	if err != nil {
		return nil, noResource, err
	}
	bearer := ""
	if destination.Transport.BearerEnv != "" {
		var ok bool
		bearer, ok = factory.resolveToken(destination.Transport.BearerEnv)
		if !ok {
			return nil, noResource, newError(ErrorSecretUnavailable)
		}
	}
	tlsOptions, err := factory.loadTLS(ctx, destination.Transport.TLS)
	if err != nil {
		return nil, noResource, err
	}
	network := destination.Transport.NetworkSafety
	adapter, prepareErr := newHTTPJSONLSafely(ctx, push.HTTPJSONLConfig{
		Destination: destination.Name, Endpoint: destination.Transport.Endpoint,
		Method: destination.Transport.Method, Headers: headers, BearerToken: bearer,
		TLS: tlsOptions,
		Network: push.NetworkOptions{
			AllowPrivateNetworks: network.AllowPrivateNetworks,
			AllowCGNAT:           network.AllowCGNAT,
			Resolver:             factory.resolver, Dialer: factory.dialer,
		},
		Observer: factory.warnings,
	})
	if prepareErr != nil {
		return nil, noResource, newError(ErrorAdapterPrepare)
	}
	cleanup := retryableCleanup(func(context.Context) error {
		adapter.CloseIdleConnections()
		return nil
	})
	if err := ctx.Err(); err != nil {
		return nil, cleanup, err
	}
	return adapter, cleanup, nil
}

func newSplunkSafely(ctx context.Context, config push.SplunkHECConfig) (adapter *push.SplunkHEC, err error) {
	defer func() {
		if recover() != nil {
			adapter, err = nil, newError(ErrorAdapterPrepare)
		}
	}()
	return push.NewSplunkHEC(ctx, config)
}

func newHTTPJSONLSafely(ctx context.Context, config push.HTTPJSONLConfig) (adapter *push.HTTPJSONL, err error) {
	defer func() {
		if recover() != nil {
			adapter, err = nil, newError(ErrorAdapterPrepare)
		}
	}()
	return push.NewHTTPJSONL(ctx, config)
}

func (factory *Factory) resolveHeaders(
	source map[string]config.ObservabilityV8HeaderValue,
) (map[string]string, error) {
	names := make([]string, 0, len(source))
	for name := range source {
		names = append(names, name)
	}
	sort.Strings(names)
	result := make(map[string]string, len(source))
	for _, name := range names {
		value := source[name]
		switch {
		case value.Static != nil && value.Secret == nil:
			if !validHeaderValue(*value.Static) {
				return nil, newError(ErrorInvalidDestination)
			}
			result[name] = *value.Static
		case value.Static == nil && value.Secret != nil && validSecretReference(value.Secret.Env):
			resolved, ok := factory.resolveReference(value.Secret.Env)
			if !ok || !validHeaderValue(resolved) || strings.TrimSpace(resolved) == "" {
				return nil, newError(ErrorSecretUnavailable)
			}
			result[name] = resolved
		default:
			return nil, newError(ErrorInvalidDestination)
		}
	}
	return result, nil
}

func (factory *Factory) resolveToken(reference string) (string, bool) {
	if !validSecretReference(reference) {
		return "", false
	}
	value, ok := factory.resolveReference(reference)
	return value, ok && validToken(value)
}

func (factory *Factory) resolveReference(reference string) (value string, ok bool) {
	defer func() {
		if recover() != nil {
			value, ok = "", false
		}
	}()
	return factory.secrets.ResolveObservabilitySecret(reference)
}

func (factory *Factory) loadTLS(
	ctx context.Context,
	source *config.ObservabilityV8TLSSource,
) (push.TLSOptions, error) {
	if source == nil || source.Insecure {
		return push.TLSOptions{}, newError(ErrorInvalidDestination)
	}
	if err := ctx.Err(); err != nil {
		return push.TLSOptions{}, err
	}
	result := push.TLSOptions{InsecureSkipVerify: source.InsecureSkipVerify}
	if source.CACert == "" {
		return result, nil
	}
	bundle, ok := factory.loadCABundle(ctx, source.CACert)
	if !ok || len(bundle) == 0 || len(bundle) > maxCABundleBytes {
		return push.TLSOptions{}, newError(ErrorCALoadFailed)
	}
	if err := ctx.Err(); err != nil {
		return push.TLSOptions{}, err
	}
	result.CABundle = append([]byte(nil), bundle...)
	return result, nil
}

func (factory *Factory) loadCABundle(ctx context.Context, path string) (bundle []byte, ok bool) {
	defer func() {
		if recover() != nil {
			bundle, ok = nil, false
		}
	}()
	result, err := factory.caLoader.LoadObservabilityCA(ctx, path)
	return result, err == nil
}

func factoryOwns(kind config.ObservabilityV8DestinationKind) bool {
	switch kind {
	case config.ObservabilityV8DestinationJSONL,
		config.ObservabilityV8DestinationConsole,
		config.ObservabilityV8DestinationSplunkHEC,
		config.ObservabilityV8DestinationHTTPJSONL:
		return true
	default:
		return false
	}
}

func validCompiledDestination(destination config.ObservabilityV8EffectiveDestination) bool {
	if !destination.Enabled || !observability.IsStableToken(destination.Name) ||
		len(destination.SelectedSignals) != 1 || destination.SelectedSignals[0] != observability.SignalLogs ||
		len(destination.Capabilities.Signals) != 1 || destination.Capabilities.Signals[0] != observability.SignalLogs ||
		!validQueue(destination.Transport.Batch) {
		return false
	}
	switch destination.Kind {
	case config.ObservabilityV8DestinationJSONL:
		return validJSONLTransport(destination.Transport)
	case config.ObservabilityV8DestinationConsole:
		return validConsoleTransport(destination.Transport)
	case config.ObservabilityV8DestinationSplunkHEC:
		return validSplunkTransport(destination.Transport)
	case config.ObservabilityV8DestinationHTTPJSONL:
		return validHTTPJSONLTransport(destination.Transport)
	default:
		return false
	}
}

func validQueue(batch *config.ObservabilityV8BatchSource) bool {
	return batch != nil && batch.MaxQueueSize >= 1 && batch.MaxQueueSize <= maxQueueItems &&
		batch.MaxQueueBytes >= minQueueBytes && batch.MaxQueueBytes <= maxQueueBytes
}

func validJSONLTransport(transport config.ObservabilityV8TransportPlan) bool {
	return transport.Path != "" && filepath.IsAbs(transport.Path) &&
		transport.Rotation != nil && transport.Rotation.MaxSizeMB > 0 &&
		transport.Rotation.MaxBackups >= 0 && transport.Rotation.MaxAgeDays >= 0 &&
		queueOnlyBatch(transport.Batch) && noCommonRemoteFields(transport)
}

func validConsoleTransport(transport config.ObservabilityV8TransportPlan) bool {
	return queueOnlyBatch(transport.Batch) && transport.Path == "" && transport.Rotation == nil &&
		noCommonRemoteFields(transport)
}

func noCommonRemoteFields(transport config.ObservabilityV8TransportPlan) bool {
	return transport.Listen == "" && transport.Endpoint == "" && transport.Protocol == "" &&
		transport.Method == "" && transport.Headers == nil && transport.TokenEnv == "" &&
		transport.BearerEnv == "" && transport.Index == "" && transport.Source == "" &&
		transport.SourceType == "" && transport.SourceTypeOverrides == nil &&
		transport.LoggerName == "" && transport.TimeoutMS == 0 && transport.TLS == nil &&
		transport.NetworkSafety == nil && transport.SignalOverrides == nil
}

func queueOnlyBatch(batch *config.ObservabilityV8BatchSource) bool {
	return batch != nil && batch.MaxExportBatchSize == 0 && batch.MaxExportBatchBytes == 0 &&
		batch.ScheduledDelayMS == 0
}

func validPushTransport(transport config.ObservabilityV8TransportPlan) bool {
	if transport.Path != "" || transport.Rotation != nil || transport.Listen != "" ||
		transport.Protocol != "" || transport.LoggerName != "" || transport.SignalOverrides != nil ||
		transport.Endpoint == "" || transport.TimeoutMS <= 0 || transport.TLS == nil ||
		transport.TLS.Insecure || len(transport.TLS.CACert) > 4_096 ||
		(transport.TLS.CACert != "" && !filepath.IsAbs(transport.TLS.CACert)) ||
		transport.NetworkSafety == nil || !validPushBatch(transport.Batch) {
		return false
	}
	maxDurationMilliseconds := int64(^uint64(0)>>1) / int64(time.Millisecond)
	return int64(transport.TimeoutMS) <= maxDurationMilliseconds
}

func validPushBatch(batch *config.ObservabilityV8BatchSource) bool {
	return validQueue(batch) && batch.MaxExportBatchSize >= 1 && batch.MaxExportBatchSize <= maxBatchItems &&
		batch.MaxExportBatchSize <= batch.MaxQueueSize &&
		batch.MaxExportBatchBytes >= minBatchBytes && batch.MaxExportBatchBytes <= maxBatchBytes &&
		batch.ScheduledDelayMS >= 1 && batch.ScheduledDelayMS <= maxBatchDelayMS
}

func validSplunkTransport(transport config.ObservabilityV8TransportPlan) bool {
	if !validPushTransport(transport) || transport.Method != "" || transport.Headers != nil ||
		transport.BearerEnv != "" || !validSecretReference(transport.TokenEnv) {
		return false
	}
	if len(transport.Index) > maxWireValueBytes || len(transport.Source) > maxWireValueBytes ||
		len(transport.SourceType) > maxWireValueBytes || len(transport.SourceTypeOverrides) > 1_024 {
		return false
	}
	for action, sourceType := range transport.SourceTypeOverrides {
		if !observability.IsStableToken(string(action)) || sourceType == "" || len(sourceType) > 256 {
			return false
		}
	}
	return true
}

func validHTTPJSONLTransport(transport config.ObservabilityV8TransportPlan) bool {
	if !validPushTransport(transport) || transport.TokenEnv != "" || transport.Index != "" ||
		transport.Source != "" || transport.SourceType != "" || transport.SourceTypeOverrides != nil {
		return false
	}
	if transport.Method != "POST" && transport.Method != "PUT" && transport.Method != "PATCH" {
		return false
	}
	if transport.BearerEnv != "" && !validSecretReference(transport.BearerEnv) {
		return false
	}
	return len(transport.Headers) <= 1_024
}

func validSecretReference(reference string) bool {
	return secretReferencePattern.MatchString(reference)
}

func validHeaderValue(value string) bool {
	if len(value) > maxHeaderBytes || !utf8.ValidString(value) {
		return false
	}
	for _, character := range value {
		if character == '\r' || character == '\n' || character == 0 || character == 0x7f {
			return false
		}
	}
	return true
}

func validToken(value string) bool {
	if value == "" || len(value) > maxSecretBytes || !utf8.ValidString(value) {
		return false
	}
	for _, character := range value {
		if character <= 0x20 || character == 0x7f {
			return false
		}
	}
	return true
}

func noopCleanup() observabilityruntime.DestinationAdapterCleanup {
	return func(context.Context) error { return nil }
}

func retryableCleanup(
	operation func(context.Context) error,
) observabilityruntime.DestinationAdapterCleanup {
	var mutex sync.Mutex
	complete := false
	return func(ctx context.Context) error {
		mutex.Lock()
		defer mutex.Unlock()
		if complete {
			return nil
		}
		if operation == nil {
			return newError(ErrorInvalidDependencies)
		}
		if err := operation(ctx); err != nil {
			return err
		}
		complete = true
		return nil
	}
}

func nilInterface(value any) bool {
	if value == nil {
		return true
	}
	reflected := reflect.ValueOf(value)
	switch reflected.Kind() {
	case reflect.Chan, reflect.Func, reflect.Interface, reflect.Map,
		reflect.Pointer, reflect.Slice:
		return reflected.IsNil()
	default:
		return false
	}
}
