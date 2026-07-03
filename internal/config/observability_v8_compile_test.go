// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// SPDX-License-Identifier: Apache-2.0

package config

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/observability"
	"gopkg.in/yaml.v3"
)

func TestCompileObservabilityV8AbsentAndEmptyDefaults(t *testing.T) {
	absent := mustCompileObservabilityV8(t, nil)
	empty := mustCompileObservabilityV8(t, &ObservabilityV8Source{})
	if absent.Digest() != empty.Digest() || !bytes.Equal(absent.EffectiveJSON(), empty.EffectiveJSON()) {
		t.Fatal("absent and empty observability sources compiled differently")
	}
	snapshot := absent.Snapshot()
	if snapshot.BucketCatalogVersion != 1 || len(snapshot.Buckets) != 14 {
		t.Fatalf("catalog = %d with %d buckets", snapshot.BucketCatalogVersion, len(snapshot.Buckets))
	}
	for _, bucket := range snapshot.Buckets {
		if !bucket.Collect.Logs || !bucket.Collect.Traces || !bucket.Collect.Metrics || bucket.RedactionProfile != "none" {
			t.Errorf("default bucket %q = %+v", bucket.Bucket, bucket)
		}
	}
	if snapshot.Local.RetentionDays != 90 || snapshot.TracePolicy.Sampler != "parentbased_always_on" ||
		snapshot.MetricPolicy.ExportIntervalSeconds != 60 || snapshot.MetricPolicy.Temporality != "delta" {
		t.Fatalf("effective defaults = local=%+v trace=%+v metric=%+v", snapshot.Local, snapshot.TracePolicy, snapshot.MetricPolicy)
	}
	if len(snapshot.Destinations) != 1 {
		t.Fatalf("destinations = %d, want generated local only", len(snapshot.Destinations))
	}
	local := snapshot.Destinations[0]
	if local.Name != "local-sqlite" || local.Kind != ObservabilityV8DestinationLocalSQLite || !local.Enabled || !local.Generated || len(local.Routes) != 1 {
		t.Fatalf("generated local destination = %+v", local)
	}
	if !local.Routes[0].IncludesMandatoryFloor || len(local.Routes[0].Selector.Buckets) != 14 ||
		!reflect.DeepEqual(local.SelectedSignals, []observability.Signal{observability.SignalLogs}) {
		t.Fatalf("generated local route = %+v", local.Routes[0])
	}
}

func TestObservabilityV8MinimalEffectivePlanGolden(t *testing.T) {
	compiled, err := ParseCompileObservabilityV8(
		"golden.yaml",
		[]byte("config_version: 8\nobservability: {}\n"),
		ObservabilityV8CompileOptions{DefaultDataDir: "/var/lib/defenseclaw"},
	)
	if err != nil {
		t.Fatal(err)
	}
	want, err := os.ReadFile(filepath.Join("testdata", "observability_v8", "minimal_effective_plan.json"))
	if err != nil {
		t.Fatal(err)
	}
	var compact bytes.Buffer
	if err := json.Compact(&compact, want); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(compiled.Plan.EffectiveJSON(), compact.Bytes()) {
		t.Fatalf("minimal effective plan changed; update the reviewed golden intentionally\nwant: %s\n got: %s", compact.Bytes(), compiled.Plan.EffectiveJSON())
	}
}

func TestCompileObservabilityV8BucketOverridesAreFieldLocal(t *testing.T) {
	falseValue, trueValue := false, true
	plan := mustCompileObservabilityV8(t, &ObservabilityV8Source{
		Defaults: ObservabilityV8BucketPolicySource{
			Collect:          ObservabilityV8CollectSource{Logs: &falseValue, Traces: &falseValue, Metrics: &falseValue},
			RedactionProfile: "strict",
		},
		Buckets: map[observability.Bucket]ObservabilityV8BucketPolicySource{
			observability.BucketModelIO: {
				Collect:          ObservabilityV8CollectSource{Logs: &trueValue},
				RedactionProfile: "sensitive",
			},
		},
	})
	model, _ := plan.Bucket(observability.BucketModelIO)
	if !model.Collect.Logs || model.Collect.Traces || model.Collect.Metrics || model.RedactionProfile != "sensitive" {
		t.Fatalf("model override = %+v", model)
	}
	tool, _ := plan.Bucket(observability.BucketToolActivity)
	if tool.Collect.Logs || tool.Collect.Traces || tool.Collect.Metrics || tool.RedactionProfile != "strict" {
		t.Fatalf("inherited tool policy = %+v", tool)
	}
	local, _ := plan.Destination(ObservabilityV8LocalDestinationName)
	if got := local.Routes[0].RedactionProfileByBucket[observability.BucketModelIO]; got != "sensitive" {
		t.Fatalf("local model profile = %q", got)
	}
}

func TestCompileObservabilityV8CapabilityDefaultsAndEnabledPointer(t *testing.T) {
	falseValue := false
	var tests []struct {
		Name    string                         `json:"name"`
		Kind    ObservabilityV8DestinationKind `json:"kind"`
		Preset  string                         `json:"preset"`
		Signals []observability.Signal         `json:"signals"`
	}
	fixture, err := os.ReadFile(filepath.Join("testdata", "observability_v8", "capability_defaults.json"))
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(fixture, &tests); err != nil {
		t.Fatal(err)
	}
	for _, test := range tests {
		t.Run(test.Name, func(t *testing.T) {
			var enabled *bool
			if test.Name == "galileo" {
				enabled = &falseValue
			}
			source := validObservabilityV8Destination(test.Name, test.Kind)
			source.Preset = test.Preset
			source.Enabled = enabled
			plan := mustCompileObservabilityV8(t, &ObservabilityV8Source{Destinations: []ObservabilityV8DestinationSource{source}})
			destination, ok := plan.Destination(test.Name)
			if !ok {
				t.Fatal("compiled destination not found")
			}
			wantEnabled := enabled == nil || *enabled
			if destination.Enabled != wantEnabled || destination.PolicyForm != ObservabilityV8PolicyCapabilityDefault ||
				!reflect.DeepEqual(destination.Capabilities.Signals, test.Signals) ||
				!reflect.DeepEqual(destination.SelectedSignals, test.Signals) {
				t.Fatalf("destination = %+v", destination)
			}
			if len(destination.Routes) != 1 || len(destination.Routes[0].Selector.Buckets) != 14 ||
				destination.Routes[0].Action != ObservabilityV8RouteSend {
				t.Fatalf("capability route = %+v", destination.Routes)
			}
			if reflect.DeepEqual(test.Signals, []observability.Signal{observability.SignalMetrics}) {
				if destination.Routes[0].RedactionProfileByBucket != nil {
					t.Fatal("metric-only route unexpectedly has redaction profiles")
				}
			} else if destination.Routes[0].RedactionProfileByBucket[observability.BucketModelIO] != "none" {
				t.Fatal("capability-default content route is not explicitly unredacted")
			}
		})
	}
}

func TestCompileObservabilityV8TransportDefaultsAndPresetExpansion(t *testing.T) {
	maxBackups, maxAge, compress := 0, 0, false
	source := &ObservabilityV8Source{Destinations: []ObservabilityV8DestinationSource{
		validObservabilityV8Destination("jsonl-defaults", ObservabilityV8DestinationJSONL),
		{
			Name: "jsonl-explicit-zero", Kind: ObservabilityV8DestinationJSONL, Path: "/tmp/explicit.jsonl",
			Rotation: ObservabilityV8RotationSource{MaxSizeMB: 1, MaxBackups: &maxBackups, MaxAgeDays: &maxAge, Compress: &compress},
		},
		validObservabilityV8Destination("http", ObservabilityV8DestinationHTTPJSONL),
		validObservabilityV8Destination("otlp", ObservabilityV8DestinationOTLP),
		func() ObservabilityV8DestinationSource {
			destination := validObservabilityV8Destination("galileo", ObservabilityV8DestinationOTLP)
			destination.Preset = "galileo"
			return destination
		}(),
	}}
	plan := mustCompileObservabilityV8(t, source)

	jsonl, _ := plan.Destination("jsonl-defaults")
	if jsonl.Transport.Rotation == nil || *jsonl.Transport.Rotation != (ObservabilityV8EffectiveRotation{MaxSizeMB: 50, MaxBackups: 5, MaxAgeDays: 30, Compress: true}) {
		t.Fatalf("jsonl defaults = %+v", jsonl.Transport.Rotation)
	}
	explicit, _ := plan.Destination("jsonl-explicit-zero")
	if explicit.Transport.Rotation == nil || *explicit.Transport.Rotation != (ObservabilityV8EffectiveRotation{MaxSizeMB: 1, MaxBackups: 0, MaxAgeDays: 0, Compress: false}) {
		t.Fatalf("jsonl explicit rotation = %+v", explicit.Transport.Rotation)
	}
	httpDestination, _ := plan.Destination("http")
	if httpDestination.Transport.Method != "POST" || httpDestination.Transport.TimeoutMS != 10_000 ||
		httpDestination.Transport.Batch == nil || *httpDestination.Transport.Batch != (ObservabilityV8BatchSource{MaxQueueSize: 2_048, MaxExportBatchSize: 512, ScheduledDelayMS: 5_000}) {
		t.Fatalf("http defaults = %+v", httpDestination.Transport)
	}
	otlp, _ := plan.Destination("otlp")
	if otlp.Transport.Protocol != "grpc" {
		t.Fatalf("general OTLP protocol = %q", otlp.Transport.Protocol)
	}
	galileo, _ := plan.Destination("galileo")
	if galileo.PresetProfile != "galileo-rich-v2" || galileo.Transport.Protocol != "http/protobuf" || galileo.Transport.Batch == nil ||
		galileo.Transport.Batch.ScheduledDelayMS != 1_000 {
		t.Fatalf("galileo preset expansion = %+v", galileo)
	}
	if got := plan.Snapshot().TracePolicy.SemanticProfileLock; got != observabilityV8SemanticProfileLock {
		t.Fatalf("semantic profile lock = %+v", got)
	}
}

func TestCompileObservabilityV8TransportValidation(t *testing.T) {
	logs := []observability.Signal{observability.SignalLogs}
	traces := []observability.Signal{observability.SignalTraces}
	mixed := []observability.Signal{observability.SignalLogs, observability.SignalTraces}
	tests := []struct {
		name        string
		destination ObservabilityV8DestinationSource
		want        string
	}{
		{name: "jsonl path", destination: ObservabilityV8DestinationSource{Name: "jsonl", Kind: ObservabilityV8DestinationJSONL}, want: ".path"},
		{name: "prometheus listen", destination: ObservabilityV8DestinationSource{Name: "metrics", Kind: ObservabilityV8DestinationPrometheus, Path: "/metrics"}, want: ".listen"},
		{name: "prometheus port", destination: ObservabilityV8DestinationSource{Name: "metrics", Kind: ObservabilityV8DestinationPrometheus, Listen: "127.0.0.1:not-a-port", Path: "/metrics"}, want: "port must"},
		{name: "splunk token", destination: ObservabilityV8DestinationSource{Name: "splunk", Kind: ObservabilityV8DestinationSplunkHEC, Endpoint: "https://splunk.example.test"}, want: "token_env"},
		{name: "http endpoint", destination: ObservabilityV8DestinationSource{Name: "http", Kind: ObservabilityV8DestinationHTTPJSONL}, want: "endpoint"},
		{name: "kind-specific field", destination: ObservabilityV8DestinationSource{Name: "console", Kind: ObservabilityV8DestinationConsole, Endpoint: "https://collector.example.test"}, want: "not supported"},
		{name: "otlp resolved endpoint", destination: ObservabilityV8DestinationSource{Name: "otlp", Kind: ObservabilityV8DestinationOTLP, Send: &ObservabilityV8SendSource{Signals: traces, Buckets: []observability.Bucket{"*"}}}, want: "no resolved endpoint"},
		{name: "otlp partial overrides", destination: ObservabilityV8DestinationSource{Name: "otlp", Kind: ObservabilityV8DestinationOTLP, Send: &ObservabilityV8SendSource{Signals: mixed, Buckets: []observability.Bucket{"*"}}, SignalOverrides: map[observability.Signal]ObservabilityV8SignalOverrideSource{observability.SignalTraces: {Endpoint: "https://traces.example.test"}}}, want: "logs.endpoint"},
		{name: "unsupported OTLP JSON wire format", destination: ObservabilityV8DestinationSource{Name: "otlp", Kind: ObservabilityV8DestinationOTLP, Protocol: "http/json", Endpoint: "https://otel.example.test"}, want: "unsupported value"},
		{name: "batch relation", destination: ObservabilityV8DestinationSource{Name: "http", Kind: ObservabilityV8DestinationHTTPJSONL, Endpoint: "https://archive.example.test", Batch: ObservabilityV8BatchSource{MaxQueueSize: 10, MaxExportBatchSize: 11}}, want: "must not exceed"},
		{name: "galileo protocol", destination: ObservabilityV8DestinationSource{Name: "galileo", Kind: ObservabilityV8DestinationOTLP, Preset: "galileo", Protocol: "grpc", Endpoint: "https://api.galileo.ai/otel/traces", Send: &ObservabilityV8SendSource{Signals: traces, Buckets: []observability.Bucket{"*"}}}, want: "requires http/protobuf"},
		{name: "unregistered event", destination: ObservabilityV8DestinationSource{Name: "console", Kind: ObservabilityV8DestinationConsole, Routes: []ObservabilityV8RouteSource{{Name: "bad", Signals: logs, Selector: &ObservabilityV8SelectorSource{EventNames: []observability.EventName{"made_up.event"}}}}}, want: "unregistered event"},
		{name: "unregistered action", destination: ObservabilityV8DestinationSource{Name: "console", Kind: ObservabilityV8DestinationConsole, Routes: []ObservabilityV8RouteSource{{Name: "bad", Signals: logs, Selector: &ObservabilityV8SelectorSource{Actions: []observability.ProducerKey{"made-up-action"}}}}}, want: "unregistered action"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			_, err := CompileObservabilityV8(&ObservabilityV8Source{Destinations: []ObservabilityV8DestinationSource{test.destination}})
			if err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("error = %v, want substring %q", err, test.want)
			}
		})
	}

	overrideOnly := ObservabilityV8DestinationSource{
		Name: "override-only", Kind: ObservabilityV8DestinationOTLP, Protocol: "http/protobuf",
		Send: &ObservabilityV8SendSource{Signals: traces, Buckets: []observability.Bucket{"*"}},
		SignalOverrides: map[observability.Signal]ObservabilityV8SignalOverrideSource{
			observability.SignalTraces: {Endpoint: "https://traces.example.test/v1/traces"},
		},
	}
	if _, err := CompileObservabilityV8(&ObservabilityV8Source{Destinations: []ObservabilityV8DestinationSource{overrideOnly}}); err != nil {
		t.Fatalf("override-only OTLP was rejected: %v", err)
	}
}

func TestCompileObservabilityV8CompatibilityAdapterFields(t *testing.T) {
	logs := []observability.Signal{observability.SignalLogs}
	splunk := validObservabilityV8Destination("splunk", ObservabilityV8DestinationSplunkHEC)
	splunk.SourceTypeOverrides = map[observability.ProducerKey]string{
		"llm-judge-response": "defenseclaw:judge",
		"guardrail-verdict":  "defenseclaw:verdict",
	}
	otlp := validObservabilityV8Destination("otel-logs", ObservabilityV8DestinationOTLP)
	otlp.LoggerName = "defenseclaw.audit"
	otlp.Send = &ObservabilityV8SendSource{Signals: logs, Buckets: []observability.Bucket{"*"}}

	plan := mustCompileObservabilityV8(t, &ObservabilityV8Source{Destinations: []ObservabilityV8DestinationSource{splunk, otlp}})
	compiledSplunk, _ := plan.RuntimeDestination("splunk")
	if got := compiledSplunk.Transport.SourceTypeOverrides["llm-judge-response"]; got != "defenseclaw:judge" {
		t.Fatalf("compiled sourcetype override = %q", got)
	}
	compiledOTLP, _ := plan.RuntimeDestination("otel-logs")
	if compiledOTLP.Transport.LoggerName != "defenseclaw.audit" {
		t.Fatalf("compiled logger_name = %q", compiledOTLP.Transport.LoggerName)
	}

	compiledSplunk.Transport.SourceTypeOverrides["llm-judge-response"] = "mutated"
	again, _ := plan.RuntimeDestination("splunk")
	if got := again.Transport.SourceTypeOverrides["llm-judge-response"]; got != "defenseclaw:judge" {
		t.Fatalf("transport plan exposed mutable sourcetype overrides: %q", got)
	}

	tooLong := strings.Repeat("x", 257)
	invalid := []struct {
		name        string
		destination ObservabilityV8DestinationSource
		want        string
	}{
		{
			name: "unregistered splunk producer",
			destination: func() ObservabilityV8DestinationSource {
				value := validObservabilityV8Destination("splunk", ObservabilityV8DestinationSplunkHEC)
				value.SourceTypeOverrides = map[observability.ProducerKey]string{"not-registered": "defenseclaw:unknown"}
				return value
			}(),
			want: "unregistered audit producer key",
		},
		{
			name: "oversized splunk sourcetype",
			destination: func() ObservabilityV8DestinationSource {
				value := validObservabilityV8Destination("splunk", ObservabilityV8DestinationSplunkHEC)
				value.SourceTypeOverrides = map[observability.ProducerKey]string{"guardrail-verdict": tooLong}
				return value
			}(),
			want: "1 through 256 bytes",
		},
		{
			name: "logger without logs",
			destination: func() ObservabilityV8DestinationSource {
				value := validObservabilityV8Destination("otel", ObservabilityV8DestinationOTLP)
				value.LoggerName = "defenseclaw.audit"
				value.Send = &ObservabilityV8SendSource{Signals: []observability.Signal{observability.SignalTraces}, Buckets: []observability.Bucket{"*"}}
				return value
			}(),
			want: "requires logs",
		},
		{
			name: "oversized logger",
			destination: func() ObservabilityV8DestinationSource {
				value := validObservabilityV8Destination("otel", ObservabilityV8DestinationOTLP)
				value.LoggerName = tooLong
				return value
			}(),
			want: "1 through 256 bytes",
		},
	}
	for _, test := range invalid {
		t.Run(test.name, func(t *testing.T) {
			_, err := CompileObservabilityV8(&ObservabilityV8Source{Destinations: []ObservabilityV8DestinationSource{test.destination}})
			if err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("error = %v, want substring %q", err, test.want)
			}
		})
	}
}

func TestCompileObservabilityV8EndpointNetworkSafety(t *testing.T) {
	tests := []struct {
		name     string
		endpoint string
		safety   ObservabilityV8NetworkSafetySource
		valid    bool
	}{
		{name: "public", endpoint: "https://collector.example.test/v1/logs", valid: true},
		{name: "userinfo", endpoint: "https://user:password@collector.example.test/v1/logs"},
		{name: "empty hostname", endpoint: "https://:4318/v1/logs"},
		{name: "invalid port", endpoint: "https://collector.example.test:not-a-port/v1/logs"},
		{name: "loopback blocked", endpoint: "https://127.0.0.1:4318/v1/logs"},
		{name: "loopback allowed", endpoint: "https://127.0.0.1:4318/v1/logs", safety: ObservabilityV8NetworkSafetySource{AllowPrivateNetworks: true}, valid: true},
		{name: "private blocked", endpoint: "https://10.1.2.3:4318/v1/logs"},
		{name: "ula allowed", endpoint: "https://[fd00::1]:4318/v1/logs", safety: ObservabilityV8NetworkSafetySource{AllowPrivateNetworks: true}, valid: true},
		{name: "cgnat blocked", endpoint: "https://100.64.1.2:4318/v1/logs"},
		{name: "cgnat allowed", endpoint: "https://100.64.1.2:4318/v1/logs", safety: ObservabilityV8NetworkSafetySource{AllowCGNAT: true}, valid: true},
		{name: "metadata remains blocked", endpoint: "https://100.100.100.200/metadata", safety: ObservabilityV8NetworkSafetySource{AllowCGNAT: true}},
		{name: "link local remains blocked", endpoint: "https://169.254.170.2/credentials", safety: ObservabilityV8NetworkSafetySource{AllowPrivateNetworks: true}},
		{name: "metadata hostname", endpoint: "https://metadata.google.internal/computeMetadata/v1/"},
		{name: "benchmark range", endpoint: "https://198.18.0.1:4318/v1/logs"},
		{name: "documentation range", endpoint: "https://203.0.113.10:4318/v1/logs"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			destination := validObservabilityV8Destination("archive", ObservabilityV8DestinationHTTPJSONL)
			destination.Endpoint = test.endpoint
			destination.NetworkSafety = test.safety
			_, err := CompileObservabilityV8(&ObservabilityV8Source{Destinations: []ObservabilityV8DestinationSource{destination}})
			if test.valid && err != nil {
				t.Fatalf("valid endpoint rejected: %v", err)
			}
			if !test.valid && err == nil {
				t.Fatal("unsafe endpoint accepted")
			}
		})
	}
	for _, endpoint := range []string{"collector.example.test:not-a-port", "user@collector.example.test:4317", ":4317"} {
		destination := validObservabilityV8Destination("otel", ObservabilityV8DestinationOTLP)
		destination.Protocol = "grpc"
		destination.Endpoint = endpoint
		if _, err := CompileObservabilityV8(&ObservabilityV8Source{Destinations: []ObservabilityV8DestinationSource{destination}}); err == nil {
			t.Fatalf("malformed gRPC authority %q was accepted", endpoint)
		}
	}
}

func TestCompileObservabilityV8WarningsAndProvenance(t *testing.T) {
	zero := 0
	destination := validObservabilityV8Destination("private", ObservabilityV8DestinationHTTPJSONL)
	destination.NetworkSafety.AllowPrivateNetworks = true
	destination.TLS.InsecureSkipVerify = true
	plan := mustCompileObservabilityV8(t, &ObservabilityV8Source{
		Local:        ObservabilityV8LocalSource{RetentionDays: &zero},
		Destinations: []ObservabilityV8DestinationSource{destination},
	})
	snapshot := plan.Snapshot()
	var warningCodes []string
	for _, warning := range snapshot.Warnings {
		warningCodes = append(warningCodes, warning.Code)
	}
	if !reflect.DeepEqual(warningCodes, []string{"retention_unbounded", "tls_verification_disabled", "private_export_network_allowed"}) {
		t.Fatalf("warnings = %v", warningCodes)
	}
	if len(snapshot.Provenance) < 34 {
		t.Fatalf("effective provenance is incomplete: %d entries", len(snapshot.Provenance))
	}
}

func TestCompileObservabilityV8RejectsSecretBearingResourceAttributes(t *testing.T) {
	for _, attributes := range []map[string]string{
		{"service.api_key": "not-rendered"},
		{"service.note": "Bearer not-rendered"},
		{"service.endpoint": "https://user:not-rendered@example.test"},
		{"service.note": "-----BEGIN PRIVATE KEY-----not-rendered"},
	} {
		_, err := CompileObservabilityV8(&ObservabilityV8Source{Resource: ObservabilityV8ResourceSource{Attributes: attributes}})
		if err == nil || strings.Contains(err.Error(), "not-rendered") {
			t.Fatalf("resource secret error was absent or value-unsafe: %v", err)
		}
	}
	if _, err := CompileObservabilityV8(&ObservabilityV8Source{Resource: ObservabilityV8ResourceSource{Attributes: map[string]string{"service.tokenizer": "tiktoken"}}}); err != nil {
		t.Fatalf("non-secret resource attribute was rejected: %v", err)
	}
}

func TestCompileObservabilityV8ConciseSendAndDerivedSignals(t *testing.T) {
	plan := mustCompileObservabilityV8(t, &ObservabilityV8Source{Destinations: []ObservabilityV8DestinationSource{{
		Name: "otel", Kind: ObservabilityV8DestinationOTLP, Endpoint: "https://otel.example.test",
		Send: &ObservabilityV8SendSource{
			Signals:          []observability.Signal{observability.SignalMetrics, observability.SignalLogs},
			Buckets:          []observability.Bucket{observability.BucketSecurityFinding, observability.BucketPlatformHealth},
			RedactionProfile: "strict",
		},
	}}})
	destination, _ := plan.Destination("otel")
	if destination.PolicyForm != ObservabilityV8PolicyConciseSend || !destination.FirstMatchPerSignal || len(destination.Routes) != 1 {
		t.Fatalf("concise destination = %+v", destination)
	}
	wantSelected := []observability.Signal{observability.SignalLogs, observability.SignalMetrics}
	if !reflect.DeepEqual(destination.SelectedSignals, wantSelected) {
		t.Fatalf("derived signals = %v, want %v", destination.SelectedSignals, wantSelected)
	}
	route := destination.Routes[0]
	if route.Name != "send" || !route.Generated || route.Index != 0 || route.RedactionProfileByBucket[observability.BucketSecurityFinding] != "strict" {
		t.Fatalf("compiled concise route = %+v", route)
	}
}

func TestCompileObservabilityV8AdvancedRoutesPreserveFirstMatchOrder(t *testing.T) {
	diagnostic := ObservabilityV8SelectorSource{Buckets: []observability.Bucket{observability.BucketDiagnostic}}
	all := ObservabilityV8SelectorSource{Buckets: []observability.Bucket{"*"}}
	plan := mustCompileObservabilityV8(t, &ObservabilityV8Source{Destinations: []ObservabilityV8DestinationSource{{
		Name: "console", Kind: ObservabilityV8DestinationConsole,
		Routes: []ObservabilityV8RouteSource{
			{Name: "drop-diagnostic", Signals: []observability.Signal{observability.SignalLogs}, Selector: &diagnostic, Action: ObservabilityV8RouteDrop},
			{Name: "send-rest", Signals: []observability.Signal{observability.SignalLogs}, Selector: &all, RedactionProfile: "sensitive"},
		},
	}}})
	destination, _ := plan.Destination("console")
	if destination.PolicyForm != ObservabilityV8PolicyAdvancedRoutes || !destination.FirstMatchPerSignal || len(destination.Routes) != 2 {
		t.Fatalf("advanced destination = %+v", destination)
	}
	if destination.Routes[0].Index != 0 || destination.Routes[0].Action != ObservabilityV8RouteDrop ||
		destination.Routes[1].Index != 1 || destination.Routes[1].Action != ObservabilityV8RouteSend ||
		len(destination.Routes[1].Selector.Buckets) != 14 {
		t.Fatalf("ordered routes = %+v", destination.Routes)
	}
}

func TestCompileObservabilityV8RejectsInvalidRouting(t *testing.T) {
	emptySelector := &ObservabilityV8SelectorSource{}
	logs := []observability.Signal{observability.SignalLogs}
	tests := []struct {
		name   string
		source ObservabilityV8Source
		want   string
	}{
		{name: "reserved name", source: ObservabilityV8Source{Destinations: []ObservabilityV8DestinationSource{{Name: "local-sqlite", Kind: ObservabilityV8DestinationJSONL}}}, want: "reserved"},
		{name: "source sqlite", source: ObservabilityV8Source{Destinations: []ObservabilityV8DestinationSource{{Name: "local", Kind: ObservabilityV8DestinationLocalSQLite}}}, want: "generated"},
		{name: "duplicate destination", source: ObservabilityV8Source{Destinations: []ObservabilityV8DestinationSource{{Name: "same", Kind: ObservabilityV8DestinationConsole}, {Name: "same", Kind: ObservabilityV8DestinationConsole}}}, want: "duplicate"},
		{name: "send and routes", source: ObservabilityV8Source{Destinations: []ObservabilityV8DestinationSource{{Name: "mixed", Kind: ObservabilityV8DestinationConsole, Send: &ObservabilityV8SendSource{Signals: logs, Buckets: []observability.Bucket{"*"}}, Routes: []ObservabilityV8RouteSource{{Name: "route", Signals: logs, Selector: emptySelector}}}}}, want: "mutually exclusive"},
		{name: "wildcard mixed", source: ObservabilityV8Source{Destinations: []ObservabilityV8DestinationSource{{Name: "wild", Kind: ObservabilityV8DestinationConsole, Send: &ObservabilityV8SendSource{Signals: logs, Buckets: []observability.Bucket{"*", observability.BucketDiagnostic}}}}}, want: "wildcard"},
		{name: "unsupported signal", source: ObservabilityV8Source{Destinations: []ObservabilityV8DestinationSource{{Name: "console", Kind: ObservabilityV8DestinationConsole, Send: &ObservabilityV8SendSource{Signals: []observability.Signal{observability.SignalTraces}, Buckets: []observability.Bucket{"*"}}}}}, want: "not supported"},
		{name: "metric redaction", source: ObservabilityV8Source{Destinations: []ObservabilityV8DestinationSource{{Name: "metrics", Kind: ObservabilityV8DestinationPrometheus, Send: &ObservabilityV8SendSource{Signals: []observability.Signal{observability.SignalMetrics}, Buckets: []observability.Bucket{"*"}, RedactionProfile: "strict"}}}}, want: "metric-only"},
		{name: "drop redaction", source: ObservabilityV8Source{Destinations: []ObservabilityV8DestinationSource{{Name: "drop", Kind: ObservabilityV8DestinationConsole, Routes: []ObservabilityV8RouteSource{{Name: "drop", Signals: logs, Selector: emptySelector, Action: ObservabilityV8RouteDrop, RedactionProfile: "strict"}}}}}, want: "drop route"},
		{name: "empty routes", source: ObservabilityV8Source{Destinations: []ObservabilityV8DestinationSource{{Name: "empty", Kind: ObservabilityV8DestinationConsole, Routes: []ObservabilityV8RouteSource{}}}}, want: "must not be empty"},
		{name: "override not selected", source: ObservabilityV8Source{Destinations: []ObservabilityV8DestinationSource{{Name: "otel", Kind: ObservabilityV8DestinationOTLP, Endpoint: "https://otel.example.test", Send: &ObservabilityV8SendSource{Signals: logs, Buckets: []observability.Bucket{"*"}}, SignalOverrides: map[observability.Signal]ObservabilityV8SignalOverrideSource{observability.SignalTraces: {Path: "/v1/traces"}}}}}, want: "not selected"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			_, err := CompileObservabilityV8(&test.source)
			if err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("error = %v, want substring %q", err, test.want)
			}
		})
	}
}

func TestCompileObservabilityV8Profiles(t *testing.T) {
	plan := mustCompileObservabilityV8(t, &ObservabilityV8Source{
		RedactionProfiles: map[string]ObservabilityV8RedactionProfileSource{
			"soc": {
				Extends:      "sensitive",
				Detectors:    []ObservabilityV8DetectorGroup{ObservabilityV8DetectorPII, ObservabilityV8DetectorCredentials},
				FieldClasses: map[ObservabilityV8FieldClass]ObservabilityV8FieldMode{ObservabilityV8FieldEvidence: ObservabilityV8ModeWhole},
			},
		},
		Buckets: map[observability.Bucket]ObservabilityV8BucketPolicySource{
			observability.BucketSecurityFinding: {RedactionProfile: "soc"},
		},
	})
	profiles := plan.Snapshot().Profiles
	if len(profiles) != 6 || profiles[4].Name != "legacy-v7" || profiles[5].Name != "soc" || profiles[5].FieldClasses[ObservabilityV8FieldEvidence] != ObservabilityV8ModeWhole {
		t.Fatalf("compiled profiles = %+v", profiles)
	}
	for _, fieldClass := range []ObservabilityV8FieldClass{
		ObservabilityV8FieldContent,
		ObservabilityV8FieldReason,
		ObservabilityV8FieldEvidence,
		ObservabilityV8FieldError,
	} {
		if profiles[1].FieldClasses[fieldClass] != ObservabilityV8ModeDetect {
			t.Errorf("sensitive %s mode = %q, want detect", fieldClass, profiles[1].FieldClasses[fieldClass])
		}
		if profiles[2].FieldClasses[fieldClass] != ObservabilityV8ModeWhole {
			t.Errorf("content %s mode = %q, want whole", fieldClass, profiles[2].FieldClasses[fieldClass])
		}
		if profiles[3].FieldClasses[fieldClass] != ObservabilityV8ModeRemove {
			t.Errorf("strict %s mode = %q, want remove", fieldClass, profiles[3].FieldClasses[fieldClass])
		}
	}
	if profiles[1].FieldClasses[ObservabilityV8FieldPath] != ObservabilityV8ModeHash ||
		profiles[2].FieldClasses[ObservabilityV8FieldPath] != ObservabilityV8ModeHash ||
		profiles[3].FieldClasses[ObservabilityV8FieldPath] != ObservabilityV8ModeRemove {
		t.Fatalf("built-in path modes = sensitive:%q content:%q strict:%q",
			profiles[1].FieldClasses[ObservabilityV8FieldPath],
			profiles[2].FieldClasses[ObservabilityV8FieldPath],
			profiles[3].FieldClasses[ObservabilityV8FieldPath])
	}
	legacy := profiles[4]
	if len(legacy.Detectors) != 0 || legacy.FieldClasses[ObservabilityV8FieldMetadata] != ObservabilityV8ModePreserve {
		t.Fatalf("legacy-v7 metadata/detectors = %+v", legacy)
	}
	for _, fieldClass := range []ObservabilityV8FieldClass{
		ObservabilityV8FieldIdentifier, ObservabilityV8FieldContent, ObservabilityV8FieldReason,
		ObservabilityV8FieldEvidence, ObservabilityV8FieldError, ObservabilityV8FieldPath, ObservabilityV8FieldCredential,
	} {
		if legacy.FieldClasses[fieldClass] != ObservabilityV8ModeWhole {
			t.Errorf("legacy-v7 %s mode = %q, want whole", fieldClass, legacy.FieldClasses[fieldClass])
		}
	}

	invalid := []ObservabilityV8Source{
		{RedactionProfiles: map[string]ObservabilityV8RedactionProfileSource{"raw": {Extends: "none"}}},
		{RedactionProfiles: map[string]ObservabilityV8RedactionProfileSource{"legacy-v7": {Extends: "strict"}}},
		{RedactionProfiles: map[string]ObservabilityV8RedactionProfileSource{"compat": {Extends: "legacy-v7"}}},
		{RedactionProfiles: map[string]ObservabilityV8RedactionProfileSource{"a": {Extends: "b"}, "b": {Extends: "a"}}},
		{RedactionProfiles: map[string]ObservabilityV8RedactionProfileSource{"bad": {Extends: "strict", Detectors: []ObservabilityV8DetectorGroup{"unknown"}}}},
		{RedactionProfiles: map[string]ObservabilityV8RedactionProfileSource{"bad": {Extends: "sensitive", FieldClasses: map[ObservabilityV8FieldClass]ObservabilityV8FieldMode{ObservabilityV8FieldContent: ObservabilityV8ModePreserve}}}},
	}
	for index := range invalid {
		if _, err := CompileObservabilityV8(&invalid[index]); err == nil {
			t.Errorf("invalid profile case %d compiled", index)
		}
	}
}

func TestObservabilityV8PlanIsCopySafeAndDeterministic(t *testing.T) {
	sourceA := ObservabilityV8Source{
		Resource: ObservabilityV8ResourceSource{Attributes: map[string]string{"z": "last", "a": "first"}},
		Destinations: []ObservabilityV8DestinationSource{{
			Name: "otel", Kind: ObservabilityV8DestinationOTLP, Endpoint: "https://otel.example.test",
			Headers: map[string]ObservabilityV8HeaderValue{
				"X-Static":      ObservabilityV8StaticHeader("value"),
				"Authorization": ObservabilityV8EnvironmentHeader("OTEL_AUTHORIZATION"),
				"X-API-Key":     ObservabilityV8StaticHeader("inline-compat-secret"),
				"X-Password":    ObservabilityV8StaticHeader("password-shaped-header"),
				"X-Auth":        ObservabilityV8StaticHeader("auth-shaped-header"),
			},
		}},
	}
	sourceB := ObservabilityV8Source{
		Resource: ObservabilityV8ResourceSource{Attributes: map[string]string{"a": "first", "z": "last"}},
		Destinations: []ObservabilityV8DestinationSource{{
			Name: "otel", Kind: ObservabilityV8DestinationOTLP, Endpoint: "https://otel.example.test",
			Headers: map[string]ObservabilityV8HeaderValue{
				"Authorization": ObservabilityV8EnvironmentHeader("OTEL_AUTHORIZATION"),
				"X-API-Key":     ObservabilityV8StaticHeader("inline-compat-secret"),
				"X-Password":    ObservabilityV8StaticHeader("password-shaped-header"),
				"X-Auth":        ObservabilityV8StaticHeader("auth-shaped-header"),
				"X-Static":      ObservabilityV8StaticHeader("value"),
			},
		}},
	}
	planA := mustCompileObservabilityV8(t, &sourceA)
	planB := mustCompileObservabilityV8(t, &sourceB)
	if planA.Digest() != planB.Digest() || !bytes.Equal(planA.EffectiveJSON(), planB.EffectiveJSON()) {
		t.Fatal("map insertion order changed the effective plan")
	}
	if bytes.Contains(planA.EffectiveJSON(), []byte("inline-compat-secret")) ||
		bytes.Contains(planA.EffectiveJSON(), []byte("password-shaped-header")) ||
		bytes.Contains(planA.EffectiveJSON(), []byte("auth-shaped-header")) {
		t.Fatal("masked effective JSON exposed an inline authorization secret")
	}
	display, _ := planA.Destination("otel")
	if display.Transport.Headers["X-API-Key"].Static == nil || *display.Transport.Headers["X-API-Key"].Static != "[REDACTED]" {
		t.Fatalf("display header was not masked: %+v", display.Transport.Headers["X-API-Key"])
	}
	runtimeDestination, _ := planA.RuntimeDestination("otel")
	if runtimeDestination.Transport.Headers["X-API-Key"].Static == nil || *runtimeDestination.Transport.Headers["X-API-Key"].Static != "inline-compat-secret" {
		t.Fatal("runtime adapter projection lost the source-declared static header")
	}
	original := append([]byte(nil), planA.EffectiveJSON()...)
	snapshot := planA.Snapshot()
	snapshot.ResourceAttributes["a"] = "mutated"
	snapshot.Destinations[1].Routes[0].Selector.Buckets[0] = observability.BucketDiagnostic
	snapshot.Destinations[1].Routes[0].RedactionProfileByBucket[observability.BucketModelIO] = "strict"
	snapshot.Destinations[1].Transport.Headers["Authorization"] = ObservabilityV8StaticHeader("mutated")
	returned, _ := planA.Destination("otel")
	returned.Routes[0].Signals[0] = observability.SignalMetrics
	if !bytes.Equal(original, planA.EffectiveJSON()) {
		t.Fatal("mutating returned copies changed the immutable plan")
	}
}

func TestCompileObservabilityV8StructuralRouteLimit(t *testing.T) {
	selector := &ObservabilityV8SelectorSource{}
	routes := make([]ObservabilityV8RouteSource, ObservabilityV8MaxRoutesPerDestination+1)
	for index := range routes {
		routes[index] = ObservabilityV8RouteSource{Name: "route-" + string(rune(index+1)), Signals: []observability.Signal{observability.SignalLogs}, Selector: selector}
	}
	_, err := CompileObservabilityV8(&ObservabilityV8Source{Destinations: []ObservabilityV8DestinationSource{{Name: "too-many", Kind: ObservabilityV8DestinationConsole, Routes: routes}}})
	if err == nil || !strings.Contains(err.Error(), "maximum") {
		t.Fatalf("route-limit error = %v", err)
	}
}

func TestCompileObservabilityV8RejectsTraceLimitAboveHardCeiling(t *testing.T) {
	tests := []struct {
		name   string
		limits ObservabilityV8TraceLimitsSource
	}{
		{"attributes", ObservabilityV8TraceLimitsSource{MaxAttributesPerSpan: 257}},
		{"events", ObservabilityV8TraceLimitsSource{MaxEventsPerSpan: 129}},
		{"links", ObservabilityV8TraceLimitsSource{MaxLinksPerSpan: 65}},
		{"event attributes", ObservabilityV8TraceLimitsSource{MaxAttributesPerEvent: 65}},
		{"attribute bytes", ObservabilityV8TraceLimitsSource{MaxAttributeValueBytes: 65_537}},
		{"span bytes", ObservabilityV8TraceLimitsSource{MaxProjectedSpanBytes: 1_048_577}},
		{"stacktrace bytes", ObservabilityV8TraceLimitsSource{MaxStacktraceBytes: 131_073}},
		{"message items", ObservabilityV8TraceLimitsSource{MaxMessageItems: 513}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			_, err := CompileObservabilityV8(&ObservabilityV8Source{
				TracePolicy: ObservabilityV8TracePolicySource{Limits: test.limits},
			})
			if err == nil || !strings.Contains(err.Error(), "must be from") {
				t.Fatalf("hard-ceiling error = %v", err)
			}
		})
	}
}

func TestCompileObservabilityV8RejectsTraceLimitBelowFamilyMinimum(t *testing.T) {
	for _, test := range []struct {
		name   string
		limits ObservabilityV8TraceLimitsSource
	}{
		{"attributes", ObservabilityV8TraceLimitsSource{MaxAttributesPerSpan: 31}},
		{"event attributes", ObservabilityV8TraceLimitsSource{MaxAttributesPerEvent: 3}},
		{"attribute bytes", ObservabilityV8TraceLimitsSource{MaxAttributeValueBytes: 255}},
		{"span bytes", ObservabilityV8TraceLimitsSource{MaxProjectedSpanBytes: 4_095}},
		{"stacktrace bytes", ObservabilityV8TraceLimitsSource{MaxStacktraceBytes: 255}},
	} {
		t.Run(test.name, func(t *testing.T) {
			_, err := CompileObservabilityV8(&ObservabilityV8Source{TracePolicy: ObservabilityV8TracePolicySource{Limits: test.limits}})
			if err == nil || !strings.Contains(err.Error(), "must be from") {
				t.Fatalf("family-minimum error = %v", err)
			}
		})
	}
}

func TestCompileObservabilityV8SamplerVocabulary(t *testing.T) {
	for _, sampler := range []string{
		"always_on", "always_off", "parentbased_always_on", "parentbased_always_off",
		"traceidratio", "parentbased_traceidratio",
	} {
		t.Run(sampler, func(t *testing.T) {
			argument := ""
			if strings.Contains(sampler, "traceidratio") {
				argument = "0.5"
			}
			if _, err := CompileObservabilityV8(&ObservabilityV8Source{TracePolicy: ObservabilityV8TracePolicySource{Sampler: sampler, SamplerArg: argument}}); err != nil {
				t.Fatalf("schema-declared sampler rejected: %v", err)
			}
		})
	}
	for _, argument := range []string{"NaN", "+Inf", "-Inf"} {
		if _, err := CompileObservabilityV8(&ObservabilityV8Source{TracePolicy: ObservabilityV8TracePolicySource{Sampler: "traceidratio", SamplerArg: argument}}); err == nil {
			t.Fatalf("non-finite sampler ratio %q was accepted", argument)
		}
	}
}

func TestObservabilityV8HeaderValueSourceShapes(t *testing.T) {
	var headers map[string]ObservabilityV8HeaderValue
	if err := yaml.Unmarshal([]byte("static: visible\nsecret: {env: TOKEN_ENV}\n"), &headers); err != nil {
		t.Fatal(err)
	}
	if headers["static"].Static == nil || *headers["static"].Static != "visible" ||
		headers["secret"].Secret == nil || headers["secret"].Secret.Env != "TOKEN_ENV" {
		t.Fatalf("decoded headers = %+v", headers)
	}
	raw, err := json.Marshal(headers)
	if err != nil {
		t.Fatal(err)
	}
	if string(raw) != `{"secret":{"env":"TOKEN_ENV"},"static":"visible"}` {
		t.Fatalf("header JSON = %s", raw)
	}
	var decoded map[string]ObservabilityV8HeaderValue
	if err := json.Unmarshal(raw, &decoded); err != nil {
		t.Fatal(err)
	}
	if decoded["secret"].Secret == nil || decoded["secret"].Secret.Env != "TOKEN_ENV" {
		t.Fatalf("JSON-decoded headers = %+v", decoded)
	}
	for _, invalid := range []string{
		"header: {env: ''}\n",
		"header: {env: TOKEN, other: value}\n",
		"header: [TOKEN]\n",
	} {
		if err := yaml.Unmarshal([]byte(invalid), &headers); err == nil {
			t.Fatalf("invalid header shape accepted: %q", invalid)
		}
	}
	var trailing ObservabilityV8HeaderValue
	if err := trailing.UnmarshalJSON([]byte(`{"env":"TOKEN"} {"env":"SECOND"}`)); err == nil {
		t.Fatal("header JSON accepted trailing content")
	}
}

func TestObservabilityV8EffectivePlanMasksEndpointQueryAndFragment(t *testing.T) {
	destination := validObservabilityV8Destination("archive", ObservabilityV8DestinationHTTPJSONL)
	destination.Endpoint = "https://collector.example.test/events?api_key=query-secret#private-fragment"
	plan, err := CompileObservabilityV8(&ObservabilityV8Source{Destinations: []ObservabilityV8DestinationSource{destination}})
	if err != nil {
		t.Fatal(err)
	}
	display := string(plan.EffectiveJSON())
	if strings.Contains(display, "query-secret") || strings.Contains(display, "private-fragment") {
		t.Fatalf("effective plan leaked endpoint query or fragment: %s", display)
	}
	runtimeDestination, ok := plan.RuntimeDestination("archive")
	if !ok || !strings.Contains(runtimeDestination.Transport.Endpoint, "query-secret") ||
		!strings.Contains(runtimeDestination.Transport.Endpoint, "private-fragment") {
		t.Fatalf("runtime endpoint was altered: %+v", runtimeDestination.Transport)
	}
}

func mustCompileObservabilityV8(t *testing.T, source *ObservabilityV8Source) *ObservabilityV8Plan {
	t.Helper()
	plan, err := CompileObservabilityV8(source)
	if err != nil {
		t.Fatalf("CompileObservabilityV8: %v", err)
	}
	return plan
}

func validObservabilityV8Destination(name string, kind ObservabilityV8DestinationKind) ObservabilityV8DestinationSource {
	destination := ObservabilityV8DestinationSource{Name: name, Kind: kind}
	switch kind {
	case ObservabilityV8DestinationJSONL:
		destination.Path = "/tmp/defenseclaw-events.jsonl"
	case ObservabilityV8DestinationPrometheus:
		destination.Listen = "127.0.0.1:9464"
		destination.Path = "/metrics"
	case ObservabilityV8DestinationSplunkHEC:
		destination.Endpoint = "https://splunk.example.test/services/collector/event"
		destination.TokenEnv = "SPLUNK_HEC_TOKEN"
	case ObservabilityV8DestinationHTTPJSONL:
		destination.Endpoint = "https://archive.example.test/events"
	case ObservabilityV8DestinationOTLP:
		destination.Endpoint = "https://otel.example.test"
	}
	return destination
}
