// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// SPDX-License-Identifier: Apache-2.0

package observability

import (
	"errors"
	"reflect"
	"strings"
	"sync"
	"testing"
)

func TestInboundCatalogGeneratedInventoryAndCrossReferences(t *testing.T) {
	catalog, err := LoadInboundCatalog()
	if err != nil {
		t.Fatalf("LoadInboundCatalog() error = %v", err)
	}
	if got, want := len(catalog.Aliases()), 9; got != want {
		t.Fatalf("aliases = %d, want %d", got, want)
	}
	if got, want := len(catalog.snapshot.matches), 237; got != want {
		t.Fatalf("matches = %d, want %d", got, want)
	}
	if got, want := len(catalog.snapshot.targets), 245; got != want {
		t.Fatalf("targets = %d, want %d", got, want)
	}
	if got, want := len(catalog.snapshot.markers), 24; got != want {
		t.Fatalf("markers = %d, want %d", got, want)
	}
	if got, want := len(catalog.snapshot.echoes), 249; got != want {
		t.Fatalf("echo recognizers = %d, want %d", got, want)
	}
	if got, want := len(catalog.snapshot.contexts), 93; got != want {
		t.Fatalf("import contexts = %d, want %d", got, want)
	}

	for id, index := range catalog.snapshot.matchByID {
		match, ok := catalog.Match(id)
		if !ok || match.index != index || match.ID() != id {
			t.Fatalf("match lookup %q did not round trip", id)
		}
		for _, target := range match.Targets() {
			if target.MatchID() != id {
				t.Fatalf("target %q match = %q, want %q", target.ID(), target.MatchID(), id)
			}
		}
	}
	for id, index := range catalog.snapshot.targetByID {
		target, ok := catalog.Target(id)
		if !ok || target.index != index || target.ID() != id {
			t.Fatalf("target lookup %q did not round trip", id)
		}
		fields := target.Fields()
		if got, want := len(fields), len(catalog.snapshot.targets[index].descriptor.familyDescriptorContract().fields); got != want {
			t.Fatalf("target %q fields = %d, want %d", id, got, want)
		}
		for fieldIndex, field := range fields {
			if field.FieldRef() != catalog.snapshot.targets[index].descriptor.familyDescriptorContract().fields[fieldIndex].key {
				t.Fatalf("target %q field %d lost descriptor order", id, fieldIndex)
			}
		}
	}
	for _, marker := range catalog.snapshot.markers {
		resolved, ok := catalog.NativeMarker(marker.signal, marker.location, marker.key)
		if !ok || resolved.ID() != marker.id {
			t.Fatalf("native marker %q did not round trip", marker.id)
		}
	}
	for _, echo := range catalog.snapshot.echoes {
		resolved, ok := catalog.EchoRecognizer(echo.signal, echo.family, echo.bucket, echo.eventName, echo.instrumentName)
		if !ok || resolved.ID() != echo.id {
			t.Fatalf("echo recognizer %q did not round trip", echo.id)
		}
		var wire InboundEchoRecognizer
		switch echo.signal {
		case SignalLogs, SignalTraces:
			wire, ok = catalog.EchoRecognizerForWireIdentity(echo.signal, echo.bucket, echo.eventName, "")
		case SignalMetrics:
			wire, ok = catalog.EchoRecognizerForWireIdentity(echo.signal, "", "", echo.instrumentName)
		}
		if !ok || wire.ID() != echo.id {
			t.Fatalf("echo wire identity %q did not round trip", echo.id)
		}
	}
	for _, context := range catalog.snapshot.contexts {
		byID, ok := catalog.ImportContext(context.id)
		if !ok || byID.FamilyDescriptorID() != context.familyDescriptorID {
			t.Fatalf("import context %q did not round trip by ID", context.id)
		}
		byFamily, ok := catalog.ImportContextForFamily(context.familyDescriptorID)
		if !ok || byFamily.ID() != context.id {
			t.Fatalf("import context %q did not round trip by family", context.id)
		}
	}
}

func TestInboundCatalogSourceFilteringIsExact(t *testing.T) {
	catalog := mustInboundCatalog(t)
	for _, signal := range Signals() {
		for _, source := range []string{"codex", "claudecode", "another_authenticated_source"} {
			matches := catalog.Matches(signal, source)
			for _, match := range matches {
				if match.Signal() != signal || !inboundSourceApplies(match.Sources(), source) {
					t.Fatalf("Matches(%q, %q) returned %q with sources %v", signal, source, match.ID(), match.Sources())
				}
			}
		}
	}
	if got := catalog.Matches(SignalLogs, "any_authenticated"); got != nil {
		t.Fatalf("caller wildcard returned %d matches, want nil", len(got))
	}
	if got := catalog.Matches("unknown", "codex"); got != nil {
		t.Fatalf("unknown signal returned %d matches, want nil", len(got))
	}
	assertMatchPresence := func(source, id string, want bool) {
		t.Helper()
		found := false
		for _, match := range catalog.Matches(SignalLogs, source) {
			found = found || match.ID() == id
		}
		if found != want {
			t.Fatalf("Matches(logs, %q) contains %q = %v, want %v", source, id, found, want)
		}
	}
	assertMatchPresence("codex", "otlp.codex.user_prompt.v1.log.model.request", true)
	assertMatchPresence("claudecode", "otlp.codex.user_prompt.v1.log.model.request", false)
	assertMatchPresence("claudecode", "otlp.claudecode.user_prompt.v1.log.model.request", true)
	assertMatchPresence("codex", "otlp.claudecode.user_prompt.v1.log.model.request", false)
	if alias, ok := catalog.Alias("unknown"); ok || alias.ID() != "" {
		t.Fatalf("unknown alias returned (%q, %v)", alias.ID(), ok)
	}
	if match, ok := catalog.Match("unknown"); ok || match.ID() != "" {
		t.Fatalf("unknown match returned (%q, %v)", match.ID(), ok)
	}
	if target, ok := catalog.Target("unknown"); ok || target.ID() != "" {
		t.Fatalf("unknown target returned (%q, %v)", target.ID(), ok)
	}
	if marker, ok := catalog.NativeMarker(SignalLogs, InboundLocationLeafAttribute, "unknown"); ok || marker.ID() != "" {
		t.Fatalf("unknown marker returned (%q, %v)", marker.ID(), ok)
	}
	if echo, ok := catalog.EchoRecognizer(SignalLogs, "unknown", BucketDiagnostic, "unknown", ""); ok || echo.ID() != "" {
		t.Fatalf("unknown echo returned (%q, %v)", echo.ID(), ok)
	}
	if echo, ok := catalog.EchoRecognizerForWireIdentity(SignalLogs, BucketDiagnostic, "unknown", "irrelevant"); ok || echo.ID() != "" {
		t.Fatalf("log wire echo accepted irrelevant instrument (%q, %v)", echo.ID(), ok)
	}
	if echo, ok := catalog.EchoRecognizerForWireIdentity(SignalMetrics, BucketModelIO, "metric.ignored", "gen_ai.client.operation.duration"); ok || echo.ID() != "" {
		t.Fatalf("metric wire echo accepted irrelevant bucket/event (%q, %v)", echo.ID(), ok)
	}
	histogramEcho, ok := catalog.EchoRecognizerForWireIdentity(SignalMetrics, "", "", "gen_ai.client.operation.duration")
	if !ok || histogramEcho.Family() != "metric.gen_ai.client.operation.duration" {
		t.Fatalf("non-reversible metric echo = (%q, %q, %v)", histogramEcho.ID(), histogramEcho.Family(), ok)
	}
	if context, ok := catalog.ImportContext("unknown"); ok || context.ID() != "" {
		t.Fatalf("unknown context returned (%q, %v)", context.ID(), ok)
	}
}

func TestInboundCatalogWorkflowOverrideAndOrderedFields(t *testing.T) {
	catalog := mustInboundCatalog(t)
	match, ok := catalog.Match("otlp.genai.span.operation.v1.span.workflow.run")
	if !ok {
		t.Fatal("workflow match not found")
	}
	override, ok := match.TargetOverride()
	if !ok || override.Source() != "gen_ai.workflow.name" ||
		override.Target() != "defenseclaw.workflow.name" || override.Normalization() != "identifier-v1" {
		t.Fatalf("workflow override = (%q, %q, %q, %v)", override.Source(), override.Target(), override.Normalization(), ok)
	}
	for _, candidate := range catalog.snapshot.matches {
		if candidate.id == match.ID() {
			continue
		}
		if _, present := candidate.targetOverride.Get(); present {
			t.Fatalf("unexpected override on %q", candidate.id)
		}
	}
	workflowTargets := match.Targets()
	if len(workflowTargets) != 2 {
		t.Fatalf("workflow targets = %d, want 2", len(workflowTargets))
	}
	var primary InboundTarget
	for _, target := range workflowTargets {
		if target.TargetKind() == InboundTargetPrimary {
			primary = target
		}
	}
	if primary.Family() != "span.workflow.run" || primary.Role() != InboundTargetImport || primary.TargetKind() != InboundTargetPrimary {
		t.Fatalf("workflow primary = %q/%q/%q", primary.Family(), primary.Role(), primary.TargetKind())
	}
	fields := primary.Fields()
	found := false
	for index, field := range fields {
		want := "span:span.workflow.run:" + field.FieldRef()
		if field.DescriptorID() != want {
			t.Fatalf("field %d descriptor = %q, want %q", index, field.DescriptorID(), want)
		}
		if field.FieldRef() == "defenseclaw.workflow.name" {
			found = true
		}
	}
	if !found {
		t.Fatal("workflow target does not contain defenseclaw.workflow.name")
	}
}

func TestInboundCatalogTerminalNativePolicies(t *testing.T) {
	catalog := mustInboundCatalog(t)
	policies := catalog.Policies()
	if policies != (InboundTerminalPolicies{
		UnknownFields:                   "drop_and_count",
		NativeMarkerRule:                "any_declared_native_marker_selects_native_candidate",
		StructuralMarkerRule:            "exact_declared_structure_only",
		NativeMalformedDisposition:      "invalid_record",
		NativeMalformedExternalFallback: "forbidden",
	}) {
		t.Fatalf("terminal policies = %#v", policies)
	}
	wire := catalog.WireContract()
	if wire.MaxForwardHops != 4 || wire.ForwardInstanceKey != "defenseclaw.telemetry.forward.instance_id" ||
		wire.SemanticInstanceKey != "defenseclaw.instance.id" {
		t.Fatalf("wire contract = %#v", wire)
	}
	for _, signal := range Signals() {
		markers := catalog.NativeMarkers(signal)
		if len(markers) == 0 {
			t.Fatalf("signal %q has no native markers", signal)
		}
		for _, marker := range markers {
			if marker.Signal() != signal {
				t.Fatalf("marker %q signal = %q, want %q", marker.ID(), marker.Signal(), signal)
			}
		}
	}
}

func TestInboundCatalogImportContextsAreOrdinaryAndConcrete(t *testing.T) {
	catalog := mustInboundCatalog(t)
	agentDiscovery, ok := catalog.ImportContextForFamily("log.agent.discovery.completed")
	if !ok || agentDiscovery.Bucket() != BucketAgentLifecycle ||
		agentDiscovery.EventName() != "agent.discovery.completed" ||
		agentDiscovery.ConstructionMode() != "ordinary_import_only" {
		t.Fatalf("generated agent-discovery context = (%q, %q, %q, %q, %v)",
			agentDiscovery.ID(), agentDiscovery.Bucket(), agentDiscovery.EventName(), agentDiscovery.ConstructionMode(), ok)
	}
	for _, viewType := range []reflect.Type{reflect.TypeOf(InboundTarget{}), reflect.TypeOf(InboundImportContext{})} {
		for index := 0; index < viewType.NumMethod(); index++ {
			methodName := viewType.Method(index).Name
			if strings.HasPrefix(methodName, "Build") ||
				(strings.HasPrefix(methodName, "Construct") && methodName != "ConstructionMode") {
				t.Fatalf("opaque view %s unexpectedly exposes construction method %s", viewType, methodName)
			}
		}
	}
	for index, context := range catalog.snapshot.contexts {
		view := InboundImportContext{snapshot: catalog.snapshot, index: index}
		if view.ConstructionMode() != "ordinary_import_only" ||
			!reflect.DeepEqual(view.Capabilities(), []string{"validate", "construct_ordinary"}) {
			t.Fatalf("context %q exposes non-ordinary capability", view.ID())
		}
		contract := context.descriptor.familyDescriptorContract()
		if contract.identity.Signal != SignalLogs || contract.id != view.FamilyDescriptorID() ||
			contract.identity.Bucket != view.Bucket() || contract.identity.Name != view.EventName() {
			t.Fatalf("context %q descriptor identity mismatch", view.ID())
		}
		typeOf := reflect.TypeOf(context.descriptor)
		if typeOf.Kind() != reflect.Struct || typeOf.NumField() != 0 || typeOf.String() != context.descriptorType {
			t.Fatalf("context %q descriptor binding = %v/%q", view.ID(), typeOf, context.descriptorType)
		}
	}
	for index, target := range catalog.snapshot.targets {
		contract := target.descriptor.familyDescriptorContract()
		if contract.id != target.family || reflect.TypeOf(target.descriptor).String() != target.descriptorType {
			t.Fatalf("target %q lost exact concrete descriptor", target.id)
		}
		view := InboundTarget{snapshot: catalog.snapshot, index: index}
		if context, present := view.ImportContext(); present {
			if target.signal != SignalLogs || target.role != InboundTargetImport || context.FamilyDescriptorID() != target.family {
				t.Fatalf("target %q has invalid context %q", target.id, context.ID())
			}
		}
	}
}

func TestInboundCatalogViewsAreCopyIsolated(t *testing.T) {
	catalog := mustInboundCatalog(t)
	alias := catalog.Aliases()[0]
	sources := alias.Sources()
	wantSource := sources[0]
	sources[0] = "mutated"
	if got := alias.Sources()[0]; got != wantSource {
		t.Fatalf("alias source mutated shared catalog: got %q, want %q", got, wantSource)
	}

	match, ok := catalog.Match("otlp.genai.span.operation.v1.span.workflow.run")
	if !ok {
		t.Fatal("workflow match missing")
	}
	predicates := match.Predicates()
	wantKey := predicates[0].Key()
	predicates[0].key = "mutated"
	values := predicates[1].Values()
	if len(values) != 1 {
		t.Fatalf("predicate values = %d, want 1", len(values))
	}
	values[0].stringValue = "mutated"
	if got := match.Predicates()[0].Key(); got != wantKey {
		t.Fatalf("predicate mutated shared catalog: got %q, want %q", got, wantKey)
	}

	fields := match.Targets()[0].Fields()
	wantField := fields[0].FieldRef()
	fields[0].fieldRef = "mutated"
	if got := match.Targets()[0].Fields()[0].FieldRef(); got != wantField {
		t.Fatalf("target fields mutated shared catalog: got %q, want %q", got, wantField)
	}
	unitMatch, ok := catalog.Match("otlp.genai.duration.metric.v1.gen-ai-client")
	if !ok {
		t.Fatal("duration match missing")
	}
	unitEntries := unitMatch.SourceUnitRule().Accepted()
	unitEntries[0].sourceUnit = "mutated"
	if got := unitMatch.SourceUnitRule().Accepted()[0].SourceUnit(); got != "" {
		t.Fatalf("source-unit entries mutated shared catalog: got %q", got)
	}

	markers := catalog.NativeMarkers(SignalTraces)
	var markerWithValue InboundNativeMarker
	for _, marker := range markers {
		if len(marker.Values()) > 0 {
			markerWithValue = marker
			break
		}
	}
	markerValues := markerWithValue.Values()
	if len(markerValues) != 1 {
		t.Fatalf("valued marker has %d values, want 1", len(markerValues))
	}
	markerValues[0].stringValue = "mutated"
	if reflect.DeepEqual(markerValues, markerWithValue.Values()) {
		t.Fatal("marker values were not detached")
	}
}

func TestInboundCatalogGeneratedSourceUnitAuthorityIsExact(t *testing.T) {
	catalog := mustInboundCatalog(t)
	durationWant := []InboundSourceUnitScale{
		{sourceUnit: "", scale: 1},
		{sourceUnit: "s", scale: 1},
		{sourceUnit: "second", scale: 1},
		{sourceUnit: "seconds", scale: 1},
		{sourceUnit: "ms", scale: 0.001},
		{sourceUnit: "millisecond", scale: 0.001},
		{sourceUnit: "milliseconds", scale: 0.001},
		{sourceUnit: "us", scale: 0.000001},
		{sourceUnit: "microsecond", scale: 0.000001},
		{sourceUnit: "microseconds", scale: 0.000001},
		{sourceUnit: "ns", scale: 0.000000001},
		{sourceUnit: "nanosecond", scale: 0.000000001},
		{sourceUnit: "nanoseconds", scale: 0.000000001},
	}
	for _, suffix := range []string{"gen-ai-client", "gen-ai", "llm", "claude-code", "codex"} {
		match, ok := catalog.Match("otlp.genai.duration.metric.v1." + suffix)
		if !ok {
			t.Fatalf("duration match %q missing", suffix)
		}
		rule := match.SourceUnitRule()
		if rule.Kind() != InboundSourceUnitScaleTable || rule.TargetUnit() != "s" ||
			!reflect.DeepEqual(rule.Accepted(), durationWant) {
			t.Fatalf("duration rule %q = %#v", suffix, rule)
		}
		for _, expected := range durationWant {
			if scale, found := rule.ScaleFor(expected.SourceUnit()); !found || scale != expected.Scale() {
				t.Fatalf("duration rule %q unit %q = %v/%v", suffix, expected.SourceUnit(), scale, found)
			}
		}
		for _, rejected := range []string{"MS", " ms", "ms ", "minute", "sec"} {
			if _, found := rule.ScaleFor(rejected); found {
				t.Fatalf("duration rule %q accepted unsupported unit %q", suffix, rejected)
			}
		}
		targets := match.Targets()
		if len(targets) != 1 || targets[0].InstrumentUnit() != "s" ||
			!reflect.DeepEqual(targets[0].SourceUnitRule().Accepted(), durationWant) {
			t.Fatalf("duration target %q lost sealed unit authority", suffix)
		}
	}

	token, ok := catalog.Match("otlp.claudecode.token_usage.v1.metric.gen_ai.client.token.usage")
	if !ok {
		t.Fatal("Claude token match missing")
	}
	tokenWant := []InboundSourceUnitScale{
		{sourceUnit: "", scale: 1},
		{sourceUnit: "{token}", scale: 1},
		{sourceUnit: "token", scale: 1},
		{sourceUnit: "tokens", scale: 1},
	}
	if rule := token.SourceUnitRule(); rule.Kind() != InboundSourceUnitScaleTable ||
		rule.TargetUnit() != "{token}" || !reflect.DeepEqual(rule.Accepted(), tokenWant) {
		t.Fatalf("Claude token rule = %#v", rule)
	}
	for _, rejected := range []string{"Token", " tokens", "tokens ", "{tokens}"} {
		if _, found := token.SourceUnitRule().ScaleFor(rejected); found {
			t.Fatalf("Claude token rule accepted unsupported unit %q", rejected)
		}
	}

	nativeCount := 0
	unitFixtureCases := 0
	for _, match := range catalog.snapshot.matches {
		if match.sourceUnitRule.kind != InboundSourceUnitNone {
			unitFixtureCases += len(match.sourceUnitRule.accepted) + 2
		}
		if match.classID != "otlp.native.metric.v8" {
			continue
		}
		nativeCount++
		view := InboundMatch{snapshot: catalog.snapshot, index: catalog.snapshot.matchByID[match.id]}
		targets := view.Targets()
		if len(targets) != 1 {
			t.Fatalf("native metric %q targets=%d", match.id, len(targets))
		}
		target := targets[0]
		rule := view.SourceUnitRule()
		if rule.Kind() != InboundSourceUnitTargetEquality || rule.TargetUnit() != target.InstrumentUnit() ||
			!reflect.DeepEqual(rule.Accepted(), []InboundSourceUnitScale{{sourceUnit: target.InstrumentUnit(), scale: 1}}) {
			t.Fatalf("native metric %q unit=%q rule=%#v", match.id, target.InstrumentUnit(), rule)
		}
	}
	if nativeCount != 104 {
		t.Fatalf("native metric unit authority matches=%d, want 104", nativeCount)
	}
	if unitFixtureCases != 393 {
		t.Fatalf("materialized source-unit fixture cases=%d, want 393", unitFixtureCases)
	}

	logMatch, ok := catalog.Match("otlp.codex.user_prompt.v1.log.model.request")
	if !ok || logMatch.SourceUnitRule().Kind() != InboundSourceUnitNone ||
		logMatch.SourceUnitRule().TargetUnit() != "" || len(logMatch.SourceUnitRule().Accepted()) != 0 {
		t.Fatalf("non-metric match acquired source-unit authority: %#v", logMatch.SourceUnitRule())
	}
}

func TestInboundCatalogConcurrentReads(t *testing.T) {
	catalog := mustInboundCatalog(t)
	const readers = 64
	var wait sync.WaitGroup
	wait.Add(readers)
	for reader := 0; reader < readers; reader++ {
		go func() {
			defer wait.Done()
			for iteration := 0; iteration < 100; iteration++ {
				loaded, err := LoadInboundCatalog()
				if err != nil {
					t.Errorf("LoadInboundCatalog() error = %v", err)
					return
				}
				matches := loaded.Matches(SignalTraces, "codex")
				if len(matches) == 0 {
					t.Error("no trace matches for authenticated source")
					return
				}
				_ = matches[0].Predicates()
				_ = matches[0].Targets()
				_ = catalog.NativeMarkers(SignalMetrics)
			}
		}()
	}
	wait.Wait()
}

func TestInboundCatalogRejectsMalformedOrDuplicateGeneratedData(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*generatedInboundCatalogSource)
	}{
		{
			name: "duplicate alias",
			mutate: func(source *generatedInboundCatalogSource) {
				source.aliases[1].ID = source.aliases[0].ID
			},
		},
		{
			name: "malformed predicate JSON",
			mutate: func(source *generatedInboundCatalogSource) {
				source.matches[0].Predicates[0].ValuesJSON = "not-json"
			},
		},
		{
			name: "duplicate exact discriminator",
			mutate: func(source *generatedInboundCatalogSource) {
				duplicate := source.matches[0]
				duplicate.ID = "otlp.synthetic.duplicate"
				source.matches = append(source.matches, duplicate)
			},
		},
		{
			name: "outcome rule trailing JSON",
			mutate: func(source *generatedInboundCatalogSource) {
				source.matches[0].OutcomeRuleJSON += " {}"
			},
		},
		{
			name: "outcome rule duplicate member",
			mutate: func(source *generatedInboundCatalogSource) {
				source.matches[1].OutcomeRuleJSON = `{"fixed":"attempted","fixed":"attempted"}`
			},
		},
		{
			name: "duplicate target",
			mutate: func(source *generatedInboundCatalogSource) {
				source.targets[1].ID = source.targets[0].ID
			},
		},
		{
			name: "target descriptor drift",
			mutate: func(source *generatedInboundCatalogSource) {
				source.targets[0].Descriptor = source.targets[1].Descriptor
			},
		},
		{
			name: "target instrument unit drift",
			mutate: func(source *generatedInboundCatalogSource) {
				source.targets[0].InstrumentUnit = "unsupported"
			},
		},
		{
			name: "target source unit scale drift",
			mutate: func(source *generatedInboundCatalogSource) {
				for index := range source.targets {
					if source.targets[index].SourceUnitRule.Kind == string(InboundSourceUnitScaleTable) {
						source.targets[index].SourceUnitRule.Accepted[0].Scale = 2
						return
					}
				}
			},
		},
		{
			name: "match target source unit mismatch",
			mutate: func(source *generatedInboundCatalogSource) {
				for index := range source.matches {
					if source.matches[index].SourceUnitRule.Kind == string(InboundSourceUnitScaleTable) {
						source.matches[index].SourceUnitRule.Accepted[0].Scale = 2
						return
					}
				}
			},
		},
		{
			name: "duplicate native marker",
			mutate: func(source *generatedInboundCatalogSource) {
				source.markers[1].ID = source.markers[0].ID
			},
		},
		{
			name: "duplicate echo wire identity",
			mutate: func(source *generatedInboundCatalogSource) {
				source.echoes[1].Bucket = source.echoes[0].Bucket
				source.echoes[1].EventName = source.echoes[0].EventName
			},
		},
		{
			name: "malformed terminal policy",
			mutate: func(source *generatedInboundCatalogSource) {
				source.policies.NativeMalformedExternalFallback = "external"
			},
		},
		{
			name: "floor-capable import context",
			mutate: func(source *generatedInboundCatalogSource) {
				source.contexts[0].Capabilities = append(source.contexts[0].Capabilities, "mandatory")
			},
		},
		{
			name: "context descriptor drift",
			mutate: func(source *generatedInboundCatalogSource) {
				source.contexts[0].Descriptor = source.contexts[1].Descriptor
			},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			source := cloneGeneratedInboundCatalogSource(generatedInboundCatalogSourceValue())
			test.mutate(&source)
			if _, err := buildInboundCatalog(source); !errors.Is(err, ErrInboundCatalogInvalid) {
				t.Fatalf("buildInboundCatalog() error = %v, want ErrInboundCatalogInvalid", err)
			}
		})
	}
}

func mustInboundCatalog(t *testing.T) InboundCatalog {
	t.Helper()
	catalog, err := LoadInboundCatalog()
	if err != nil {
		t.Fatalf("LoadInboundCatalog() error = %v", err)
	}
	return catalog
}

func cloneGeneratedInboundCatalogSource(input generatedInboundCatalogSource) generatedInboundCatalogSource {
	output := input
	output.aliases = append([]generatedInboundAlias(nil), input.aliases...)
	for index := range output.aliases {
		output.aliases[index].Sources = append([]string(nil), input.aliases[index].Sources...)
	}
	output.matches = append([]generatedInboundMatch(nil), input.matches...)
	for index := range output.matches {
		output.matches[index].Sources = append([]string(nil), input.matches[index].Sources...)
		output.matches[index].Predicates = append([]generatedInboundPredicate(nil), input.matches[index].Predicates...)
		output.matches[index].AliasIDs = append([]string(nil), input.matches[index].AliasIDs...)
		output.matches[index].TargetIDs = append([]string(nil), input.matches[index].TargetIDs...)
		if input.matches[index].TargetOverride != nil {
			value := *input.matches[index].TargetOverride
			output.matches[index].TargetOverride = &value
		}
		output.matches[index].SourceUnitRule.Accepted = append(
			[]generatedInboundUnitScale(nil), input.matches[index].SourceUnitRule.Accepted...,
		)
	}
	output.targets = append([]generatedInboundTarget(nil), input.targets...)
	for index := range output.targets {
		output.targets[index].FieldRefs = append([]string(nil), input.targets[index].FieldRefs...)
		output.targets[index].FieldDescriptorIDs = append([]string(nil), input.targets[index].FieldDescriptorIDs...)
		output.targets[index].SourceUnitRule.Accepted = append(
			[]generatedInboundUnitScale(nil), input.targets[index].SourceUnitRule.Accepted...,
		)
	}
	output.markers = append([]generatedInboundNativeMarker(nil), input.markers...)
	output.echoes = append([]generatedInboundEchoRecognizer(nil), input.echoes...)
	output.contexts = append([]generatedInboundImportContext(nil), input.contexts...)
	for index := range output.contexts {
		output.contexts[index].Capabilities = append([]string(nil), input.contexts[index].Capabilities...)
	}
	return output
}
