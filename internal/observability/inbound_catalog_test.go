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
			name: "duplicate native marker",
			mutate: func(source *generatedInboundCatalogSource) {
				source.markers[1].ID = source.markers[0].ID
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
	}
	output.targets = append([]generatedInboundTarget(nil), input.targets...)
	for index := range output.targets {
		output.targets[index].FieldRefs = append([]string(nil), input.targets[index].FieldRefs...)
		output.targets[index].FieldDescriptorIDs = append([]string(nil), input.targets[index].FieldDescriptorIDs...)
	}
	output.markers = append([]generatedInboundNativeMarker(nil), input.markers...)
	output.echoes = append([]generatedInboundEchoRecognizer(nil), input.echoes...)
	output.contexts = append([]generatedInboundImportContext(nil), input.contexts...)
	for index := range output.contexts {
		output.contexts[index].Capabilities = append([]string(nil), input.contexts[index].Capabilities...)
	}
	return output
}
