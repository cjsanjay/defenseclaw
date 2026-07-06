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
	"encoding/json"
	"reflect"
	"slices"
	"sort"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/observability"
	publicschemas "github.com/defenseclaw/defenseclaw/schemas"
)

func TestObservabilityV8CompatibilityProfilesComeFromGeneratedCatalog(t *testing.T) {
	profiles, err := observabilityV8CatalogCompatibilityProfiles()
	if err != nil {
		t.Fatal(err)
	}
	for _, test := range []struct {
		profile string
		family  observability.EventName
	}{
		{"galileo-rich-v2", observability.EventName("span.model.chat")},
		{"galileo-rich-v2", observability.EventName("span.agent.invoke")},
		{"local-observability-v1", observability.EventName("span.tool.execute")},
		{"openinference-v1", observability.EventName("span.retrieval.search")},
	} {
		profile, ok := profiles[test.profile]
		if !ok || profile.Availability != "pending" || !slices.ContainsFunc(profile.TraceFamilies, func(family observabilityV8CatalogTraceFamily) bool {
			return family.EventName == test.family && family.Availability == "pending"
		}) {
			t.Fatalf("generated profile %q does not contain %q: %+v", test.profile, test.family, profile)
		}
	}
	first := profiles["galileo-rich-v2"]
	first.TraceFamilies[0].EventName = "span.mutated"
	second, err := observabilityV8CatalogCompatibilityProfiles()
	if err != nil {
		t.Fatal(err)
	}
	if slices.ContainsFunc(
		second["galileo-rich-v2"].TraceFamilies,
		func(family observabilityV8CatalogTraceFamily) bool { return family.EventName == "span.mutated" },
	) {
		t.Fatal("generated compatibility accessor returned mutable shared state")
	}
}

func TestObservabilityV8CompatibilityAccessorExactlyMatchesGeneratedTraceMembership(t *testing.T) {
	var catalog struct {
		CompatibilityManifests []struct {
			ID           string `json:"id"`
			Availability string `json:"availability"`
		} `json:"compatibility_manifests"`
		Families []struct {
			EventName             string               `json:"event_name"`
			Bucket                observability.Bucket `json:"bucket"`
			Signal                observability.Signal `json:"signal"`
			CompatibilityProfiles []struct {
				ID           string `json:"id"`
				Availability string `json:"availability"`
			} `json:"compatibility_profiles"`
		} `json:"families"`
	}
	if err := json.Unmarshal(publicschemas.TelemetryV8Catalog(), &catalog); err != nil {
		t.Fatal(err)
	}
	expectedAvailability := make(map[string]string)
	for _, profile := range catalog.CompatibilityManifests {
		expectedAvailability[profile.ID] = profile.Availability
	}
	expected := make(map[string][]string)
	for _, family := range catalog.Families {
		if family.Signal != observability.SignalTraces {
			continue
		}
		for _, profile := range family.CompatibilityProfiles {
			expected[profile.ID] = append(expected[profile.ID], family.EventName+"|"+string(family.Bucket)+"|"+profile.Availability)
		}
	}
	for profile := range expected {
		sort.Strings(expected[profile])
	}
	actualProfiles, err := observabilityV8CatalogCompatibilityProfiles()
	if err != nil {
		t.Fatal(err)
	}
	actual := make(map[string][]string)
	for id, profile := range actualProfiles {
		if profile.Availability != expectedAvailability[id] {
			t.Fatalf("profile %q availability=%q, want %q", id, profile.Availability, expectedAvailability[id])
		}
		for _, family := range profile.TraceFamilies {
			actual[id] = append(actual[id], string(family.EventName)+"|"+string(family.Bucket)+"|"+family.Availability)
		}
		sort.Strings(actual[id])
	}
	if !reflect.DeepEqual(actual, expected) {
		t.Fatalf("generated trace compatibility membership drifted\nactual: %#v\nexpected: %#v", actual, expected)
	}
}

func TestObservabilityV8EffectivePlanPublishesCompatibilityAndReloadApplicability(t *testing.T) {
	local := validObservabilityV8Destination(observability.RuntimeLocalObservabilityDestination, ObservabilityV8DestinationOTLP)
	galileo := validObservabilityV8Destination("galileo", ObservabilityV8DestinationOTLP)
	galileo.Preset = "galileo"
	generic := validObservabilityV8Destination("generic", ObservabilityV8DestinationOTLP)
	prometheus := validObservabilityV8Destination("prometheus", ObservabilityV8DestinationPrometheus)
	plan := mustCompileObservabilityV8(t, &ObservabilityV8Source{
		Destinations: []ObservabilityV8DestinationSource{local, galileo, generic, prometheus},
	})

	snapshot := plan.Snapshot()
	for _, bucket := range snapshot.Buckets {
		if bucket.ReloadApplicability != ObservabilityV8LiveReloadable {
			t.Fatalf("bucket %q reload applicability = %q", bucket.Bucket, bucket.ReloadApplicability)
		}
	}
	assertDestination := func(name string) ObservabilityV8EffectiveDestination {
		t.Helper()
		destination, ok := plan.Destination(name)
		if !ok {
			t.Fatalf("destination %q missing", name)
		}
		return destination
	}
	localSQLite := assertDestination(ObservabilityV8LocalDestinationName)
	if localSQLite.ReloadApplicability.Policy != ObservabilityV8LiveReloadable ||
		localSQLite.ReloadApplicability.Transport != ObservabilityV8RestartRequired {
		t.Fatalf("local SQLite reload applicability = %+v", localSQLite.ReloadApplicability)
	}
	for _, name := range []string{observability.RuntimeLocalObservabilityDestination, "galileo", "generic"} {
		destination := assertDestination(name)
		if destination.ReloadApplicability.Policy != ObservabilityV8LiveReloadable ||
			destination.ReloadApplicability.Transport != ObservabilityV8LiveReloadable {
			t.Fatalf("destination %q reload applicability = %+v", name, destination.ReloadApplicability)
		}
	}
	prometheusReload := assertDestination("prometheus").ReloadApplicability
	if prometheusReload.Policy != ObservabilityV8RestartRequired ||
		prometheusReload.Transport != ObservabilityV8RestartRequired {
		t.Fatalf("Prometheus reload applicability = %+v", prometheusReload)
	}
	localProfile := assertDestination(observability.RuntimeLocalObservabilityDestination).CompatibilityProfiles
	if len(localProfile) != 1 || localProfile[0].ID != observability.RuntimeLocalObservabilityProfile ||
		localProfile[0].Availability != "pending" ||
		!slices.ContainsFunc(localProfile[0].EligibleSpanFamilies, func(family ObservabilityV8EffectiveSpanFamily) bool {
			return family.EventName == "span.tool.execute" && family.Bucket == observability.BucketToolActivity &&
				family.Availability == "pending"
		}) {
		t.Fatalf("local compatibility = %+v", localProfile)
	}
	galileoProfile := assertDestination("galileo").CompatibilityProfiles
	if len(galileoProfile) != 1 || galileoProfile[0].ID != "galileo-rich-v2" ||
		galileoProfile[0].Availability != "pending" ||
		!slices.ContainsFunc(galileoProfile[0].EligibleSpanFamilies, func(family ObservabilityV8EffectiveSpanFamily) bool {
			return family.EventName == "span.model.chat" && family.Bucket == observability.BucketModelIO &&
				family.Availability == "pending"
		}) {
		t.Fatalf("Galileo compatibility = %+v", galileoProfile)
	}
	if profiles := assertDestination("generic").CompatibilityProfiles; len(profiles) != 0 {
		t.Fatalf("generic OTLP destination invented compatibility profiles: %+v", profiles)
	}
}
