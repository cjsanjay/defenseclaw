// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
// SPDX-License-Identifier: Apache-2.0

package observability

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"sort"
	"strings"
	"testing"
)

func TestEventNameRegistryRejectsArbitraryWellShapedNames(t *testing.T) {
	t.Parallel()

	for _, name := range []EventName{
		"plausible.but.unregistered",
		"arbitrary_snake_case",
		"span.unregistered.family",
		"defenseclaw.unregistered.metric",
		"",
	} {
		if IsRegisteredEventName(name) {
			t.Errorf("arbitrary event name %q is registered", name)
		}
	}
	for _, name := range []EventName{
		"finding.observed",
		"hook_decision",
		"session_start",
		"span.workflow.run",
		"defenseclaw.gateway.events.emitted",
		"gen_ai.client.token.usage",
	} {
		if !IsRegisteredEventName(name) {
			t.Errorf("declared event name %q is not registered", name)
		}
	}
}

func TestEventNamesAreSortedUniqueAndCopySafe(t *testing.T) {
	t.Parallel()

	first := EventNames()
	if len(first) == 0 {
		t.Fatal("event registry is empty")
	}
	if !sort.SliceIsSorted(first, func(left, right int) bool { return first[left] < first[right] }) {
		t.Fatal("EventNames is not sorted")
	}
	for i, name := range first {
		if !IsRegisteredEventName(name) {
			t.Errorf("EventNames returned unregistered name %q", name)
		}
		if i > 0 && first[i-1] == name {
			t.Errorf("EventNames contains duplicate %q", name)
		}
	}

	wantFirst := first[0]
	first[0] = "caller.mutation"
	second := EventNames()
	if second[0] != wantFirst {
		t.Fatalf("caller mutated event registry: got first name %q, want %q", second[0], wantFirst)
	}
}

func TestClassifiedDefaultEventNamesMatchReviewedSnapshot(t *testing.T) {
	t.Parallel()

	names := classificationDefaultEventNames()
	for _, name := range names {
		if !IsRegisteredEventName(name) {
			t.Errorf("classified default event name %q is not registered", name)
		}
	}

	const wantSHA256 = "8d13244d9299118ce4812bd41dba7cbf208c6a6ffa1e19903a94ad96ba79b332"
	sum := sha256.Sum256([]byte(strings.Join(eventNamesToStrings(names), "\n")))
	if got := hex.EncodeToString(sum[:]); got != wantSHA256 {
		t.Fatalf("classified default event-name snapshot changed: sha256=%s names=%v", got, names)
	}
}

func TestMetricInstrumentEventNamesMatchCanonicalSchema(t *testing.T) {
	t.Parallel()

	var catalog struct {
		Metrics []struct {
			Name EventName `json:"name"`
		} `json:"x-emitted-metrics"`
	}
	readJSONFile(t, repositoryFile(t, "schemas/otel/metrics.schema.json"), &catalog)

	fromSchema := make([]EventName, 0, len(catalog.Metrics))
	for _, metric := range catalog.Metrics {
		fromSchema = append(fromSchema, metric.Name)
		if !IsRegisteredEventName(metric.Name) {
			t.Errorf("canonical metric %q is not registered", metric.Name)
		}
	}
	assertSameEventNameSet(t, metricInstrumentEventNames[:], fromSchema)
}

func TestSpanFamilyEventNamesMatchSpecCatalog(t *testing.T) {
	t.Parallel()

	raw, err := os.ReadFile(repositoryFile(t, "docs/design/observability-v8/11-trace-and-span-contract.md"))
	if err != nil {
		t.Fatalf("read trace contract: %v", err)
	}
	inCatalog := false
	var fromSpec []EventName
	for _, line := range strings.Split(string(raw), "\n") {
		switch {
		case line == "## 7. Span Family Catalog":
			inCatalog = true
		case inCatalog && strings.HasPrefix(line, "## "):
			inCatalog = false
		case inCatalog && strings.HasPrefix(line, "| `"):
			columns := strings.Split(line, "|")
			if len(columns) < 4 {
				t.Fatalf("malformed span family table row %q", line)
			}
			family := strings.Trim(strings.TrimSpace(columns[2]), "`")
			fromSpec = append(fromSpec, EventName(family))
		}
	}
	if len(fromSpec) == 0 {
		t.Fatal("span family catalog was not found in trace contract")
	}
	for _, family := range fromSpec {
		if !IsRegisteredEventName(family) {
			t.Errorf("declared span family %q is not registered", family)
		}
	}
	assertSameEventNameSet(t, spanFamilyEventNames[:], fromSpec)
}

func TestLifecycleCompatibilityNamesMatchCanonicalSchema(t *testing.T) {
	t.Parallel()

	var schema struct {
		Properties map[string]struct {
			Enum []EventName `json:"enum"`
		} `json:"properties"`
	}
	readJSONFile(t, repositoryFile(t, "schemas/otel/agent-lifecycle-event.schema.json"), &schema)
	fromSchema := schema.Properties["defenseclaw.agent.lifecycle.event"].Enum
	want := make([]EventName, 0, len(compatibilityEventNames)-1)
	for _, name := range compatibilityEventNames {
		if name != "hook_decision" {
			want = append(want, name)
		}
		if !IsRegisteredEventName(name) {
			t.Errorf("compatibility event name %q is not registered", name)
		}
	}
	assertSameEventNameSet(t, want, fromSchema)
}

func classificationDefaultEventNames() []EventName {
	unique := make(map[EventName]struct{})
	for _, classifications := range []map[ProducerKey]Classification{
		gatewayEventClassifications,
		auditActionClassifications,
	} {
		for _, classification := range classifications {
			if classification.DefaultEventName != "" {
				unique[classification.DefaultEventName] = struct{}{}
			}
		}
	}
	names := make([]EventName, 0, len(unique))
	for name := range unique {
		names = append(names, name)
	}
	sort.Slice(names, func(left, right int) bool { return names[left] < names[right] })
	return names
}

func assertSameEventNameSet(t *testing.T, left, right []EventName) {
	t.Helper()
	leftCopy := append([]EventName(nil), left...)
	rightCopy := append([]EventName(nil), right...)
	sort.Slice(leftCopy, func(i, j int) bool { return leftCopy[i] < leftCopy[j] })
	sort.Slice(rightCopy, func(i, j int) bool { return rightCopy[i] < rightCopy[j] })
	if !reflect.DeepEqual(leftCopy, rightCopy) {
		t.Fatalf("event-name sets differ\nregistry: %v\nsource:   %v", leftCopy, rightCopy)
	}
}

func eventNamesToStrings(names []EventName) []string {
	result := make([]string, len(names))
	for i, name := range names {
		result[i] = string(name)
	}
	return result
}

func repositoryFile(t *testing.T, path string) string {
	t.Helper()
	_, currentFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("resolve event registry test path")
	}
	return filepath.Join(filepath.Dir(currentFile), "..", "..", path)
}

func readJSONFile(t *testing.T, path string, target any) {
	t.Helper()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	if err := json.Unmarshal(raw, target); err != nil {
		t.Fatalf("decode %s: %v", path, err)
	}
}
