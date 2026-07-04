// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// SPDX-License-Identifier: Apache-2.0

package galileo

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"sort"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/observability"
	"github.com/defenseclaw/defenseclaw/internal/observability/redaction"
)

func TestProjectAcceptsExactRichV2Shapes(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name       string
		bucket     observability.Bucket
		family     observability.EventName
		spanName   string
		kind       any
		attributes map[string]any
		wantShape  Shape
		wantOIKind string
	}{
		{
			name: "agent", bucket: observability.BucketAgentLifecycle, family: "span.agent.invoke",
			spanName: "invoke_agent reviewer", kind: "INTERNAL", wantShape: ShapeAgent, wantOIKind: "AGENT",
			attributes: map[string]any{
				"gen_ai.operation.name": "invoke_agent", "gen_ai.provider.name": "openai",
				"gen_ai.agent.name": "reviewer", "gen_ai.input.messages": messages("user", "inspect"),
				"gen_ai.output.messages": messages("assistant", "done"),
			},
		},
		{
			name: "chat", bucket: observability.BucketModelIO, family: "span.model.chat",
			spanName: "chat gpt-5", kind: 3, wantShape: ShapeLLM, wantOIKind: "LLM",
			attributes: map[string]any{
				"gen_ai.operation.name": "chat", "gen_ai.provider.name": "openai",
				"gen_ai.request.model": "gpt-5", "gen_ai.input.messages": messages("user", "hello"),
				"gen_ai.output.messages": messages("assistant", "hello"),
			},
		},
		{
			name: "text completion", bucket: observability.BucketModelIO, family: "span.model.chat",
			spanName: "text_completion llama", kind: json.Number("3"), wantShape: ShapeLLM, wantOIKind: "LLM",
			attributes: map[string]any{
				"gen_ai.operation.name": "text_completion", "gen_ai.provider.name": "local",
				"gen_ai.input.messages":  messages("user", "prefix"),
				"gen_ai.output.messages": messages("assistant", "suffix"),
			},
		},
		{
			name: "tool", bucket: observability.BucketToolActivity, family: "span.tool.execute",
			spanName: "execute_tool search", kind: "CLIENT", wantShape: ShapeTool, wantOIKind: "TOOL",
			attributes: map[string]any{
				"gen_ai.operation.name": "execute_tool", "gen_ai.tool.name": "search",
				"gen_ai.tool.call.id": "call-9", "gen_ai.tool.call.arguments": `{"q":"otel"}`,
				"gen_ai.tool.call.result": `{"hits":2}`,
			},
		},
		{
			name: "retriever", bucket: observability.BucketToolActivity, family: "span.retrieval.search",
			spanName: "retrieve vector-store", kind: "CLIENT", wantShape: ShapeRetriever, wantOIKind: "RETRIEVER",
			attributes: map[string]any{
				"db.operation.name": "search", "input.value": "redacted query",
				"gen_ai.output.messages": messages("assistant", "bounded document summary"),
			},
		},
		{
			name: "workflow", bucket: observability.BucketAgentLifecycle, family: "span.workflow.run",
			spanName: "workflow retrieval-turn", kind: "INTERNAL", wantShape: ShapeWorkflow, wantOIKind: "CHAIN",
			attributes: map[string]any{
				"defenseclaw.workflow.name": "retrieval-turn",
				"input.value":               "turn input", "output.value": "turn output",
			},
		},
		{
			name: "judge chat", bucket: observability.BucketGuardrailEvaluation, family: "span.guardrail.judge",
			spanName: "chat judge-model", kind: "CLIENT", wantShape: ShapeLLM, wantOIKind: "LLM",
			attributes: map[string]any{
				"gen_ai.operation.name": "chat", "gen_ai.provider.name": "openai",
				"gen_ai.request.model": "judge-model", "gen_ai.input.messages": messages("user", "[REDACTED]"),
				"gen_ai.output.messages": messages("assistant", "allow"),
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			projection := projectRecord(t, test.bucket, test.family, test.spanName, map[string]any{
				"kind": test.kind, "attributes": test.attributes,
			}, redaction.ProfileNone)
			result := Project(projection, Limits{})
			if !result.Eligible() || result.Reason() != ReasonEligible || result.Shape() != test.wantShape {
				t.Fatalf("result = eligible:%v reason:%q shape:%q missing:%v", result.Eligible(), result.Reason(), result.Shape(), result.MissingFields())
			}
			wire := resultWire(t, result)
			if got := wire["compatibility_profile"]; got != ProfileID {
				t.Fatalf("profile = %v", got)
			}
			attrs := resultAttributes(t, result)
			if got := attrs["openinference.span.kind"]; got != test.wantOIKind {
				t.Fatalf("openinference kind = %v", got)
			}
			if _, ok := attrs["gen_ai.input.messages"]; !ok {
				t.Fatal("input messages missing")
			}
			if _, ok := attrs["gen_ai.output.messages"]; !ok {
				t.Fatal("output messages missing")
			}
			if _, suppliedAsValue := test.attributes["input.value"]; suppliedAsValue {
				if attrs["defenseclaw.telemetry.input.reported"] != true || attrs["gen_ai.input.messages"] == "[]" {
					t.Fatalf("input.value was not projected as reported messages: %#v", attrs)
				}
			}
			if test.family == "span.guardrail.judge" && attrs["defenseclaw.guardrail.judge"] != true {
				t.Fatal("judge marker missing")
			}
			if test.family == "span.workflow.run" && attrs["defenseclaw.workflow.name"] != "retrieval-turn" {
				t.Fatalf("workflow name = %#v", attrs["defenseclaw.workflow.name"])
			}
			first, _ := result.Bytes()
			second, _ := Project(projection, Limits{}).Bytes()
			if !bytes.Equal(first, second) {
				t.Fatal("projection is not deterministic")
			}
		})
	}
}

func TestProjectMalformedAndUnicodeContentStates(t *testing.T) {
	t.Parallel()
	projection := projectRecord(t, observability.BucketModelIO, "span.model.chat", "chat unicode", map[string]any{
		"kind": "CLIENT",
		"attributes": map[string]any{
			"gen_ai.operation.name": "chat", "gen_ai.provider.name": "openai",
			"gen_ai.input.messages":  `[{"role":"user","content":`,
			"gen_ai.output.messages": messages("assistant", "こんにちは 🦀"),
			"error.type":             "invalid_response",
		},
		"status": map[string]any{"code": 2, "description": "bounded redacted failure"},
	}, redaction.ProfileNone)
	result := Project(projection, Limits{})
	if !result.Eligible() {
		t.Fatalf("result = %q, missing %v", result.Reason(), result.MissingFields())
	}
	attributes := resultAttributes(t, result)
	if attributes["gen_ai.input.messages"] != "[]" || attributes["defenseclaw.telemetry.input.reported"] != true ||
		attributes["defenseclaw.telemetry.input.state"] != "failed_closed" {
		t.Fatalf("malformed input state = %#v", attributes)
	}
	if !strings.Contains(attributes["gen_ai.output.messages"].(string), "こんにちは") || attributes["error.type"] != "invalid_response" {
		t.Fatalf("unicode/error projection = %#v", attributes)
	}
	body := resultWire(t, result)["body"].(map[string]any)
	status := body["status"].(map[string]any)
	if status["code"] != json.Number("2") || status["description"] != "bounded redacted failure" {
		t.Fatalf("status = %#v", status)
	}
}

func TestProjectMissingContentUsesHonestPlaceholders(t *testing.T) {
	t.Parallel()
	projection := projectRecord(t, observability.BucketModelIO, "span.model.chat", "chat", map[string]any{
		"kind": "CLIENT",
		"attributes": map[string]any{
			"gen_ai.operation.name": "chat", "gen_ai.provider.name": "openai",
			"defenseclaw.telemetry.input.reported": false,
		},
	}, redaction.ProfileNone)
	result := Project(projection, Limits{})
	if !result.Eligible() {
		t.Fatalf("result = %q, missing %v", result.Reason(), result.MissingFields())
	}
	attributes := resultAttributes(t, result)
	for _, direction := range []string{"input", "output"} {
		if got := attributes["gen_ai."+direction+".messages"]; got != "[]" {
			t.Errorf("%s placeholder = %#v", direction, got)
		}
		if got := attributes["defenseclaw.telemetry."+direction+".reported"]; got != false {
			t.Errorf("%s reported = %#v", direction, got)
		}
		if got := attributes["defenseclaw.telemetry."+direction+".state"]; got != "not_reported" {
			t.Errorf("%s state = %#v", direction, got)
		}
	}
	if _, exists := attributes["gen_ai.request.model"]; exists {
		t.Fatal("unknown model was fabricated")
	}
}

func TestProjectToolRemovedContentIsAnExplicitSchemaMiss(t *testing.T) {
	t.Parallel()
	projection := projectRecord(t, observability.BucketToolActivity, "span.tool.execute", "execute_tool shell", map[string]any{
		"kind": "INTERNAL",
		"attributes": map[string]any{
			"gen_ai.operation.name": "execute_tool", "gen_ai.tool.name": "shell",
		},
	}, redaction.ProfileNone)
	result := Project(projection, Limits{})
	want := []string{"gen_ai.tool.call.arguments", "gen_ai.tool.call.result"}
	if result.Eligible() || result.Reason() != ReasonSchemaMissingRequired || !reflect.DeepEqual(result.MissingFields(), want) {
		t.Fatalf("result = eligible:%v reason:%q missing:%v", result.Eligible(), result.Reason(), result.MissingFields())
	}
}

func TestProjectRejectsSchemaMissAndNativeNonGalileoShapes(t *testing.T) {
	t.Parallel()
	missingProvider := projectRecord(t, observability.BucketModelIO, "span.model.chat", "chat model", map[string]any{
		"kind": "CLIENT", "attributes": map[string]any{
			"gen_ai.operation.name": "chat", "gen_ai.input.messages": messages("user", "x"),
			"gen_ai.output.messages": messages("assistant", "y"),
		},
	}, redaction.ProfileNone)
	result := Project(missingProvider, Limits{})
	if result.Eligible() || result.Reason() != ReasonSchemaMissingRequired ||
		!reflect.DeepEqual(result.MissingFields(), []string{"gen_ai.provider.name"}) {
		t.Fatalf("schema miss = eligible:%v reason:%q missing:%v", result.Eligible(), result.Reason(), result.MissingFields())
	}
	if _, err := result.Bytes(); !IsProjectionError(err, ReasonSchemaMissingRequired) || strings.Contains(err.Error(), "model") {
		t.Fatalf("safe rejection error = %v", err)
	}

	nativeGuardrail := projectRecord(t, observability.BucketGuardrailEvaluation, "span.guardrail.apply", "apply_guardrail pii input", map[string]any{
		"kind": "INTERNAL", "attributes": map[string]any{
			"gen_ai.operation.name": "chat", "gen_ai.provider.name": "openai",
			"gen_ai.input.messages": messages("user", "x"), "gen_ai.output.messages": messages("assistant", "y"),
		},
	}, redaction.ProfileNone)
	if got := Project(nativeGuardrail, Limits{}); got.Reason() != ReasonUnsupportedShape {
		t.Fatalf("native guardrail reason = %q", got.Reason())
	}

	wrongOperation := projectRecord(t, observability.BucketAgentLifecycle, "span.agent.invoke", "invoke_agent a", map[string]any{
		"kind": "INTERNAL", "attributes": map[string]any{"gen_ai.operation.name": "execute_tool"},
	}, redaction.ProfileNone)
	if got := Project(wrongOperation, Limits{}); got.Reason() != ReasonUnsupportedShape {
		t.Fatalf("wrong operation reason = %q", got.Reason())
	}

	for _, test := range []struct {
		name       string
		spanName   string
		attributes map[string]any
		missing    []string
	}{
		{
			name: "missing workflow name", spanName: "workflow retrieval-turn",
			attributes: map[string]any{}, missing: []string{"defenseclaw.workflow.name"},
		},
		{
			name: "unbounded workflow name", spanName: "workflow " + strings.Repeat("a", 129),
			attributes: map[string]any{"defenseclaw.workflow.name": strings.Repeat("a", 129)},
			missing:    []string{"defenseclaw.workflow.name"},
		},
		{
			name: "invalid workflow token", spanName: "workflow Retrieval Turn",
			attributes: map[string]any{"defenseclaw.workflow.name": "Retrieval Turn"},
			missing:    []string{"defenseclaw.workflow.name"},
		},
		{
			name: "rendered workflow name mismatch", spanName: "workflow other-turn",
			attributes: map[string]any{"defenseclaw.workflow.name": "retrieval-turn"},
			missing:    []string{"span_name"},
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			projection := projectRecord(t, observability.BucketAgentLifecycle, "span.workflow.run", test.spanName, map[string]any{
				"kind": "INTERNAL", "attributes": test.attributes,
			}, redaction.ProfileNone)
			got := Project(projection, Limits{})
			if got.Eligible() || got.Reason() != ReasonSchemaMissingRequired || !reflect.DeepEqual(got.MissingFields(), test.missing) {
				t.Fatalf("workflow result = eligible:%v reason:%q missing:%v", got.Eligible(), got.Reason(), got.MissingFields())
			}
		})
	}
}

func TestProjectPreservesLifecycleCorrelationAndSafeSecurityEvents(t *testing.T) {
	t.Parallel()
	body := map[string]any{
		"kind":           "INTERNAL",
		"parent_span_id": "0011223344556677",
		"attributes": map[string]any{
			"gen_ai.operation.name": "invoke_agent", "gen_ai.provider.name": "anthropic", "gen_ai.agent.name": "reviewer",
			"gen_ai.agent.id": "child", "gen_ai.agent.type": "subagent", "gen_ai.conversation.id": "conversation",
			"gen_ai.input.messages": messages("user", "review"), "gen_ai.output.messages": messages("assistant", "done"),
			"defenseclaw.agent.root.id": "root", "defenseclaw.agent.parent.id": "parent",
			"defenseclaw.agent.lifecycle.id": "life", "defenseclaw.agent.execution.id": "exec",
			"defenseclaw.agent.lifecycle.event": "subagent_start", "defenseclaw.agent.lifecycle.state": "active",
			"defenseclaw.agent.phase": "model", "defenseclaw.agent.phase.previous": "planning",
			"defenseclaw.agent.phase.code": 3, "defenseclaw.agent.sequence": 7, "defenseclaw.agent.depth": 2,
			"defenseclaw.session.root.id": "root-session", "defenseclaw.session.parent.id": "parent-session",
			"defenseclaw.session.source": "claude-code", "defenseclaw.session.resumed": true,
			"defenseclaw.operation.id": "operation", "defenseclaw.turn.id": "turn",
			"defenseclaw.guardrail.decision": "block", "defenseclaw.guardrail.reason": "do not export this detail",
			"defenseclaw.llm.request.body": "not a safe overlay alias", "arbitrary.secret": "not allowed",
		},
		"events": []any{
			map[string]any{"name": "guardrail.decision", "attributes": map[string]any{
				"evaluation_id": "eval", "decision": "block", "severity": "HIGH", "reason": "unsafe detail",
			}},
			map[string]any{"name": "security.finding.observed", "attributes": map[string]any{
				"finding_id": "finding", "rule_id": "rule", "category": "injection", "evidence": "unsafe evidence",
			}},
			map[string]any{"name": "custom.raw", "attributes": map[string]any{"content": "raw"}},
		},
		"links": []any{
			map[string]any{"trace_id": strings.Repeat("1", 32), "span_id": strings.Repeat("2", 16), "attributes": map[string]any{
				"defenseclaw.link.relation": "delegates_to", "defenseclaw.agent.root.id": "root", "reason": "drop",
			}},
		},
	}
	projection := projectRecord(t, observability.BucketAgentLifecycle, "span.agent.invoke", "invoke_agent reviewer", body, redaction.ProfileNone)
	result := Project(projection, Limits{})
	if !result.Eligible() {
		t.Fatalf("result = %q", result.Reason())
	}
	attributes := resultAttributes(t, result)
	for key, want := range map[string]any{
		"defenseclaw.agent.root.id": "root", "defenseclaw.agent.parent.id": "parent",
		"defenseclaw.agent.lifecycle.id": "life", "defenseclaw.agent.execution.id": "exec",
		"defenseclaw.agent.lifecycle.event": "subagent_start", "defenseclaw.agent.lifecycle.state": "active",
		"defenseclaw.session.root.id": "root-session", "defenseclaw.session.parent.id": "parent-session",
		"defenseclaw.operation.id": "operation", "defenseclaw.turn.id": "turn",
	} {
		if got := attributes[key]; got != want {
			t.Errorf("%s = %#v, want %#v", key, got, want)
		}
	}
	for _, key := range []string{"defenseclaw.guardrail.reason", "defenseclaw.llm.request.body", "arbitrary.secret"} {
		if _, exists := attributes[key]; exists {
			t.Errorf("unsafe attribute %q retained", key)
		}
	}
	wire := resultWire(t, result)
	correlation := wire["correlation"].(map[string]any)
	for key, want := range map[string]any{
		"session_id": "session-1", "turn_id": "turn-1", "agent_id": "agent-1",
		"agent_instance_id": "instance-1", "tool_invocation_id": "tool-1",
	} {
		if got := correlation[key]; got != want {
			t.Errorf("correlation %s = %#v, want %#v", key, got, want)
		}
	}
	resultBody := wire["body"].(map[string]any)
	events := resultBody["events"].([]any)
	if len(events) != 2 {
		t.Fatalf("events = %d", len(events))
	}
	for _, eventValue := range events {
		event := eventValue.(map[string]any)
		eventAttributes := event["attributes"].(map[string]any)
		if _, unsafe := eventAttributes["reason"]; unsafe {
			t.Error("event reason retained")
		}
		if _, unsafe := eventAttributes["evidence"]; unsafe {
			t.Error("event evidence retained")
		}
	}
	links := resultBody["links"].([]any)
	linkAttributes := links[0].(map[string]any)["attributes"].(map[string]any)
	if linkAttributes["defenseclaw.link.relation"] != "delegates_to" || linkAttributes["defenseclaw.agent.root.id"] != "root" {
		t.Fatalf("safe delegation link = %#v", linkAttributes)
	}
	if _, exists := linkAttributes["reason"]; exists {
		t.Fatal("unsafe link reason retained")
	}
}

func TestProjectNeverRecoversRawContentAndDestinationProjectionsRemainIndependent(t *testing.T) {
	t.Parallel()
	const canary = "GALILEO-RAW-CANARY-7c786fc9"
	body := map[string]any{
		"kind": "INTERNAL",
		"attributes": map[string]any{
			"gen_ai.operation.name": "invoke_agent", "gen_ai.provider.name": "openai", "gen_ai.agent.name": "defenseclaw",
			"gen_ai.input.messages": messages("user", canary), "gen_ai.output.messages": messages("assistant", canary),
			canaryMarkerKey: true, canaryOperationKey: canaryOperationValue,
		},
		"events": []any{map[string]any{"name": "guardrail.decision", "attributes": map[string]any{"decision": "allow", "reason": canary}}},
		"status": map[string]any{"code": 1, "message": canary},
	}
	record := newTraceRecord(t, observability.BucketDiagnostic, canaryFamily, "invoke_agent defenseclaw", body)
	rawRoute := redactRecord(t, record, redaction.ProfileNone)
	strictRoute := redactRecord(t, record, redaction.ProfileStrict)
	rawBefore, _ := rawRoute.Bytes()
	strictBefore, _ := strictRoute.Bytes()

	rawResult := Project(rawRoute, Limits{})
	strictResult := Project(strictRoute, Limits{})
	if !rawResult.Eligible() || !strictResult.Eligible() {
		t.Fatalf("raw=%q strict=%q missing=%v", rawResult.Reason(), strictResult.Reason(), strictResult.MissingFields())
	}
	rawBytes, _ := rawResult.Bytes()
	strictBytes, _ := strictResult.Bytes()
	if !bytes.Contains(rawBytes, []byte(canary)) {
		t.Fatal("none route unexpectedly lost operator-selected raw content")
	}
	if bytes.Contains(strictBytes, []byte(canary)) {
		t.Fatal("strict route recovered raw content")
	}
	strictAttributes := resultAttributes(t, strictResult)
	if strictAttributes["gen_ai.input.messages"] != "[]" || strictAttributes["defenseclaw.telemetry.input.reported"] != false {
		t.Fatalf("strict content state = %#v", strictAttributes)
	}
	rawAfter, _ := rawRoute.Bytes()
	strictAfter, _ := strictRoute.Bytes()
	if !bytes.Equal(rawBefore, rawAfter) || !bytes.Equal(strictBefore, strictAfter) {
		t.Fatal("compatibility projection mutated a destination projection")
	}
}

func TestProjectCanarySurfaceIsExact(t *testing.T) {
	t.Parallel()
	base := map[string]any{
		"gen_ai.operation.name": "chat", "gen_ai.provider.name": "openai",
		"gen_ai.input.messages": messages("user", "canary"), "gen_ai.output.messages": messages("assistant", "ok"),
		canaryMarkerKey: true, canaryOperationKey: canaryOperationValue,
	}
	valid := projectRecord(t, observability.BucketDiagnostic, canaryFamily, "chat canary", map[string]any{
		"kind": "CLIENT", "attributes": base,
	}, redaction.ProfileNone)
	if result := Project(valid, Limits{}); !result.Eligible() || result.Shape() != ShapeLLM {
		t.Fatalf("valid canary = %q/%q", result.Reason(), result.Shape())
	}
	for _, mutation := range []func(map[string]any){
		func(attributes map[string]any) { delete(attributes, canaryMarkerKey) },
		func(attributes map[string]any) { attributes[canaryMarkerKey] = false },
		func(attributes map[string]any) { attributes[canaryOperationKey] = "probe" },
	} {
		attributes := cloneObject(base)
		mutation(attributes)
		projection := projectRecord(t, observability.BucketDiagnostic, canaryFamily, "chat canary", map[string]any{
			"kind": "CLIENT", "attributes": attributes,
		}, redaction.ProfileNone)
		if result := Project(projection, Limits{}); result.Reason() != ReasonUnsupportedShape {
			t.Fatalf("invalid canary reason = %q", result.Reason())
		}
	}
}

func TestProjectBoundsAreDeterministicAndFailClosed(t *testing.T) {
	t.Parallel()
	attributes := map[string]any{
		"gen_ai.operation.name": "chat", "gen_ai.provider.name": "openai",
		"gen_ai.input.messages": messagesMany(3), "gen_ai.output.messages": strings.Repeat("x", 400),
	}
	for index := 0; index < 40; index++ {
		attributes[fmt.Sprintf("gen_ai.request.compatibility_extra_%02d", index)] = strings.Repeat(string(rune('a'+index%26)), 180)
	}
	body := map[string]any{
		"kind": "CLIENT", "attributes": attributes,
		"events": []any{
			map[string]any{"name": "model.retry", "attributes": map[string]any{"attempt": 1, "backoff_ms": 2, "error.type": "timeout", "evaluation_id": "e", "finding_id": "f"}},
			map[string]any{"name": "guardrail.decision", "attributes": map[string]any{"decision": "allow"}},
		},
		"links": []any{
			map[string]any{"trace_id": strings.Repeat("1", 32)}, map[string]any{"trace_id": strings.Repeat("2", 32)},
		},
	}
	projection := projectRecord(t, observability.BucketModelIO, "span.model.chat", "chat model", body, redaction.ProfileNone)
	limits := Limits{
		MaxAttributesPerSpan: 32, MaxEventsPerSpan: 1, MaxLinksPerSpan: 1,
		MaxAttributesPerEvent: 4, MaxAttributeValueBytes: 256,
		MaxProjectedSpanBytes: 1024 * 1024, MaxMessageItems: 1,
	}
	result := Project(projection, limits)
	if !result.Eligible() {
		t.Fatalf("bounded result = %q", result.Reason())
	}
	resultBody := resultWire(t, result)["body"].(map[string]any)
	if got := len(resultBody["attributes"].(map[string]any)); got > limits.MaxAttributesPerSpan {
		t.Fatalf("attribute count = %d", got)
	}
	if got := len(resultBody["events"].([]any)); got != 1 {
		t.Fatalf("event count = %d", got)
	}
	if got := len(resultBody["links"].([]any)); got != 1 {
		t.Fatalf("link count = %d", got)
	}
	boundedAttributes := resultBody["attributes"].(map[string]any)
	if boundedAttributes["defenseclaw.telemetry.input.state"] != "truncated" {
		t.Fatalf("input state = %#v", boundedAttributes["defenseclaw.telemetry.input.state"])
	}
	if boundedAttributes["gen_ai.output.messages"] != "[]" || boundedAttributes["defenseclaw.telemetry.output.state"] != "failed_closed" {
		t.Fatalf("oversize output was not failed closed: %#v", boundedAttributes)
	}
	for _, required := range requiredAttributeKeys(shapeContract{shape: ShapeLLM}) {
		if _, ok := boundedAttributes[required]; !ok {
			t.Errorf("required attribute %q dropped", required)
		}
	}

	tooSmall := limits
	tooSmall.MaxProjectedSpanBytes = minProjectedSpanBytes
	if got := Project(projection, tooSmall); got.Reason() != ReasonProjectionTooLarge {
		t.Fatalf("oversize reason = %q", got.Reason())
	}
	invalid := limits
	invalid.MaxMessageItems = maxMessageItems + 1
	if got := Project(projection, invalid); got.Reason() != ReasonInvalidLimits {
		t.Fatalf("invalid-limit reason = %q", got.Reason())
	}
}

func TestProjectIsConcurrentDeterministicAndImmutable(t *testing.T) {
	t.Parallel()
	projection := projectRecord(t, observability.BucketAgentLifecycle, "span.agent.invoke", "invoke_agent child", map[string]any{
		"kind": "INTERNAL", "attributes": map[string]any{
			"gen_ai.operation.name": "invoke_agent", "gen_ai.provider.name": "openai", "gen_ai.agent.name": "child",
			"gen_ai.input.messages": messages("user", "input"), "gen_ai.output.messages": messages("assistant", "output"),
			"defenseclaw.agent.root.id": "root", "defenseclaw.agent.parent.id": "parent",
		},
	}, redaction.ProfileNone)
	before, _ := projection.Bytes()
	want, err := Project(projection, Limits{}).Bytes()
	if err != nil {
		t.Fatal(err)
	}
	const workers = 64
	errorsOut := make(chan error, workers)
	var group sync.WaitGroup
	for index := 0; index < workers; index++ {
		group.Add(1)
		go func() {
			defer group.Done()
			got, projectErr := Project(projection, Limits{}).Bytes()
			if projectErr != nil {
				errorsOut <- projectErr
				return
			}
			if !bytes.Equal(got, want) {
				errorsOut <- errors.New("non-deterministic projection")
			}
		}()
	}
	group.Wait()
	close(errorsOut)
	for err := range errorsOut {
		t.Error(err)
	}
	after, _ := projection.Bytes()
	if !bytes.Equal(before, after) {
		t.Fatal("source projection mutated")
	}
	copyOut, _ := Project(projection, Limits{}).Bytes()
	copyOut[0] ^= 0xff
	again, _ := Project(projection, Limits{}).Bytes()
	if !bytes.Equal(again, want) {
		t.Fatal("returned bytes alias internal state")
	}
}

func TestProjectRejectsZeroProjectionWithoutRawFallback(t *testing.T) {
	t.Parallel()
	result := Project(redaction.Projection{}, Limits{})
	if result.Reason() != ReasonInvalidProjection || result.Eligible() {
		t.Fatalf("zero projection = %q eligible=%v", result.Reason(), result.Eligible())
	}
	if result.Shape() != "" || len(result.MissingFields()) != 0 {
		t.Fatalf("zero projection retained details: shape=%q missing=%v", result.Shape(), result.MissingFields())
	}
}

func messages(role, content string) string {
	encoded, _ := json.Marshal([]map[string]string{{"role": role, "content": content}})
	return string(encoded)
}

func messagesMany(count int) string {
	messages := make([]map[string]string, count)
	for index := range messages {
		messages[index] = map[string]string{"role": "user", "content": strconv.Itoa(index)}
	}
	encoded, _ := json.Marshal(messages)
	return string(encoded)
}

func projectRecord(
	t *testing.T,
	bucket observability.Bucket,
	family observability.EventName,
	spanName string,
	body map[string]any,
	profileName redaction.ProfileName,
) redaction.Projection {
	t.Helper()
	return redactRecord(t, newTraceRecord(t, bucket, family, spanName, body), profileName)
}

func newTraceRecord(
	t *testing.T,
	bucket observability.Bucket,
	family observability.EventName,
	spanName string,
	body map[string]any,
) observability.Record {
	t.Helper()
	record, err := observability.NewRecord(observability.RecordInput{
		Timestamp: time.Date(2026, 7, 3, 12, 0, 0, 0, time.UTC),
		RecordID:  "galileo-" + strings.ReplaceAll(string(family), ".", "-"),
		Identity: observability.EventIdentity{
			Bucket: bucket, Signal: observability.SignalTraces, Name: family,
		},
		SpanName: spanName, Source: observability.SourceGateway,
		Correlation: observability.Correlation{
			RunID: "run-1", SessionID: "session-1", TurnID: "turn-1",
			TraceID: strings.Repeat("a", 32), SpanID: strings.Repeat("b", 16),
			AgentID: "agent-1", AgentInstanceID: "instance-1", ToolInvocationID: "tool-1",
		},
		Provenance: observability.Provenance{
			Producer: "gateway.trace", BinaryVersion: "v8-test",
			RegistrySchemaVersion: 1, ConfigGeneration: 7,
		},
		Body: body, FieldClasses: fieldClasses(body),
	})
	if err != nil {
		t.Fatal(err)
	}
	return record
}

func redactRecord(t *testing.T, record observability.Record, profileName redaction.ProfileName) redaction.Projection {
	t.Helper()
	engine, err := redaction.NewEngine(bytes.Repeat([]byte{0x2a}, 32))
	if err != nil {
		t.Fatal(err)
	}
	profile, ok := redaction.BuiltInProfile(profileName)
	if !ok {
		t.Fatalf("profile %q not found", profileName)
	}
	projection, _, err := engine.Project(record, profile)
	if err != nil {
		t.Fatal(err)
	}
	return projection
}

func fieldClasses(body map[string]any) map[string]observability.FieldClass {
	classes := make(map[string]observability.FieldClass)
	var visit func(any, string, string)
	visit = func(value any, pointer, key string) {
		switch typed := value.(type) {
		case map[string]any:
			if len(typed) == 0 {
				classes[pointer] = classForKey(key)
				return
			}
			keys := make([]string, 0, len(typed))
			for childKey := range typed {
				keys = append(keys, childKey)
			}
			sort.Strings(keys)
			for _, childKey := range keys {
				visit(typed[childKey], pointer+"/"+pointerToken(childKey), childKey)
			}
		case []any:
			if len(typed) == 0 {
				classes[pointer] = classForKey(key)
				return
			}
			for index, child := range typed {
				visit(child, pointer+"/"+strconv.Itoa(index), key)
			}
		default:
			classes[pointer] = classForKey(key)
		}
	}
	visit(body, "", "")
	return classes
}

func classForKey(key string) observability.FieldClass {
	lower := strings.ToLower(key)
	switch {
	case strings.Contains(lower, "message"), strings.Contains(lower, "content"),
		strings.Contains(lower, "argument"), strings.Contains(lower, "result"),
		lower == "input.value", lower == "output.value", lower == "body":
		return observability.FieldClassContent
	case strings.Contains(lower, "reason"):
		return observability.FieldClassReason
	case strings.Contains(lower, "evidence"):
		return observability.FieldClassEvidence
	case strings.Contains(lower, "secret"):
		return observability.FieldClassCredential
	default:
		return observability.FieldClassMetadata
	}
}

func pointerToken(input string) string {
	return strings.ReplaceAll(strings.ReplaceAll(input, "~", "~0"), "/", "~1")
}

func resultWire(t *testing.T, result Result) map[string]any {
	t.Helper()
	encoded, err := result.Bytes()
	if err != nil {
		t.Fatal(err)
	}
	decoder := json.NewDecoder(bytes.NewReader(encoded))
	decoder.UseNumber()
	var wire map[string]any
	if err := decoder.Decode(&wire); err != nil {
		t.Fatal(err)
	}
	return wire
}

func resultAttributes(t *testing.T, result Result) map[string]any {
	t.Helper()
	body, ok := resultWire(t, result)["body"].(map[string]any)
	if !ok {
		t.Fatal("projected body missing")
	}
	attributes, ok := body["attributes"].(map[string]any)
	if !ok {
		t.Fatal("projected attributes missing")
	}
	return attributes
}
