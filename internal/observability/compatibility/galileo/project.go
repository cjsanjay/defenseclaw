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
	"io"
	"sort"
	"strconv"
	"strings"
	"unicode/utf8"

	"github.com/defenseclaw/defenseclaw/internal/observability/redaction"
)

const (
	canaryFamily         = "span.diagnostic.canary"
	canaryMarkerKey      = "defenseclaw.telemetry.canary"
	canaryOperationKey   = "defenseclaw.telemetry.canary.operation"
	canaryOperationValue = "runtime-pipeline-test"
)

// Project evaluates galileo-rich-v2 after route redaction. A rejection has no
// side effect on the supplied projection or any other destination projection.
func Project(input redaction.Projection, configured Limits) Result {
	limits, ok := configured.resolved()
	if !ok {
		return rejected(ReasonInvalidLimits)
	}
	encoded, err := input.Bytes()
	if err != nil {
		return rejected(ReasonInvalidProjection)
	}
	var envelope projectedEnvelope
	decoder := json.NewDecoder(bytes.NewReader(encoded))
	decoder.UseNumber()
	if err := decoder.Decode(&envelope); err != nil || !validEnvelope(envelope) {
		return rejected(ReasonInvalidProjection)
	}
	var trailing any
	if err := decoder.Decode(&trailing); err != io.EOF {
		return rejected(ReasonInvalidProjection)
	}
	attributes, ok := object(envelope.Body["attributes"])
	if !ok {
		return rejected(ReasonSchemaMissingRequired, "body.attributes")
	}
	contract, reason, missing := selectContract(envelope, attributes)
	if reason != ReasonEligible {
		return rejected(reason, missing...)
	}

	projectedAttributes := projectAttributes(attributes, limits.MaxAttributeValueBytes)
	missing = prepareRequiredProjection(contract, envelope, projectedAttributes, limits)
	if len(missing) > 0 {
		return rejected(ReasonSchemaMissingRequired, missing...)
	}
	projectedAttributes = trimAttributes(
		projectedAttributes, requiredAttributeKeys(contract), limits.MaxAttributesPerSpan,
	)
	body := projectBody(envelope.Body, projectedAttributes, limits)
	output := outputEnvelope{
		Profile: ProfileID, Shape: contract.shape,
		SchemaVersion: envelope.SchemaVersion, BucketCatalogVersion: envelope.BucketCatalogVersion,
		Timestamp: envelope.Timestamp, ObservedAt: envelope.ObservedAt,
		RecordID: envelope.RecordID, Bucket: envelope.Bucket, Signal: envelope.Signal,
		Family: envelope.Family, SpanName: envelope.SpanName, Source: envelope.Source,
		Connector: envelope.Connector, Action: envelope.Action, Phase: envelope.Phase, Outcome: envelope.Outcome,
		Correlation: cloneObject(envelope.Correlation), Provenance: cloneObject(envelope.Provenance),
		Projection: cloneObject(envelope.Projection), Body: body,
	}
	projected, err := json.Marshal(output)
	if err != nil {
		return rejected(ReasonInvalidProjection)
	}
	if len(projected) > limits.MaxProjectedSpanBytes {
		return rejected(ReasonProjectionTooLarge)
	}
	return accepted(contract.shape, projected)
}

func validEnvelope(envelope projectedEnvelope) bool {
	return envelope.SchemaVersion > 0 && envelope.BucketCatalogVersion > 0 &&
		envelope.RecordID != "" && envelope.Bucket != "" && envelope.Signal == "traces" &&
		envelope.Family != "" && envelope.SpanName != "" && envelope.Source != "" &&
		envelope.Timestamp != nil && envelope.Correlation != nil && envelope.Provenance != nil &&
		projectionMetadataValid(envelope.Projection) && envelope.Body != nil
}

func projectionMetadataValid(metadata map[string]any) bool {
	profile, profileOK := metadata["redaction_profile"].(string)
	state, stateOK := metadata["state"].(string)
	return profileOK && strings.TrimSpace(profile) != "" && stateOK && strings.TrimSpace(state) != ""
}

func selectContract(envelope projectedEnvelope, attributes map[string]any) (shapeContract, Reason, []string) {
	family := envelope.Family
	operation, operationPresent := stringAttribute(attributes, "gen_ai.operation.name")
	if family == canaryFamily {
		marker, markerOK := boolAttribute(attributes, canaryMarkerKey)
		canaryOperation, operationOK := stringAttribute(attributes, canaryOperationKey)
		if !markerOK || !marker || !operationOK || canaryOperation != canaryOperationValue {
			return shapeContract{}, ReasonUnsupportedShape, nil
		}
		switch operation {
		case "invoke_agent":
			return contract(ShapeAgent, family, operation, "AGENT", internalOrClient), ReasonEligible, nil
		case "chat", "text_completion":
			return contract(ShapeLLM, family, operation, "LLM", clientOnly), ReasonEligible, nil
		default:
			if !operationPresent {
				return shapeContract{}, ReasonSchemaMissingRequired, []string{"gen_ai.operation.name"}
			}
			return shapeContract{}, ReasonUnsupportedShape, nil
		}
	}

	switch family {
	case "span.agent.invoke":
		if !operationPresent {
			return shapeContract{}, ReasonSchemaMissingRequired, []string{"gen_ai.operation.name"}
		}
		if operation != "invoke_agent" {
			return shapeContract{}, ReasonUnsupportedShape, nil
		}
		return contract(ShapeAgent, family, operation, "AGENT", internalOrClient), ReasonEligible, nil
	case "span.model.chat", "span.guardrail.judge":
		if !operationPresent {
			return shapeContract{}, ReasonSchemaMissingRequired, []string{"gen_ai.operation.name"}
		}
		if operation != "chat" && operation != "text_completion" {
			return shapeContract{}, ReasonUnsupportedShape, nil
		}
		return contract(ShapeLLM, family, operation, "LLM", clientOnly), ReasonEligible, nil
	case "span.tool.execute":
		if !operationPresent {
			return shapeContract{}, ReasonSchemaMissingRequired, []string{"gen_ai.operation.name"}
		}
		if operation != "execute_tool" {
			return shapeContract{}, ReasonUnsupportedShape, nil
		}
		return contract(ShapeTool, family, operation, "TOOL", internalOrClient), ReasonEligible, nil
	case "span.retrieval.search":
		dbOperation, present := stringAttribute(attributes, "db.operation.name")
		if !present {
			return shapeContract{}, ReasonSchemaMissingRequired, []string{"db.operation.name"}
		}
		if dbOperation != "query" && dbOperation != "search" {
			return shapeContract{}, ReasonUnsupportedShape, nil
		}
		return contract(ShapeRetriever, family, dbOperation, "RETRIEVER", internalOrClient), ReasonEligible, nil
	case "span.workflow.run":
		if _, present := canonicalWorkflowName(attributes); !present {
			return shapeContract{}, ReasonSchemaMissingRequired, []string{"defenseclaw.workflow.name"}
		}
		kind, present := stringAttribute(attributes, "openinference.span.kind")
		if present && kind != "CHAIN" {
			return shapeContract{}, ReasonUnsupportedShape, nil
		}
		return contract(ShapeWorkflow, family, "", "CHAIN", internalOnly), ReasonEligible, nil
	default:
		return shapeContract{}, ReasonUnsupportedShape, nil
	}
}

func contract(shape Shape, family, operation, oiKind string, kinds map[string]struct{}) shapeContract {
	return shapeContract{shape: shape, family: family, operation: operation, oiKind: oiKind, allowedKinds: kinds}
}

func prepareRequiredProjection(
	contract shapeContract,
	envelope projectedEnvelope,
	attributes map[string]any,
	limits Limits,
) []string {
	missing := make([]string, 0, 8)
	kind, present := normalizedSpanKind(envelope.Body["kind"])
	if !present {
		missing = append(missing, "body.kind")
	} else if _, allowed := contract.allowedKinds[kind]; !allowed {
		missing = append(missing, "body.kind")
	}
	if !validSpanName(contract, envelope.SpanName, attributes) {
		missing = append(missing, "span_name")
	}

	attributes["openinference.span.kind"] = contract.oiKind
	if contract.operation != "" && contract.shape != ShapeRetriever {
		attributes["gen_ai.operation.name"] = contract.operation
	}
	if contract.family == "span.guardrail.judge" {
		attributes["defenseclaw.guardrail.judge"] = true
	}

	switch contract.shape {
	case ShapeAgent:
		requireNonEmptyString(attributes, "gen_ai.provider.name", &missing)
		requireNonEmptyString(attributes, "gen_ai.agent.name", &missing)
		ensureMessages(attributes, "input", "user", contentFallback(attributes, "input", limits), limits)
		ensureMessages(attributes, "output", "assistant", contentFallback(attributes, "output", limits), limits)
	case ShapeLLM:
		requireNonEmptyString(attributes, "gen_ai.provider.name", &missing)
		ensureMessages(attributes, "input", "user", contentFallback(attributes, "input", limits), limits)
		ensureMessages(attributes, "output", "assistant", contentFallback(attributes, "output", limits), limits)
	case ShapeTool:
		requireNonEmptyString(attributes, "gen_ai.tool.name", &missing)
		arguments, argumentsOK := boundedString(attributes["gen_ai.tool.call.arguments"], limits.MaxAttributeValueBytes)
		result, resultOK := boundedString(attributes["gen_ai.tool.call.result"], limits.MaxAttributeValueBytes)
		delete(attributes, "gen_ai.tool.call.arguments")
		delete(attributes, "gen_ai.tool.call.result")
		if !argumentsOK {
			arguments, argumentsOK = contentScalar(attributes, "input", limits.MaxAttributeValueBytes)
		}
		if !resultOK {
			result, resultOK = contentScalar(attributes, "output", limits.MaxAttributeValueBytes)
		}
		if argumentsOK {
			attributes["gen_ai.tool.call.arguments"] = arguments
		} else {
			missing = append(missing, "gen_ai.tool.call.arguments")
		}
		if resultOK {
			attributes["gen_ai.tool.call.result"] = result
		} else {
			missing = append(missing, "gen_ai.tool.call.result")
		}
		ensureMessages(attributes, "input", "user", valueWhen(argumentsOK, arguments), limits)
		ensureMessages(attributes, "output", "tool", valueWhen(resultOK, result), limits)
		setContentState(attributes, "arguments", argumentsOK, arguments, limits.MaxAttributeValueBytes)
		setContentState(attributes, "result", resultOK, result, limits.MaxAttributeValueBytes)
	case ShapeRetriever:
		ensureMessages(attributes, "input", "user", contentFallback(attributes, "input", limits), limits)
		ensureMessages(attributes, "output", "assistant", contentFallback(attributes, "output", limits), limits)
	case ShapeWorkflow:
		ensureMessages(attributes, "input", "user", contentFallback(attributes, "input", limits), limits)
		ensureMessages(attributes, "output", "assistant", contentFallback(attributes, "output", limits), limits)
	}

	for _, key := range requiredAttributeKeys(contract) {
		if _, ok := attributes[key]; !ok {
			missing = append(missing, key)
		}
	}
	missing = uniqueSorted(missing)
	return missing
}

func validSpanName(contract shapeContract, name string, attributes map[string]any) bool {
	if !utf8.ValidString(name) || len(name) == 0 || len(name) > 512 || strings.ContainsAny(name, "\r\n\x00") {
		return false
	}
	switch contract.shape {
	case ShapeAgent:
		return name == "invoke_agent" ||
			(strings.HasPrefix(name, "invoke_agent ") && strings.TrimSpace(strings.TrimPrefix(name, "invoke_agent ")) != "")
	case ShapeLLM:
		return name == contract.operation ||
			(strings.HasPrefix(name, contract.operation+" ") && strings.TrimSpace(strings.TrimPrefix(name, contract.operation+" ")) != "")
	case ShapeTool:
		return strings.HasPrefix(name, "execute_tool ") && strings.TrimSpace(strings.TrimPrefix(name, "execute_tool ")) != ""
	case ShapeRetriever:
		return strings.HasPrefix(name, "retrieve ") && strings.TrimSpace(strings.TrimPrefix(name, "retrieve ")) != ""
	case ShapeWorkflow:
		workflowName, ok := canonicalWorkflowName(attributes)
		return ok && name == "workflow "+workflowName
	default:
		return false
	}
}

func normalizedSpanKind(value any) (string, bool) {
	switch typed := value.(type) {
	case string:
		kind := strings.ToUpper(strings.TrimSpace(typed))
		switch kind {
		case "INTERNAL", "CLIENT":
			return kind, true
		default:
			return "", false
		}
	case json.Number:
		value, err := strconv.Atoi(typed.String())
		if err != nil {
			return "", false
		}
		return normalizedSpanKind(float64(value))
	case float64:
		if typed != float64(int(typed)) {
			return "", false
		}
		switch int(typed) {
		case 1:
			return "INTERNAL", true
		case 3:
			return "CLIENT", true
		default:
			return "", false
		}
	default:
		return "", false
	}
}

func projectBody(input, attributes map[string]any, limits Limits) map[string]any {
	output := make(map[string]any)
	for _, key := range []string{
		"kind", "parent_span_id", "start_time_unix_nano", "end_time_unix_nano", "duration_nano",
		"dropped_attributes_count", "dropped_events_count", "dropped_links_count",
	} {
		if value, ok := input[key]; ok {
			output[key] = cloneJSON(value)
		}
	}
	if kind, ok := normalizedSpanKind(input["kind"]); ok {
		output["kind"] = kind
	}
	output["attributes"] = cloneObject(attributes)
	if events := projectEvents(input["events"], limits); len(events) > 0 {
		output["events"] = events
	}
	if links := projectLinks(input["links"], limits); len(links) > 0 {
		output["links"] = links
	}
	if status := projectStatus(input["status"], limits.MaxAttributeValueBytes); len(status) > 0 {
		output["status"] = status
	}
	if resource := projectResource(input["resource"], limits.MaxAttributeValueBytes); len(resource) > 0 {
		output["resource"] = resource
	}
	if scope := projectScope(input["scope"], limits.MaxAttributeValueBytes); len(scope) > 0 {
		output["scope"] = scope
	}
	return output
}

func projectResource(value any, maximum int) map[string]any {
	resource, ok := object(value)
	if !ok {
		return nil
	}
	attributes, ok := object(resource["attributes"])
	if !ok {
		return nil
	}
	allowed := map[string]struct{}{
		"service.name": {}, "service.version": {}, "service.namespace": {}, "service.instance.id": {},
		"deployment.environment.name": {}, "deployment.environment": {}, "host.name": {},
		"host.arch": {}, "os.type": {}, "tenant.id": {}, "workspace.id": {},
		"defenseclaw.instance.id": {}, "deployment.mode": {}, "defenseclaw.claw.mode": {},
		"discovery.source": {}, "defenseclaw.device.id": {},
	}
	projected := make(map[string]any)
	for _, key := range sortedKeys(attributes) {
		if _, ok := allowed[key]; !ok || !valueWithinLimit(attributes[key], maximum) {
			continue
		}
		projected[key] = cloneJSON(attributes[key])
	}
	if len(projected) == 0 {
		return nil
	}
	output := map[string]any{"attributes": projected}
	if schemaURL, ok := boundedString(resource["schema_url"], maximum); ok {
		output["schema_url"] = schemaURL
	}
	return output
}

func projectScope(value any, maximum int) map[string]any {
	scope, ok := object(value)
	if !ok {
		return nil
	}
	output := make(map[string]any, 4)
	for _, key := range []string{"name", "version", "schema_url"} {
		if text, ok := boundedString(scope[key], maximum); ok && text != "" {
			output[key] = text
		}
	}
	if attributes, ok := object(scope["attributes"]); ok {
		projected := make(map[string]any)
		for _, key := range []string{
			"defenseclaw.trace.schema_version", "defenseclaw.semantic_profile",
			"defenseclaw.galileo.compatibility_profile",
		} {
			if value, exists := attributes[key]; exists && valueWithinLimit(value, maximum) {
				projected[key] = cloneJSON(value)
			}
		}
		if len(projected) > 0 {
			output["attributes"] = projected
		}
	}
	return output
}

func projectAttributes(input map[string]any, maxValueBytes int) map[string]any {
	keys := sortedKeys(input)
	output := make(map[string]any, len(keys))
	for _, key := range keys {
		if !allowedAttribute(key) {
			continue
		}
		if !isContentAttribute(key) && !valueWithinLimit(input[key], maxValueBytes) {
			continue
		}
		output[key] = cloneJSON(input[key])
	}
	return output
}

func isContentAttribute(key string) bool {
	switch key {
	case "gen_ai.input.messages", "gen_ai.output.messages", "gen_ai.tool.call.arguments",
		"gen_ai.tool.call.result", "input.value", "output.value":
		return true
	default:
		return false
	}
}

func valueWithinLimit(value any, maximum int) bool {
	encoded, err := json.Marshal(value)
	return err == nil && len(encoded) <= maximum
}

func allowedAttribute(key string) bool {
	if strings.HasPrefix(key, "gen_ai.") || strings.HasPrefix(key, "openinference.") ||
		strings.HasPrefix(key, "db.") || strings.HasPrefix(key, "input.") || strings.HasPrefix(key, "output.") {
		return true
	}
	switch key {
	case "connector", "user.id", "tenant.id", "workspace.id", "error.type",
		"defenseclaw.bucket", "defenseclaw.span.family", "defenseclaw.span.family_schema_version",
		"defenseclaw.source", "defenseclaw.config.generation", "defenseclaw.outcome",
		"defenseclaw.run.id", "defenseclaw.operation.id", "defenseclaw.request.id",
		"defenseclaw.turn.id", "defenseclaw.turn_id", "defenseclaw.agent.instance_id",
		"defenseclaw.agent.root.id", "defenseclaw.agent.parent.id",
		"defenseclaw.agent.lifecycle.id", "defenseclaw.agent.execution.id",
		"defenseclaw.agent.lifecycle.event", "defenseclaw.agent.lifecycle.state",
		"defenseclaw.agent.phase", "defenseclaw.agent.phase.previous",
		"defenseclaw.agent.phase.code", "defenseclaw.agent.sequence",
		"defenseclaw.agent.depth", "defenseclaw.agent.stream.mode",
		"defenseclaw.workflow.name",
		"defenseclaw.agent.lifecycle.transition", "defenseclaw.agent.reported_cost.present",
		"defenseclaw.agent.reported_cost.usd", "defenseclaw.session.root.id",
		"defenseclaw.session.parent.id", "defenseclaw.session.source",
		"defenseclaw.session.resumed", "defenseclaw.user.name",
		"defenseclaw.connector.source", "defenseclaw.destination.app",
		"defenseclaw.policy.id", "defenseclaw.policy.version",
		"defenseclaw.evaluation.id", "defenseclaw.finding.occurrence_id",
		"defenseclaw.enforcement.action.id", "defenseclaw.approval.id",
		"defenseclaw.guardrail.judge", "defenseclaw.guardrail.decision",
		"defenseclaw.guardrail.raw_action", "defenseclaw.guardrail.effective_action",
		"defenseclaw.guardrail.mode", "defenseclaw.guardrail.would_block",
		"defenseclaw.guardrail.enforced", "defenseclaw.guardrail.severity",
		"defenseclaw.guardrail.evaluation.id", "defenseclaw.guardrail.finding.count",
		"defenseclaw.llm.tool_calls", "defenseclaw.llm.guardrail", "defenseclaw.llm.guardrail.result",
		"defenseclaw.tool.status", "defenseclaw.tool.dangerous", "defenseclaw.tool.provider",
		"defenseclaw.tool.exit_code", "defenseclaw.tool.output_length",
		canaryMarkerKey, canaryOperationKey, "defenseclaw.telemetry.canary.destination":
		return true
	}
	return strings.HasPrefix(key, "defenseclaw.telemetry.input.") ||
		strings.HasPrefix(key, "defenseclaw.telemetry.output.") ||
		strings.HasPrefix(key, "defenseclaw.telemetry.arguments.") ||
		strings.HasPrefix(key, "defenseclaw.telemetry.result.")
}

func requiredAttributeKeys(contract shapeContract) []string {
	common := []string{
		"openinference.span.kind", "gen_ai.input.messages", "gen_ai.output.messages",
		"defenseclaw.telemetry.input.reported", "defenseclaw.telemetry.input.state",
		"defenseclaw.telemetry.output.reported", "defenseclaw.telemetry.output.state",
	}
	switch contract.shape {
	case ShapeAgent:
		return append(common, "gen_ai.operation.name", "gen_ai.provider.name", "gen_ai.agent.name")
	case ShapeLLM:
		return append(common, "gen_ai.operation.name", "gen_ai.provider.name")
	case ShapeTool:
		return append(common,
			"gen_ai.operation.name", "gen_ai.tool.name", "gen_ai.tool.call.arguments", "gen_ai.tool.call.result",
			"defenseclaw.telemetry.arguments.reported", "defenseclaw.telemetry.arguments.state",
			"defenseclaw.telemetry.result.reported", "defenseclaw.telemetry.result.state",
		)
	case ShapeRetriever:
		return append(common, "db.operation.name")
	case ShapeWorkflow:
		return append(common, "defenseclaw.workflow.name")
	default:
		return nil
	}
}

func trimAttributes(attributes map[string]any, required []string, maximum int) map[string]any {
	if len(attributes) <= maximum {
		return attributes
	}
	requiredSet := make(map[string]struct{}, len(required))
	for _, key := range required {
		requiredSet[key] = struct{}{}
	}
	keys := sortedKeys(attributes)
	output := make(map[string]any, maximum)
	for _, key := range required {
		if value, ok := attributes[key]; ok && len(output) < maximum {
			output[key] = cloneJSON(value)
		}
	}
	for _, key := range keys {
		if len(output) >= maximum {
			break
		}
		if _, required := requiredSet[key]; required {
			continue
		}
		output[key] = cloneJSON(attributes[key])
	}
	return output
}

func ensureMessages(attributes map[string]any, direction, role string, fallback any, limits Limits) {
	key := "gen_ai." + direction + ".messages"
	value, supplied := attributes[key]
	reportedKey := "defenseclaw.telemetry." + direction + ".reported"
	reportedOverride, hasReportedOverride := boolAttribute(attributes, reportedKey)
	if !supplied && fallback != nil {
		value = []any{map[string]any{"role": role, "content": fallback}}
		supplied = true
	}
	encoded, state, reported := normalizeMessages(value, supplied, limits)
	if hasReportedOverride && !reportedOverride {
		encoded, state, reported = "[]", "not_reported", false
	}
	attributes[key] = encoded
	attributes[reportedKey] = reported
	attributes["defenseclaw.telemetry."+direction+".state"] = state
	if reported {
		attributes["defenseclaw.telemetry."+direction+".original_bytes"] = len(encoded)
	}
	attributes["defenseclaw.telemetry."+direction+".content_type"] = "application/json"
	if _, ok := attributes[direction+".mime_type"]; !ok {
		attributes[direction+".mime_type"] = "application/json"
	}
}

func normalizeMessages(value any, supplied bool, limits Limits) (string, string, bool) {
	if !supplied {
		return "[]", "not_reported", false
	}
	var messages []any
	switch typed := value.(type) {
	case string:
		decoder := json.NewDecoder(strings.NewReader(typed))
		decoder.UseNumber()
		if err := decoder.Decode(&messages); err != nil {
			return "[]", "failed_closed", true
		}
	case []any:
		messages = cloneArray(typed)
	default:
		return "[]", "failed_closed", true
	}
	state := "preserved"
	if len(messages) > limits.MaxMessageItems {
		messages = messages[:limits.MaxMessageItems]
		state = "truncated"
	}
	encoded, err := json.Marshal(messages)
	if err != nil || len(encoded) > limits.MaxAttributeValueBytes {
		return "[]", "failed_closed", true
	}
	if state == "preserved" {
		state = redactionState(string(encoded))
	}
	return string(encoded), state, true
}

func redactionState(value string) string {
	trimmed := strings.TrimSpace(value)
	if strings.Contains(trimmed, "<redacted:") || strings.Contains(trimmed, "[REDACTED]") {
		if strings.HasPrefix(trimmed, "<redacted:") || trimmed == "[REDACTED]" {
			return "whole_redacted"
		}
		return "partially_redacted"
	}
	return "preserved"
}

func contentScalar(attributes map[string]any, direction string, maximum int) (string, bool) {
	if value, ok := boundedString(attributes[direction+".value"], maximum); ok {
		return value, true
	}
	value, ok := boundedString(attributes["gen_ai."+direction+".messages"], maximum)
	if !ok {
		return "", false
	}
	var messages []map[string]any
	if json.Unmarshal([]byte(value), &messages) != nil || len(messages) == 0 {
		return "", false
	}
	content, ok := messages[0]["content"].(string)
	if !ok || len(content) > maximum {
		return "", false
	}
	return content, true
}

func contentFallback(attributes map[string]any, direction string, limits Limits) any {
	value, ok := boundedString(attributes[direction+".value"], limits.MaxAttributeValueBytes)
	if !ok {
		return nil
	}
	return value
}

func setContentState(attributes map[string]any, slot string, reported bool, value string, maximum int) {
	attributes["defenseclaw.telemetry."+slot+".reported"] = reported
	if !reported {
		attributes["defenseclaw.telemetry."+slot+".state"] = "not_reported"
		return
	}
	state := redactionState(value)
	if len(value) > maximum {
		state = "failed_closed"
	}
	attributes["defenseclaw.telemetry."+slot+".state"] = state
	attributes["defenseclaw.telemetry."+slot+".original_bytes"] = len(value)
}

func valueWhen(ok bool, value string) any {
	if !ok {
		return nil
	}
	return value
}

func projectEvents(value any, limits Limits) []any {
	events, ok := value.([]any)
	if !ok {
		return nil
	}
	output := make([]any, 0, min(len(events), limits.MaxEventsPerSpan))
	for _, candidate := range events {
		if len(output) >= limits.MaxEventsPerSpan {
			break
		}
		event, ok := object(candidate)
		if !ok {
			continue
		}
		name, ok := event["name"].(string)
		if !ok || !allowedEvent(name) {
			continue
		}
		projected := map[string]any{"name": name}
		if timestamp, ok := event["timestamp"]; ok {
			projected["timestamp"] = cloneJSON(timestamp)
		}
		if timestamp, ok := event["time_unix_nano"]; ok {
			projected["time_unix_nano"] = cloneJSON(timestamp)
		}
		if attributes, ok := object(event["attributes"]); ok {
			projected["attributes"] = projectEventAttributes(attributes, limits.MaxAttributesPerEvent)
		}
		output = append(output, projected)
	}
	return output
}

func allowedEvent(name string) bool {
	switch name {
	case "guardrail.decision", "hook.decision", "security.finding.observed",
		"approval.requested", "approval.resolved", "enforcement.requested",
		"enforcement.applied", "enforcement.failed", "tool.flagged",
		"content.redacted", "content.truncated", "model.retry", "model.stream.first_token":
		return true
	default:
		return false
	}
}

func projectEventAttributes(input map[string]any, maximum int) map[string]any {
	keys := sortedKeys(input)
	output := make(map[string]any, min(len(keys), maximum))
	for _, key := range keys {
		if len(output) >= maximum {
			break
		}
		if !safeEventAttribute(key) {
			continue
		}
		output[key] = cloneJSON(input[key])
	}
	return output
}

func safeEventAttribute(key string) bool {
	for _, forbidden := range []string{"content", "reason", "evidence", "pattern", "message", "stack", "body", "argument", "result"} {
		if strings.Contains(strings.ToLower(key), forbidden) {
			return false
		}
	}
	return strings.HasSuffix(key, ".id") || strings.HasSuffix(key, "_id") ||
		strings.HasSuffix(key, ".count") || strings.HasSuffix(key, "_count") ||
		strings.HasSuffix(key, ".bytes") || strings.HasSuffix(key, "_bytes") ||
		strings.HasSuffix(key, ".ms") || strings.HasSuffix(key, "_ms") ||
		strings.Contains(key, "decision") || strings.Contains(key, "action") ||
		strings.Contains(key, "severity") || strings.Contains(key, "category") ||
		strings.Contains(key, "outcome") || strings.Contains(key, "enforced") ||
		strings.Contains(key, "would_block") || strings.Contains(key, "field_class") ||
		strings.Contains(key, "profile") || strings.Contains(key, "attempt") || key == "error.type"
}

func projectLinks(value any, limits Limits) []any {
	links, ok := value.([]any)
	if !ok {
		return nil
	}
	output := make([]any, 0, min(len(links), limits.MaxLinksPerSpan))
	for _, candidate := range links {
		if len(output) >= limits.MaxLinksPerSpan {
			break
		}
		link, ok := object(candidate)
		if !ok {
			continue
		}
		projected := make(map[string]any)
		for _, key := range []string{"trace_id", "span_id", "trace_state"} {
			if value, ok := link[key]; ok {
				projected[key] = cloneJSON(value)
			}
		}
		if attributes, ok := object(link["attributes"]); ok {
			projected["attributes"] = projectLinkAttributes(attributes, limits.MaxAttributesPerEvent)
		}
		if len(projected) > 0 {
			output = append(output, projected)
		}
	}
	return output
}

func projectLinkAttributes(input map[string]any, maximum int) map[string]any {
	keys := sortedKeys(input)
	output := make(map[string]any, min(len(keys), maximum))
	for _, key := range keys {
		if len(output) >= maximum {
			break
		}
		if key == "defenseclaw.link.relation" || allowedAttribute(key) || safeEventAttribute(key) {
			output[key] = cloneJSON(input[key])
		}
	}
	return output
}

func projectStatus(value any, maximum int) map[string]any {
	status, ok := object(value)
	if !ok {
		return nil
	}
	output := make(map[string]any, 2)
	if code, ok := status["code"]; ok {
		output["code"] = cloneJSON(code)
	}
	if message, ok := boundedString(status["message"], maximum); ok {
		output["message"] = message
	}
	if description, ok := boundedString(status["description"], maximum); ok {
		output["description"] = description
	}
	return output
}

func requireNonEmptyString(attributes map[string]any, key string, missing *[]string) {
	if value, ok := stringAttribute(attributes, key); !ok || value == "" {
		*missing = append(*missing, key)
	}
}

func stringAttribute(attributes map[string]any, key string) (string, bool) {
	value, ok := attributes[key].(string)
	if !ok {
		return "", false
	}
	value = strings.TrimSpace(value)
	return value, value != ""
}

func boolAttribute(attributes map[string]any, key string) (bool, bool) {
	value, ok := attributes[key].(bool)
	return value, ok
}

func canonicalWorkflowName(attributes map[string]any) (string, bool) {
	value, ok := attributes["defenseclaw.workflow.name"].(string)
	if !ok || len(value) == 0 || len(value) > 128 {
		return "", false
	}
	for index := range len(value) {
		character := value[index]
		if index == 0 {
			if character < 'a' || character > 'z' {
				if character < '0' || character > '9' {
					return "", false
				}
			}
			continue
		}
		if (character < 'a' || character > 'z') &&
			(character < '0' || character > '9') &&
			character != '_' && character != '.' && character != '-' {
			return "", false
		}
	}
	return value, true
}

func boundedString(value any, maximum int) (string, bool) {
	text, ok := value.(string)
	return text, ok && utf8.ValidString(text) && len(text) <= maximum
}

func object(value any) (map[string]any, bool) {
	typed, ok := value.(map[string]any)
	return typed, ok
}

func cloneObject(input map[string]any) map[string]any {
	output := make(map[string]any, len(input))
	for key, value := range input {
		output[strings.Clone(key)] = cloneJSON(value)
	}
	return output
}

func cloneArray(input []any) []any {
	output := make([]any, len(input))
	for index, value := range input {
		output[index] = cloneJSON(value)
	}
	return output
}

func cloneJSON(value any) any {
	switch typed := value.(type) {
	case map[string]any:
		return cloneObject(typed)
	case []any:
		return cloneArray(typed)
	case string:
		return strings.Clone(typed)
	case json.Number:
		return json.Number(strings.Clone(typed.String()))
	default:
		return typed
	}
}

func sortedKeys(input map[string]any) []string {
	keys := make([]string, 0, len(input))
	for key := range input {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	return keys
}

func uniqueSorted(input []string) []string {
	set := make(map[string]struct{}, len(input))
	for _, value := range input {
		set[value] = struct{}{}
	}
	output := make([]string, 0, len(set))
	for value := range set {
		output = append(output, value)
	}
	sort.Strings(output)
	return output
}

func min(left, right int) int {
	if left < right {
		return left
	}
	return right
}
