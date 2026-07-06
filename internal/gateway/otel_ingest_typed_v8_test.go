// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"reflect"
	"testing"

	commonpb "go.opentelemetry.io/proto/otlp/common/v1"
)

func otlpStringAttribute(key, value string) *commonpb.KeyValue {
	return &commonpb.KeyValue{Key: key, Value: &commonpb.AnyValue{
		Value: &commonpb.AnyValue_StringValue{StringValue: value},
	}}
}

func TestOTLPTypedAttributeIndexRejectsDuplicatesWithoutCoercion(t *testing.T) {
	index := newOTLPTypedAttributeIndex([]*commonpb.KeyValue{
		otlpStringAttribute("event.name", "first"),
		otlpStringAttribute("event.name", "first"),
		otlpStringAttribute("Event.Name", "case-sensitive"),
		otlpStringAttribute("token.count", "17"),
		{Key: "actual.count", Value: &commonpb.AnyValue{Value: &commonpb.AnyValue_IntValue{IntValue: 17}}},
		{Key: "ratio", Value: &commonpb.AnyValue{Value: &commonpb.AnyValue_DoubleValue{DoubleValue: 0.5}}},
		{Key: "enabled", Value: &commonpb.AnyValue{Value: &commonpb.AnyValue_BoolValue{BoolValue: true}}},
	})

	if value, state := index.stringValue("event.name"); value != "" || state != otlpTypedAttributeDuplicate {
		t.Fatalf("duplicate string value=%q state=%d", value, state)
	}
	if value, state := index.stringValue("Event.Name"); value != "case-sensitive" || state != otlpTypedAttributeUnique {
		t.Fatalf("exact string value=%q state=%d", value, state)
	}
	if value, state := index.int64Value("token.count"); value != 0 || state != otlpTypedAttributeInvalid {
		t.Fatalf("string-to-int coercion value=%d state=%d", value, state)
	}
	if value, state := index.int64Value("actual.count"); value != 17 || state != otlpTypedAttributeUnique {
		t.Fatalf("int value=%d state=%d", value, state)
	}
	if value, state := index.doubleValue("ratio"); value != 0.5 || state != otlpTypedAttributeUnique {
		t.Fatalf("double value=%v state=%d", value, state)
	}
	if value, state := index.boolValue("enabled"); !value || state != otlpTypedAttributeUnique {
		t.Fatalf("bool value=%t state=%d", value, state)
	}
	if _, state := index.lookup("missing"); state != otlpTypedAttributeAbsent {
		t.Fatalf("missing state=%d", state)
	}
	wantKeys := []string{"Event.Name", "actual.count", "enabled", "event.name", "ratio", "token.count"}
	if keys := index.keys(); !reflect.DeepEqual(keys, wantKeys) {
		t.Fatalf("keys=%v want=%v", keys, wantKeys)
	}
}

func TestOTLPTypedAttributeIndexRetainsMalformedAndNestedStates(t *testing.T) {
	index := newOTLPTypedAttributeIndex([]*commonpb.KeyValue{
		nil,
		otlpStringAttribute("", "empty-key"),
		{Key: "malformed", Value: nil},
		otlpStringAttribute("malformed", "second-value"),
		{Key: "empty-oneof", Value: &commonpb.AnyValue{}},
		{Key: "array", Value: &commonpb.AnyValue{Value: &commonpb.AnyValue_ArrayValue{
			ArrayValue: &commonpb.ArrayValue{Values: []*commonpb.AnyValue{{
				Value: &commonpb.AnyValue_StringValue{StringValue: "content"},
			}}},
		}}},
		{Key: "object", Value: &commonpb.AnyValue{Value: &commonpb.AnyValue_KvlistValue{
			KvlistValue: &commonpb.KeyValueList{Values: []*commonpb.KeyValue{
				otlpStringAttribute("nested", "value"),
			}},
		}}},
		{Key: "bytes", Value: &commonpb.AnyValue{Value: &commonpb.AnyValue_BytesValue{BytesValue: []byte("raw")}}},
	})

	if index.invalidCount() != 4 {
		t.Fatalf("invalid count=%d want=4", index.invalidCount())
	}
	if _, state := index.lookup("malformed"); state != otlpTypedAttributeDuplicate {
		t.Fatalf("malformed duplicate state=%d", state)
	}
	if _, state := index.lookup("empty-oneof"); state != otlpTypedAttributeInvalid {
		t.Fatalf("empty oneof state=%d", state)
	}
	for key, kind := range map[string]otlpTypedAnyValueKind{
		"array": otlpTypedAnyValueArray, "object": otlpTypedAnyValueKeyValueList,
		"bytes": otlpTypedAnyValueBytes,
	} {
		value, state := index.lookup(key)
		if state != otlpTypedAttributeUnique || otlpTypedValueKind(value) != kind {
			t.Fatalf("key=%s state=%d kind=%d want=%d", key, state, otlpTypedValueKind(value), kind)
		}
		if _, state := index.stringValue(key); state != otlpTypedAttributeInvalid {
			t.Fatalf("nested/bytes key=%s was flattened to string", key)
		}
	}
}
