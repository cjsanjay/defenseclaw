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
	"go/ast"
	"go/parser"
	"go/token"
	"path/filepath"
	"reflect"
	"runtime"
	"sort"
	"strings"
	"testing"
)

func TestFamilyBuilderPublicInputsDoNotExposeCatalogAuthority(t *testing.T) {
	for name, typ := range map[string]reflect.Type{
		"FamilyEnvelopeInput":   reflect.TypeOf(FamilyEnvelopeInput{}),
		"FamilyProvenanceInput": reflect.TypeOf(FamilyProvenanceInput{}),
		"TraceResourceInput":    reflect.TypeOf(TraceResourceInput{}),
		"TraceScopeInput":       reflect.TypeOf(TraceScopeInput{}),
		"TraceEventInput":       reflect.TypeOf(TraceEventInput{}),
		"TraceLinkInput":        reflect.TypeOf(TraceLinkInput{}),
		"TraceStatusInput":      reflect.TypeOf(TraceStatusInput{}),
	} {
		t.Run(name, func(t *testing.T) {
			for index := 0; index < typ.NumField(); index++ {
				field := typ.Field(index)
				if field.PkgPath != "" { // Package-private generated bindings are trusted.
					continue
				}
				switch field.Name {
				case "Bucket", "Signal", "Identity", "EventName", "Family", "FamilyID",
					"FamilySchemaVersion", "RegistrySchemaVersion", "SpanName",
					"Instrument", "InstrumentName", "InstrumentType", "Unit", "Temporality",
					"FieldClasses", "Mandatory", "FloorOnly":
					t.Fatalf("%s exposes catalog-owned field %s", name, field.Name)
				}
				if field.Type == reflect.TypeOf(EventIdentity{}) || field.Type == reflect.TypeOf(FieldClass("")) {
					t.Fatalf("%s exposes catalog-owned type through %s", name, field.Name)
				}
				if field.Type.Kind() == reflect.Map {
					t.Fatalf("%s exposes free-form map through %s", name, field.Name)
				}
			}
		})
	}
}

func TestFamilyBuilderHasNoGenericExportedBuildEscapeHatch(t *testing.T) {
	typeOfBuilder := reflect.TypeOf(&FamilyBuilder{})
	var exported []string
	for index := 0; index < typeOfBuilder.NumMethod(); index++ {
		exported = append(exported, typeOfBuilder.Method(index).Name)
	}
	if len(exported) != 0 {
		sort.Strings(exported)
		t.Fatalf("FamilyBuilder exports generic construction methods: %v", exported)
	}
}

func TestSchemaDerivedConstructorsAreTerminatedByFamilyBuilder(t *testing.T) {
	packageDir := observabilityPackageDir(t)
	files, err := filepath.Glob(filepath.Join(packageDir, "*.go"))
	if err != nil {
		t.Fatal(err)
	}
	var unauthorized []string
	for _, filename := range files {
		if strings.HasSuffix(filename, "_test.go") {
			continue
		}
		fileSet := token.NewFileSet()
		parsed, err := parser.ParseFile(fileSet, filename, nil, 0)
		if err != nil {
			t.Fatalf("parse %s: %v", filename, err)
		}
		ast.Inspect(parsed, func(node ast.Node) bool {
			call, ok := node.(*ast.CallExpr)
			if !ok {
				return true
			}
			identifier, ok := call.Fun.(*ast.Ident)
			if !ok || (identifier.Name != "newSchemaDerivedRecord" && identifier.Name != "newSchemaDerivedLogRecord") {
				return true
			}
			if filepath.Base(filename) != "family_builder.go" {
				position := fileSet.Position(call.Pos())
				unauthorized = append(unauthorized, filepath.Base(filename)+":"+position.String())
			}
			return true
		})
	}
	if len(unauthorized) != 0 {
		sort.Strings(unauthorized)
		t.Fatalf("schema-derived constructors bypass the family kernel: %v", unauthorized)
	}
}

func TestSchemaDerivedLogConstructorRequiresPrivateFamilyContract(t *testing.T) {
	packageDir := observabilityPackageDir(t)
	parsed, err := parser.ParseFile(token.NewFileSet(), filepath.Join(packageDir, "record.go"), nil, 0)
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, declaration := range parsed.Decls {
		function, ok := declaration.(*ast.FuncDecl)
		if !ok || function.Name.Name != "newSchemaDerivedLogRecord" {
			continue
		}
		found = true
		if function.Type.Params == nil || len(function.Type.Params.List) != 2 {
			t.Fatalf("newSchemaDerivedLogRecord parameters changed")
		}
		contractType, ok := function.Type.Params.List[1].Type.(*ast.Ident)
		if !ok || contractType.Name != "schemaDerivedLogFamilyContract" {
			t.Fatalf("newSchemaDerivedLogRecord no longer requires the private family contract")
		}
	}
	if !found {
		t.Fatal("newSchemaDerivedLogRecord declaration not found")
	}
}

func observabilityPackageDir(t *testing.T) string {
	t.Helper()
	_, filename, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("resolve observability package directory")
	}
	return filepath.Dir(filename)
}
