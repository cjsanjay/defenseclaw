// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/observability/destinationtest"
)

func TestRecordDestinationTestActivityUsesAuthenticatedLoopbackOnly(t *testing.T) {
	t.Setenv("DEFENSECLAW_GATEWAY_TOKEN", "")
	t.Setenv("OPENCLAW_GATEWAY_TOKEN", "")
	t.Setenv("HTTP_PROXY", "http://127.0.0.1:1")
	t.Setenv("HTTPS_PROXY", "http://127.0.0.1:1")
	const token = "gateway-token-must-not-appear"
	want := destinationtest.Activity{
		Phase: "outcome", Destination: "soc", ProbeID: "probe-1",
		Mode: "handshake", Result: "failed", FailureClass: "timeout",
	}
	received := make(chan destinationtest.Activity, 1)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
		if request.URL.Path != destinationtest.EndpointPath || request.Method != http.MethodPost {
			t.Errorf("request = %s %s", request.Method, request.URL.Path)
			http.NotFound(w, request)
			return
		}
		if request.Header.Get("Authorization") != "Bearer "+token ||
			request.Header.Get("X-DefenseClaw-Client") != "python-cli" ||
			request.Header.Get("Content-Type") != "application/json" {
			t.Errorf("unexpected authenticated request headers")
			http.Error(w, "rejected", http.StatusForbidden)
			return
		}
		var activity destinationtest.Activity
		if err := json.NewDecoder(request.Body).Decode(&activity); err != nil {
			t.Errorf("decode activity: %v", err)
			http.Error(w, "rejected", http.StatusBadRequest)
			return
		}
		received <- activity
		w.WriteHeader(http.StatusNoContent)
	}))
	defer server.Close()

	parsed, err := url.Parse(server.URL)
	if err != nil {
		t.Fatal(err)
	}
	port, err := strconv.Atoi(parsed.Port())
	if err != nil {
		t.Fatal(err)
	}
	directory := t.TempDir()
	path := filepath.Join(directory, "config.yaml")
	source := fmt.Sprintf("config_version: 8\ndata_dir: %s\ngateway:\n  api_port: %d\n  token: %s\nobservability: {}\n", directory, port, token)
	if err := os.WriteFile(path, []byte(source), 0o600); err != nil {
		t.Fatal(err)
	}
	payload, err := json.Marshal(want)
	if err != nil {
		t.Fatal(err)
	}
	if err := recordDestinationTestActivity(t.Context(), bytes.NewReader(payload), path, directory); err != nil {
		t.Fatal(err)
	}
	if got := <-received; got != want {
		t.Fatalf("activity = %+v, want %+v", got, want)
	}
}

func TestRecordDestinationTestActivityBoundsRemoteFailure(t *testing.T) {
	t.Setenv("DEFENSECLAW_GATEWAY_TOKEN", "")
	t.Setenv("OPENCLAW_GATEWAY_TOKEN", "")
	const secret = "server-response-secret"
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, secret, http.StatusInternalServerError)
	}))
	defer server.Close()
	parsed, err := url.Parse(server.URL)
	if err != nil {
		t.Fatal(err)
	}
	directory := t.TempDir()
	path := filepath.Join(directory, "config.yaml")
	source := fmt.Sprintf("config_version: 8\ndata_dir: %s\ngateway:\n  api_port: %s\n  token: local-token\nobservability: {}\n", directory, parsed.Port())
	if err := os.WriteFile(path, []byte(source), 0o600); err != nil {
		t.Fatal(err)
	}
	activity := `{"phase":"attempt","destination":"soc","probe_id":"probe-1","mode":"handshake","result":"attempted"}`
	err = recordDestinationTestActivity(t.Context(), strings.NewReader(activity), path, directory)
	if err == nil || strings.Contains(err.Error(), secret) || strings.Contains(err.Error(), "local-token") {
		t.Fatalf("bounded error = %v", err)
	}
}

func TestDecodeDestinationTestActivityFailsClosed(t *testing.T) {
	valid := `{"phase":"attempt","destination":"soc","probe_id":"probe-1","mode":"handshake","result":"attempted"}`
	if _, err := decodeDestinationTestActivity(strings.NewReader(valid)); err != nil {
		t.Fatal(err)
	}
	invalid := []string{
		``,
		`{}`,
		valid + valid,
		`{"phase":"attempt","destination":"soc","probe_id":"probe-1","mode":"handshake","result":"attempted","secret":"x"}`,
		strings.Repeat(" ", destinationtest.MaxEncodedBytes+1),
	}
	for _, payload := range invalid {
		if _, err := decodeDestinationTestActivity(strings.NewReader(payload)); err == nil {
			t.Fatalf("invalid activity accepted (bytes=%d)", len(payload))
		}
	}
}
