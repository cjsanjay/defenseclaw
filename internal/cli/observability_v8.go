// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/observability/destinationtest"
)

const destinationTestComplianceTimeout = 5 * time.Second

var (
	observabilityV8ConfigPath string
	observabilityV8DataDir    string
)

var observabilityV8Cmd = &cobra.Command{
	Use:    "observability-v8",
	Short:  "Internal observability-v8 operations",
	Hidden: true,
	PersistentPreRunE: func(_ *cobra.Command, _ []string) error {
		return nil
	},
	PersistentPostRun: func(_ *cobra.Command, _ []string) {},
}

var observabilityV8RecordDestinationTestCmd = &cobra.Command{
	Use:    "record-destination-test-activity",
	Short:  "Persist one content-free local destination-test activity",
	Hidden: true,
	Args:   cobra.NoArgs,
	RunE: func(cmd *cobra.Command, _ []string) error {
		if err := recordDestinationTestActivity(
			cmd.Context(), cmd.InOrStdin(), observabilityV8ConfigPath, observabilityV8DataDir,
		); err != nil {
			return err
		}
		encoder := json.NewEncoder(cmd.OutOrStdout())
		encoder.SetEscapeHTML(false)
		return encoder.Encode(map[string]bool{"recorded": true})
	},
}

func init() {
	observabilityV8Cmd.PersistentFlags().StringVar(
		&observabilityV8ConfigPath,
		"config",
		"",
		"configuration file (default: DEFENSECLAW_CONFIG or <data-dir>/config.yaml)",
	)
	observabilityV8Cmd.PersistentFlags().StringVar(
		&observabilityV8DataDir,
		"data-dir",
		"",
		"default data directory when data_dir is omitted from the source",
	)
	observabilityV8Cmd.AddCommand(observabilityV8RecordDestinationTestCmd)
	rootCmd.AddCommand(observabilityV8Cmd)
}

type destinationTestGatewayAccess struct {
	port  int
	token string
}

func recordDestinationTestActivity(
	ctx context.Context,
	input io.Reader,
	configPath string,
	dataDir string,
) error {
	if ctx == nil || input == nil {
		return errors.New("destination-test compliance recorder is unavailable")
	}
	activity, err := decodeDestinationTestActivity(input)
	if err != nil {
		return err
	}
	loaded, err := loadConfigV8File(configPath, dataDir)
	if err != nil {
		return errors.New("destination-test compliance configuration is invalid")
	}
	access, err := destinationTestAccess(loaded)
	if err != nil {
		return err
	}
	payload, err := json.Marshal(activity)
	if err != nil {
		return errors.New("destination-test compliance activity is invalid")
	}
	address := net.JoinHostPort("127.0.0.1", strconv.Itoa(access.port))
	requestURL := (&url.URL{Scheme: "http", Host: address, Path: destinationtest.EndpointPath}).String()
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, requestURL, bytes.NewReader(payload))
	if err != nil {
		return errors.New("destination-test compliance recorder is unavailable")
	}
	request.Header.Set("Authorization", "Bearer "+access.token)
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("X-DefenseClaw-Client", "python-cli")

	dialer := &net.Dialer{Timeout: destinationTestComplianceTimeout}
	client := &http.Client{
		Timeout: destinationTestComplianceTimeout,
		Transport: &http.Transport{
			Proxy:               nil,
			DialContext:         dialer.DialContext,
			DisableCompression:  true,
			ForceAttemptHTTP2:   false,
			MaxIdleConns:        1,
			MaxIdleConnsPerHost: 1,
			IdleConnTimeout:     time.Second,
		},
		CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	response, err := client.Do(request)
	if err != nil {
		return errors.New("destination-test compliance recorder is unavailable")
	}
	defer response.Body.Close()
	_, _ = io.Copy(io.Discard, io.LimitReader(response.Body, 1024))
	if response.StatusCode != http.StatusNoContent {
		return errors.New("destination-test compliance recorder rejected the activity")
	}
	return nil
}

func decodeDestinationTestActivity(input io.Reader) (destinationtest.Activity, error) {
	raw, err := io.ReadAll(io.LimitReader(input, destinationtest.MaxEncodedBytes+1))
	if err != nil || len(raw) == 0 || len(raw) > destinationtest.MaxEncodedBytes {
		return destinationtest.Activity{}, errors.New("destination-test compliance activity is invalid")
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	var activity destinationtest.Activity
	if err := decoder.Decode(&activity); err != nil {
		return destinationtest.Activity{}, errors.New("destination-test compliance activity is invalid")
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return destinationtest.Activity{}, errors.New("destination-test compliance activity is invalid")
	}
	if err := activity.Validate(); err != nil {
		return destinationtest.Activity{}, errors.New("destination-test compliance activity is invalid")
	}
	return activity, nil
}

func destinationTestAccess(loaded *loadedConfigV8File) (destinationTestGatewayAccess, error) {
	if loaded == nil || loaded.document == nil || loaded.gatewayAPIPort < 1 || loaded.gatewayAPIPort > 65535 {
		return destinationTestGatewayAccess{}, errors.New("destination-test compliance configuration is invalid")
	}
	gateway := config.GatewayConfig{}
	if source, ok := loaded.document.Plain["gateway"].(map[string]any); ok {
		if value, present := source["token"]; present {
			text, typed := value.(string)
			if !typed {
				return destinationTestGatewayAccess{}, errors.New("destination-test compliance configuration is invalid")
			}
			gateway.Token = text
		}
		if value, present := source["token_env"]; present {
			text, typed := value.(string)
			if !typed {
				return destinationTestGatewayAccess{}, errors.New("destination-test compliance configuration is invalid")
			}
			gateway.TokenEnv = text
		}
	}
	token := strings.TrimSpace(gateway.ResolvedToken())
	if token == "" {
		return destinationTestGatewayAccess{}, errors.New(
			"destination-test compliance authentication is unavailable; set DEFENSECLAW_GATEWAY_TOKEN or run defenseclaw setup gateway",
		)
	}
	return destinationTestGatewayAccess{port: loaded.gatewayAPIPort, token: token}, nil
}
