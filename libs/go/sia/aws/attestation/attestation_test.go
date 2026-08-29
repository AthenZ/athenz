//
// Copyright The Athenz Authors
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

package attestation

import (
	"encoding/json"
	"fmt"
	"os"
	"testing"

	"github.com/AthenZ/athenz/libs/go/sia/aws/stssession"
	"github.com/aws/aws-sdk-go-v2/service/sts/types"
)

func TestGetECSTaskId(test *testing.T) {
	os.Setenv("ECS_CONTAINER_METADATA_FILE", "data/task.json")
	taskId := GetECSTaskId()
	if taskId != "776b2c2e-6bfb-4328-bd04-204536cfb7f2" {
		test.Errorf("Unable to extract task id")
		return
	}
	os.Setenv("ECS_CONTAINER_METADATA_FILE", "data/task-new-arn.json")
	taskId = GetECSTaskId()
	if taskId != "776b2c2e-6bfb-4328-bd04-204536cfb7f2" {
		test.Errorf("Unable to extract task id")
		return
	}
	//invalid file
	os.Setenv("ECS_CONTAINER_METADATA_FILE", "data/nonexistent-task.json")
	taskId = GetECSTaskId()
	if taskId != "" {
		test.Errorf("Invalid file returned valid task id: %s", taskId)
		return
	}
}

// TestNewWebIdentity_StructHasIdentityToken verifies that NewWebIdentity populates
// identityToken and omits access/secret/token.
func TestNewWebIdentity_StructHasIdentityToken(t *testing.T) {
	orig := stssession.WebIdentityTokenFetcher
	defer func() { stssession.WebIdentityTokenFetcher = orig }()

	const fakeJWT = "header.payload.signature"
	stssession.WebIdentityTokenFetcher = func(_ bool, _, _, _ string, _ int32, _ []types.Tag) (string, error) {
		return fakeJWT, nil
	}

	jsonStr, err := NewWebIdentity("domain", "service", "us-east-1",
		"https://zts.example.com", "ES384", false, false, 300, nil, "", "")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	var data AttestationData
	if err := json.Unmarshal([]byte(jsonStr), &data); err != nil {
		t.Fatalf("unmarshal failed: %v", err)
	}

	if data.IdentityToken != fakeJWT {
		t.Errorf("expected identityToken %q, got %q", fakeJWT, data.IdentityToken)
	}
	// JWT-only: STS credentials must be absent
	if data.Access != "" {
		t.Errorf("expected no Access field in JWT-only mode, got %q", data.Access)
	}
	if data.Secret != "" {
		t.Errorf("expected no Secret field in JWT-only mode, got %q", data.Secret)
	}
	if data.Token != "" {
		t.Errorf("expected no Token field in JWT-only mode, got %q", data.Token)
	}
	if data.Role != "domain.service" {
		t.Errorf("expected Role 'domain.service', got %q", data.Role)
	}
	if data.CommonName != "domain.service" {
		t.Errorf("expected CommonName 'domain.service', got %q", data.CommonName)
	}
}

// TestNewWebIdentity_OmitDomain verifies role is just the service name when omitDomain=true.
func TestNewWebIdentity_OmitDomain(t *testing.T) {
	orig := stssession.WebIdentityTokenFetcher
	defer func() { stssession.WebIdentityTokenFetcher = orig }()

	stssession.WebIdentityTokenFetcher = func(_ bool, _, _, _ string, _ int32, _ []types.Tag) (string, error) {
		return "tok", nil
	}

	jsonStr, err := NewWebIdentity("domain", "svc", "us-east-1",
		"https://zts.example.com", "ES384", false, true /*omitDomain*/, 300, nil, "", "")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	var data AttestationData
	if err := json.Unmarshal([]byte(jsonStr), &data); err != nil {
		t.Fatalf("unmarshal failed: %v", err)
	}
	if data.Role != "svc" {
		t.Errorf("expected Role 'svc' (omitDomain), got %q", data.Role)
	}
}

// TestNewWebIdentity_PassesAudienceToFetcher verifies audience, algorithm, duration, and useRegionalSTS are forwarded.
func TestNewWebIdentity_PassesAudienceToFetcher(t *testing.T) {
	orig := stssession.WebIdentityTokenFetcher
	defer func() { stssession.WebIdentityTokenFetcher = orig }()

	var capturedRegionalSTS bool
	var capturedAudience, capturedAlgorithm string
	var capturedDuration int32
	stssession.WebIdentityTokenFetcher = func(useRegionalSTS bool, _, audience, algorithm string, duration int32, _ []types.Tag) (string, error) {
		capturedRegionalSTS = useRegionalSTS
		capturedAudience = audience
		capturedAlgorithm = algorithm
		capturedDuration = duration
		return "tok", nil
	}

	_, err := NewWebIdentity("d", "s", "us-east-1",
		"https://zts.custom.com", "ES384", true /*useRegionalSTS*/, false, 300, nil, "", "")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !capturedRegionalSTS {
		t.Error("expected useRegionalSTS=true to be forwarded to fetcher")
	}
	if capturedAudience != "https://zts.custom.com" {
		t.Errorf("expected audience 'https://zts.custom.com', got %q", capturedAudience)
	}
	if capturedAlgorithm != "ES384" {
		t.Errorf("expected algorithm 'ES384', got %q", capturedAlgorithm)
	}
	if capturedDuration != 300 {
		t.Errorf("expected duration 300, got %d", capturedDuration)
	}
}

// TestNewWebIdentity_FetchError propagates the token fetch error.
func TestNewWebIdentity_FetchError(t *testing.T) {
	orig := stssession.WebIdentityTokenFetcher
	defer func() { stssession.WebIdentityTokenFetcher = orig }()

	stssession.WebIdentityTokenFetcher = func(_ bool, _, _, _ string, _ int32, _ []types.Tag) (string, error) {
		return "", fmt.Errorf("sts failure")
	}

	_, err := NewWebIdentity("d", "s", "us-east-1",
		"https://zts.example.com", "ES384", false, false, 300, nil, "", "")
	if err == nil {
		t.Fatal("expected error, got nil")
	}
}

// TestAttestationData_IdentityTokenOmittedWhenEmpty checks that identityToken is
// omitted from JSON when not set (omitempty).
func TestAttestationData_IdentityTokenOmittedWhenEmpty(t *testing.T) {
	data := AttestationData{
		Role:       "my.service",
		CommonName: "my.service",
		Access:     "AKID",
		Secret:     "secret",
		Token:      "session",
	}
	b, err := json.Marshal(data)
	if err != nil {
		t.Fatalf("marshal failed: %v", err)
	}
	var m map[string]interface{}
	if err := json.Unmarshal(b, &m); err != nil {
		t.Fatalf("unmarshal failed: %v", err)
	}
	if _, ok := m["identityToken"]; ok {
		t.Error("identityToken should be omitted from JSON when empty")
	}
}
