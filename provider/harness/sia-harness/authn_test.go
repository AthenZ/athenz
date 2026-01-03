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

package sia

import (
	"crypto/rand"
	"crypto/rsa"
	"github.com/stretchr/testify/assert"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
)

func startHttpServer(token string, statusCode int) *httptest.Server {
	router := http.NewServeMux()
	router.HandleFunc("POST /oidc", func(w http.ResponseWriter, r *http.Request) {
		log.Println("/oidc token endpoint is called")
		w.WriteHeader(statusCode)
		io.WriteString(w, "{\"value\": \""+token+"\"}")
	})

	return httptest.NewServer(router)
}

func TestGetOIDCToken(t *testing.T) {

	validToken := "eyJraWQiOiJlY2tleTEiLCJhbGciOiJFUzI1NiJ9.eyJzdWIiOiJhY2NvdW50LzEyMzQ6b3JnL2F0aGVuem9yZzpwcm9qZWN0L2F0aGVuejpwaXBlbGluZS9qb2ItdXVpZCIsImF1ZCI6Imh0dHBzOi8vYXRoZW56LmlvIiwiYWNjb3VudF9pZCI6IjEyMzQiLCJwcm9qZWN0X2lkIjoiYXRoZW56Iiwib3JnYW5pemF0aW9uX2lkIjoiYXRoZW56b3JnIiwiY29udGV4dCI6InRyaWdnZXJUeXBlOm1hbnVhbC90cmlnZ2VyRXZlbnQ6bnVsbC9zZXF1ZW5jZUlkOjEiLCJpc3MiOiJodHRwczovL2F0aGVuei5oYXJuZXNzLmlvIiwicGlwZWxpbmVfaWQiOiJqb2ItdXVpZCIsImV4cCI6MTcyOTYyOTkwOCwiaWF0IjoxNzI5NjI2MzA4fQ.RLIzKol2GOfQXeCFrTyfLDgHXOGWXNvmS79VP6M2tC-XI-WNO_mh3uaytjWwWsLVTfBi7zB_n_UCsQXJOb58Sg"

	os.Setenv("HARNESS_OIDC_API_KEY", "api-token")

	os.Setenv("HARNESS_ACCOUNT_ID", "1234")
	os.Setenv("HARNESS_ORG_ID", "athenzorg")
	os.Setenv("HARNESS_PROJECT_ID", "athenz")
	os.Setenv("HARNESS_PIPELINE_ID", "job-uuid")
	os.Setenv("HARNESS_TRIGGER_TYPE", "manual")
	os.Setenv("HARNESS_SEQUENCE_ID", "1")

	ts := startHttpServer(validToken, http.StatusOK)
	defer ts.Close()

	_, claims, err := GetOIDCToken("https://athenz.io", ts.URL+"/oidc")
	assert.Nil(t, err)
	assert.Equal(t, "https://athenz.io", claims["aud"].(string))
	assert.Equal(t, "account/1234:org/athenzorg:project/athenz:pipeline/job-uuid", claims["sub"].(string))
	assert.Equal(t, "1234", claims["account_id"].(string))
	assert.Equal(t, "athenz", claims["project_id"].(string))
	assert.Equal(t, "athenzorg", claims["organization_id"].(string))
	assert.Equal(t, "job-uuid", claims["pipeline_id"].(string))
	assert.Equal(t, "triggerType:manual/triggerEvent:null/sequenceId:1", claims["context"].(string))

	os.Clearenv()
}

func TestGetOIDCTokenEnvNotSet(t *testing.T) {

	// both env variables missing - first check is for request url
	_, _, err := GetOIDCToken("https://athenz.io", "http://localhost:0/oidc")
	assert.NotNil(t, err)
	assert.Equal(t, "HARNESS_OIDC_API_KEY environment variable not set", err.Error())

	os.Clearenv()
}

func TestGetOIDCTokenInvalidStatusCode(t *testing.T) {

	os.Setenv("HARNESS_OIDC_API_KEY", "api-token")

	os.Setenv("HARNESS_ACCOUNT_ID", "acct1")
	os.Setenv("HARNESS_ORG_ID", "org2")
	os.Setenv("HARNESS_PROJECT_ID", "project3")
	os.Setenv("HARNESS_PIPELINE_ID", "pipeline4")
	os.Setenv("HARNESS_TRIGGER_TYPE", "MANUAL")
	os.Setenv("HARNESS_SEQUENCE_ID", "5")

	ts := startHttpServer("invalid-token", http.StatusBadRequest)
	defer ts.Close()

	_, _, err := GetOIDCToken("https://athenz.io", ts.URL+"/oidc")
	assert.NotNil(t, err)
	assert.Equal(t, "oidc token get status error: 400", err.Error())

	os.Clearenv()
}

func TestGetOIDCTokenInvalidToken(t *testing.T) {

	os.Setenv("HARNESS_OIDC_API_KEY", "api-token")

	os.Setenv("HARNESS_ACCOUNT_ID", "acct1")
	os.Setenv("HARNESS_ORG_ID", "org2")
	os.Setenv("HARNESS_PROJECT_ID", "project3")
	os.Setenv("HARNESS_PIPELINE_ID", "pipeline4")
	os.Setenv("HARNESS_TRIGGER_TYPE", "MANUAL")
	os.Setenv("HARNESS_SEQUENCE_ID", "5")

	ts := startHttpServer("invalid-token", http.StatusOK)
	defer ts.Close()

	_, _, err := GetOIDCToken("https://athenz.io", ts.URL+"/oidc")
	assert.NotNil(t, err)
	assert.Equal(t, "unable to parse oidc token: go-jose/go-jose: compact JWS format must have three parts", err.Error())

	os.Clearenv()
}

func TestGetCSRDetails(t *testing.T) {

	privateKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	csr, err := GetCSRDetails(privateKey, "sports", "api", "sys.auth.harness", "0001", "athenz.io", "athenz", "", "", "")
	assert.Nil(t, err)
	assert.True(t, csr != "")
}

func TestGetInstanceId(t *testing.T) {
	claims := map[string]interface{}{
		"organization_id": "org",
		"project_id":      "project",
		"pipeline_id":     "pipeline",
		"context":         "triggerType:manual/triggerEvent:trigger/sequenceId:1",
	}
	instanceId, err := GetInstanceId(claims)
	assert.Nil(t, err)
	assert.Equal(t, "org:project:pipeline:1", instanceId)
}

func TestGetInstanceIdMissingOrgId(t *testing.T) {
	claims := map[string]interface{}{
		"project_id":  "project",
		"pipeline_id": "pipeline",
		"context":     "triggerType:manual/triggerEvent:trigger/sequenceId:1",
	}
	_, err := GetInstanceId(claims)
	assert.NotNil(t, err)
	assert.Equal(t, "unable to extract organization_id from oidc token claims", err.Error())
}

func TestGetInstanceIdMissingProjectId(t *testing.T) {
	claims := map[string]interface{}{
		"organization_id": "org",
		"pipeline_id":     "pipeline",
		"context":         "triggerType:manual/triggerEvent:trigger/sequenceId:1",
	}
	_, err := GetInstanceId(claims)
	assert.NotNil(t, err)
	assert.Equal(t, "unable to extract project_id from oidc token claims", err.Error())
}

func TestGetInstanceIdMissingPipelineId(t *testing.T) {
	claims := map[string]interface{}{
		"organization_id": "org",
		"project_id":      "project",
		"context":         "triggerType:manual/triggerEvent:trigger/sequenceId:1",
	}
	_, err := GetInstanceId(claims)
	assert.NotNil(t, err)
	assert.Equal(t, "unable to extract pipeline_id from oidc token claims", err.Error())
}

func TestGetInstanceIdMissingContext(t *testing.T) {
	claims := map[string]interface{}{
		"organization_id": "org",
		"project_id":      "project",
		"pipeline_id":     "pipeline",
	}
	_, err := GetInstanceId(claims)
	assert.NotNil(t, err)
	assert.Equal(t, "unable to extract context from oidc token claims", err.Error())
}

func TestGetInstanceIdMissingOrg(t *testing.T) {
	claims := map[string]interface{}{
		"organization_id": "org",
		"project_id":      "project",
		"pipeline_id":     "pipeline",
		"context":         "triggerType:manual",
	}
	_, err := GetInstanceId(claims)
	assert.NotNil(t, err)
	assert.Equal(t, "unable to extract sequenceId from context: triggerType:manual", err.Error())
}

func TestExtractFieldFromContext(test *testing.T) {

	tests := []struct {
		name    string
		context string
		field   string
		value   string
	}{
		{"last-component", "triggerType:manual/triggerEvent:trigger/sequenceId:1", "sequenceId", "1"},
		{"mid-component", "triggerType:manual/triggerEvent:trigger/sequenceId:1", "triggerEvent", "trigger"},
		{"component-not-present", "triggerType:webhook/triggerEvent:pr/sequenceId:1", "accountId", ""},
	}
	for _, tt := range tests {
		test.Run(tt.name, func(t *testing.T) {
			result := extractFieldFromContext(tt.context, tt.field)
			if result != tt.value {
				t.Errorf("extractFieldFromContext returned invalid value: %s", result)
			}
		})
	}
}

func TestGeneratePolicyAction(test *testing.T) {

	tests := []struct {
		name    string
		context string
		action  string
	}{
		{"event-null", "triggerType:manual/triggerEvent:null/sequenceId:1", "harness.manual"},
		{"event-not-present", "triggerType:manual/sequenceId:1", "harness.manual"},
		{"event-present", "triggerType:webhook/triggerEvent:pr/sequenceId:1", "harness.webhook.pr"},
	}
	for _, tt := range tests {
		test.Run(tt.name, func(t *testing.T) {
			claims := map[string]interface{}{
				"context": tt.context,
			}
			result := GeneratePolicyAction(claims)
			if result != tt.action {
				t.Errorf("GeneratePolicyAction returned invalid action: %s", result)
			}
		})
	}
}
