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
	"github.com/gorilla/mux"
	"github.com/stretchr/testify/assert"
	"io"
	"log"
	"net/http"
	"os"
	"testing"
	"time"
)

func startHttpServer(uri, token string, statusCode int) {
	router := mux.NewRouter()
	router.HandleFunc("/oidc", func(w http.ResponseWriter, r *http.Request) {
		log.Println("/oidc token endpoint is called")
		w.WriteHeader(statusCode)
		io.WriteString(w, "{\"data\": \""+token+"\"}")
	}).Methods("POST")

	err := http.ListenAndServe(uri, router)
	if err != nil {
		log.Fatal("ListenAndServe: ", err)
	}
}

func TestGetOIDCToken(t *testing.T) {

	validToken := "eyJraWQiOiJlY2tleTEiLCJhbGciOiJFUzI1NiJ9.eyJhdWQiOiJodHRwczovL2F0aGVuei5pbyIsInN1YiI6ImFjY291bnQvMTIzNDpvcmcvYXRoZW56b3JnOnByb2plY3QvYXRoZW56OnBpcGVsaW5lL2pvYi11dWlkIiwiYWNjb3VudF9pZCI6IjEyMzQiLCJwcm9qZWN0X2lkIjoiYXRoZW56Iiwib3JnYW5pemF0aW9uX2lkIjoiYXRoZW56b3JnIiwiY29udGV4dCI6InRyaWdnZXJUeXBlOm1hbnVhbC90cmlnZ2VySWQ6bnVsbC9zZXF1ZW5jZUlkOjEiLCJwaXBlbGluZV9pZCI6ImpvYi11dWlkIiwiaXNzIjoiaHR0cHM6Ly9hdGhlbnouaGFybmVzcy5pbyIsImV4cCI6MTcyOTM5NjIzNiwiaWF0IjoxNzI5MzkyNjM2fQ.20W0hqjYvaQgJU-SMICE35WiAJx6J1K3iOrusrqsD6Y8TK-ODjw6XayMSRGzeY56SOcdmP8Zhe_LfYaZzg58Fw"
	os.Setenv("OIDC_SA_TOKEN_SECRET_PATH", "api-token")

	os.Setenv("HARNESS_ACCOUNT_ID", "1234")
	os.Setenv("HARNESS_ORG_ID", "athenzorg")
	os.Setenv("HARNESS_PROJECT_ID", "athenz")
	os.Setenv("HARNESS_PIPELINE_ID", "job-uuid")
	os.Setenv("HARNESS_TRIGGER_TYPE", "manual")
	os.Setenv("HARNESS_SEQUENCE_ID", "1")

	go startHttpServer("localhost:8081", validToken, http.StatusOK)
	time.Sleep(2 * time.Second)

	_, claims, err := GetOIDCToken("https://athenz.io", "http://localhost:8081/oidc")
	assert.Nil(t, err)
	assert.Equal(t, "https://athenz.io", claims["aud"].(string))
	assert.Equal(t, "account/1234:org/athenzorg:project/athenz:pipeline/job-uuid", claims["sub"].(string))
	assert.Equal(t, "1234", claims["account_id"].(string))
	assert.Equal(t, "athenz", claims["project_id"].(string))
	assert.Equal(t, "athenzorg", claims["organization_id"].(string))
	assert.Equal(t, "job-uuid", claims["pipeline_id"].(string))
	assert.Equal(t, "triggerType:manual/triggerId:null/sequenceId:1", claims["context"].(string))

	os.Clearenv()
}

func TestGetOIDCTokenEnvNotSet(t *testing.T) {

	// both env variables missing - first check is for request url
	_, _, err := GetOIDCToken("https://athenz.io", "http://localhost:8081/oidc")
	assert.NotNil(t, err)
	assert.Equal(t, "OIDC_SA_TOKEN_SECRET_PATH environment variable not set", err.Error())

	os.Clearenv()
}

func TestGetOIDCTokenInvalidStatusCode(t *testing.T) {

	os.Setenv("OIDC_SA_TOKEN_SECRET_PATH", "api-token")

	os.Setenv("HARNESS_ACCOUNT_ID", "acct1")
	os.Setenv("HARNESS_ORG_ID", "org2")
	os.Setenv("HARNESS_PROJECT_ID", "project3")
	os.Setenv("HARNESS_PIPELINE_ID", "pipeline4")
	os.Setenv("HARNESS_TRIGGER_TYPE", "MANUAL")
	os.Setenv("HARNESS_SEQUENCE_ID", "5")

	go startHttpServer("localhost:8082", "invalid-token", http.StatusBadRequest)
	time.Sleep(2 * time.Second)

	_, _, err := GetOIDCToken("https://athenz.io", "http://localhost:8082/oidc")
	assert.NotNil(t, err)
	assert.Equal(t, "oidc token get status error: 400", err.Error())

	os.Clearenv()
}

func TestGetOIDCTokenInvalidToken(t *testing.T) {

	os.Setenv("OIDC_SA_TOKEN_SECRET_PATH", "api-token")

	os.Setenv("HARNESS_ACCOUNT_ID", "acct1")
	os.Setenv("HARNESS_ORG_ID", "org2")
	os.Setenv("HARNESS_PROJECT_ID", "project3")
	os.Setenv("HARNESS_PIPELINE_ID", "pipeline4")
	os.Setenv("HARNESS_TRIGGER_TYPE", "MANUAL")
	os.Setenv("HARNESS_SEQUENCE_ID", "5")

	go startHttpServer("localhost:8083", "invalid-token", http.StatusOK)
	time.Sleep(2 * time.Second)

	_, _, err := GetOIDCToken("https://athenz.io", "http://localhost:8083/oidc")
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
