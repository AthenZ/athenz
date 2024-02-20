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
		io.WriteString(w, "{\"value\": \""+token+"\"}")
	}).Methods("GET")

	err := http.ListenAndServe(uri, router)
	if err != nil {
		log.Fatal("ListenAndServe: ", err)
	}
}

func TestGetOIDCToken(t *testing.T) {

	validToken := "eyJraWQiOiIwIiwiYWxnIjoiRVMyNTYifQ.eyJleHAiOjE3MDgwMjc4MTcsImlzcyI6Imh0dHBzOi8vdG9rZW4uYWN0aW9ucy5naXRodWJ1c2VyY29udGVudC5jb20iLCJhdWQiOiJodHRwczovL2F0aGVuei5pbyIsInJ1bl9pZCI6IjAwMDEiLCJlbnRlcnByaXNlIjoiYXRoZW56Iiwic3ViIjoicmVwbzphdGhlbnovc2lhOnJlZjpyZWZzL2hlYWRzL21haW4iLCJldmVudF9uYW1lIjoicHVzaCIsImlhdCI6MTcwODAyNDIxN30.ykt6O1mIjIjalTrmaU9AuSSsQghZ7Mx61gDsjVPHV0-SCqYpZNy7RtEbvgjKVCZ0kJ6BijH3aEf3EGArLHjTOQ"
	os.Setenv("ACTIONS_ID_TOKEN_REQUEST_URL", "http://localhost:8081/oidc?type=jwt")
	os.Setenv("ACTIONS_ID_TOKEN_REQUEST_TOKEN", "test-token")

	go startHttpServer("localhost:8081", validToken, http.StatusOK)
	time.Sleep(2 * time.Second)

	_, claims, err := GetOIDCToken("https://athenz.io")
	assert.Nil(t, err)
	assert.Equal(t, "0001", claims["run_id"].(string))
	assert.Equal(t, "athenz", claims["enterprise"].(string))

	os.Clearenv()
}

func TestGetOIDCTokenEnvNotSet(t *testing.T) {

	// both env variables missing - first check is for request url
	_, _, err := GetOIDCToken("https://athenz.io")
	assert.NotNil(t, err)
	assert.Equal(t, "ACTIONS_ID_TOKEN_REQUEST_URL environment variable not set", err.Error())

	// now let's set the request url but not the token
	os.Setenv("ACTIONS_ID_TOKEN_REQUEST_URL", "http://localhost:8081/oidc?type=jwt")
	_, _, err = GetOIDCToken("https://athenz.io")
	assert.NotNil(t, err)
	assert.Equal(t, "ACTIONS_ID_TOKEN_REQUEST_TOKEN environment variable not set", err.Error())

	os.Clearenv()
}

func TestGetOIDCTokenInvalidStatusCode(t *testing.T) {

	os.Setenv("ACTIONS_ID_TOKEN_REQUEST_URL", "http://localhost:8082/oidc?type=jwt")
	os.Setenv("ACTIONS_ID_TOKEN_REQUEST_TOKEN", "test-token")

	go startHttpServer("localhost:8082", "invalid-token", http.StatusBadRequest)
	time.Sleep(2 * time.Second)

	_, _, err := GetOIDCToken("https://athenz.io")
	assert.NotNil(t, err)
	assert.Equal(t, "oidc token get status error: 400", err.Error())

	os.Clearenv()
}

func TestGetOIDCTokenInvalidToken(t *testing.T) {

	os.Setenv("ACTIONS_ID_TOKEN_REQUEST_URL", "http://localhost:8083/oidc?type=jwt")
	os.Setenv("ACTIONS_ID_TOKEN_REQUEST_TOKEN", "test-token")

	go startHttpServer("localhost:8083", "invalid-token", http.StatusOK)
	time.Sleep(2 * time.Second)

	_, _, err := GetOIDCToken("https://athenz.io")
	assert.NotNil(t, err)
	assert.Equal(t, "unable to parse oidc token: square/go-jose: compact JWS format must have three parts", err.Error())

	os.Clearenv()
}

func TestGetCSRDetails(t *testing.T) {

	privateKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	csr, err := GetCSRDetails(privateKey, "sports", "api", "sys.auth.github-actions", "0001", "athenz.io", "athenz", "", "", "")
	assert.Nil(t, err)
	assert.True(t, csr != "")
}
