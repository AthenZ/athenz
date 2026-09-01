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
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

// validOIDCToken is a signed jwt carrying the run_id, enterprise, repository,
// sub and event_name claims the provider reads.
const validOIDCToken = "eyJraWQiOiIwIiwiYWxnIjoiRVMyNTYifQ.eyJleHAiOjE3MDgwMjc4MTcsImlzcyI6Imh0dHBzOi8vdG9rZW4uYWN0aW9ucy5naXRodWJ1c2VyY29udGVudC5jb20iLCJhdWQiOiJodHRwczovL2F0aGVuei5pbyIsInJ1bl9pZCI6IjAwMDEiLCJlbnRlcnByaXNlIjoiYXRoZW56Iiwic3ViIjoicmVwbzphdGhlbnovc2lhOnJlZjpyZWZzL2hlYWRzL21haW4iLCJldmVudF9uYW1lIjoicHVzaCIsImlhdCI6MTcwODAyNDIxN30.ykt6O1mIjIjalTrmaU9AuSSsQghZ7Mx61gDsjVPHV0-SCqYpZNy7RtEbvgjKVCZ0kJ6BijH3aEf3EGArLHjTOQ"

type customFormatter struct{}

func (f *customFormatter) FormatServiceURI(trustDomain, namespace, domain, service, workloadId string) string {
	return fmt.Sprintf("spiffe://custom.github/svc/%s/%s", domain, service)
}

func (f *customFormatter) FormatRoleURI(trustDomain, domain, role string) string {
	return ""
}

func (f *customFormatter) FormatUserURI(trustDomain, namespace, principalName, deviceId string) string {
	return ""
}

func startHttpServer(token string, statusCode int) *httptest.Server {
	router := http.NewServeMux()
	router.HandleFunc("GET /oidc", func(w http.ResponseWriter, r *http.Request) {
		log.Println("/oidc token endpoint is called")
		w.WriteHeader(statusCode)
		io.WriteString(w, "{\"value\": \""+token+"\"}")
	})

	return httptest.NewServer(router)
}

func TestGetOIDCToken(t *testing.T) {

	ts := startHttpServer(validOIDCToken, http.StatusOK)
	defer ts.Close()

	t.Setenv("ACTIONS_ID_TOKEN_REQUEST_URL", ts.URL+"/oidc?type=jwt")
	t.Setenv("ACTIONS_ID_TOKEN_REQUEST_TOKEN", "test-token")

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
	os.Setenv("ACTIONS_ID_TOKEN_REQUEST_URL", "http://localhost:0/oidc?type=jwt")
	_, _, err = GetOIDCToken("https://athenz.io")
	assert.NotNil(t, err)
	assert.Equal(t, "ACTIONS_ID_TOKEN_REQUEST_TOKEN environment variable not set", err.Error())

	os.Clearenv()
}

func TestGetOIDCTokenInvalidStatusCode(t *testing.T) {

	ts := startHttpServer("test-token", http.StatusBadRequest)
	defer ts.Close()

	os.Setenv("ACTIONS_ID_TOKEN_REQUEST_URL", ts.URL+"/oidc?type=jwt")
	os.Setenv("ACTIONS_ID_TOKEN_REQUEST_TOKEN", "test-token")

	_, _, err := GetOIDCToken("https://athenz.io")
	assert.NotNil(t, err)
	assert.Equal(t, "oidc token get status error: 400", err.Error())

	os.Clearenv()
}

func TestGetOIDCTokenInvalidToken(t *testing.T) {

	ts := startHttpServer("invalid-token", http.StatusOK)
	defer ts.Close()

	os.Setenv("ACTIONS_ID_TOKEN_REQUEST_URL", ts.URL+"/oidc?type=jwt")
	os.Setenv("ACTIONS_ID_TOKEN_REQUEST_TOKEN", "test-token")

	_, _, err := GetOIDCToken("https://athenz.io")
	assert.NotNil(t, err)
	assert.Equal(t, "unable to parse oidc token: go-jose/go-jose: compact JWS format must have three parts", err.Error())

	os.Clearenv()
}

func TestGetCSRDetails(t *testing.T) {

	privateKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	csr, err := GetCSRDetails(privateKey, "sports", "api", "sys.auth.github-actions", "0001", "athenz.io", "athenz", "", "", "")
	assert.Nil(t, err)
	assert.True(t, csr != "")
}

func TestGetCSRDetailsWithCustomSpiffeFormatter(t *testing.T) {
	privateKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	formatter := &customFormatter{}
	csr, err := GetCSRDetailsWithSpiffeFormatter(privateKey, "sports", "api", "sys.auth.github-actions", "0001", "athenz.io", "athenz", "", "", "", formatter)
	assert.Nil(t, err)

	block, _ := pem.Decode([]byte(csr))
	parsedCSR, err := x509.ParseCertificateRequest(block.Bytes)
	assert.Nil(t, err)
	assert.Equal(t, "spiffe://custom.github/svc/sports/api", parsedCSR.URIs[0].String())
}

// startCountingHttpServer returns a server that fails the first failureCount
// requests with the given status code and serves the token afterwards, along
// with a counter of the requests it has received.
func startCountingHttpServer(token string, failureStatusCode, failureCount int) (*httptest.Server, *int32) {
	var requests int32
	router := http.NewServeMux()
	router.HandleFunc("GET /oidc", func(w http.ResponseWriter, r *http.Request) {
		if atomic.AddInt32(&requests, 1) <= int32(failureCount) {
			w.WriteHeader(failureStatusCode)
			return
		}
		w.WriteHeader(http.StatusOK)
		io.WriteString(w, "{\"value\": \""+token+"\"}")
	})
	return httptest.NewServer(router), &requests
}

// startSlowHttpServer returns a server that waits for the given delay before
// serving the token, so that a request timeout can be exercised.
func startSlowHttpServer(token string, delay time.Duration) *httptest.Server {
	router := http.NewServeMux()
	router.HandleFunc("GET /oidc", func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(delay)
		w.WriteHeader(http.StatusOK)
		io.WriteString(w, "{\"value\": \""+token+"\"}")
	})
	return httptest.NewServer(router)
}

func TestDefaultOIDCTokenOptions(t *testing.T) {

	// the defaults must retain the original behavior: a 10 second timeout
	// and no retries

	options := DefaultOIDCTokenOptions()
	assert.Equal(t, 10*time.Second, options.RequestTimeout)
	assert.Equal(t, DefaultOIDCRequestTimeout, options.RequestTimeout)
	assert.Equal(t, 0, options.Retries)
	assert.Equal(t, time.Second, options.RetryDelay)
	assert.Nil(t, options.validate())
}

func TestGetOIDCTokenWithOptions(t *testing.T) {

	ts := startHttpServer(validOIDCToken, http.StatusOK)
	defer ts.Close()

	t.Setenv("ACTIONS_ID_TOKEN_REQUEST_URL", ts.URL+"/oidc?type=jwt")
	t.Setenv("ACTIONS_ID_TOKEN_REQUEST_TOKEN", "test-token")

	options := DefaultOIDCTokenOptions()
	options.RequestTimeout = 30 * time.Second
	_, claims, err := GetOIDCTokenWithOptions("https://athenz.io", options)
	assert.Nil(t, err)
	assert.Equal(t, "0001", claims["run_id"].(string))
}

func TestGetOIDCTokenWithOptionsCustomTimeoutHonored(t *testing.T) {

	// the server takes longer than our short timeout, so the request must fail,
	// and then succeed once the timeout is extended past the server's delay

	ts := startSlowHttpServer(validOIDCToken, 300*time.Millisecond)
	defer ts.Close()

	t.Setenv("ACTIONS_ID_TOKEN_REQUEST_URL", ts.URL+"/oidc?type=jwt")
	t.Setenv("ACTIONS_ID_TOKEN_REQUEST_TOKEN", "test-token")

	options := DefaultOIDCTokenOptions()
	options.RequestTimeout = 50 * time.Millisecond
	_, _, err := GetOIDCTokenWithOptions("https://athenz.io", options)
	assert.NotNil(t, err)
	assert.True(t, strings.HasPrefix(err.Error(), "unable to execute http get request:"), err.Error())

	options.RequestTimeout = 30 * time.Second
	_, claims, err := GetOIDCTokenWithOptions("https://athenz.io", options)
	assert.Nil(t, err)
	assert.Equal(t, "0001", claims["run_id"].(string))
}

func TestGetOIDCTokenWithOptionsInvalidTimeout(t *testing.T) {

	// a 0 timeout must be rejected rather than silently handed to http.Client,
	// where it means no timeout at all

	t.Setenv("ACTIONS_ID_TOKEN_REQUEST_URL", "http://localhost:0/oidc?type=jwt")
	t.Setenv("ACTIONS_ID_TOKEN_REQUEST_TOKEN", "test-token")

	options := DefaultOIDCTokenOptions()
	options.RequestTimeout = 0
	_, _, err := GetOIDCTokenWithOptions("https://athenz.io", options)
	assert.NotNil(t, err)
	assert.Equal(t, "invalid oidc request timeout: 0s - must be greater than 0", err.Error())

	options.RequestTimeout = -5 * time.Second
	_, _, err = GetOIDCTokenWithOptions("https://athenz.io", options)
	assert.NotNil(t, err)
	assert.Equal(t, "invalid oidc request timeout: -5s - must be greater than 0", err.Error())
}

func TestGetOIDCTokenWithOptionsInvalidRetries(t *testing.T) {

	options := DefaultOIDCTokenOptions()
	options.Retries = -1
	_, _, err := GetOIDCTokenWithOptions("https://athenz.io", options)
	assert.NotNil(t, err)
	assert.Equal(t, "invalid oidc request retries: -1 - must not be negative", err.Error())
}

func TestGetOIDCTokenWithOptionsInvalidRetryDelay(t *testing.T) {

	options := DefaultOIDCTokenOptions()
	options.Retries = 2
	options.RetryDelay = 0
	_, _, err := GetOIDCTokenWithOptions("https://athenz.io", options)
	assert.NotNil(t, err)
	assert.Equal(t, "invalid oidc request retry delay: 0s - must be greater than 0", err.Error())

	// the retry delay is irrelevant when retries are disabled, so it must not
	// be rejected in that case
	options.Retries = 0
	assert.Nil(t, options.validate())
}

func TestGetOIDCTokenWithOptionsRetriesTransientFailure(t *testing.T) {

	ts, requests := startCountingHttpServer(validOIDCToken, http.StatusServiceUnavailable, 2)
	defer ts.Close()

	t.Setenv("ACTIONS_ID_TOKEN_REQUEST_URL", ts.URL+"/oidc?type=jwt")
	t.Setenv("ACTIONS_ID_TOKEN_REQUEST_TOKEN", "test-token")

	options := DefaultOIDCTokenOptions()
	options.Retries = 3
	options.RetryDelay = time.Millisecond
	_, claims, err := GetOIDCTokenWithOptions("https://athenz.io", options)
	assert.Nil(t, err)
	assert.Equal(t, "0001", claims["run_id"].(string))
	assert.Equal(t, int32(3), atomic.LoadInt32(requests))
}

func TestGetOIDCTokenWithOptionsRetriesExhausted(t *testing.T) {

	ts, requests := startCountingHttpServer(validOIDCToken, http.StatusBadGateway, 100)
	defer ts.Close()

	t.Setenv("ACTIONS_ID_TOKEN_REQUEST_URL", ts.URL+"/oidc?type=jwt")
	t.Setenv("ACTIONS_ID_TOKEN_REQUEST_TOKEN", "test-token")

	options := DefaultOIDCTokenOptions()
	options.Retries = 2
	options.RetryDelay = time.Millisecond
	_, _, err := GetOIDCTokenWithOptions("https://athenz.io", options)
	assert.NotNil(t, err)
	assert.Equal(t, "oidc token get status error: 502", err.Error())
	assert.Equal(t, int32(3), atomic.LoadInt32(requests))
}

func TestGetOIDCTokenWithOptionsNoRetryOnPermanentFailure(t *testing.T) {

	// a rejected credential fails identically on every attempt, so retrying it
	// only multiplies the wait

	ts, requests := startCountingHttpServer(validOIDCToken, http.StatusForbidden, 100)
	defer ts.Close()

	t.Setenv("ACTIONS_ID_TOKEN_REQUEST_URL", ts.URL+"/oidc?type=jwt")
	t.Setenv("ACTIONS_ID_TOKEN_REQUEST_TOKEN", "test-token")

	options := DefaultOIDCTokenOptions()
	options.Retries = 5
	options.RetryDelay = time.Millisecond
	_, _, err := GetOIDCTokenWithOptions("https://athenz.io", options)
	assert.NotNil(t, err)
	assert.Equal(t, "oidc token get status error: 403", err.Error())
	assert.Equal(t, int32(1), atomic.LoadInt32(requests))
}

func TestRetryableStatusCode(t *testing.T) {

	assert.True(t, retryableStatusCode(http.StatusRequestTimeout))
	assert.True(t, retryableStatusCode(http.StatusTooManyRequests))
	assert.True(t, retryableStatusCode(http.StatusInternalServerError))
	assert.True(t, retryableStatusCode(http.StatusBadGateway))
	assert.True(t, retryableStatusCode(http.StatusServiceUnavailable))
	assert.True(t, retryableStatusCode(http.StatusGatewayTimeout))

	assert.False(t, retryableStatusCode(http.StatusBadRequest))
	assert.False(t, retryableStatusCode(http.StatusUnauthorized))
	assert.False(t, retryableStatusCode(http.StatusForbidden))
	assert.False(t, retryableStatusCode(http.StatusNotFound))
}

func TestOidcRetryDelay(t *testing.T) {

	// the delay doubles per attempt and is jittered into the upper half of the
	// interval, so each value must fall within [delay/2, delay]

	for attempt, expected := range []time.Duration{time.Second, 2 * time.Second, 4 * time.Second, 8 * time.Second} {
		delay := oidcRetryDelay(time.Second, attempt)
		assert.True(t, delay >= expected/2 && delay <= expected, "attempt %d: %v", attempt, delay)
	}

	// a delay too small to jitter is returned as is
	assert.Equal(t, time.Duration(1), oidcRetryDelay(time.Duration(1), 0))

	// the backoff must be clamped rather than growing without bound or
	// overflowing for large attempt counts
	for _, attempt := range []int{10, 62, 63, 64, 1000} {
		delay := oidcRetryDelay(time.Second, attempt)
		assert.True(t, delay >= maxOIDCRequestRetryDelay/2 && delay <= maxOIDCRequestRetryDelay,
			"attempt %d: %v", attempt, delay)
	}
}
