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
	"crypto/rsa"
	"fmt"
	"io"
	"log"
	"math/rand"
	"net/http"
	"net/url"
	"os"
	"time"

	"github.com/AthenZ/athenz/libs/go/sia/spiffe"
	"github.com/AthenZ/athenz/libs/go/sia/util"
	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
	"k8s.io/apimachinery/pkg/util/json"
)

const (
	// DefaultOIDCRequestTimeout is the timeout applied to the http request
	// carried out against the GitHub OIDC token endpoint.
	DefaultOIDCRequestTimeout = 10 * time.Second

	// DefaultOIDCRequestRetries is the number of additional attempts carried out
	// when the OIDC token request fails with a transient error. The default of 0
	// retains the original single attempt behavior.
	DefaultOIDCRequestRetries = 0

	// DefaultOIDCRequestRetryDelay is the base delay for the exponential backoff
	// applied between retry attempts.
	DefaultOIDCRequestRetryDelay = time.Second

	// maxOIDCRequestRetryDelay is the ceiling applied to the exponential backoff
	// so that the delay between attempts cannot grow without bound.
	maxOIDCRequestRetryDelay = 30 * time.Second
)

// OIDCTokenOptions carries the tunables for the http request issued against the
// GitHub OIDC token endpoint. Use DefaultOIDCTokenOptions to obtain a value
// pre-populated with the defaults and override only the fields of interest.
type OIDCTokenOptions struct {
	// RequestTimeout is the http client timeout for a single attempt. It must be
	// greater than 0 - a value of 0 is rejected rather than being passed through
	// to http.Client, where it would mean no timeout at all.
	RequestTimeout time.Duration

	// Retries is the number of additional attempts carried out when the request
	// fails with a transient error. 0 disables retries.
	Retries int

	// RetryDelay is the base delay for the exponential backoff between attempts.
	// The effective delay is jittered and capped at maxOIDCRequestRetryDelay.
	RetryDelay time.Duration
}

// DefaultOIDCTokenOptions returns the OIDC token request options with the
// default settings applied.
func DefaultOIDCTokenOptions() OIDCTokenOptions {
	return OIDCTokenOptions{
		RequestTimeout: DefaultOIDCRequestTimeout,
		Retries:        DefaultOIDCRequestRetries,
		RetryDelay:     DefaultOIDCRequestRetryDelay,
	}
}

func (options OIDCTokenOptions) validate() error {
	if options.RequestTimeout <= 0 {
		return fmt.Errorf("invalid oidc request timeout: %v - must be greater than 0", options.RequestTimeout)
	}
	if options.Retries < 0 {
		return fmt.Errorf("invalid oidc request retries: %d - must not be negative", options.Retries)
	}
	if options.Retries > 0 && options.RetryDelay <= 0 {
		return fmt.Errorf("invalid oidc request retry delay: %v - must be greater than 0", options.RetryDelay)
	}
	return nil
}

// GetOIDCToken retrieves the OIDC token from the GitHub Actions token endpoint
// for the given audience using the default request options.
func GetOIDCToken(ztsUrl string) (string, map[string]interface{}, error) {
	return GetOIDCTokenWithOptions(ztsUrl, DefaultOIDCTokenOptions())
}

// GetOIDCTokenWithOptions retrieves the OIDC token from the GitHub Actions token
// endpoint for the given audience, honoring the given request options. GitHub's
// token endpoint is occasionally slow enough to exceed the default 10 second
// timeout, which fails the identity request outright, so the caller is given the
// ability to extend the timeout and, optionally, to retry transient failures.
func GetOIDCTokenWithOptions(ztsUrl string, options OIDCTokenOptions) (string, map[string]interface{}, error) {

	if err := options.validate(); err != nil {
		return "", nil, err
	}

	requestUrl := os.Getenv("ACTIONS_ID_TOKEN_REQUEST_URL")
	if requestUrl == "" {
		return "", nil, fmt.Errorf("ACTIONS_ID_TOKEN_REQUEST_URL environment variable not set")
	}

	requestToken := os.Getenv("ACTIONS_ID_TOKEN_REQUEST_TOKEN")
	if requestToken == "" {
		return "", nil, fmt.Errorf("ACTIONS_ID_TOKEN_REQUEST_TOKEN environment variable not set")
	}

	// get the id token for the GitHub actions
	// we're going to use this token to authenticate our request to the ZTS server

	githubUrl := fmt.Sprintf("%s&audience=%s", requestUrl, ztsUrl)
	req, err := http.NewRequest(http.MethodGet, githubUrl, nil)
	if err != nil {
		return "", nil, fmt.Errorf("unable to generate new http request: %v", err)
	}

	req.Header.Add("User-Agent", "actions/oidc-client")
	req.Header.Add("Authorization", "Bearer "+requestToken)

	contents, err := fetchOIDCToken(req, options)
	if err != nil {
		return "", nil, err
	}

	var jsonData map[string]interface{}
	err = json.Unmarshal(contents, &jsonData)
	if err != nil {
		return "", nil, fmt.Errorf("unable to parse oidc token response: %v", err)
	}

	signatureAlgorithms := []jose.SignatureAlgorithm{jose.RS256, jose.RS384, jose.RS512, jose.PS256, jose.PS384, jose.PS512, jose.ES256, jose.ES384, jose.ES512, jose.EdDSA}
	oidcToken := jsonData["value"].(string)
	tok, err := jwt.ParseSigned(oidcToken, signatureAlgorithms)
	if err != nil {
		return "", nil, fmt.Errorf("unable to parse oidc token: %v", err)
	}

	var claims map[string]interface{}
	err = tok.UnsafeClaimsWithoutVerification(&claims)
	if err != nil {
		return "", nil, fmt.Errorf("unable to extract oidc token claims: %v", err)
	}
	return oidcToken, claims, nil
}

// fetchOIDCToken carries out the token request, retrying transient failures up
// to options.Retries additional times. Only the token fetch is retried - the
// caller has not written any state at this point - and only failures that stand
// a chance of succeeding on a subsequent attempt are retried.
func fetchOIDCToken(req *http.Request, options OIDCTokenOptions) ([]byte, error) {

	client := &http.Client{Timeout: options.RequestTimeout}

	var lastErr error
	for attempt := 0; attempt <= options.Retries; attempt++ {
		if attempt > 0 {
			delay := oidcRetryDelay(options.RetryDelay, attempt-1)
			log.Printf("oidc token request failed: %v - retrying in %v (attempt %d of %d)\n", lastErr, delay, attempt+1, options.Retries+1)
			time.Sleep(delay)
		}
		contents, retryable, err := oidcTokenRequest(client, req)
		if err == nil {
			return contents, nil
		}
		lastErr = err
		if !retryable {
			return nil, err
		}
	}
	return nil, lastErr
}

// oidcTokenRequest carries out a single token request attempt and reports
// whether the failure, if any, is worth retrying.
func oidcTokenRequest(client *http.Client, req *http.Request) ([]byte, bool, error) {

	resp, err := client.Do(req)
	if err != nil {
		// transport level failures, which include the client timeout being
		// exceeded, are the transient case we are guarding against
		return nil, true, fmt.Errorf("unable to execute http get request: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, retryableStatusCode(resp.StatusCode), fmt.Errorf("oidc token get status error: %d", resp.StatusCode)
	}

	contents, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, false, fmt.Errorf("uanble to read response body: %v", err)
	}
	return contents, false, nil
}

// retryableStatusCode reports whether the given status code represents a
// transient server side failure. Client errors - an invalid request or a
// rejected credential - will fail identically on every attempt, so they are
// returned to the caller right away.
func retryableStatusCode(statusCode int) bool {
	switch statusCode {
	case http.StatusRequestTimeout, http.StatusTooManyRequests:
		return true
	}
	return statusCode >= http.StatusInternalServerError
}

// oidcRetryDelay returns the jittered exponential backoff delay for the given
// zero based retry attempt. The delay is doubled per attempt but capped at
// maxOIDCRequestRetryDelay, so it cannot overflow or grow without bound, and it
// is jittered so that concurrent jobs failing at the same instant do not march
// back into the token endpoint in lockstep.
func oidcRetryDelay(baseDelay time.Duration, attempt int) time.Duration {

	delay := baseDelay
	for i := 0; i < attempt && delay < maxOIDCRequestRetryDelay; i++ {
		delay *= 2
	}
	if delay > maxOIDCRequestRetryDelay {
		delay = maxOIDCRequestRetryDelay
	}

	// apply jitter over the upper half of the interval so that the delay stays
	// within [delay/2, delay]
	half := delay / 2
	if half <= 0 {
		return delay
	}
	return half + time.Duration(rand.Int63n(int64(half)+1))
}

func GetCSRDetails(privateKey *rsa.PrivateKey, domain, service, provider, instanceId, dnsDomain, spiffeTrustDomain, subjC, subjO, subjOU string) (string, error) {
	return GetCSRDetailsWithSpiffeFormatter(privateKey, domain, service, provider, instanceId, dnsDomain, spiffeTrustDomain, subjC, subjO, subjOU, nil)
}

func GetCSRDetailsWithSpiffeFormatter(privateKey *rsa.PrivateKey, domain, service, provider, instanceId, dnsDomain, spiffeTrustDomain, subjC, subjO, subjOU string, spiffeFormatter spiffe.URIFormatter) (string, error) {
	if spiffeFormatter == nil {
		spiffeFormatter = spiffe.GetDefaultFormatter()
	}
	// note: RFC 6125 states that if the SAN (Subject Alternative Name) exists,
	// it is used, not the CA. So, we will always put the Athenz name in the CN
	// (it is *not* a DNS domain name), and put the host name into the SAN.

	var csrDetails util.CertReqDetails
	csrDetails.CommonName = fmt.Sprintf("%s.%s", domain, service)
	csrDetails.Country = subjC
	csrDetails.OrgUnit = subjOU
	csrDetails.Org = subjO

	csrDetails.HostList = []string{}
	csrDetails.HostList = append(csrDetails.HostList, util.SanDNSHostname(domain, service, dnsDomain))

	// add our uri fields. spiffe uri must be the first entry
	csrDetails.URIs = []*url.URL{}
	spiffeURI := spiffeFormatter.FormatServiceURI(spiffeTrustDomain, "default", domain, service, instanceId)
	csrDetails.URIs = util.AppendUri(csrDetails.URIs, spiffeURI)
	csrDetails.URIs = util.AppendUri(csrDetails.URIs, util.SanURIInstanceId(provider, instanceId))

	return util.GenerateX509CSR(privateKey, csrDetails)
}
