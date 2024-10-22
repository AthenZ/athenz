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
	"bytes"
	"crypto/rsa"
	"encoding/json"
	"fmt"
	"github.com/AthenZ/athenz/libs/go/sia/util"
	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
	"io"
	"net/http"
	"net/url"
	"os"
	"time"
)

type RequestBody struct {
	AccountId   string     `json:"accountId,omitempty"`
	CustomAttrs TokenAttrs `json:"oidcIdTokenCustomAttributesStructure,omitempty"`
}

type TokenAttrs struct {
	AccountId      string `json:"account_id,omitempty"`
	OrganizationId string `json:"organization_id,omitempty"`
	ProjectId      string `json:"project_id,omitempty"`
	PipelineId     string `json:"pipeline_id,omitempty"`
	Context        string `json:"context,omitempty"`
}

func generateTokenRequestBody(audience string) (io.Reader, error) {

	triggerContext := "triggerType:" + os.Getenv("HARNESS_TRIGGER_TYPE") +
		"/triggerEvent:" + os.Getenv("HARNESS_TRIGGER_EVENT") +
		"/sequenceId:" + os.Getenv("HARNESS_SEQUENCE_ID")

	values := RequestBody{
		AccountId: os.Getenv("HARNESS_ACCOUNT_ID"),
		CustomAttrs: TokenAttrs{
			AccountId:      os.Getenv("HARNESS_ACCOUNT_ID"),
			OrganizationId: os.Getenv("HARNESS_ORG_ID"),
			ProjectId:      os.Getenv("HARNESS_PROJECT_ID"),
			PipelineId:     os.Getenv("HARNESS_PIPELINE_ID"),
			Context:        triggerContext,
		},
	}
	jsonValue, err := json.Marshal(values)
	if err != nil {
		return nil, err
	}
	return bytes.NewBuffer(jsonValue), nil
}

func GetOIDCToken(audience, harnessUrl string) (string, map[string]interface{}, error) {

	apiToken := os.Getenv("OIDC_SA_TOKEN_SECRET_PATH")
	if apiToken == "" {
		return "", nil, fmt.Errorf("OIDC_SA_TOKEN_SECRET_PATH environment variable not set")
	}

	// get the id token for the harness pipeline
	// we're going to use this token to authenticate our request to the ZTS server

	requestBody, err := generateTokenRequestBody(audience)
	if err != nil {
		return "", nil, fmt.Errorf("unable to generate token request body: %v", err)
	}
	req, err := http.NewRequest(http.MethodPost, harnessUrl, requestBody)
	if err != nil {
		return "", nil, fmt.Errorf("unable to generate new http request: %v", err)
	}

	req.Header.Add("Content-Type", "application/json")
	req.Header.Add("User-Agent", "athenz/oidc-client")
	req.Header.Add("x-api-key", apiToken)

	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return "", nil, fmt.Errorf("unable to execute http get request: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return "", nil, fmt.Errorf("oidc token get status error: %d", resp.StatusCode)
	}

	contents, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", nil, fmt.Errorf("uanble to read response body: %v", err)
	}

	var jsonData map[string]interface{}
	err = json.Unmarshal(contents, &jsonData)
	if err != nil {
		return "", nil, fmt.Errorf("unable to parse oidc token response: %v", err)
	}

	signatureAlgorithms := []jose.SignatureAlgorithm{jose.RS256, jose.RS384, jose.RS512, jose.PS256, jose.PS384, jose.PS512, jose.ES256, jose.ES384, jose.ES512, jose.EdDSA}
	oidcToken := jsonData["data"].(string)
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

func GetCSRDetails(privateKey *rsa.PrivateKey, domain, service, provider, instanceId, dnsDomain, spiffeTrustDomain, subjC, subjO, subjOU string) (string, error) {
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
	csrDetails.URIs = util.AppendUri(csrDetails.URIs, util.GetSvcSpiffeUri(spiffeTrustDomain, "default", domain, service))
	csrDetails.URIs = util.AppendUri(csrDetails.URIs, util.SanURIInstanceId(provider, instanceId))

	return util.GenerateX509CSR(privateKey, csrDetails)
}
