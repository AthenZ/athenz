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
	"github.com/AthenZ/athenz/libs/go/sia/util"
	"gopkg.in/square/go-jose.v2/jwt"
	"io"
	"k8s.io/apimachinery/pkg/util/json"
	"net/http"
	"net/url"
	"os"
	"time"
)

func GetOIDCToken(ztsUrl string) (string, map[string]interface{}, error) {

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

	oidcToken := jsonData["value"].(string)
	tok, err := jwt.ParseSigned(oidcToken)
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
