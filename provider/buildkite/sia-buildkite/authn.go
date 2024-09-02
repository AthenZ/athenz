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
	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
	"net/url"
)

func GetOIDCTokenClaims(oidcToken string) (map[string]interface{}, error) {
	signatureAlgorithms := []jose.SignatureAlgorithm{jose.RS256, jose.RS384, jose.RS512, jose.PS256, jose.PS384, jose.PS512, jose.ES256, jose.ES384, jose.ES512, jose.EdDSA}
	tok, err := jwt.ParseSigned(oidcToken, signatureAlgorithms)
	if err != nil {
		return nil, fmt.Errorf("unable to parse BuildKite oidc token: %v", err)
	}

	var claims map[string]interface{}
	err = tok.UnsafeClaimsWithoutVerification(&claims)
	if err != nil {
		return nil, fmt.Errorf("unable to extract BuildKite oidc token claims: %v", err)
	}
	return claims, nil
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
