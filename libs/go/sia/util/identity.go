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

package util

import (
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"github.com/AthenZ/athenz/clients/go/zts"
	"log"
	"net/url"
	"strconv"
	"strings"
	"time"
)

const (
	SiaYieldMapperX509CertPemKey   = "cert_pem"
	SiaYieldMapperPvtPemKey        = "key_pem"
	SiaYieldMapperCertSignerPemKey = "ca_pem"
	SiaYieldMapperIssueTimeKey     = "time"
)

// SiaCertData response of GetAthenzIdentity()
type SiaCertData struct {
	PrivateKey               *rsa.PrivateKey
	PrivateKeyPem            string
	X509Certificate          *x509.Certificate
	X509CertificatePem       string
	X509CertificateSignerPem string
	TLSCertificate           tls.Certificate
}

// CsrSubjectFields are optional fields for the CSR: the fields will appear in the created certificate's "Subject".
type CsrSubjectFields struct {
	Country          string
	State            string
	Locality         string
	Organization     string
	OrganizationUnit string
}

func GenerateSecretJsonData(athenzDomain, athenzService string, siaCertData *SiaCertData) ([]byte, error) {

	siaYield := make(map[string]string)
	siaYield[athenzDomain+"."+athenzService+".cert.pem"] = siaCertData.X509CertificatePem
	siaYield[athenzDomain+"."+athenzService+".key.pem"] = siaCertData.PrivateKeyPem
	siaYield["ca.cert.pem"] = siaCertData.X509CertificateSignerPem

	// Add the current time to the JSON.
	siaYield["time"] = strconv.FormatInt(time.Now().Unix(), 10)

	return json.MarshalIndent(siaYield, "", "  ")
}

// GenerateCustomSecretJsonData get SiaCertData data as string in json format with custom field names.
// It supports only 4 json fields 'cert_pem', 'key_pem', 'ca_pem' and 'time', similar to `GenerateSecretJsonData`.
// Out of 4 fields 'cert_pem' and 'key_pem' are mandatory, and resulted json will contain  X509CertificateSignerPem
// and timestamp only if the corresponding json field names are set.
// sample `jsonFieldMapper` map: [{"cert_pem": "certPem"}, {"key_pem": "keyPem"}]
func GenerateCustomSecretJsonData(siaCertData *SiaCertData, jsonFieldMapper map[string]string) ([]byte, error) {
	if nil == jsonFieldMapper {
		return nil, fmt.Errorf("json keys mapper is misssing, required atleast certificate and private key fields")
	}
	x509CertPemKey, okx509 := jsonFieldMapper[SiaYieldMapperX509CertPemKey]
	pvtPemKey, okPem := jsonFieldMapper[SiaYieldMapperPvtPemKey]

	if !okx509 || !okPem || "" == strings.TrimSpace(x509CertPemKey) || "" == strings.TrimSpace(pvtPemKey) {
		return nil, fmt.Errorf("x509 certificate pem and private pem keys are mandatory")
	}

	certSignerPemKey, okCA := jsonFieldMapper[SiaYieldMapperCertSignerPemKey]
	issueTimeKey, okTime := jsonFieldMapper[SiaYieldMapperIssueTimeKey]
	siaYield := make(map[string]string)
	siaYield[strings.TrimSpace(x509CertPemKey)] = siaCertData.X509CertificatePem
	siaYield[strings.TrimSpace(pvtPemKey)] = siaCertData.PrivateKeyPem

	if okCA {
		siaYield[strings.TrimSpace(certSignerPemKey)] = siaCertData.X509CertificateSignerPem
	}
	if okTime {
		// Add the current time to the JSON.
		siaYield[strings.TrimSpace(issueTimeKey)] = strconv.FormatInt(time.Now().Unix(), 10)
	}

	return json.MarshalIndent(siaYield, "", "  ")
}

func RegisterIdentity(athenzDomain, athenzService, athenzProvider, ztsUrl, instanceId, attestationData, spiffeTrustDomain string, sanDNSDomains []string, csrSubjectFields CsrSubjectFields, instanceIdSanDNS bool, privateKey *rsa.PrivateKey) (*SiaCertData, error) {

	var csrDetails CertReqDetails
	csrDetails.CommonName = fmt.Sprintf("%s.%s", athenzDomain, athenzService)
	csrDetails.Country = csrSubjectFields.Country
	csrDetails.OrgUnit = csrSubjectFields.OrganizationUnit
	csrDetails.Locality = csrSubjectFields.Locality
	csrDetails.Org = csrSubjectFields.Organization
	csrDetails.Province = csrSubjectFields.State

	csrDetails.HostList = []string{}
	for _, sanDNSDomain := range sanDNSDomains {
		csrDetails.HostList = append(csrDetails.HostList, SanDNSHostname(athenzDomain, athenzService, sanDNSDomain))
	}
	if instanceIdSanDNS {
		instanceIdHost := fmt.Sprintf("%s.instanceid.athenz.%s", instanceId, sanDNSDomains[0])
		csrDetails.HostList = append(csrDetails.HostList, instanceIdHost)
	}
	// add our uri fields. spiffe uri must be the first entry
	csrDetails.URIs = []*url.URL{}
	csrDetails.URIs = AppendUri(csrDetails.URIs, GetSvcSpiffeUri(spiffeTrustDomain, "default", athenzDomain, athenzService))
	csrDetails.URIs = AppendUri(csrDetails.URIs, SanURIInstanceId(athenzProvider, instanceId))

	csr, err := GenerateX509CSR(privateKey, csrDetails)
	if err != nil {
		return nil, err
	}

	ztsClient, err := ZtsClient(ztsUrl, "", "", "", "")
	if err != nil {
		return nil, err
	}
	identity, _, err := ztsClient.PostInstanceRegisterInformation(&zts.InstanceRegisterInformation{
		Domain:          zts.DomainName(athenzDomain),
		Service:         zts.SimpleName(athenzService),
		Provider:        zts.ServiceName(athenzProvider),
		AttestationData: attestationData,
		Csr:             csr,
	})
	if err != nil {
		log.Printf("Unable to do PostInstanceRegisterInformation, err: %v\n", err)
		return nil, err
	}

	// Decode the ZTS certificate from PEM format.
	x509Certificate, err := ParseCertificate(identity.X509Certificate)
	if err != nil {
		return nil, err
	}

	privateKeyPem := PrivatePem(privateKey)
	tlsCertificate, err := tls.X509KeyPair([]byte(identity.X509Certificate), []byte(privateKeyPem))

	return &SiaCertData{
		PrivateKey:               privateKey,
		PrivateKeyPem:            privateKeyPem,
		X509Certificate:          x509Certificate,
		X509CertificatePem:       identity.X509Certificate,
		X509CertificateSignerPem: identity.X509CertificateSigner,
		TLSCertificate:           tlsCertificate,
	}, err
}
