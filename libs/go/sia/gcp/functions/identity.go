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

package functions

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	secretmanager "cloud.google.com/go/secretmanager/apiv1"
	"cloud.google.com/go/secretmanager/apiv1/secretmanagerpb"
	"github.com/AthenZ/athenz/clients/go/zts"
	gcpa "github.com/AthenZ/athenz/libs/go/sia/gcp/attestation"
	"github.com/AthenZ/athenz/libs/go/sia/util"
)

// SiaCertData response of GetAthenzIdentity()
type SiaCertData struct {
	PrivateKey               *rsa.PrivateKey
	PrivateKeyPem            string
	X509Certificate          *x509.Certificate
	X509CertificatePem       string
	X509CertificateSignerPem string
}

// CsrSubjectFields are optional fields for the CSR: the fields will appear in the created certificate's "Subject".
type CsrSubjectFields struct {
	Country          string
	State            string
	Locality         string
	Organization     string
	OrganizationUnit string
}

// GetAthenzIdentity this method can be called from within a GCF (Google Cloud Function) - to get an Athenz certificate from ZTS.
// See https://cloud.google.com/functions/docs/writing/write-http-functions#http-example-go
func GetAthenzIdentity(athenzDomain, athenzService, gcpProjectId, athenzProvider, ztsUrl, certDomain, spiffeTrustDomain string, optionalSubjectFields CsrSubjectFields) (*SiaCertData, error) {

	athenzDomain = strings.ToLower(athenzDomain)
	athenzService = strings.ToLower(athenzService)
	athenzProvider = strings.ToLower(athenzProvider)

	// Get an identity-document for this GCF from GCP.

	attestationData, err := gcpa.New("http://metadata", "", ztsUrl)
	if err != nil {
		return nil, err
	}

	// Create a private-key.
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, err
	}

	// Create a CSR (and a private-key).
	csr, err := generateCsr(
		privateKey,
		athenzDomain+"."+athenzService,
		optionalSubjectFields,
		[]string{},
		[]string{
			util.SanDNSHostname(athenzDomain, athenzService, certDomain),
		},
		[]string{
			util.GetSvcSpiffeUri(spiffeTrustDomain, "default", athenzDomain, athenzService),
			util.SanURIInstanceId(athenzProvider, "gcp-function-"+gcpProjectId),
		})

	// Encode the CSR to PEM.
	var csrPemBuffer bytes.Buffer
	err = pem.Encode(&csrPemBuffer, &pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csr})
	if err != nil {
		return nil, fmt.Errorf("cannot encode CSR to PEM: %v", err)
	}

	// Send CSR to ZTS.
	siaCertData, err := getCredsFromZts(
		ztsUrl,
		zts.InstanceRegisterInformation{
			Domain:          zts.DomainName(athenzDomain),
			Service:         zts.SimpleName(athenzService),
			Provider:        zts.ServiceName(athenzProvider),
			AttestationData: attestationData,
			Csr:             csrPemBuffer.String(),
		})
	if err != nil {
		return nil, err
	}

	siaCertData.PrivateKey = privateKey
	siaCertData.PrivateKeyPem = util.PrivatePem(privateKey)
	return siaCertData, nil
}

// Generate a CSR.
func generateCsr(privateKey *rsa.PrivateKey, commonName string, csrSubjectFields CsrSubjectFields, altNamesIp, altNamesDns, altNamesUri []string) ([]byte, error) {

	//note: RFC 6125 states that if the SAN (Subject Alternative Name)
	//exists, it is used, not the CN. So, we will always put the Athenz
	//name in the CN (it is *not* a DNS domain name), and put the host
	//name into the SAN.
	subj := pkix.Name{CommonName: commonName}
	if csrSubjectFields.Country != "" {
		subj.Country = []string{csrSubjectFields.Country}
	}
	if csrSubjectFields.State != "" {
		subj.Province = []string{csrSubjectFields.State}
	}
	if csrSubjectFields.Locality != "" {
		subj.Locality = []string{csrSubjectFields.Locality}
	}
	if csrSubjectFields.Organization != "" {
		subj.Organization = []string{csrSubjectFields.Organization}
	}
	if csrSubjectFields.OrganizationUnit != "" {
		subj.OrganizationalUnit = []string{csrSubjectFields.OrganizationUnit}
	}
	template := x509.CertificateRequest{
		Subject:            subj,
		SignatureAlgorithm: x509.SHA256WithRSA,
	}

	// SAN IPs.
	template.IPAddresses = make([]net.IP, 0)
	for _, ipString := range altNamesIp {
		ip := net.ParseIP(ipString)
		if ip == nil {
			log.Printf("WARNING: SAN IP %q is not a valid IP address", ipString)
		} else {
			template.IPAddresses = append(template.IPAddresses, ip)
		}
	}

	// SAN DNS names.
	template.DNSNames = altNamesDns

	// SAN URIs
	template.URIs = []*url.URL{}
	for _, uriString := range altNamesUri {
		uri, err := url.Parse(uriString)
		if err != nil {
			log.Printf("WARNING: SAN URI %q is invalid: %v", uriString, err)
		} else {
			template.URIs = append(template.URIs, uri)
		}
	}

	csr, err := x509.CreateCertificateRequest(rand.Reader, &template, privateKey)
	if err != nil {
		return nil, fmt.Errorf("cannot create CSR: %v", err)
	}

	return csr, nil
}

// Send CSR to ZTS.
func getCredsFromZts(ztsUrl string, instanceRegisterInformation zts.InstanceRegisterInformation) (*SiaCertData, error) {
	requestUrl := ztsUrl + "/instance"

	requestPayload, err := json.Marshal(instanceRegisterInformation)
	if err != nil {
		return nil, fmt.Errorf("can't JSON-encode request body: %v", err)
	}

	req, err := http.NewRequest(http.MethodPost, requestUrl, bytes.NewReader(requestPayload))
	if err != nil {
		return nil, fmt.Errorf("failed to prepare HTTP request to    %q    : %v", requestUrl, err)
	}
	req.Header.Add("Content-type", "application/json")
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to make HTTP request to    %q    : %v", requestUrl, err)
	}
	resBody, err := io.ReadAll(res.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response of HTTP request to    %q    : %v", requestUrl, err)
	}
	if res.StatusCode != 201 {
		// Bad HTTP status code.
		return nil, fmt.Errorf("HTTP request to    %q    returned %d (%s). Body:\n%s", requestUrl, res.StatusCode, res.Status, string(resBody))
	}

	// Parse response.
	var instanceIdentity zts.InstanceIdentity
	err = json.Unmarshal(resBody, &instanceIdentity)
	if err != nil {
		return nil, fmt.Errorf("failed to parse JSON response from    %q    : %v", requestUrl, err)
	}

	// Decode the ZTS certificate from PEM format.
	x509CertificateBlock, _ := pem.Decode([]byte(instanceIdentity.X509Certificate))
	if x509CertificateBlock == nil || x509CertificateBlock.Type != "CERTIFICATE" {
		log.Fatalf("Failed to decode PEM block containing the certificate from ZTS")
	}
	x509Certificate, err := x509.ParseCertificate(x509CertificateBlock.Bytes)
	if err != nil {
		log.Fatalf("Failed to parse the certificate from ZTS")
	}

	return &SiaCertData{
		X509Certificate:          x509Certificate,
		X509CertificatePem:       instanceIdentity.X509Certificate,
		X509CertificateSignerPem: instanceIdentity.X509CertificateSigner,
	}, nil
}

func generateSecretJsonData(athenzDomain, athenzService string, siaCertData *SiaCertData) ([]byte, error) {

	siaYield := make(map[string]string)
	siaYield[athenzDomain+"."+athenzService+".cert.pem"] = siaCertData.X509CertificatePem
	siaYield[athenzDomain+"."+athenzService+".key.pem"] = siaCertData.PrivateKeyPem
	siaYield["ca.cert.pem"] = siaCertData.X509CertificateSignerPem

	// Add the current time to the JSON.
	siaYield["time"] = strconv.FormatInt(time.Now().Unix(), 10)

	return json.MarshalIndent(siaYield, "", "  ")
}

// StoreAthenzIdentityInSecretManager store the retrieved athenz identity in the
// specified secret. The secret is stored in the following json format:
//
//	{
//	   "<domain>.<service>.cert.pem":"<x509-cert-pem>,
//	   "<domain>.<service>.key.pem":"<pkey-pem>,
//	   "ca.cert.pem":"<ca-cert-pem>,
//	   "time": <utc-timestamp>
//	}
//
// The secret specified by the name must be pre-created and the service account
// that the function is invoked with must have been authorized to assume the
// "Secret Manager Secret Version Adder" role
func StoreAthenzIdentityInSecretManager(athenzDomain, athenzService, gcpProjectId, secretName string, siaCertData *SiaCertData) error {

	// Create the GCP secret-manager client.
	ctx := context.Background()
	secretManagerClient, err := secretmanager.NewClient(ctx)
	if err != nil {
		return err
	}
	defer (func() {
		_ = secretManagerClient.Close()
	})()

	// generate our payload
	keyCertJson, err := generateSecretJsonData(athenzDomain, athenzService, siaCertData)
	if err != nil {
		return err
	}

	// Build the request
	addSecretVersionReq := &secretmanagerpb.AddSecretVersionRequest{
		Parent: "projects/" + gcpProjectId + "/secrets/" + secretName,
		Payload: &secretmanagerpb.SecretPayload{
			Data: keyCertJson,
		},
	}

	// Call the API.
	_, err = secretManagerClient.AddSecretVersion(ctx, addSecretVersionReq)
	return err
}
