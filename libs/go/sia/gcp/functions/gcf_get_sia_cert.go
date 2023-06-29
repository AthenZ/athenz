package functions

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"github.com/AthenZ/athenz/clients/go/zts"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"strings"
)

// GcfGetSiaCerts this method can be called from within a GCF (Google Cloud Function) -
//
//	to get an Athenz certificate from ZTS.
//
// This file should usually be copied without changes into the GCF source-code.
//
// See https://cloud.google.com/functions/docs/writing/write-http-functions#http-example-go
func GcfGetSiaCerts(
	athenzDomain string,
	athenzService string,
	gcpProjectId string,
	athenzProvider string,
	ztsUrl string,
	certDomain string,
	optionalSubjectFields CsrSubjectFields,
) (*SiaCertData, error) {

	athenzDomain = strings.ToLower(athenzDomain)
	athenzService = strings.ToLower(athenzService)
	athenzProvider = strings.ToLower(athenzProvider)

	// Get an identity-document for this GCF from GCP.
	attestationData, err := getGcpFunctionAttestationData(ztsUrl)
	if err != nil {
		return nil, err
	}
	//log.Printf("GCP Attestation Data: %s", attestationData) // commented out - sensitive info

	// Create a private-key.
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, err
	}

	// Convert the private-key to PEM format.
	privateKeyDer := x509.MarshalPKCS1PrivateKey(privateKey)
	privateKeyBlock := pem.Block{Type: "RSA PRIVATE KEY", Bytes: privateKeyDer}
	privateKeyPem := pem.EncodeToMemory(&privateKeyBlock)
	//log.Printf("Private Key:\n%s", privateKeyPem) // commented out - sensitive info

	// Create a CSR (and a private-key).
	csr, err := generateCsr(
		privateKey,
		athenzDomain+"."+athenzService,
		optionalSubjectFields,
		[]string{},
		[]string{
			athenzService + "." + strings.Replace(athenzDomain, ".", "-", -1) + "." + certDomain,
		},
		[]string{
			"spiffe://" + athenzDomain + "/sa/" + athenzService,
			"athenz://instanceid/" + athenzProvider + "/gcp-function-" + gcpProjectId,
		})

	// Encode the CSR to PEM.
	var csrPemBuffer bytes.Buffer
	err = pem.Encode(&csrPemBuffer, &pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csr})
	if err != nil {
		return nil, fmt.Errorf("cannot encode CSR to PEM: %v", err)
	}
	csrPem := csrPemBuffer.String()
	//log.Printf("CSR to send to ZTS:\n%s", csrPem) // commented out - sensitive info

	// Send CSR to ZTS.
	siaCertData, err := getCredsFromZts(
		ztsUrl,
		zts.InstanceRegisterInformation{
			Domain:          zts.DomainName(athenzDomain),
			Service:         zts.SimpleName(athenzService),
			Provider:        zts.ServiceName(athenzProvider),
			AttestationData: attestationData,
			Csr:             csrPem,
		})
	if err != nil {
		return nil, err
	}

	siaCertData.privateKey = privateKey
	siaCertData.privateKeyPem = string(privateKeyPem)
	return siaCertData, nil
}

// SiaCertData response of GcfGetSiaCerts()
type SiaCertData struct {
	privateKey               *rsa.PrivateKey
	privateKeyPem            string
	x509Certificate          *x509.Certificate
	x509CertificatePem       string
	x509CertificateSignerPem string
}

// CsrSubjectFields are optional fields for the CSR: the fields will appear in the created certificate's "Subject".
type CsrSubjectFields struct {
	Country          string
	State            string
	Locality         string
	Organization     string
	OrganizationUnit string
}

// Get an identity-document for this GCF from GCP.
func getGcpFunctionAttestationData(ztsUrl string) (string, error) {
	gcpIdentityUrl := "http://metadata/computeMetadata/v1/instance/service-accounts/default/identity?audience=" + ztsUrl + "&format=full"
	//log.Printf("Getting GCF identity from: %s", gcpIdentityUrl)

	req, err := http.NewRequest(http.MethodGet, gcpIdentityUrl, nil)
	if err != nil {
		return "", fmt.Errorf("failed to prepare HTTP request to    %q    : %v", gcpIdentityUrl, err)
	}
	req.Header.Add("Metadata-Flavor", "Google")
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("failed to make HTTP request to    %q    : %v", gcpIdentityUrl, err)
	}
	resBody, err := io.ReadAll(res.Body)
	if err != nil {
		return "", fmt.Errorf("failed to read response of HTTP request to    %q    : %v", gcpIdentityUrl, err)
	}
	if res.StatusCode != 200 {
		// Bad HTTP status code.
		return "", fmt.Errorf("HTTP request to    %q    returned %d (%s). Body:\n%s", gcpIdentityUrl, res.StatusCode, res.Status, string(resBody))
	}
	return "{\"identityToken\":\"" + string(resBody) + "\"}", nil
}

// Generate a CSR.
func generateCsr(
	privateKey *rsa.PrivateKey,
	commonName string,
	csrSubjectFields CsrSubjectFields,
	altNamesIp []string,
	altNamesDns []string,
	altNamesUri []string,
) ([]byte, error) {

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
		x509Certificate:          x509Certificate,
		x509CertificatePem:       instanceIdentity.X509Certificate,
		x509CertificateSignerPem: instanceIdentity.X509CertificateSigner,
	}, nil
}
