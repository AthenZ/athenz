// Copyright The Athenz Authors
// Licensed under the terms of the Apache version 2.0 license. See LICENSE file for terms.

// Package usercert provides a reusable library for requesting User X509
// Certificates from an Athenz ZTS Server using IdP (Identity Provider)
// authentication. It handles the full OAuth2 authorization code flow,
// CSR generation, and certificate request submission.
//
// Users can build thin CLI wrappers that hard-code organisation-specific
// options and delegate all logic to this package:
//
//	func main() {
//	    usercert.Run(usercert.Options{
//	        IdpEndpoint:    "https://idp.example.com/oauth2/authorize",
//	        IdpClientId:    "my-client-id",
//	        SubjectOrg:     "Example Inc.",
//	        SubjectOrgUnit: "Engineering",
//	    })
//	}
package usercert

import (
	"bytes"
	"crypto"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"log"
	"net/http"
	"net/url"
	"os"

	"github.com/AthenZ/athenz/clients/go/zts"
	"github.com/AthenZ/athenz/libs/go/athenzutils"
	"github.com/AthenZ/athenz/libs/go/tls/config"
)

// Options configures the user certificate request flow.
// Fields that are pre-set (non-zero) before calling Run are treated as
// hard-coded and will NOT be overridden by command-line flags.
type Options struct {
	ZtsURL            string // ZTS server URL (required)
	PrivateKeyFile    string // path to private key PEM file (required)
	UserName          string // user name without domain prefix (required)
	IdpEndpoint       string // IdP OAuth2 authorization endpoint (required)
	IdpClientId       string // IdP OAuth2 client ID (required)
	CertFile          string // output cert file; empty means stdout
	CACertFile        string // CA cert file for ZTS TLS verification
	SubjectCountry    string // CSR subject Country field
	SubjectOrg        string // CSR subject Organization field
	SubjectOrgUnit    string // CSR subject OrganizationalUnit field
	SpiffeTrustDomain string // SPIFFE trust domain for URI SAN
	Scope             string // OIDC scope parameter (default: "openid")
	CallbackPort      int    // local port for OAuth2 callback server
	CallbackTimeout   int    // seconds to wait for IdP callback
	ExpiryTime        int    // certificate expiry in minutes (0 = server default)
	PKCE              bool   // enable PKCE for IdP auth flow
	Proxy             bool   // use HTTP proxy from environment
	Verbose           bool   // enable verbose logging
}

type signer struct {
	key       crypto.Signer
	algorithm x509.SignatureAlgorithm
}

// RequestCertificate performs the full user certificate request flow:
// reading the private key, generating a CSR, running the IdP auth flow,
// and submitting the request to ZTS. It returns the certificate PEM string.
// All required fields in opts must be populated.
func RequestCertificate(opts Options) (string, error) {

	keyBytes, err := os.ReadFile(opts.PrivateKeyFile)
	if err != nil {
		return "", fmt.Errorf("unable to read private key file %s: %v", opts.PrivateKeyFile, err)
	}

	pkSigner, err := newSigner(keyBytes)
	if err != nil {
		return "", fmt.Errorf("unable to retrieve private key %s: %v", opts.PrivateKeyFile, err)
	}

	csrData, err := generateCSR(pkSigner, opts.UserName, opts.SubjectCountry, opts.SubjectOrg,
		opts.SubjectOrgUnit, opts.SpiffeTrustDomain)
	if err != nil {
		return "", fmt.Errorf("unable to generate CSR: %v", err)
	}

	if opts.Verbose {
		log.Printf("Starting IdP authentication flow against %s\n", opts.IdpEndpoint)
	}

	scope := opts.Scope
	if scope == "" {
		scope = "openid"
	}
	authCode, codeVerifier, err := GetAuthCode(opts.IdpEndpoint, opts.IdpClientId, scope, opts.CallbackPort,
		opts.CallbackTimeout, opts.PKCE, opts.Verbose)
	if err != nil {
		return "", fmt.Errorf("failed to obtain IdP auth code: %v", err)
	}

	if opts.Verbose {
		log.Println("Successfully obtained IdP auth code")
	}

	config, err := tlsConfigFromPEM(opts.CACertFile)
	if err != nil {
		return "", fmt.Errorf("unable to create TLS config: %v", err)
	}
	transport := &http.Transport{
		TLSClientConfig: config,
	}
	if opts.Proxy {
		transport.Proxy = http.ProxyFromEnvironment
	}
	client := zts.NewClient(opts.ZtsURL, transport)

	attestationData := authCode
	if codeVerifier != "" {
		attestationData = fmt.Sprintf("%s&code_verifier=%s", authCode, codeVerifier)
	}
	req := &zts.UserCertificateRequest{
		Name:            opts.UserName,
		Csr:             csrData,
		AttestationData: attestationData,
	}
	if opts.ExpiryTime > 0 {
		expiry := int32(opts.ExpiryTime)
		req.ExpiryTime = &expiry
	}

	if opts.Verbose {
		log.Printf("Requesting user certificate for %s from %s\n", opts.UserName, opts.ZtsURL)
	}

	userCert, err := client.PostUserCertificateRequest(req)
	if err != nil {
		return "", fmt.Errorf("PostUserCertificateRequest failed for %s: %v", opts.UserName, err)
	}

	return userCert.X509Certificate, nil
}

// Run executes the full user certificate request flow.
// It writes the certificate to CertFile and returns
// the certificate string and any errors that occur.
func Run(opts Options) (string, error) {

	if opts.PrivateKeyFile == "" || opts.UserName == "" {
		return "", fmt.Errorf("missing required Private Key File or User Name")
	}

	if opts.ZtsURL == "" || opts.IdpEndpoint == "" || opts.IdpClientId == "" {
		defaultConfig, _ := athenzutils.ReadDefaultConfig()
		if opts.ZtsURL == "" && defaultConfig != nil {
			opts.ZtsURL = defaultConfig.Zts
		}
		if opts.ZtsURL == "" || opts.IdpEndpoint == "" || opts.IdpClientId == "" {
			return "", fmt.Errorf("missing required ZTS URL, IdP Endpoint, or IdP Client ID")
		}
	}

	cert, err := RequestCertificate(opts)
	if err != nil {
		return "", fmt.Errorf("RequestCertificate failed: %v", err)
	}

	if opts.CertFile != "" {
		err = os.WriteFile(opts.CertFile, []byte(cert), 0600)
		if err != nil {
			return "", fmt.Errorf("Unable to save user certificate to %s: %v", opts.CertFile, err)
		}
	}
	return cert, nil
}

func generateCSR(keySigner *signer, principalName, subjC, subjO, subjOU, spiffeTrustDomain string) (string, error) {

	subj := pkix.Name{
		CommonName: principalName,
	}
	if subjC != "" {
		subj.Country = []string{subjC}
	}
	if subjO != "" {
		subj.Organization = []string{subjO}
	}
	if subjOU != "" {
		subj.OrganizationalUnit = []string{subjOU}
	}
	template := x509.CertificateRequest{
		Subject:            subj,
		SignatureAlgorithm: keySigner.algorithm,
	}

	if spiffeTrustDomain != "" {
		spiffeURI := fmt.Sprintf("spiffe://%s/ns/default/sa/%s", spiffeTrustDomain, principalName)
		uriPtr, err := url.Parse(spiffeURI)
		if err == nil {
			template.URIs = []*url.URL{uriPtr}
		}
	}

	csr, err := x509.CreateCertificateRequest(rand.Reader, &template, keySigner.key)
	if err != nil {
		return "", fmt.Errorf("cannot create CSR: %v", err)
	}
	block := &pem.Block{
		Type:  "CERTIFICATE REQUEST",
		Bytes: csr,
	}
	var buf bytes.Buffer
	err = pem.Encode(&buf, block)
	if err != nil {
		return "", fmt.Errorf("cannot encode CSR to PEM: %v", err)
	}
	return buf.String(), nil
}

func newSigner(privateKeyPEM []byte) (*signer, error) {
	key, algorithm, err := athenzutils.ExtractSignerInfo(privateKeyPEM)
	if err != nil {
		return nil, err
	}
	return &signer{key: key, algorithm: algorithm}, nil
}

func tlsConfigFromPEM(cacertFile string) (*tls.Config, error) {
	config := config.ClientTLSConfig()
	if cacertFile == "" {
		return config, nil
	}
	cacertpem, err := os.ReadFile(cacertFile)
	if err != nil {
		return nil, fmt.Errorf("unable to read CA certificate file %s: %v", cacertFile, err)
	}
	certPool := x509.NewCertPool()
	certPool.AppendCertsFromPEM(cacertpem)
	config.RootCAs = certPool
	return config, nil
}
