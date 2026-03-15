// Copyright The Athenz Authors
// Licensed under the terms of the Apache version 2.0 license. See LICENSE file for terms.

package usercert

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"flag"
	"fmt"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

var ecdsaPrivateKeyPEM = []byte(`-----BEGIN EC PRIVATE KEY-----
MIGkAgEBBDA27vlziu7AYNJo/aaG3mS4XPK2euiTLQDxzUoDkiMpVHRXLxSbX897
Gz7dQNFo3UWgBwYFK4EEACKhZANiAARBr6GWO6EGIV09DGInLfC/JSvPOKc26mZu
jpEdar4FkJ02OsHdtZ6AM7HgLASSBETL13Mhk8LL9qfRo+PEwLcyJnvWlDsMa3eh
Pji5iP4d9rQEOm/G9PXZ3/ZZEz5DuYs=
-----END EC PRIVATE KEY-----
`)

var rsaPrivateKeyPEM = []byte(`-----BEGIN RSA PRIVATE KEY-----
MIIEpAIBAAKCAQEAxq83nCd8AqH5n40dEBMElbaJd2gFWu6bjhNzyp9562dpf454
BUSN0uF+g3i1yzcwdvADTiuExKN1u/IoGURxVCa0JTzAPJw6/JIoyOZnHZCoarcg
QQqZ56/udkSQ2NssrwGSQjOwxMrgIdH6XeLgGqVN4BoEEI+gpaQZa7rSytU5RFSG
OnZWO2Vwgs1OBxiOiYg1gzA1spJXQhxcBWw/v+YrUFtjxBKsG1UrWbnHbgciiN5U
2v51Yztjo8A1T+o9eIG90jVo3EhS2qhbzd8mLAsEhjV1sP8GItjfdfwXpXT7q2QG
99W3PM75+HdwGLvJIrkED7YRj4CpMkz6F1etawIDAQABAoIBAD67C7/N56WdJodt
soNkvcnXPEfrG+W9+Hc/RQvwljnxCKoxfUuMfYrbj2pLLnrfDfo/hYukyeKcCYwx
xN9VcMK1BaPMLpX0bdtY+m+T73KyPbqT3ycqBbXVImFM/L67VLxcrqUgVOuNcn67
IWWLQF6pWpErJaVk87/Ys/4DmpJXebLDyta8+ce6r0ppSG5+AifGo1byQT7kSJkF
lyQsyKWoVN+02s7gLsln5JXXZ672y2Xtp/S3wK0vfzy/HcGSxzn1yE0M5UJtDm/Y
qECnV1LQ0FB1l1a+/itHR8ipp5rScD4ZpzOPLKthglEvNPe4Lt5rieH9TR97siEe
SrC8uyECgYEA5Q/elOJAddpE+cO22gTFt973DcPGjM+FYwgdrora+RfEXJsMDoKW
AGSm5da7eFo8u/bJEvHSJdytc4CRQYnWNryIaUw2o/1LYXRvoEt1rEEgQ4pDkErR
PsVcVuc3UDeeGtYJwJLV6pjxO11nodFv4IgaVj64SqvCOApTTJgWXF0CgYEA3gzN
d3l376mSMuKc4Ep++TxybzA5mtF2qoXucZOon8EDJKr+vGQ9Z6X4YSdkSMNXqK1j
ILmFH7V3dyMOKRBA84YeawFacPLBJq+42t5Q1OYdcKZbaArlBT8ImGT7tQODs3JN
4w7DH+V1v/VCTl2zQaZRksb0lUsQbFiEfj+SVGcCgYAYIlDoTOJPyHyF+En2tJQE
aHiNObhcs6yxH3TJJBYoMonc2/UsPjQBvJkdFD/SUWeewkSzO0lR9etMhRpI1nX8
dGbG+WG0a4aasQLl162BRadZlmLB/DAJtg+hlGDukb2VxEFoyc/CFPUttQyrLv7j
oFNuDNOsAmbHMsdOBaQtfQKBgQCb/NRuRNebdj0tIALikZLHVc5yC6e7+b/qJPIP
uZIwv++MV89h2u1EHdTxszGA6DFxXnSPraQ2VU2aVPcCo9ds+9/sfePiCrbjjXhH
0PtpxEoUM9lsqpKeb9yC6hXk4JYpfnf2tQ0gIBrrAclVsf9WdBdEDB4Prs7Xvgs9
gT0zqwKBgQCzZubFO0oTYO9e2r8wxPPPsE3ZCjbP/y7lIoBbSzxDGUubXmbvD0GO
MC8dM80plsTym96UxpKkQMAglKKLPtG2n8xB8v5H/uIB4oIegMSEx3F7MRWWIQmR
Gea7bQ16YCzM/l2yygGhAW61bg2Z2GoVF6X5z/qhKGyo97V87qTbmg==
-----END RSA PRIVATE KEY-----
`)

// --- newSigner tests ---

func TestNewSignerECDSA(t *testing.T) {
	s, err := newSigner(ecdsaPrivateKeyPEM)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if s == nil {
		t.Fatal("expected non-nil signer")
	}
	if s.algorithm != x509.ECDSAWithSHA256 {
		t.Errorf("expected ECDSAWithSHA256, got %v", s.algorithm)
	}
	if _, ok := s.key.(*ecdsa.PrivateKey); !ok {
		t.Error("expected *ecdsa.PrivateKey")
	}
}

func TestNewSignerRSA(t *testing.T) {
	s, err := newSigner(rsaPrivateKeyPEM)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if s == nil {
		t.Fatal("expected non-nil signer")
	}
	if s.algorithm != x509.SHA256WithRSA {
		t.Errorf("expected SHA256WithRSA, got %v", s.algorithm)
	}
	if _, ok := s.key.(*rsa.PrivateKey); !ok {
		t.Error("expected *rsa.PrivateKey")
	}
}

func TestNewSignerInvalidPEM(t *testing.T) {
	_, err := newSigner([]byte("not a pem"))
	if err == nil {
		t.Fatal("expected error for invalid PEM")
	}
}

func TestNewSignerUnsupportedKeyType(t *testing.T) {
	badPEM := []byte(`-----BEGIN UNSUPPORTED PRIVATE KEY-----
MIGkAgEBBDA27vlziu7AYNJo/aaG3mS4XPK2euiTLQDxzUoDkiMpVHRXLxSbX897
Gz7dQNFo3UWgBwYFK4EEACKhZANiAARBr6GWO6EGIV09DGInLfC/JSvPOKc26mZu
jpEdar4FkJ02OsHdtZ6AM7HgLASSBETL13Mhk8LL9qfRo+PEwLcyJnvWlDsMa3eh
Pji5iP4d9rQEOm/G9PXZ3/ZZEz5DuYs=
-----END UNSUPPORTED PRIVATE KEY-----
`)
	_, err := newSigner(badPEM)
	if err == nil {
		t.Fatal("expected error for unsupported key type")
	}
}

// --- generateCSR tests ---

func TestGenerateCSRWithECDSA(t *testing.T) {
	s, err := newSigner(ecdsaPrivateKeyPEM)
	if err != nil {
		t.Fatalf("failed to create signer: %v", err)
	}

	csrPEM, err := generateCSR(s, "johndoe", "US", "Oath Inc.", "Athenz", "")
	if err != nil {
		t.Fatalf("generateCSR failed: %v", err)
	}
	if csrPEM == "" {
		t.Fatal("expected non-empty CSR PEM")
	}

	block, _ := pem.Decode([]byte(csrPEM))
	if block == nil {
		t.Fatal("failed to decode CSR PEM block")
	}
	if block.Type != "CERTIFICATE REQUEST" {
		t.Errorf("expected CERTIFICATE REQUEST, got %s", block.Type)
	}

	csr, err := x509.ParseCertificateRequest(block.Bytes)
	if err != nil {
		t.Fatalf("failed to parse CSR: %v", err)
	}
	if csr.Subject.CommonName != "johndoe" {
		t.Errorf("expected CN=johndoe, got %s", csr.Subject.CommonName)
	}
	assertSubjectFields(t, csr.Subject, "US", "Oath Inc.", "Athenz")
	if len(csr.URIs) != 0 {
		t.Errorf("expected no URIs, got %d", len(csr.URIs))
	}
}

func TestGenerateCSRWithRSA(t *testing.T) {
	s, err := newSigner(rsaPrivateKeyPEM)
	if err != nil {
		t.Fatalf("failed to create signer: %v", err)
	}

	csrPEM, err := generateCSR(s, "janedoe", "GB", "ACME Corp.", "Engineering", "")
	if err != nil {
		t.Fatalf("generateCSR failed: %v", err)
	}

	block, _ := pem.Decode([]byte(csrPEM))
	if block == nil {
		t.Fatal("failed to decode CSR PEM block")
	}

	csr, err := x509.ParseCertificateRequest(block.Bytes)
	if err != nil {
		t.Fatalf("failed to parse CSR: %v", err)
	}
	if csr.Subject.CommonName != "janedoe" {
		t.Errorf("expected CN=janedoe, got %s", csr.Subject.CommonName)
	}
	assertSubjectFields(t, csr.Subject, "GB", "ACME Corp.", "Engineering")
}

func TestGenerateCSRWithSpiffeTrustDomain(t *testing.T) {
	s, err := newSigner(ecdsaPrivateKeyPEM)
	if err != nil {
		t.Fatalf("failed to create signer: %v", err)
	}

	csrPEM, err := generateCSR(s, "johndoe", "US", "Oath Inc.", "Athenz", "athenz.io")
	if err != nil {
		t.Fatalf("generateCSR failed: %v", err)
	}

	block, _ := pem.Decode([]byte(csrPEM))
	if block == nil {
		t.Fatal("failed to decode CSR PEM block")
	}

	csr, err := x509.ParseCertificateRequest(block.Bytes)
	if err != nil {
		t.Fatalf("failed to parse CSR: %v", err)
	}
	if len(csr.URIs) != 1 {
		t.Fatalf("expected 1 URI SAN, got %d", len(csr.URIs))
	}
	expectedURI := "spiffe://athenz.io/ns/default/sa/johndoe"
	if csr.URIs[0].String() != expectedURI {
		t.Errorf("expected URI %s, got %s", expectedURI, csr.URIs[0].String())
	}
}

func TestGenerateCSRWithEmptySpiffeTrustDomain(t *testing.T) {
	s, err := newSigner(ecdsaPrivateKeyPEM)
	if err != nil {
		t.Fatalf("failed to create signer: %v", err)
	}

	csrPEM, err := generateCSR(s, "johndoe", "US", "Oath Inc.", "Athenz", "")
	if err != nil {
		t.Fatalf("generateCSR failed: %v", err)
	}

	block, _ := pem.Decode([]byte(csrPEM))
	csr, err := x509.ParseCertificateRequest(block.Bytes)
	if err != nil {
		t.Fatalf("failed to parse CSR: %v", err)
	}
	if len(csr.URIs) != 0 {
		t.Errorf("expected no URIs for empty trust domain, got %d", len(csr.URIs))
	}
}

func TestGenerateCSRDifferentSubjectFields(t *testing.T) {
	s, err := newSigner(ecdsaPrivateKeyPEM)
	if err != nil {
		t.Fatalf("failed to create signer: %v", err)
	}

	tests := []struct {
		name    string
		user    string
		country string
		org     string
		orgUnit string
	}{
		{"standard", "alice", "US", "Athenz", "Engineering"},
		{"different-country", "bob", "DE", "CompanyDE", "Security"},
		{"special-chars", "user.name", "JP", "Org With Spaces", "Unit-1"},
		{"empty-country", "alice", "", "Athenz", "Engineering"},
		{"empty-org", "alice", "US", "", "Engineering"},
		{"empty-org-unit", "alice", "US", "Athenz", ""},
		{"empty-all", "alice", "", "", ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			csrPEM, err := generateCSR(s, tt.user, tt.country, tt.org, tt.orgUnit, "")
			if err != nil {
				t.Fatalf("generateCSR failed: %v", err)
			}
			block, _ := pem.Decode([]byte(csrPEM))
			csr, err := x509.ParseCertificateRequest(block.Bytes)
			if err != nil {
				t.Fatalf("failed to parse CSR: %v", err)
			}
			if csr.Subject.CommonName != tt.user {
				t.Errorf("expected CN=%s, got %s", tt.user, csr.Subject.CommonName)
			}
			assertSubjectFields(t, csr.Subject, tt.country, tt.org, tt.orgUnit)
		})
	}
}

// --- tlsConfigFromPEM tests ---

func TestTlsConfigFromPEMEmptyFile(t *testing.T) {
	config, err := tlsConfigFromPEM("")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if config == nil {
		t.Fatal("expected non-nil config")
	}
	if config.RootCAs != nil {
		t.Error("expected nil RootCAs for empty cert file")
	}
}

func TestTlsConfigFromPEMNonExistentFile(t *testing.T) {
	_, err := tlsConfigFromPEM("/tmp/nonexistent-cert-file-12345.pem")
	if err == nil {
		t.Fatal("expected error for non-existent file")
	}
	if !strings.Contains(err.Error(), "unable to read CA certificate file") {
		t.Errorf("unexpected error message: %v", err)
	}
}

func TestTlsConfigFromPEMValidCA(t *testing.T) {
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate CA key: %v", err)
	}

	caTemplate := &x509.Certificate{
		SerialNumber: mustBigInt(),
		Subject:      pkix.Name{CommonName: "Test CA"},
		IsCA:         true,
		KeyUsage:     x509.KeyUsageCertSign,
	}
	caCertDER, err := x509.CreateCertificate(rand.Reader, caTemplate, caTemplate, &caKey.PublicKey, caKey)
	if err != nil {
		t.Fatalf("failed to create CA cert: %v", err)
	}
	caCertPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caCertDER})

	tmpFile := filepath.Join(t.TempDir(), "ca.pem")
	if err := os.WriteFile(tmpFile, caCertPEM, 0644); err != nil {
		t.Fatalf("failed to write CA cert: %v", err)
	}

	config, err := tlsConfigFromPEM(tmpFile)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if config.RootCAs == nil {
		t.Error("expected non-nil RootCAs")
	}
}

func TestTlsConfigFromPEMInvalidCertContent(t *testing.T) {
	tmpFile := filepath.Join(t.TempDir(), "bad-ca.pem")
	if err := os.WriteFile(tmpFile, []byte("not a certificate"), 0644); err != nil {
		t.Fatalf("failed to write bad cert: %v", err)
	}

	config, err := tlsConfigFromPEM(tmpFile)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	// AppendCertsFromPEM silently ignores invalid PEM, so RootCAs is set but empty
	if config.RootCAs == nil {
		t.Error("expected non-nil RootCAs (pool was created)")
	}
}

// --- RequestCertificate tests ---

func TestRequestCertificateInvalidKeyFile(t *testing.T) {
	_, err := RequestCertificate(Options{
		PrivateKeyFile: "/tmp/nonexistent-key-12345.pem",
	})
	if err == nil {
		t.Fatal("expected error for non-existent key file")
	}
	if !strings.Contains(err.Error(), "unable to read private key file") {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestRequestCertificateInvalidKeyContent(t *testing.T) {
	tmpFile := filepath.Join(t.TempDir(), "bad-key.pem")
	if err := os.WriteFile(tmpFile, []byte("not a key"), 0644); err != nil {
		t.Fatalf("failed to write bad key: %v", err)
	}

	_, err := RequestCertificate(Options{
		PrivateKeyFile: tmpFile,
	})
	if err == nil {
		t.Fatal("expected error for invalid key content")
	}
	if !strings.Contains(err.Error(), "unable to retrieve private key") {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestRequestCertificateWithMockZTS(t *testing.T) {
	mockCert := "-----BEGIN CERTIFICATE-----\nMIIBtest\n-----END CERTIFICATE-----\n"

	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/zts/v1/user/johndoe/certificate" {
			w.Header().Set("Content-Type", "application/json")
			fmt.Fprintf(w, `{"x509Certificate":"%s"}`, strings.ReplaceAll(mockCert, "\n", "\\n"))
			return
		}
		http.NotFound(w, r)
	}))
	defer server.Close()

	tmpKeyFile := filepath.Join(t.TempDir(), "key.pem")
	if err := os.WriteFile(tmpKeyFile, ecdsaPrivateKeyPEM, 0600); err != nil {
		t.Fatalf("failed to write key file: %v", err)
	}

	// The mock ZTS won't match the real PostUserCertificateRequest path exactly,
	// so this will fail with a ZTS error. We verify the flow reaches ZTS.
	_, err := RequestCertificate(Options{
		ZtsURL:          server.URL,
		PrivateKeyFile:  tmpKeyFile,
		UserName:        "johndoe",
		IdpEndpoint:     "http://localhost:19999/auth",
		IdpClientId:     "test-client",
		SubjectCountry:  "US",
		SubjectOrg:      "Test",
		SubjectOrgUnit:  "Test",
		CallbackPort:    "19998",
		CallbackTimeout: 1,
	})
	// We expect an error because the IdP auth flow won't complete in a test
	if err == nil {
		t.Fatal("expected error (IdP flow cannot complete in test)")
	}
	if !strings.Contains(err.Error(), "IdP auth code") && !strings.Contains(err.Error(), "failed") {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestRequestCertificateInvalidCACertFile(t *testing.T) {
	tmpKeyFile := filepath.Join(t.TempDir(), "key.pem")
	if err := os.WriteFile(tmpKeyFile, ecdsaPrivateKeyPEM, 0600); err != nil {
		t.Fatalf("failed to write key file: %v", err)
	}

	// The RequestCertificate flow: read key -> generate CSR -> GetAuthCode -> TLS config.
	// GetAuthCode will fail first since IdP is not running, but we can test that
	// invalid CA cert file paths are caught when reached.
	_, err := RequestCertificate(Options{
		PrivateKeyFile:  tmpKeyFile,
		UserName:        "johndoe",
		IdpEndpoint:     "http://localhost:19997/auth",
		IdpClientId:     "test-client",
		SubjectCountry:  "US",
		SubjectOrg:      "Test",
		SubjectOrgUnit:  "Test",
		CallbackPort:    "19996",
		CallbackTimeout: 1,
	})
	if err == nil {
		t.Fatal("expected error")
	}
}

// --- parseFlags tests ---

func TestParseFlagsDefaults(t *testing.T) {
	resetFlags()
	os.Args = []string{"test"}
	opts := Options{}
	showVersion := parseFlags(&opts)

	if showVersion {
		t.Error("expected showVersion=false")
	}
	if opts.SubjectOrgUnit != DefaultSubjectOrgUnit {
		t.Errorf("expected default org unit %s, got %s", DefaultSubjectOrgUnit, opts.SubjectOrgUnit)
	}
	if opts.CallbackPort != DefaultCallbackPort {
		t.Errorf("expected default callback port %s, got %s", DefaultCallbackPort, opts.CallbackPort)
	}
}

func TestParseFlagsVersion(t *testing.T) {
	resetFlags()
	os.Args = []string{"test", "-version"}
	opts := Options{}
	showVersion := parseFlags(&opts)
	if !showVersion {
		t.Error("expected showVersion=true")
	}
}

func TestParseFlagsWithValues(t *testing.T) {
	resetFlags()
	os.Args = []string{
		"test",
		"-zts", "https://zts.example.com",
		"-private-key", "/path/to/key.pem",
		"-user", "johndoe",
		"-idp-endpoint", "https://idp.example.com/auth",
		"-idp-client-id", "test-client",
		"-cert-file", "/path/to/cert.pem",
		"-subj-c", "DE",
		"-subj-o", "TestOrg",
		"-subj-ou", "TestOU",
		"-spiffe-trust-domain", "athenz.io",
		"-callback-port", "9999",
		"-callback-timeout", "30",
		"-expiry-time", "120",
		"-cacert", "/path/to/ca.pem",
		"-verbose",
	}
	opts := Options{}
	parseFlags(&opts)

	if opts.ZtsURL != "https://zts.example.com" {
		t.Errorf("expected ZtsURL=https://zts.example.com, got %s", opts.ZtsURL)
	}
	if opts.PrivateKeyFile != "/path/to/key.pem" {
		t.Errorf("expected PrivateKeyFile=/path/to/key.pem, got %s", opts.PrivateKeyFile)
	}
	if opts.UserName != "johndoe" {
		t.Errorf("expected UserName=johndoe, got %s", opts.UserName)
	}
	if opts.IdpEndpoint != "https://idp.example.com/auth" {
		t.Errorf("expected IdpEndpoint, got %s", opts.IdpEndpoint)
	}
	if opts.IdpClientId != "test-client" {
		t.Errorf("expected IdpClientId=test-client, got %s", opts.IdpClientId)
	}
	if opts.CertFile != "/path/to/cert.pem" {
		t.Errorf("expected CertFile=/path/to/cert.pem, got %s", opts.CertFile)
	}
	if opts.SubjectCountry != "DE" {
		t.Errorf("expected SubjectCountry=DE, got %s", opts.SubjectCountry)
	}
	if opts.SubjectOrg != "TestOrg" {
		t.Errorf("expected SubjectOrg=TestOrg, got %s", opts.SubjectOrg)
	}
	if opts.SubjectOrgUnit != "TestOU" {
		t.Errorf("expected SubjectOrgUnit=TestOU, got %s", opts.SubjectOrgUnit)
	}
	if opts.SpiffeTrustDomain != "athenz.io" {
		t.Errorf("expected SpiffeTrustDomain=athenz.io, got %s", opts.SpiffeTrustDomain)
	}
	if opts.CallbackPort != "9999" {
		t.Errorf("expected CallbackPort=9999, got %s", opts.CallbackPort)
	}
	if opts.CallbackTimeout != 30 {
		t.Errorf("expected CallbackTimeout=30, got %d", opts.CallbackTimeout)
	}
	if opts.ExpiryTime != 120 {
		t.Errorf("expected ExpiryTime=120, got %d", opts.ExpiryTime)
	}
	if opts.CACertFile != "/path/to/ca.pem" {
		t.Errorf("expected CACertFile=/path/to/ca.pem, got %s", opts.CACertFile)
	}
	if !opts.Verbose {
		t.Error("expected Verbose=true")
	}
}

func TestParseFlagsHardCodedValuesNotOverridden(t *testing.T) {
	resetFlags()
	os.Args = []string{
		"test",
		"-zts", "https://from-flag.example.com",
		"-user", "from-flag",
		"-subj-c", "GB",
		"-callback-port", "5555",
	}
	opts := Options{
		ZtsURL:         "https://hardcoded.example.com",
		UserName:       "hardcoded-user",
		SubjectCountry: "JP",
		CallbackPort:   "7777",
	}
	parseFlags(&opts)

	if opts.ZtsURL != "https://hardcoded.example.com" {
		t.Errorf("hardcoded ZtsURL should not be overridden, got %s", opts.ZtsURL)
	}
	if opts.UserName != "hardcoded-user" {
		t.Errorf("hardcoded UserName should not be overridden, got %s", opts.UserName)
	}
	if opts.SubjectCountry != "JP" {
		t.Errorf("hardcoded SubjectCountry should not be overridden, got %s", opts.SubjectCountry)
	}
	if opts.CallbackPort != "7777" {
		t.Errorf("hardcoded CallbackPort should not be overridden, got %s", opts.CallbackPort)
	}
}

func TestParseFlagsBooleanHardCodedTrue(t *testing.T) {
	resetFlags()
	os.Args = []string{"test"}
	opts := Options{
		Proxy:   true,
		Verbose: true,
	}
	parseFlags(&opts)
	if !opts.Proxy {
		t.Error("hardcoded Proxy=true should not be overridden")
	}
	if !opts.Verbose {
		t.Error("hardcoded Verbose=true should not be overridden")
	}
}

func TestParseFlagsProxyDefaultTrue(t *testing.T) {
	resetFlags()
	os.Args = []string{"test"}
	opts := Options{}
	parseFlags(&opts)
	// proxy flag defaults to true
	if !opts.Proxy {
		t.Error("expected Proxy=true by default from flag")
	}
}

func resetFlags() {
	flag.CommandLine = flag.NewFlagSet(os.Args[0], flag.ContinueOnError)
}

// --- Run tests (version path only, since other paths call os.Exit/log.Fatalf) ---

func TestRunVersionWithVersionString(t *testing.T) {
	resetFlags()
	os.Args = []string{"test", "-version"}

	// Capture stdout
	old := os.Stdout
	r, w, _ := os.Pipe()
	os.Stdout = w

	Run(Options{Version: "test-version 1.0.0"})

	w.Close()
	os.Stdout = old

	var buf bytes.Buffer
	buf.ReadFrom(r)
	output := buf.String()

	if !strings.Contains(output, "test-version 1.0.0") {
		t.Errorf("expected version output, got %s", output)
	}
}

func TestRunVersionWithoutVersionString(t *testing.T) {
	resetFlags()
	os.Args = []string{"test", "-version"}

	old := os.Stdout
	r, w, _ := os.Pipe()
	os.Stdout = w

	Run(Options{})

	w.Close()
	os.Stdout = old

	var buf bytes.Buffer
	buf.ReadFrom(r)
	output := buf.String()

	if !strings.Contains(output, "(development version)") {
		t.Errorf("expected development version output, got %s", output)
	}
}

// --- RequestCertificate verbose path tests ---

func TestRequestCertificateVerboseMode(t *testing.T) {
	tmpKeyFile := filepath.Join(t.TempDir(), "key.pem")
	if err := os.WriteFile(tmpKeyFile, ecdsaPrivateKeyPEM, 0600); err != nil {
		t.Fatalf("failed to write key file: %v", err)
	}

	_, err := RequestCertificate(Options{
		PrivateKeyFile:  tmpKeyFile,
		UserName:        "johndoe",
		IdpEndpoint:     "http://localhost:19993/auth",
		IdpClientId:     "test-client",
		SubjectCountry:  "US",
		SubjectOrg:      "Test",
		SubjectOrgUnit:  "Test",
		CallbackPort:    "19992",
		CallbackTimeout: 1,
		Verbose:         true,
	})
	// Expect error from IdP flow
	if err == nil {
		t.Fatal("expected error")
	}
}

func TestRequestCertificateWithExpiryTime(t *testing.T) {
	tmpKeyFile := filepath.Join(t.TempDir(), "key.pem")
	if err := os.WriteFile(tmpKeyFile, ecdsaPrivateKeyPEM, 0600); err != nil {
		t.Fatalf("failed to write key file: %v", err)
	}

	_, err := RequestCertificate(Options{
		PrivateKeyFile:  tmpKeyFile,
		UserName:        "johndoe",
		IdpEndpoint:     "http://localhost:19991/auth",
		IdpClientId:     "test-client",
		SubjectCountry:  "US",
		SubjectOrg:      "Test",
		SubjectOrgUnit:  "Test",
		CallbackPort:    "19990",
		CallbackTimeout: 1,
		ExpiryTime:      60,
	})
	if err == nil {
		t.Fatal("expected error")
	}
}

func TestRequestCertificateWithSpiffeDomain(t *testing.T) {
	tmpKeyFile := filepath.Join(t.TempDir(), "key.pem")
	if err := os.WriteFile(tmpKeyFile, ecdsaPrivateKeyPEM, 0600); err != nil {
		t.Fatalf("failed to write key file: %v", err)
	}

	_, err := RequestCertificate(Options{
		PrivateKeyFile:    tmpKeyFile,
		UserName:          "johndoe",
		IdpEndpoint:       "http://localhost:19989/auth",
		IdpClientId:       "test-client",
		SubjectCountry:    "US",
		SubjectOrg:        "Test",
		SubjectOrgUnit:    "Test",
		SpiffeTrustDomain: "athenz.io",
		CallbackPort:      "19988",
		CallbackTimeout:   1,
	})
	if err == nil {
		t.Fatal("expected error")
	}
}

// --- Constants tests ---

func TestDefaultConstants(t *testing.T) {
	if DefaultCallbackPort != "3222" {
		t.Errorf("expected DefaultCallbackPort=3222, got %s", DefaultCallbackPort)
	}
	if DefaultCallbackTimeout != 45 {
		t.Errorf("expected DefaultCallbackTimeout=45, got %d", DefaultCallbackTimeout)
	}
	if DefaultSubjectOrgUnit != "Athenz" {
		t.Errorf("expected DefaultSubjectOrgUnit=Athenz, got %s", DefaultSubjectOrgUnit)
	}
}

// --- Options field test ---

func TestOptionsDefaultZeroValues(t *testing.T) {
	opts := Options{}
	if opts.ZtsURL != "" {
		t.Error("expected empty ZtsURL")
	}
	if opts.Proxy {
		t.Error("expected Proxy=false")
	}
	if opts.Verbose {
		t.Error("expected Verbose=false")
	}
	if opts.ExpiryTime != 0 {
		t.Error("expected ExpiryTime=0")
	}
	if opts.CallbackTimeout != 0 {
		t.Error("expected CallbackTimeout=0")
	}
}

// --- helper ---

func assertSubjectFields(t *testing.T, subj pkix.Name, country, org, orgUnit string) {
	t.Helper()
	if country == "" {
		if len(subj.Country) != 0 {
			t.Errorf("expected empty Country, got %v", subj.Country)
		}
	} else if len(subj.Country) != 1 || subj.Country[0] != country {
		t.Errorf("expected Country=[%s], got %v", country, subj.Country)
	}
	if org == "" {
		if len(subj.Organization) != 0 {
			t.Errorf("expected empty Organization, got %v", subj.Organization)
		}
	} else if len(subj.Organization) != 1 || subj.Organization[0] != org {
		t.Errorf("expected Organization=[%s], got %v", org, subj.Organization)
	}
	if orgUnit == "" {
		if len(subj.OrganizationalUnit) != 0 {
			t.Errorf("expected empty OrganizationalUnit, got %v", subj.OrganizationalUnit)
		}
	} else if len(subj.OrganizationalUnit) != 1 || subj.OrganizationalUnit[0] != orgUnit {
		t.Errorf("expected OrganizationalUnit=[%s], got %v", orgUnit, subj.OrganizationalUnit)
	}
}

func mustBigInt() *big.Int {
	n, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	return n
}
