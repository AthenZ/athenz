// Copyright The Athenz Authors
// Licensed under the terms of the Apache version 2.0 license. See LICENSE file for terms.

package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"reflect"
	"testing"
	"time"

	"github.com/AthenZ/athenz/libs/go/athenzutils"
)

func newTestSigner(t *testing.T) *signer {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return &signer{key: key, algorithm: x509.ECDSAWithSHA256}
}

func parseTestCSR(t *testing.T, csrData string) *x509.CertificateRequest {
	t.Helper()
	block, _ := pem.Decode([]byte(csrData))
	if block == nil {
		t.Fatal("unable to decode CSR")
	}
	csr, err := x509.ParseCertificateRequest(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	if err = csr.CheckSignature(); err != nil {
		t.Fatal(err)
	}
	return csr
}

func TestGenerateCSRURISANs(t *testing.T) {
	keySigner := newTestSigner(t)
	subject := pkix.Name{CommonName: "test.api", Organization: []string{"Athenz"}}
	const spiffeURI = "spiffe://test/sa/api"
	const instanceURI = "athenz://instanceid/sys.auth.zts/instance-1"
	const instanceDNS = "instance-1.instanceid.athenz.example.test"
	const hostnameURI = "athenz://hostname/worker.example.test"
	const trustDomainURI = "spiffe://example.test/ns/default/sa/test.api"
	tests := []struct {
		name        string
		spiffeSvid  bool
		uri         string
		instanceURI string
		instanceDNS string
		hostnameURI string
		wantDNS     []string
		wantURIs    []string
		wantError   bool
	}{
		{
			name: "legacy combined URIs", uri: spiffeURI, instanceURI: instanceURI, instanceDNS: instanceDNS, hostnameURI: hostnameURI,
			wantURIs: []string{spiffeURI, instanceURI, hostnameURI},
		},
		{
			name: "SVID omits instance and hostname URIs", spiffeSvid: true,
			uri: spiffeURI, instanceURI: instanceURI, instanceDNS: instanceDNS, hostnameURI: hostnameURI,
			wantDNS:  []string{"api.test.example.test", instanceDNS},
			wantURIs: []string{spiffeURI},
		},
		{
			name: "SVID omits instance URI", spiffeSvid: true, uri: spiffeURI, instanceURI: instanceURI, instanceDNS: instanceDNS,
			wantDNS:  []string{"api.test.example.test", instanceDNS},
			wantURIs: []string{spiffeURI},
		},
		{
			name: "SVID omits hostname URI", spiffeSvid: true, uri: spiffeURI, hostnameURI: hostnameURI,
			wantURIs: []string{spiffeURI},
		},
		{
			name: "SVID preserves trust domain URI", spiffeSvid: true,
			uri: trustDomainURI, instanceURI: instanceURI, instanceDNS: instanceDNS, hostnameURI: hostnameURI,
			wantDNS:  []string{"api.test.example.test", instanceDNS},
			wantURIs: []string{trustDomainURI},
		},
		{
			name: "legacy without SPIFFE", instanceURI: instanceURI, hostnameURI: hostnameURI,
			wantURIs: []string{instanceURI, hostnameURI},
		},
		{name: "legacy without URIs"},
		{name: "SVID requires SPIFFE", spiffeSvid: true, instanceURI: instanceURI, wantError: true},
		{name: "SVID rejects other schemes", spiffeSvid: true, uri: hostnameURI, wantError: true},
		{name: "SVID rejects empty trust domain", spiffeSvid: true, uri: "spiffe:///sa/api", wantError: true},
		{name: "SVID rejects root path", spiffeSvid: true, uri: "spiffe://test/", wantError: true},
		{name: "invalid URI", uri: "spiffe://%", wantError: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			csrData, err := generateCSR(keySigner, subject, "api.test.example.test",
				tt.instanceURI, tt.instanceDNS, tt.hostnameURI, "192.0.2.1", tt.uri, tt.spiffeSvid)
			if tt.wantError {
				if err == nil {
					t.Fatal("expected an invalid SVID or URI to be rejected")
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			csr := parseTestCSR(t, csrData)
			var gotURIs []string
			for _, uri := range csr.URIs {
				gotURIs = append(gotURIs, uri.String())
			}
			if !reflect.DeepEqual(gotURIs, tt.wantURIs) {
				t.Errorf("URI SANs = %v, want %v", gotURIs, tt.wantURIs)
			}
			wantDNS := tt.wantDNS
			if wantDNS == nil {
				wantDNS = []string{"api.test.example.test"}
			}
			if !reflect.DeepEqual(csr.DNSNames, wantDNS) {
				t.Errorf("DNS SANs = %v, want %v", csr.DNSNames, wantDNS)
			}
			if len(csr.IPAddresses) != 1 || csr.IPAddresses[0].String() != "192.0.2.1" {
				t.Errorf("IP SANs changed: %v", csr.IPAddresses)
			}
			if csr.Subject.CommonName != subject.CommonName || !reflect.DeepEqual(csr.Subject.Organization, subject.Organization) {
				t.Errorf("Subject changed: %v", csr.Subject)
			}
		})
	}
}

func TestLoadCSRURISANs(t *testing.T) {
	keySigner := newTestSigner(t)
	tests := []struct {
		name        string
		spiffeSvid  bool
		uri         string
		instanceURI string
		hostnameURI string
		wantError   bool
	}{
		{name: "SVID accepts single SPIFFE URI", spiffeSvid: true, uri: "spiffe://test/sa/api"},
		{name: "SVID rejects instance URI", spiffeSvid: true, uri: "spiffe://test/sa/api", instanceURI: "athenz://instanceid/zts/id-1", wantError: true},
		{name: "SVID rejects hostname URI", spiffeSvid: true, uri: "spiffe://test/sa/api", hostnameURI: "athenz://hostname/worker.example.test", wantError: true},
		{name: "SVID rejects multiple SPIFFE URIs", spiffeSvid: true, uri: "spiffe://test/sa/api", instanceURI: "spiffe://test/sa/other", wantError: true},
		{name: "SVID rejects missing SPIFFE URI", spiffeSvid: true, wantError: true},
		{name: "SVID rejects non-SPIFFE URI", spiffeSvid: true, uri: "athenz://instanceid/zts/id-1", wantError: true},
		{name: "legacy accepts combined URIs", uri: "spiffe://test/sa/api", instanceURI: "athenz://instanceid/zts/id-1", hostnameURI: "athenz://hostname/worker.example.test"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			csrData, err := generateCSR(keySigner, pkix.Name{CommonName: "test.api"}, "api.example.test",
				tt.instanceURI, "", tt.hostnameURI, "", tt.uri, false)
			if err != nil {
				t.Fatal(err)
			}
			csrFile := filepath.Join(t.TempDir(), "request.csr")
			if err = os.WriteFile(csrFile, []byte(csrData), 0600); err != nil {
				t.Fatal(err)
			}
			loaded, err := loadCSR(csrFile, tt.spiffeSvid)
			if tt.wantError {
				if err == nil {
					t.Fatal("expected an invalid SVID CSR to be rejected")
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if loaded != csrData {
				t.Error("supplied CSR was modified")
			}
			parseTestCSR(t, loaded)
		})
	}
}

func TestSPIFFESVIDRegistrationThenRefresh(t *testing.T) {
	const instanceID = "instance-1"
	const instanceURI = "athenz://instanceid/sys.auth.zts/" + instanceID
	const instanceDNS = instanceID + ".instanceid.athenz.example.test"
	const spiffeURI = "spiffe://test/sa/api"
	subject := pkix.Name{CommonName: "test.api"}
	registrationKey := newTestSigner(t)
	registrationData, err := generateCSR(registrationKey, subject, "api.test.example.test", instanceURI,
		instanceDNS, "", "192.0.2.1", spiffeURI, true)
	if err != nil {
		t.Fatal(err)
	}
	registrationCSR := parseTestCSR(t, registrationData)

	// Issue a certificate from the registration CSR using an in-memory test CA.
	caKey := newTestSigner(t)
	ca := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "Test CA"},
		NotBefore:             time.Now().Add(-time.Minute),
		NotAfter:              time.Now().Add(time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, ca, ca, caKey.key.Public(), caKey.key)
	if err != nil {
		t.Fatal(err)
	}
	caCert, err := x509.ParseCertificate(caDER)
	if err != nil {
		t.Fatal(err)
	}
	leaf := &x509.Certificate{
		SerialNumber:          big.NewInt(2),
		Subject:               registrationCSR.Subject,
		NotBefore:             ca.NotBefore,
		NotAfter:              ca.NotAfter,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		DNSNames:              registrationCSR.DNSNames,
		IPAddresses:           registrationCSR.IPAddresses,
		URIs:                  registrationCSR.URIs,
	}
	leafDER, err := x509.CreateCertificate(rand.Reader, leaf, caCert, registrationCSR.PublicKey, caKey.key)
	if err != nil {
		t.Fatal(err)
	}
	certificate, err := x509.ParseCertificate(leafDER)
	if err != nil {
		t.Fatal(err)
	}
	if err = certificate.CheckSignatureFrom(caCert); err != nil {
		t.Fatal(err)
	}

	// A new key must retain the ID required to refresh the authenticated certificate.
	refreshKey := newTestSigner(t)
	refreshData, err := generateCSR(refreshKey, subject, "api.test.example.test", instanceURI,
		instanceDNS, "", "192.0.2.1", spiffeURI, true)
	if err != nil {
		t.Fatal(err)
	}
	refreshCSR := parseTestCSR(t, refreshData)
	if reflect.DeepEqual(registrationCSR.RawSubjectPublicKeyInfo, refreshCSR.RawSubjectPublicKeyInfo) {
		t.Fatal("refresh CSR did not rotate its key")
	}
	for _, stage := range []struct {
		name string
		cert *x509.Certificate
	}{
		{"registration CSR", &x509.Certificate{DNSNames: registrationCSR.DNSNames, URIs: registrationCSR.URIs}},
		{"issued certificate", certificate},
		{"refresh CSR", &x509.Certificate{DNSNames: refreshCSR.DNSNames, URIs: refreshCSR.URIs}},
	} {
		t.Run(stage.name, func(t *testing.T) {
			if len(stage.cert.URIs) != 1 || stage.cert.URIs[0].String() != spiffeURI {
				t.Fatal("expected exactly one SPIFFE URI SAN")
			}
			gotID, err := athenzutils.ExtractInstanceId(*stage.cert)
			if err != nil || gotID != instanceID {
				t.Fatalf("instance ID = %q, error = %v; want %q", gotID, err, instanceID)
			}
		})
	}
}
