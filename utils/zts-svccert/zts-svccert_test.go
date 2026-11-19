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
	"os"
	"path/filepath"
	"reflect"
	"testing"
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
	const hostnameURI = "athenz://hostname/worker.example.test"
	const trustDomainURI = "spiffe://example.test/ns/default/sa/test.api"
	tests := []struct {
		name        string
		spiffeSvid  bool
		uri         string
		instanceURI string
		hostnameURI string
		wantURIs    []string
		wantError   bool
	}{
		{
			name: "legacy combined URIs", uri: spiffeURI, instanceURI: instanceURI, hostnameURI: hostnameURI,
			wantURIs: []string{spiffeURI, instanceURI, hostnameURI},
		},
		{
			name: "SVID omits instance and hostname URIs", spiffeSvid: true,
			uri: spiffeURI, instanceURI: instanceURI, hostnameURI: hostnameURI,
			wantURIs: []string{spiffeURI},
		},
		{
			name: "SVID omits instance URI", spiffeSvid: true, uri: spiffeURI, instanceURI: instanceURI,
			wantURIs: []string{spiffeURI},
		},
		{
			name: "SVID omits hostname URI", spiffeSvid: true, uri: spiffeURI, hostnameURI: hostnameURI,
			wantURIs: []string{spiffeURI},
		},
		{
			name: "SVID preserves trust domain URI", spiffeSvid: true,
			uri: trustDomainURI, instanceURI: instanceURI, hostnameURI: hostnameURI,
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
				tt.instanceURI, tt.hostnameURI, "192.0.2.1", tt.uri, tt.spiffeSvid)
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
			if !reflect.DeepEqual(csr.DNSNames, []string{"api.test.example.test"}) {
				t.Errorf("DNS SANs changed: %v", csr.DNSNames)
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
				tt.instanceURI, tt.hostnameURI, "", tt.uri, false)
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
