// Copyright The Athenz Authors
// Licensed under the terms of the Apache version 2.0 license. See LICENSE file for terms.

package athenzutils

import (
	"testing"
)

func TestExtractServicePrincipalValid(test *testing.T) {

	tests := []struct {
		name      string
		certFile  string
		principal string
	}{
		{"id1", "data/service_identity1.cert", "athenz.production"},
		{"id2", "data/service_identity2.cert", "athenz.syncer"},
		{"email", "data/valid_email_x509.cert", "athens.zts"},
	}
	for _, tt := range tests {
		test.Run(tt.name, func(t *testing.T) {
			x509Cert, _ := LoadX509Certificate(tt.certFile)
			principal, _ := ExtractServicePrincipal(*x509Cert)
			if principal != tt.principal {
				test.Errorf("invalid principal %s from %s", principal, tt.certFile)
			}
		})
	}
}

func TestExtractServicePrincipalInValid(test *testing.T) {

	tests := []struct {
		name     string
		certFile string
	}{
		{"nocn", "data/no_cn_x509.cert"},
		{"invalidemail", "data/invalid_email_x509.cert"},
		{"multiplemeail", "data/multiple_email_x509.cert"},
		{"noemail", "data/no_email_x509.cert"},
	}
	for _, tt := range tests {
		test.Run(tt.name, func(t *testing.T) {
			x509Cert, _ := LoadX509Certificate(tt.certFile)
			principal, err := ExtractServicePrincipal(*x509Cert)
			if err == nil {
				test.Errorf("no error from invalid file %s: %s", tt.certFile, principal)
			}
		})
	}
}

func TestParsePrincipal(test *testing.T) {

	tests := []struct {
		name      string
		principal string
		domain    string
		service   string
	}{
		{"empty-string", "", "", ""},
		{"missing-dot", "john-doe", "", ""},
		{"start-dot", ".john-doe", "", ""},
		{"end-dot", "john-doe.", "", ""},
		{"valid-top-level-domain", "user.john-doe", "user", "john-doe"},
		{"valid-sub-domain", "home.john-doe.api", "home.john-doe", "api"},
		{"single-letter-domain", "a.api", "a", "api"},
		{"single-letter-service", "athenz.a", "athenz", "a"},
	}
	for _, tt := range tests {
		test.Run(tt.name, func(t *testing.T) {
			domain, service, _ := ParsePrincipal(tt.principal)
			if domain != tt.domain && service != tt.service {
				test.Errorf("incorrect parsing of principal: %s (%s/%s)", tt.principal, tt.domain, tt.service)
			}
		})
	}
}
