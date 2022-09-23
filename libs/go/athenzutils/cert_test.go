// Copyright The Athenz Authors
// Licensed under the terms of the Apache version 2.0 license. See LICENSE file for terms.

package athenzutils

import "testing"

func TestLoadCertificate(test *testing.T) {

	tests := []struct {
		name     string
		certFile string
		valid    bool
	}{
		{"id1", "data/service_identity1.cert", true},
		{"id2", "data/service_identity2.cert", true},
		{"email", "data/valid_email_x509.cert", true},
		{"notfoudn", "data/not_found.cert", false},
	}
	for _, tt := range tests {
		test.Run(tt.name, func(t *testing.T) {
			_, err := LoadX509Certificate(tt.certFile)
			if tt.valid != (err == nil) {
				test.Errorf("not expected response from processing test case: %s", tt.name)
			}
		})
	}
}
