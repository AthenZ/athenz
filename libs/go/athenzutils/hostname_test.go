// Copyright The Athenz Authors
// Licensed under the terms of the Apache version 2.0 license. See LICENSE file for terms.

package athenzutils

import "testing"

func TestExtractHostname(test *testing.T) {

	tests := []struct {
		name     string
		certFile string
		hostname string
	}{
		{"nocn", "data/no_cn_x509.cert", ""},
		{"emailnouri", "data/valid_email_x509.cert", ""},
		{
			"urihostname",
			"data/athenz.examples.uri-hostname-only.pem",
			"abc.athenz.com",
		},
	}
	for _, tt := range tests {
		test.Run(tt.name, func(t *testing.T) {
			x509Cert, err := LoadX509Certificate(tt.certFile)
			if err != nil {
				t.Fatal(err)
			}
			hostname := ExtractHostname(*x509Cert)
			if hostname != tt.hostname {
				test.Errorf("invalid hostname '%s' from %s, want %s",
					hostname, tt.certFile, tt.hostname)
			}
		})
	}
}
