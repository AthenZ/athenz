// Copyright The Athenz Authors
// Licensed under the terms of the Apache version 2.0 license. See LICENSE file for terms.

package athenzutils

import (
	"log"
	"testing"
)

func TestZmsClient(test *testing.T) {

	tests := []struct {
		name       string
		zmsUrl     string
		keyPath    string
		certPath   string
		caCertPath string
		proxy      bool
		success    bool
	}{
		{"invalid-key-file", "https://localhost", "invalid-key", "data/svc-test-cert1.pem", "", true, false},
		{"invalid-cert-file", "https://localhost", "data/svc-test-key1.pem", "invalid-cert-file", "", true, false},
		{"mismatch-key-cert", "https://localhost", "data/svc-test-key1.pem", "data/service_identity2.cert", "", true, false},
		{"invalid-cacerts", "https://localhost", "data/svc-test-key1.pem", "data/svc-test-cert1.pem", "ivnalid-cacert-file", true, false},
		{"valid-with-proxy", "https://localhost", "data/svc-test-key1.pem", "data/svc-test-cert1.pem", "", true, true},
		{"valid-without-proxy", "https://localhost", "data/svc-test-key1.pem", "data/svc-test-cert1.pem", "", false, true},
	}
	for _, tt := range tests {
		test.Run(tt.name, func(t *testing.T) {
			_, err := ZmsClient(tt.zmsUrl, tt.keyPath, tt.certPath, tt.caCertPath, tt.proxy)
			if (err != nil && tt.success) || (err == nil && !tt.success) {
				if err != nil {
					log.Printf("error message: %v\n", err)
				}
				test.Errorf("invalid zms client return object for test case: %s", tt.name)
			}
		})
	}
}
