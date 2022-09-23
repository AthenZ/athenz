// Copyright The Athenz Authors
// Licensed under the terms of the Apache version 2.0 license. See LICENSE file for terms.

package athenzutils

import "testing"

func TestExtractInstanceIdValid(test *testing.T) {

	tests := []struct {
		name       string
		certFile   string
		instanceId string
	}{
		{"nocn", "data/no_cn_x509.cert", "1001"},
		{"invalidemail", "data/invalid_email_x509.cert", "1001"},
		{"multiplemeail", "data/multiple_email_x509.cert", "1001"},
		{"noemail", "data/no_email_x509.cert", "1001"},
		{"uri", "data/athenz_instanceid_uri.cert", "id-001"},
	}
	for _, tt := range tests {
		test.Run(tt.name, func(t *testing.T) {
			x509Cert, _ := LoadX509Certificate(tt.certFile)
			instanceId, _ := ExtractInstanceId(*x509Cert)
			if instanceId != tt.instanceId {
				test.Errorf("invalid instance id %s from %s", instanceId, tt.certFile)
			}
		})
	}
}

func TestExtractInstanceIdInValid(test *testing.T) {

	tests := []struct {
		name     string
		certFile string
	}{
		{"id1", "data/service_identity1.cert"},
		{"id2", "data/service_identity2.cert"},
		{"email", "data/valid_email_x509.cert"},
	}
	for _, tt := range tests {
		test.Run(tt.name, func(t *testing.T) {
			x509Cert, _ := LoadX509Certificate(tt.certFile)
			instanceId, err := ExtractInstanceId(*x509Cert)
			if err == nil {
				test.Errorf("no error from invalid file %s: %s", tt.certFile, instanceId)
			}
		})
	}
}
