// Copyright The Athenz Authors
// Licensed under the terms of the Apache version 2.0 license. See LICENSE file for terms.

package athenzutils

import (
	"crypto/x509"
)

// ExtractHostname returns the hostname from the SAN URIs field
// of the given certificate:
// https://golang.org/pkg/crypto/x509/#Certificate.URIs.
// If the certificate does not have the hostname in the SAN URIs field,
// an empty string is returned.
func ExtractHostname(x509Cert x509.Certificate) string {

	// go through the certificate SAN URIs and see
	// if we have an instance id specified in the uri
	// format: athenz://hostname/<hostname>
	for _, uri := range x509Cert.URIs {
		if uri.Scheme == "athenz" && uri.Host == "hostname" {
			if len(uri.Path) > 1 {
				return uri.Path[1:]
			}
		}
	}
	return ""
}
