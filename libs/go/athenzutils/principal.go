// Copyright The Athenz Authors
// Licensed under the terms of the Apache version 2.0 license. See LICENSE file for terms.

package athenzutils

import (
	"crypto/x509"
	"fmt"
	"strings"
)

// ExtractServicePrincipal returns the Athenz Service principal for the given
// certificate which could be either a service certificate or a role certificate.
// If the certificate does not have the Athenz expected name format
// the method will an appropriate error.
func ExtractServicePrincipal(x509Cert x509.Certificate) (string, error) {

	// let's first get the common name of the certificate

	principal := x509Cert.Subject.CommonName
	if principal == "" {
		return "", fmt.Errorf("certificate does not have a common name")
	}

	// check to see if we're dealing with role certificate which
	// has the <domain>:role.<rolename> format or service
	// certificate which has the <domain>.<service> format

	if strings.Contains(principal, ":role.") {

		// it's a role certificate so we're going to extract
		// our service principal from the SAN email fieid
		// verify that we must have only a single email
		// field in the certificate

		emails := x509Cert.EmailAddresses
		if len(emails) != 1 {
			return "", fmt.Errorf("certificate does not have a single email SAN value")
		}

		// athenz always verifies that we include a valid
		// email in the certificate

		idx := strings.Index(emails[0], "@")
		if idx == -1 {
			return "", fmt.Errorf("certificate email is invalid: %s", emails[0])
		}

		principal = emails[0][0:idx]
	}

	return principal, nil
}

func ParsePrincipal(principal string) (string, string, error) {
	idx := strings.LastIndex(principal, ".")
	if idx == -1 || idx == 0 || idx == len(principal)-1 {
		return "", "", fmt.Errorf("invalid principal format - must be <domain>.<service>")
	}
	return principal[:idx], principal[idx+1:], nil
}
