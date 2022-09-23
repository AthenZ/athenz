// Copyright The Athenz Authors
// Licensed under the terms of the Apache version 2.0 license. See LICENSE file for terms.

package athenzutils

import (
	"crypto/x509"
	"fmt"
	"strings"
)

func ExtractInstanceId(x509Cert x509.Certificate) (string, error) {

	// first go through certificate values and see
	// if we have an instance id specified in the uri
	// format: athenz://instanceid/<provider>/<id>
	if x509Cert.URIs != nil {
		for _, uri := range x509Cert.URIs {
			if uri.Scheme == "athenz" && uri.Host == "instanceid" {
				comps := strings.Split(uri.Path, "/")
				if len(comps) == 3 {
					return comps[2], nil
				}
			}
		}
	}
	// if we didn't find the instance id in the URI
	// we're going to look for in the dnsName field
	// format: <id>.instanceid.athenz.<provider-suffix>
	if x509Cert.DNSNames != nil {
		for _, dnsName := range x509Cert.DNSNames {
			idx := strings.Index(dnsName, ".instanceid.athenz.")
			if idx != -1 {
				return dnsName[:idx], nil
			}
		}
	}
	return "", fmt.Errorf("unable to extract instance id from uri/dnsname fields")
}
