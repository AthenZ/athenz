// Copyright 2019 Oath Holdings, Inc.
// Licensed under the terms of the Apache version 2.0 license. See LICENSE file for terms.

package athenzutils

import (
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io/ioutil"
)

// LoadX509Certificate reads and parses the x509.Certificate from the specified file.
func LoadX509Certificate(certFile string) (*x509.Certificate, error) {
	pemBytes, err := ioutil.ReadFile(certFile)
	if err != nil {
		return nil, err
	}
	block, _ := pem.Decode(pemBytes)
	if block == nil {
		return nil, fmt.Errorf("unable to parse x.509 certificate pem file: %s", certFile)
	}
	return x509.ParseCertificate(block.Bytes)
}
