// Copyright The Athenz Authors
// Licensed under the terms of the Apache version 2.0 license. See LICENSE file for terms.

package athenzutils

import (
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os"
	"strings"
)

// LoadX509Certificate reads and parses the x509.Certificate from the specified file.
func LoadX509Certificate(certFile string) (*x509.Certificate, error) {
	pemBytes, err := os.ReadFile(certFile)
	if err != nil {
		return nil, err
	}
	block, _ := pem.Decode(pemBytes)
	if block == nil {
		return nil, fmt.Errorf("unable to parse x.509 certificate pem file: %s", certFile)
	}
	return x509.ParseCertificate(block.Bytes)
}

// LoadPublicKey returns public key object for the given PEM data
func LoadPublicKey(publicKeyPEM []byte) (interface{}, error) {
	block, _ := pem.Decode(publicKeyPEM)
	if block == nil {
		return nil, fmt.Errorf("unable to load public key")
	}
	if !strings.HasSuffix(block.Type, "PUBLIC KEY") {
		return nil, fmt.Errorf("invalid public key type: %s", block.Type)
	}
	return x509.ParsePKIXPublicKey(block.Bytes)
}
