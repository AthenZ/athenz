// Copyright The Athenz Authors
// Licensed under the terms of the Apache version 2.0 license. See LICENSE file for terms.

package cert

import (
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os"
	"time"
)

// FromFile to read and parse x509 certificate from file
func FromFile(filename string) (*x509.Certificate, error) {
	pemBytes, err := os.ReadFile(filename)
	if err != nil {
		return nil, err
	}
	return FromPEMBytes(pemBytes)
}

// FromPEMBytes to get parse x509 certificate from bytes
func FromPEMBytes(pemBytes []byte) (*x509.Certificate, error) {
	var derBytes []byte
	block, _ := pem.Decode(pemBytes)
	if block == nil {
		return nil, fmt.Errorf("cannot parse cert (empty pem)")
	}
	derBytes = block.Bytes
	cert, err := x509.ParseCertificate(derBytes)
	if err != nil {
		return nil, err
	}
	return cert, nil
}

// IsExpiryAfterThreshold to check if the cert expiry is after the number of thresholdDays
func IsExpiryAfterThreshold(certFile string, thresholdDays float64) (bool, error) {
	x509Cert, err := FromFile(certFile)
	if err != nil {
		return false, err
	}

	thresholdTime := time.Now().Add(time.Duration(thresholdDays*24) * time.Hour)
	certExpiry := x509Cert.NotAfter
	if certExpiry.After(thresholdTime) {
		return true, nil
	}

	return false, nil
}
