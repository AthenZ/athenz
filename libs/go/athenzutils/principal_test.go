// Copyright 2018 Oath, Inc.
// Licensed under the terms of the Apache version 2.0 license. See LICENSE file for terms.

package athenzutils

import (
	"crypto/x509"
	"encoding/pem"
	"io/ioutil"
	"testing"
)

func TestExtractServicePrincipal(test *testing.T) {

	x509Cert, _ := getCertFromFile("data/service_identity1.cert")
	principal, _ := ExtractServicePrincipal(*x509Cert)
	if principal != "athenz.production" {
		test.Errorf("invalid principal %s from data/service_identity1.cert", principal)
	}

	x509Cert, _ = getCertFromFile("data/service_identity2.cert")
	principal, _ = ExtractServicePrincipal(*x509Cert)
	if principal != "athenz.syncer" {
		test.Errorf("invalid principal %s from data/service_identity2.cert", principal)
	}

	x509Cert, _ = getCertFromFile("data/valid_email_x509.cert")
	principal, _ = ExtractServicePrincipal(*x509Cert)
	if principal != "athens.zts" {
		test.Errorf("invalid principal %s from data/valid_email.cert", principal)
	}

	x509Cert, _ = getCertFromFile("data/no_cn_x509.cert")
	principal, err := ExtractServicePrincipal(*x509Cert)
	if err == nil {
		test.Errorf("no error from invalid file data/no_cn_x509.cert: %s", principal)
	}

	x509Cert, _ = getCertFromFile("data/invalid_email_x509.cert")
	principal, err = ExtractServicePrincipal(*x509Cert)
	if err == nil {
		test.Errorf("no error from invalid file data/invalid_email_x509.cert: %s", principal)
	}

	x509Cert, _ = getCertFromFile("data/multiple_email_x509.cert")
	principal, err = ExtractServicePrincipal(*x509Cert)
	if err == nil {
		test.Errorf("no error from invalid file data/multiple_email_x509.cert: %s", principal)
	}

	x509Cert, _ = getCertFromFile("data/no_email_x509.cert")
	principal, err = ExtractServicePrincipal(*x509Cert)
	if err == nil {
		test.Errorf("no error from invalid file data/no_email_x509.cert: %s", principal)
	}
}

func getCertFromFile(certFile string) (*x509.Certificate, error) {
	data, err := ioutil.ReadFile(certFile)
	if err != nil {
		return nil, err
	}
	var block *pem.Block
	block, _ = pem.Decode(data)
	return x509.ParseCertificate(block.Bytes)
}
