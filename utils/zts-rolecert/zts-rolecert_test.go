// Copyright The Athenz Authors
// Licensed under the terms of the Apache version 2.0 license. See LICENSE file for terms.

package main

import (
	"testing"
)

func TestExtractServiceDetailsFromCert(test *testing.T) {

	domain, service, err := extractServiceDetailsFromCert("data/service_x509.pem")
	if err != nil {
		test.Errorf("unable to extract details from certificate file")
		return
	}
	if domain != "athenz" {
		test.Errorf("domain name is not expected athenz value - %s", domain)
		return
	}
	if service != "syncer" {
		test.Errorf("service name is not expected athenz value - %s", service)
		return
	}
}

func TestExtractServiceDetailsFromCertInvalidFile(test *testing.T) {

	_, _, err := extractServiceDetailsFromCert("data/unknown.pem")
	if err == nil {
		test.Errorf("incorrectly processed unknown file")
		return
	}
}

func TestExtractServiceDetailsFromEmptyFile(test *testing.T) {

	_, _, err := extractServiceDetailsFromCert("data/empty.pem")
	if err == nil {
		test.Errorf("incorrectly processed unknown file")
		return
	}
}
