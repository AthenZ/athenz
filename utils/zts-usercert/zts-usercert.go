// Copyright The Athenz Authors
// Licensed under the terms of the Apache version 2.0 license. See LICENSE file for terms.

// Zts-usercert is a program to request a User X509 Certificate
// from ZTS Server using IdP (Identity Provider) authentication.
//
// The tool initiates an IdP OAuth2 authentication flow to
// obtain an authorization code, generates a CSR, and submits
// the request to ZTS to obtain a user TLS certificate.
package main

import (
	"fmt"

	"github.com/AthenZ/athenz/libs/go/usercert"
)

var (
	// VERSION gets set by the build script via the LDFLAGS.
	VERSION string

	// BUILD_DATE gets set by the build script via the LDFLAGS.
	BUILD_DATE string
)

func versionString() string {
	if VERSION == "" {
		return "zts-usercert (development version)"
	}
	return fmt.Sprintf("zts-usercert %s %s", VERSION, BUILD_DATE)
}

func main() {
	usercert.Run(usercert.Options{
		Version: versionString(),
	})
}
