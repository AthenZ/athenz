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
	"flag"
	"fmt"

	"github.com/AthenZ/athenz/libs/go/usercert"
)

var (
	// VERSION gets set by the build script via the LDFLAGS.
	VERSION string

	// BUILD_DATE gets set by the build script via the LDFLAGS.
	BUILD_DATE string
)

const (
	DefaultCallbackPort    = "3222"
	DefaultCallbackTimeout = 45
	DefaultSubjectOrgUnit  = "Athenz"
)

func versionString() string {
	if VERSION == "" {
		return "zts-usercert (development version)"
	}
	return fmt.Sprintf("zts-usercert %s %s", VERSION, BUILD_DATE)
}

func main() {

	var ztsURL, privateKeyFile, userName, certFile string
	var idpEndpoint, idpClientId, caCertFile string
	var subjC, subjO, subjOU, spiffeTrustDomain string
	var callbackPort string
	var callbackTimeout, expiryTime int
	var proxy, verbose, showVersion bool

	flag.StringVar(&ztsURL, "zts", "", "url of the ZTS Service")
	flag.StringVar(&privateKeyFile, "private-key", "", "private key file")
	flag.StringVar(&userName, "user", "", "user name without domain prefix")
	flag.StringVar(&idpEndpoint, "idp-endpoint", "", "IdP OAuth2 endpoint URL")
	flag.StringVar(&idpClientId, "idp-client-id", "", "IdP OAuth2 client ID")
	flag.StringVar(&certFile, "cert-file", "", "output certificate file")
	flag.StringVar(&subjC, "subj-c", "", "Subject C/Country field")
	flag.StringVar(&subjO, "subj-o", "", "Subject O/Organization field")
	flag.StringVar(&subjOU, "subj-ou", DefaultSubjectOrgUnit, "Subject OU/OrganizationalUnit field")
	flag.StringVar(&spiffeTrustDomain, "spiffe-trust-domain", "", "trust domain value for SPIFFE URI")
	flag.StringVar(&callbackPort, "callback-port", DefaultCallbackPort, "local port for IdP OAuth2 callback")
	flag.IntVar(&callbackTimeout, "callback-timeout", DefaultCallbackTimeout, "timeout in seconds for IdP auth flow")
	flag.IntVar(&expiryTime, "expiry-time", 0, "expiry time in minutes for the certificate")
	flag.StringVar(&caCertFile, "cacert", "", "CA certificate file")
	flag.BoolVar(&proxy, "proxy", true, "enable proxy mode for request")
	flag.BoolVar(&verbose, "verbose", false, "enable verbose logging")
	flag.BoolVar(&showVersion, "version", false, "show version")
	flag.Parse()

	if showVersion {
		fmt.Println(versionString())
		return
	}

	// generate our options object
	opts := usercert.Options{
		ZtsURL:            ztsURL,
		PrivateKeyFile:    privateKeyFile,
		UserName:          userName,
		IdpEndpoint:       idpEndpoint,
		IdpClientId:       idpClientId,
		CertFile:          certFile,
		SubjectCountry:    subjC,
		SubjectOrg:        subjO,
		SubjectOrgUnit:    subjOU,
		SpiffeTrustDomain: spiffeTrustDomain,
		CallbackPort:      callbackPort,
		CallbackTimeout:   callbackTimeout,
		ExpiryTime:        expiryTime,
		CACertFile:        caCertFile,
		Proxy:             proxy,
		Verbose:           verbose,
	}

	usercert.Run(opts)
}
