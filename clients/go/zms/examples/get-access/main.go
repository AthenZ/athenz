// Copyright The Athenz Authors
// Licensed under the terms of the Apache version 2.0 license. See LICENSE file for terms.

// Get-access is a demo program to query if the current principal has
// "Access" to a specified resource, in a given domain.
package main

import (
	"crypto/tls"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"strings"

	"github.com/AthenZ/athenz/clients/go/zms"
)

func main() {
	var key, cert, zmsURL, domain, action, resource string
	var skipVerify bool
	flag.StringVar(&cert, "cert", "", "certificate file")
	flag.StringVar(&key, "key", "", "key file")
	flag.StringVar(&zmsURL, "zms", "", "zms endpoint")
	flag.StringVar(&domain, "domain", "", "domain the principal is from")
	flag.StringVar(&action, "action", "", "action for get access check call")
	flag.StringVar(&resource, "resource", "", "fully qualified resource for get access check call")
	flag.BoolVar(&skipVerify, "skipVerify", false, "boolean flag to skip verifying server for TLS connection, if using self-signed certs")
	flag.Parse()

	if zmsURL == "" {
		log.Fatalf("A valid zms url needs to be specified")
	}

	idx := strings.Index(resource, ":")
	if idx < 0 {
		resource = domain + ":" + resource
	}

	tlsConfig, err := getTLSConfigFromFiles(key, cert)
	if err != nil {
		log.Fatalf("Unable to load client TLS Config, error: %v", err)
	}

	transport := &http.Transport{
		TLSClientConfig: tlsConfig,
	}

	if skipVerify {
		transport.TLSClientConfig.InsecureSkipVerify = true
	}

	client := zms.NewClient(zmsURL, transport)
	access, err := client.GetAccess(zms.ActionName(action), zms.ResourceName(resource), "", "")
	if err != nil {
		log.Fatalf("unable to do GetAccess, err: %v, action: %q, resource: %q", err, action, resource)
	}

	log.Printf("Access Granted: %t", access.Granted)
}

func getTLSConfigFromFiles(keyFile, certFile string) (*tls.Config, error) {
	keypem, err := os.ReadFile(keyFile)
	if err != nil {
		return nil, fmt.Errorf("unable to read keyfile: %q, error: %v", keyFile, err)
	}

	certpem, err := os.ReadFile(certFile)
	if err != nil {
		return nil, fmt.Errorf("unable to read certfile: %q, error: %v", certFile, err)
	}

	return getTLSConfig(certpem, keypem)
}

func getTLSConfig(certpem, keypem []byte) (*tls.Config, error) {
	clientCert, err := tls.X509KeyPair(certpem, keypem)
	if err != nil {
		return nil, fmt.Errorf("unable to formulate clientCert from key and cert bytes, error: %v", err)
	}

	config := &tls.Config{}
	config.Certificates = make([]tls.Certificate, 1)
	config.Certificates[0] = clientCert

	return config, nil
}
