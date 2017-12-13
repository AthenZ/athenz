// Copyright 2017 Yahoo Holdings, Inc.
// Licensed under the terms of the Apache version 2.0 license. See LICENSE file for terms

// Get-role-token is a demo program to use the service cert present
// locally on the box to talk to ZTS and fetch a role token.
package main

import (
	"crypto/tls"
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"

	"github.com/yahoo/athenz/clients/go/zts"
)

func main() {
	var key, cert, role, domain, ztsUrl string
	var skipVerify bool
	flag.StringVar(&cert, "cert", "", "certificate file")
	flag.StringVar(&key, "key", "", "key file")
	flag.StringVar(&ztsUrl, "zts", "", "zts endpoint")
	flag.StringVar(&domain, "domain", "", "domain the principal is from")
	flag.StringVar(&role, "role", "", "role for which role-token needs to be fetched")
	flag.BoolVar(&skipVerify, "skipVerify", false, "boolean flag to skip verifying server for TLS connection, if using self-signed certs")
	flag.Parse()

	if ztsUrl == "" {
		log.Fatalf("A valid zts url needs to be specified")
	}

	tlsConfig, err := GetTLSConfigFromFiles(key, cert)
	if err != nil {
		log.Fatalf("Unable to load client TLS Config, error: %v", err)
	}

	transport := &http.Transport{
		TLSClientConfig: tlsConfig,
	}

	if skipVerify {
		transport.TLSClientConfig.InsecureSkipVerify = true
	}

	client := zts.NewClient(ztsUrl, transport)

	rt, err := client.GetRoleToken(zts.DomainName(domain), zts.EntityList(role), nil, nil, zts.EntityName(""))
	if err != nil {
		log.Fatalf("Unable to do GetRoleToken, err: %v", err)
	}

	log.Printf("RoleToken: %q", rt.Token)
}

func GetTLSConfigFromFiles(keyFile, certFile string) (*tls.Config, error) {
	keypem, err := ioutil.ReadFile(keyFile)
	if err != nil {
		return nil, fmt.Errorf("Unable to read keyfile: %q, error: %v", keyFile, err)
	}

	certpem, err := ioutil.ReadFile(certFile)
	if err != nil {
		return nil, fmt.Errorf("Unable to read certfile: %q, error: %v", certFile, err)
	}

	return GetTLSConfig(certpem, keypem)
}

func GetTLSConfig(certpem, keypem []byte) (*tls.Config, error) {
	clientCert, err := tls.X509KeyPair(certpem, keypem)
	if err != nil {
		return nil, fmt.Errorf("Unable to formulate clientCert from key and cert bytes, error: %v", err)
	}

	config := &tls.Config{}
	config.Certificates = make([]tls.Certificate, 1)
	config.Certificates[0] = clientCert

	return config, nil
}
