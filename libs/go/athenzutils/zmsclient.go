// Copyright The Athenz Authors
// Licensed under the terms of the Apache version 2.0 license. See LICENSE file for terms.

package athenzutils

import (
	"net/http"
	"os"

	"github.com/AthenZ/athenz/clients/go/zms"
	"github.com/AthenZ/athenz/libs/go/tls/config"
)

// ZmsClient creates and returns a ZMS client instance.
func ZmsClient(zmsURL, keyFile, certFile, caCertFile string, proxy bool) (*zms.ZMSClient, error) {
	keypem, err := os.ReadFile(keyFile)
	if err != nil {
		return nil, err
	}
	certpem, err := os.ReadFile(certFile)
	if err != nil {
		return nil, err
	}
	var cacertpem []byte
	if caCertFile != "" {
		cacertpem, err = os.ReadFile(caCertFile)
		if err != nil {
			return nil, err
		}
	}
	config, err := config.ClientTLSConfigFromPEM(keypem, certpem, cacertpem)
	if err != nil {
		return nil, err
	}
	tr := &http.Transport{
		TLSClientConfig: config,
	}
	if proxy {
		tr.Proxy = http.ProxyFromEnvironment
	}
	client := zms.NewClient(zmsURL, tr)
	return &client, nil
}
