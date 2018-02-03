// Copyright 2018 Yahoo Holdings, Inc.
// Licensed under the terms of the Apache version 2.0 license. See LICENSE file for terms.

package ztsclientutil

import (
	"crypto/tls"
	"io/ioutil"
	"net/http"

	"github.com/yahoo/athenz/clients/go/zts"
)

func ZtsClient(ztsUrl, keyFile, certFile string) (*zts.ZTSClient, error) {
	keypem, err := ioutil.ReadFile(keyFile)
	if err != nil {
		return nil, err
	}
	certpem, err := ioutil.ReadFile(certFile)
	if err != nil {
		return nil, err
	}
	config, err := tlsConfiguration(keypem, certpem)
	if err != nil {
		return nil, err
	}
	tr := &http.Transport{
		TLSClientConfig: config,
	}
	client := zts.NewClient(ztsUrl, tr)
	return &client, nil
}

func tlsConfiguration(keypem, certpem []byte) (*tls.Config, error) {
	config := &tls.Config{}
	if certpem != nil && keypem != nil {
		mycert, err := tls.X509KeyPair(certpem, keypem)
		if err != nil {
			return nil, err
		}
		config.Certificates = make([]tls.Certificate, 1)
		config.Certificates[0] = mycert
	}
	return config, nil
}
