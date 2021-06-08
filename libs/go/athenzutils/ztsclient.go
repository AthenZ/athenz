// Copyright 2018 Yahoo Holdings, Inc.
// Licensed under the terms of the Apache version 2.0 license. See LICENSE file for terms.

package athenzutils

import (
	"crypto/tls"
	"crypto/x509"
	"io/ioutil"
	"net/http"
	"net/url"
	"strconv"
	"strings"

	"github.com/AthenZ/athenz/clients/go/zts"
)

// ZtsClient creates and returns a ZTS client instance.
func ZtsClient(ztsURL, keyFile, certFile, caCertFile string, proxy bool) (*zts.ZTSClient, error) {
	keypem, err := ioutil.ReadFile(keyFile)
	if err != nil {
		return nil, err
	}
	certpem, err := ioutil.ReadFile(certFile)
	if err != nil {
		return nil, err
	}
	var cacertpem []byte
	if caCertFile != "" {
		cacertpem, err = ioutil.ReadFile(caCertFile)
		if err != nil {
			return nil, err
		}
	}
	config, err := tlsConfiguration(keypem, certpem, cacertpem)
	if err != nil {
		return nil, err
	}
	tr := &http.Transport{
		TLSClientConfig: config,
	}
	if proxy {
		tr.Proxy = http.ProxyFromEnvironment
	}
	client := zts.NewClient(ztsURL, tr)
	return &client, nil
}

func tlsConfiguration(keypem, certpem, cacertpem []byte) (*tls.Config, error) {
	config := &tls.Config{}
	if certpem != nil && keypem != nil {
		mycert, err := tls.X509KeyPair(certpem, keypem)
		if err != nil {
			return nil, err
		}
		config.Certificates = make([]tls.Certificate, 1)
		config.Certificates[0] = mycert
	}
	if cacertpem != nil {
		certPool := x509.NewCertPool()
		certPool.AppendCertsFromPEM(cacertpem)
		config.RootCAs = certPool
	}
	return config, nil
}

// GenerateAccessTokenRequestString generates and urlencodes an access token string.
func GenerateAccessTokenRequestString(domain, service, roles, authzDetails, proxyPrincipalSpiffeUris string, expiryTime int) string {

	params := url.Values{}
	params.Add("grant_type", "client_credentials")
	params.Add("expires_in", strconv.Itoa(expiryTime))

	var scope string
	if roles == "" {
		scope = domain + ":domain"
	} else {
		roleList := strings.Split(roles, ",")
		for idx, role := range roleList {
			if idx != 0 {
				scope += " "
			}
			scope += domain + ":role." + role
		}
	}
	if service != "" {
		scope += " openid " + domain + ":service." + service
	}

	params.Add("scope", scope)
	if authzDetails != "" {
		params.Add("authorization_details", authzDetails)
	}
	if proxyPrincipalSpiffeUris != "" {
		params.Add("proxy_principal_spiffe_uris", proxyPrincipalSpiffeUris)
	}
	return params.Encode()
}
