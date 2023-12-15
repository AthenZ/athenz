// Copyright The Athenz Authors
// Licensed under the terms of the Apache version 2.0 license. See LICENSE file for terms.

package athenzutils

import (
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"

	"github.com/AthenZ/athenz/clients/go/zts"
	"github.com/AthenZ/athenz/libs/go/tls/config"
)

// ZtsClient creates and returns a ZTS client instance.
func ZtsClient(ztsURL, keyFile, certFile, caCertFile string, proxy bool) (*zts.ZTSClient, error) {
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
	client := zts.NewClient(ztsURL, tr)
	return &client, nil
}

// GenerateAccessTokenRequestString generates and urlencodes an access token string.
func GenerateAccessTokenRequestString(domain, service, roles, authzDetails, proxyPrincipalSpiffeUris, proxyForPrincipal string, expiryTime int) string {

	params := url.Values{}
	params.Add("grant_type", "client_credentials")
	// do not include the expiry param if the client is asking
	// for the server default setting (expiryTime == 0) or any
	// invalid values (expiryTime < 0)
	if expiryTime > 0 {
		params.Add("expires_in", strconv.Itoa(expiryTime))
	}

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
	if proxyForPrincipal != "" {
		params.Add("proxy_for_principal", proxyForPrincipal)
	}
	return params.Encode()
}
