// Copyright The Athenz Authors
// Licensed under the terms of the Apache version 2.0 license. See LICENSE file for terms.

package athenzutils

import "testing"

func TestGenerateAccessTokenRequestString(test *testing.T) {

	tests := []struct {
		name              string
		domain            string
		service           string
		roles             string
		authzDetails      string
		spiffeUris        string
		proxyForPrincipal string
		expiryTime        int
		body              string
	}{
		{"domain-only", "sports", "", "", "", "", "", 1200, "expires_in=1200&grant_type=client_credentials&scope=sports%3Adomain"},
		{"roles", "sports", "", "readers,writers", "", "", "", 1400, "expires_in=1400&grant_type=client_credentials&scope=sports%3Arole.readers+sports%3Arole.writers"},
		{"domain service", "sports", "api", "readers", "", "", "", 1600, "expires_in=1600&grant_type=client_credentials&scope=sports%3Arole.readers+openid+sports%3Aservice.api"},
		{"authz-details", "sports", "", "", "[{\"type\":\"msg-access\",\"uid\":101}]", "", "", 1800, "authorization_details=%5B%7B%22type%22%3A%22msg-access%22%2C%22uid%22%3A101%7D%5D&expires_in=1800&grant_type=client_credentials&scope=sports%3Adomain"},
		{"spiffe-uri", "sports", "", "reader", "", "spiffe://athenz/sa/api", "", 2000, "expires_in=2000&grant_type=client_credentials&proxy_principal_spiffe_uris=spiffe%3A%2F%2Fathenz%2Fsa%2Fapi&scope=sports%3Arole.reader"},
		{"proxy-for-principal", "sports", "", "reader", "", "", "principal", 3000, "expires_in=3000&grant_type=client_credentials&proxy_for_principal=principal&scope=sports%3Arole.reader"},
	}
	for _, tt := range tests {
		test.Run(tt.name, func(t *testing.T) {
			body := GenerateAccessTokenRequestString(tt.domain, tt.service, tt.roles, tt.authzDetails, tt.spiffeUris, tt.proxyForPrincipal, tt.expiryTime)
			if body != tt.body {
				test.Errorf("invalid body response %s vs %s", body, tt.body)
			}
		})
	}
}
