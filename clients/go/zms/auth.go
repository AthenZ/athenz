// Copyright The Athenz Authors
// Licensed under the terms of the Apache version 2.0 license. See LICENSE file for terms.

package zms

import (
	"fmt"
	"log"
	"strings"

	"github.com/ardielle/ardielle-go/rdl"
)

// Authenticator is an unoptimized authenticator that delegates to ZMS.
// The advantage is that there is no local state or config other than the
// url of ZMS (we don't need ZMS's public key to be local).
func Authenticator(url string) rdl.Authenticator {
	return &zmsAuthenticator{url}
}

type zmsAuthenticator struct {
	url string //i.e. "http://localhost:10080/zms/v1"
}

func (ath zmsAuthenticator) HTTPHeader() string {
	return "Athenz-Principal-Auth"
}

func (ath zmsAuthenticator) Authenticate(nToken string) rdl.Principal {
	attrs := make(map[string]string)
	for _, attr := range strings.Split(nToken, ";") {
		kv := strings.Split(attr, "=")
		attrs[kv[0]] = kv[1]
	}
	if name, ok := attrs["n"]; ok {
		if domain, ok := attrs["d"]; ok {
			//do not verify the token, because we will just pass it off in the authorizer, where ZMS will do that.
			log.Printf("[Authenticate %s.%s]\n", domain, name)
			return zmsPrincipal{domain, name, nToken, ath.HTTPHeader()}
		}
	}
	return nil
}

// zmsPrincipal implements rdl.Principal the interface
type zmsPrincipal struct {
	domain string
	name   string
	creds  string
	header string
}

func (p zmsPrincipal) GetDomain() string {
	return p.domain
}

func (p zmsPrincipal) GetName() string {
	return p.name
}

func (p zmsPrincipal) GetYRN() string {
	return p.domain + "." + p.name
}

func (p zmsPrincipal) GetCredentials() string {
	return p.creds
}

func (p zmsPrincipal) GetHTTPHeaderName() string {
	return p.header
}

// Authorizer returns an authorizer that calls zms. If the url is set to
// "", then the access is logged, but always succeeds (for debug purposes).
func Authorizer(domain string, url string) rdl.Authorizer {
	return &zmsAuthorizer{domain: domain, url: url}
}

type zmsAuthorizer struct {
	domain string
	url    string
}

func (auth zmsAuthorizer) Authorize(action string, resource string, principal rdl.Principal) (bool, error) {
	// this should be done before getting here!
	if !strings.Contains(resource, ":") {
		// the resource is relative to the service's domain
		resource = auth.domain + ":" + resource
	}
	if auth.url == "" {
		log.Printf("[DEBUG Authorize %s on %s for %s]\n", action, resource, principal.GetYRN())
		return true, nil
	}
	if principal.GetHTTPHeaderName() != "Athenz-Principal-Auth" {
		return false, fmt.Errorf("Authorizer using" + principal.GetHTTPHeaderName() + " not supported")
	}
	zmsClient := NewClient(auth.url, nil)
	zmsClient.AddCredentials(principal.GetHTTPHeaderName(), principal.GetCredentials())
	check, err := zmsClient.GetAccess(ActionName(action), ResourceName(resource), "", "")
	if err != nil {
		return false, err
	}
	log.Printf("[Authorize %s on %s for %s: %v]\n", action, resource, principal.GetYRN(), check.Granted)
	return check.Granted, nil
}
