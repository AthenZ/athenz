// Copyright 2016 Yahoo Inc.
// Licensed under the terms of the Apache version 2.0 license. See LICENSE file for terms.

// Server is a program to demonstrate the use of ZMS Go client to implement
// Athenz centralized authorization support in a server.
package main

import (
	"crypto/tls"
	"flag"
	"fmt"
	"io"
	"net/http"

	"github.com/yahoo/athenz/clients/go/zms"
)

var (
	authHeader     string
	zmsURL         string
	providerDomain string
)

func authorizeRequest(ntoken, resource, action string) bool {
	// for our test example we're just going to skip
	// validating self-signed certificates
	tr := http.Transport{}
	config := &tls.Config{}
	config.InsecureSkipVerify = true
	tr.TLSClientConfig = config
	zmsClient := zms.ZMSClient{
		URL:       zmsURL,
		Transport: &tr,
	}
	zmsClient.AddCredentials(authHeader, ntoken)
	access, err := zmsClient.GetAccess(zms.ActionName(action), zms.ResourceName(resource), "", "")
	if err != nil {
		fmt.Printf("Unable to verify access: %v", err)
		return false
	}
	return access.Granted
}

func movieHandler(w http.ResponseWriter, r *http.Request) {
	// first let's verify that we have an ntoken
	if r.Header[authHeader] == nil {
		http.Error(w, "403 - Missing NToken", 403)
		return
	}
	// let's generate our resource value which is the
	// <provider domain>:<entity value>
	resource := providerDomain + ":rec.movie"
	// finally check with ZMS if the principal is authorized
	if !authorizeRequest(r.Header[authHeader][0], resource, "read") {
		http.Error(w, "403 - Unauthorized access", 403)
		return
	}
	io.WriteString(w, "Name: Slap Shot; Director: George Roy Hill\n")
}

func tvshowHandler(w http.ResponseWriter, r *http.Request) {
	// first let's verify that we have an ntoken
	if r.Header[authHeader] == nil {
		http.Error(w, "403 - Missing NToken", 403)
		return
	}
	// let's generate our resource value which is the
	// <provider domain>:<entity value>
	resource := providerDomain + ":rec.tvshow"
	// finally check with ZMS if the principal is authorized
	if !authorizeRequest(r.Header[authHeader][0], resource, "read") {
		http.Error(w, "403 - Unauthorized access", 403)
		return
	}
	io.WriteString(w, "Name: Middle; Channel: ABC\n")
}

func main() {
	flag.StringVar(&zmsURL, "zms", "https://localhost:4443/zms/v1", "url of the ZMS Service")
	flag.StringVar(&authHeader, "hdr", "Athenz-Principal-Auth", "The NToken header name")
	flag.StringVar(&providerDomain, "domain", "recommend", "The provider domain name")
	flag.Parse()

	http.HandleFunc("/rec/v1/movie", movieHandler)
	http.HandleFunc("/rec/v1/tvshow", tvshowHandler)
	http.ListenAndServe(":8080", nil)
}
