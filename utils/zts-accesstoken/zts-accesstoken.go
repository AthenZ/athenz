// Copyright 2019 Oath Holdings Inc.
// Licensed under the terms of the Apache version 2.0 license. See LICENSE file for terms.

package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"github.com/yahoo/athenz/clients/go/zts"
	"github.com/yahoo/athenz/libs/go/athenzutils"
	"io/ioutil"
	"log"
	"net/url"
	"os"
	"strconv"
	"strings"
)

func usage() {
	fmt.Println("usage: zts-accesstoken -domain <domain> [-roles <roles>] [-service <service>] <credentials> -zts <zts-server-url> [-expire-time <time-in-mins>]")
	fmt.Println("           <credentials> := -svc-key-file <private-key-file> -svc-cert-file <service-cert-file> | -ntoken-file <ntoken-file> [-hdr <auth-header-name>]")
	os.Exit(1)
}

func main() {
	var domain, service, svcKeyFile, svcCertFile, roles, ntokenFile, ztsURL, hdr string
	var expireTime int
	var proxy bool
	flag.StringVar(&domain, "domain", "", "name of provider domain")
	flag.StringVar(&service, "service", "", "name of provider service")
	flag.StringVar(&roles, "roles", "", "comma separated list of provider roles")
	flag.StringVar(&ntokenFile, "ntoken-file", "", "service identity token file")
	flag.StringVar(&svcKeyFile, "svc-key-file", "", "service identity private key file")
	flag.StringVar(&svcCertFile, "svc-cert-file", "", "service identity certificate file")
	flag.StringVar(&ztsURL, "zts", "", "url of the ZTS Service")
	flag.StringVar(&hdr, "hdr", "Athenz-Principal-Auth", "Header name")
	flag.IntVar(&expireTime, "expire-time", 120, "token expire time in minutes")
	flag.BoolVar(&proxy, "proxy", false, "enable proxy mode for request")
	flag.Parse()

	fetchAccessToken(domain, service, roles, ztsURL, svcKeyFile, svcCertFile, ntokenFile, hdr, proxy, expireTime)
}

func fetchAccessToken(domain, service, roles, ztsURL, svcKeyFile, svcCertFile, ntokenFile, hdr string, proxy bool, expireTime int) {
	if domain == "" || ztsURL == "" {
		usage()
	}

	certCredentials := false
	if svcKeyFile != "" && svcCertFile != "" {
		certCredentials = true
	} else if ntokenFile == "" {
		usage()
	}

	var client *zts.ZTSClient
	var err error
	if certCredentials {
		client, err = athenzutils.ZtsClient(ztsURL, svcKeyFile, svcCertFile, "", proxy)
	} else {
		client, err = ztsNtokenClient(ztsURL, ntokenFile, hdr)
	}
	if err != nil {
		log.Fatalf("unable to create zts client: %v\n", err)
	}

	// generate the scope for the request, convert time to seconds
	request := generateRequestString(domain, service, roles, expireTime*60)

	// request an access token
	accessTokenResponse, err := client.PostAccessTokenRequest(zts.AccessTokenRequest(request))
	if err != nil {
		log.Fatalln(err)
	}

	data, err := json.Marshal(accessTokenResponse)
	if err != nil {
		log.Fatalln(err)
	}

	fmt.Println(string(data))
}

func generateRequestString(domain, service, roles string, expiryTime int) string {

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
	return params.Encode()
}

func ztsNtokenClient(ztsURL, ntokenFile, hdr string) (*zts.ZTSClient, error) {
	// we need to load our ntoken from the given file
	bytes, err := ioutil.ReadFile(ntokenFile)
	if err != nil {
		return nil, err
	}
	ntoken := strings.TrimSpace(string(bytes))

	// use the ntoken to talk to Athenz
	client := zts.NewClient(ztsURL, nil)
	client.AddCredentials(hdr, ntoken)
	return &client, nil
}
