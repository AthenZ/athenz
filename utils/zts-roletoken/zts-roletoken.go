// Copyright 2016 Yahoo Inc.
// Licensed under the terms of the Apache version 2.0 license. See LICENSE file for terms.

package main

import (
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"strings"

	"github.com/yahoo/athenz/clients/go/zts"
	"github.com/yahoo/athenz/libs/go/ztsclientutil"
)

func usage() {
	log.Fatalln("usage: zts-roletoken -domain <domain> [-role <role>] <credentials> -zts <zts-server-url> [-hdr <auth-header-name>] [-expire-time <time-in-mins>]\n\t<credentials> := -ntoken <ntoken> | -ntoken-file <ntoken-file> | -svc-key-file <private-key-file> -svc-cert-file <service-cert-file>")
}

func main() {

	var domain, svcKeyFile, svcCertFile, role, ntoken, ntokenFile, ztsURL, hdr string
	var expireTime int
	var proxy bool
	flag.StringVar(&domain, "domain", "", "name of provider domain")
	flag.StringVar(&role, "role", "", "name of provider role")
	flag.StringVar(&ntoken, "ntoken", "", "service identity token")
	flag.StringVar(&ntokenFile, "ntoken-file", "", "service identity token file")
	flag.StringVar(&svcKeyFile, "svc-key-file", "", "service identity private key file")
	flag.StringVar(&svcCertFile, "svc-cert-file", "", "service identity certificate file")
	flag.StringVar(&ztsURL, "zts", "", "url of the ZTS Service")
	flag.StringVar(&hdr, "hdr", "Athenz-Principal-Auth", "Header name")
	flag.IntVar(&expireTime, "expire-time", 120, "token expire time in minutes")
	flag.BoolVar(&proxy, "proxy", false, "enable proxy mode for request")
	flag.Parse()

	// validate required attributes
	if domain == "" || ztsURL == "" {
		usage()
	}

	certCredentials := false
	if svcKeyFile != "" && svcCertFile != "" {
		certCredentials = true
	} else if ntoken == "" && ntokenFile == "" {
		usage()
	}

	var client *zts.ZTSClient
	var err error
	if certCredentials {
		client, err = ztsclientutil.ZtsClient(ztsURL, svcKeyFile, svcCertFile, "", proxy)
	} else {
		client, err = ztsNtokenClient(ztsURL, ntoken, ntokenFile, hdr)
	}
	if err != nil {
		log.Fatalf("unable to create zts client: %v\n", err)
	}

	// zts timeout is in seconds so we'll convert our value
	expireTimeMs := int32(expireTime * 60)

	// request a roletoken
	roleToken, err := client.GetRoleToken(zts.DomainName(domain), zts.EntityList(role), &expireTimeMs, &expireTimeMs, "")
	if err != nil {
		log.Fatalln(err)
	}

	fmt.Println(roleToken.Token)
}

func ztsNtokenClient(ztsURL, ntoken, ntokenFile, hdr string) (*zts.ZTSClient, error) {
	// if our ntoken is empty then we have a file so we
	// we need to load our ntoken from the given file
	if ntoken == "" {
		bytes, err := ioutil.ReadFile(ntokenFile)
		if err != nil {
			return nil, err
		}
		ntoken = strings.TrimSpace(string(bytes))
	}

	// use the ntoken to talk to Athenz
	client := zts.NewClient(ztsURL, nil)
	client.AddCredentials(hdr, ntoken)
	return &client, nil
}
