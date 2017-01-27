// Copyright 2016 Yahoo Inc.
// Licensed under the terms of the Apache version 2.0 license. See LICENSE file for terms.

package main

import (
	"flag"
	"fmt"
	"log"

	"github.com/yahoo/athenz/clients/go/zts"
)

const authHeader = "Athenz-Principal-Auth"

func main() {

	var domain, role, ntoken, ztsUrl string
	flag.StringVar(&domain, "domain", domain, "name of provider domain")
	flag.StringVar(&role, "role", role, "name of provider role")
	flag.StringVar(&ntoken, "ntoken", ntoken, "service identity token")
	flag.StringVar(&ztsUrl, "zts", ztsUrl, "url of the ZTS Service")
	flag.Parse()

	if domain == "" || ntoken == "" || ztsUrl == "" {
		log.Fatalln("usage: zts-roletoken -domain <domain> -role <role> -ntoken <ntoken> -zts <ZTS url>")
	}

	// use the ntoken to talk to Athenz
	client := zts.NewClient(ztsUrl, nil)
	client.AddCredentials(authHeader, ntoken)

	// request a roletoken
	roleToken, err := client.GetRoleToken(zts.DomainName(domain), zts.EntityName(role), nil, nil, "")
	if err != nil {
		log.Fatalln(err)
	}

	fmt.Println(roleToken.Token)
}
