// Copyright 2016 Yahoo Inc.
// Licensed under the terms of the Apache version 2.0 license. See LICENSE file for terms.

package main

import (
	"flag"
	"fmt"
	"log"

	"github.com/yahoo/athenz/clients/go/zts"
)

func main() {

	var domain, role, ntoken, ztsUrl, hdr string
	flag.StringVar(&domain, "domain", "", "name of provider domain")
	flag.StringVar(&role, "role", "", "name of provider role")
	flag.StringVar(&ntoken, "ntoken", "", "service identity token")
	flag.StringVar(&ztsUrl, "zts", "", "url of the ZTS Service")
	flag.StringVar(&hdr, "hdr", "Athenz-Principal-Auth", "Header name")
	flag.Parse()

	if domain == "" || ntoken == "" || ztsUrl == "" {
		log.Fatalln("usage: zts-roletoken -domain <domain> -role <role> -ntoken <ntoken> -zts <ZTS url>")
	}

	// use the ntoken to talk to Athenz
	client := zts.NewClient(ztsUrl, nil)
	client.AddCredentials(hdr, ntoken)

	// request a roletoken
	roleToken, err := client.GetRoleToken(zts.DomainName(domain), zts.EntityName(role), nil, nil, "")
	if err != nil {
		log.Fatalln(err)
	}

	fmt.Println(roleToken.Token)
}
