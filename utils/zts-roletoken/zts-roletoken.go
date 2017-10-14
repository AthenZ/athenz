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
)

func main() {

	var domain, role, ntoken, ntokenFile, ztsUrl, hdr string
	var expireTime int
	flag.StringVar(&domain, "domain", "", "name of provider domain")
	flag.StringVar(&role, "role", "", "name of provider role")
	flag.StringVar(&ntoken, "ntoken", "", "service identity token")
	flag.StringVar(&ntokenFile, "ntoken-file", "", "service identity token file")
	flag.StringVar(&ztsUrl, "zts", "", "url of the ZTS Service")
	flag.StringVar(&hdr, "hdr", "Athenz-Principal-Auth", "Header name")
	flag.IntVar(&expireTime, "expire-time", 120, "token expire time in minutes")
	flag.Parse()

	if domain == "" || (ntoken == "" && ntokenFile == "") || ztsUrl == "" {
		log.Fatalln("usage: zts-roletoken -domain <domain> [-role <role>] -ntoken <ntoken> [-ntoken-file <ntoken-file>] -zts <zts-server-url> [-hdr <auth-header-name>] [-expire-time <time-in-mins>]")
	}

	// if our ntoken is empty then we have a file so we
	// we need to load our ntoken from the given file
	if ntoken == "" {
		bytes, err := ioutil.ReadFile(ntokenFile)
		if err != nil {
			log.Fatalln(err)
		}
		ntoken = strings.TrimSpace(string(bytes))
	}

	// use the ntoken to talk to Athenz
	client := zts.NewClient(ztsUrl, nil)
	client.AddCredentials(hdr, ntoken)

	// zts timeout is in seconds so we'll convert our value
	expireTimeMs := int32(expireTime * 60)

	// request a roletoken
	roleToken, err := client.GetRoleToken(zts.DomainName(domain), zts.EntityList(role), &expireTimeMs, &expireTimeMs, "")
	if err != nil {
		log.Fatalln(err)
	}

	fmt.Println(roleToken.Token)
}
