// Copyright 2016 Yahoo Inc.
// Licensed under the terms of the Apache version 2.0 license. See LICENSE file for terms.

package main

import (
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"time"

	"github.com/yahoo/athenz/libs/go/zmssvctoken"
)

func main() {

	var privateKeyFile, domain, service, keyVersion string
	flag.StringVar(&privateKeyFile, "private-key", "", "private key file")
	flag.StringVar(&domain, "domain", "", "domain of service")
	flag.StringVar(&service, "service", "", "name of service")
	flag.StringVar(&keyVersion, "key-version", "", "key version")
	flag.Parse()

	if privateKeyFile == "" || domain == "" || service == "" || keyVersion == "" {
		log.Fatalln("usage: zms-svctoken -domain <domain> -service <service> -private-key <key-file> -key-version <version>")
	}

	// load private key
	bytes, err := ioutil.ReadFile(privateKeyFile)
	if err != nil {
		log.Fatalln(err)
	}

	// get token builder instance
	builder, err := zmssvctoken.NewTokenBuilder(domain, service, bytes, keyVersion)
	if err != nil {
		log.Fatalln(err)
	}

	// set optional attributes
	builder.SetExpiration(60 * time.Minute)

	// get a token instance that always gives you unexpired tokens values
	// safe for concurrent use
	tok := builder.Token()

	// get a token for use
	ntoken, err := tok.Value()
	if err != nil {
		log.Fatalln(err)
	}
	fmt.Println(ntoken)
}
