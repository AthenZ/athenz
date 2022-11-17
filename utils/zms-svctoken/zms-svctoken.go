// Copyright The Athenz Authors
// Licensed under the terms of the Apache version 2.0 license. See LICENSE file for terms.

package main

import (
	"flag"
	"fmt"
	"log"
	"os"
	"time"

	"github.com/AthenZ/athenz/libs/go/zmssvctoken"
)

var (
	// VERSION gets set by the build script via the LDFLAGS.
	VERSION string

	// BUILD_DATE gets set by the build script via the LDFLAGS.
	BUILD_DATE string
)

func printVersion() {
	if VERSION == "" {
		fmt.Println("zms-svctoken (development version)")
	} else {
		fmt.Println("zms-svctoken " + VERSION + " " + BUILD_DATE)
	}
}

func main() {

	var privateKeyFile, domain, service, keyVersion string
	var showVersion bool
	flag.StringVar(&privateKeyFile, "private-key", "", "private key file")
	flag.StringVar(&domain, "domain", "", "domain of service")
	flag.StringVar(&service, "service", "", "name of service")
	flag.StringVar(&keyVersion, "key-version", "", "key version")
	flag.BoolVar(&showVersion, "version", false, "Show version")
	flag.Parse()

	if showVersion {
		printVersion()
		return
	}

	if privateKeyFile == "" || domain == "" || service == "" || keyVersion == "" {
		log.Fatalln("usage: zms-svctoken -domain <domain> -service <service> -private-key <key-file> -key-version <version>")
	}

	// load private key
	bytes, err := os.ReadFile(privateKeyFile)
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
