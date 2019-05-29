// Copyright 2016 Yahoo Inc.
// Licensed under the terms of the Apache version 2.0 license. See LICENSE file for terms.

package main

import (
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/yahoo/athenz/clients/go/zts"
	"github.com/yahoo/athenz/libs/go/athenzconf"
	"github.com/yahoo/athenz/libs/go/athenzutils"
	"github.com/yahoo/athenz/libs/go/zmssvctoken"
)

func usage() {
	fmt.Println("usage: zts-roletoken -domain <domain> [-role <role>] <credentials> -zts <zts-server-url> [-hdr <auth-header-name>] [-expire-time <time-in-mins>]")
	fmt.Println("           <credentials> := -ntoken <ntoken> | -ntoken-file <ntoken-file> |")
	fmt.Println("                            -svc-key-file <private-key-file> -svc-cert-file <service-cert-file>")
	fmt.Println("       zts-roletoken -validate -role-token <role-token> -conf <athenz-conf-path>")
	os.Exit(1)
}

func main() {
	var domain, svcKeyFile, svcCertFile, role, ntoken, ntokenFile, ztsURL, hdr, roleToken, conf string
	var expireTime int
	var proxy, validate bool
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
	flag.BoolVar(&validate, "validate", false, "validate role token")
	flag.StringVar(&roleToken, "role-token", "", "role token to validate")
	flag.StringVar(&conf, "conf", "/home/athenz/conf/athenz.conf", "path to configuration file with public keys")
	flag.Parse()

	if validate {
		validateRoleToken(roleToken, conf)
	} else {
		fetchRoleToken(domain, role, ztsURL, svcKeyFile, svcCertFile, ntoken, ntokenFile, hdr, proxy, expireTime)
	}
}

func fetchRoleToken(domain, role, ztsURL, svcKeyFile, svcCertFile, ntoken, ntokenFile, hdr string, proxy bool, expireTime int) {
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
		client, err = athenzutils.ZtsClient(ztsURL, svcKeyFile, svcCertFile, "", proxy)
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

func validateRoleToken(roleToken, conf string) {
	if roleToken == "" || conf == "" {
		usage()
	}

	athenzConf, err := athenzconf.ReadConf(conf)
	if err != nil {
		log.Fatalf("unable to parse configuration file %s, error %v\n", conf, err)
	}

	// parse the token and extract our required bits
	usig := strings.SplitN(roleToken, ";s=", 2)
	if len(usig) != 2 {
		log.Fatalln("Token does not have a signature")
	}

	unsignedToken := usig[0]
	signature := usig[1]

	keyVersion := "0"
	expiryTime := time.Time{}

	parts := strings.Split(unsignedToken, ";")
	for _, part := range parts {
		inner := strings.SplitN(part, "=", 2)
		if len(inner) != 2 {
			log.Fatalf("Malformed token field %s", part)
		}
		v := inner[1]
		switch inner[0] {
		case "k":
			keyVersion = v
		case "e":
			if expiryTime, err = asTime(v); err != nil {
				log.Fatalf("Malformed expiration time %s", v)
			}
		}
	}

	//before continuing verify that the token hasn't expired
	if expiryTime.IsZero() {
		log.Fatalln("No expiry time available in token")
	}
	if expiryTime.Before(time.Now()) {
		log.Fatalln("Token has expired")
	}

	//extract the public key for zts server
	publicKey, err := athenzConf.FetchZTSPublicKey(keyVersion)
	if err != nil {
		log.Fatalf("Public key fetch failure: %v\n", err)
	}
	verifier, err := zmssvctoken.NewVerifier(publicKey)
	if err != nil {
		log.Fatalf("Unable to create verifier: %v\n", err)
	}
	err = verifier.Verify(unsignedToken, signature)
	if err != nil {
		log.Fatalln("Invalid token signature")
	}
	fmt.Println("Role Token successfully validated")
}

var zeroTime = time.Time{}

func asTime(s string) (time.Time, error) {
	n, err := strconv.ParseInt(s, 10, 64)
	if err != nil {
		return zeroTime, fmt.Errorf("Invalid field value '%s'", s)
	}
	return time.Unix(n, 0), nil
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
