// Copyright The Athenz Authors
// Licensed under the terms of the Apache version 2.0 license. See LICENSE file for terms.

package main

import (
	"flag"
	"fmt"
	"log"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/AthenZ/athenz/clients/go/zts"
	"github.com/AthenZ/athenz/libs/go/athenzconf"
	"github.com/AthenZ/athenz/libs/go/athenzutils"
	"github.com/AthenZ/athenz/libs/go/zmssvctoken"
)

var (
	// VERSION gets set by the build script via the LDFLAGS.
	VERSION string

	// BUILD_DATE gets set by the build script via the LDFLAGS.
	BUILD_DATE string
)

func usage() {
	fmt.Println("usage: zts-roletoken -domain <domain> [-role <role>] <credentials> -zts <zts-server-url> [-hdr <auth-header-name>] [-expire-time <time-in-mins>]")
	fmt.Println("           <credentials> := -svc-key-file <private-key-file> -svc-cert-file <service-cert-file> [-svc-cacert-file <ca-cert-file>] |")
	fmt.Println("                            -ntoken <ntoken> | -ntoken-file <ntoken-file> |")
	fmt.Println("       zts-roletoken -validate -role-token <role-token> -conf <athenz-conf-path>")
	os.Exit(1)
}

func printVersion() {
	if VERSION == "" {
		fmt.Println("zts-roletoken (development version)")
	} else {
		fmt.Println("zts-roletoken " + VERSION + " " + BUILD_DATE)
	}
}

func main() {
	var domain, svcKeyFile, svcCertFile, svcCACertFile, role, ntoken, ntokenFile, ztsURL, hdr, roleToken, conf string
	var expireTime int
	var proxy, validate, showVersion bool
	flag.StringVar(&domain, "domain", "", "name of provider domain")
	flag.StringVar(&role, "role", "", "name of provider role")
	flag.StringVar(&ntoken, "ntoken", "", "service identity token")
	flag.StringVar(&ntokenFile, "ntoken-file", "", "service identity token file")
	flag.StringVar(&svcCACertFile, "svc-cacert-file", "", "CA Certificates file")
	flag.StringVar(&svcKeyFile, "svc-key-file", "", "service identity private key file")
	flag.StringVar(&svcCertFile, "svc-cert-file", "", "service identity certificate file")
	flag.StringVar(&ztsURL, "zts", "", "url of the ZTS Service")
	flag.StringVar(&hdr, "hdr", "Athenz-Principal-Auth", "Header name")
	flag.IntVar(&expireTime, "expire-time", 0, "token expire time in minutes")
	flag.BoolVar(&proxy, "proxy", true, "enable proxy mode for request")
	flag.BoolVar(&validate, "validate", false, "validate role token")
	flag.StringVar(&roleToken, "role-token", "", "role token to validate")
	flag.StringVar(&conf, "conf", "/home/athenz/conf/athenz.conf", "path to configuration file with public keys")
	flag.BoolVar(&showVersion, "version", false, "Show version")
	flag.Parse()

	if showVersion {
		printVersion()
		return
	}

	if validate {
		validateRoleToken(roleToken, conf)
	} else {
		fetchRoleToken(domain, role, ztsURL, svcKeyFile, svcCertFile, svcCACertFile, ntoken, ntokenFile, hdr, proxy, expireTime)
	}
}

func fetchRoleToken(domain, role, ztsURL, svcKeyFile, svcCertFile, svcCACertFile, ntoken, ntokenFile, hdr string, proxy bool, expireTime int) {

	defaultConfig, _ := athenzutils.ReadDefaultConfig()
	// check to see if we need to use zts url from our default config file
	if ztsURL == "" && defaultConfig != nil {
		ztsURL = defaultConfig.Zts
	}

	if domain == "" || ztsURL == "" {
		usage()
	}

	// check to see if we need to use our key/cert from our default config file
	if ntoken == "" && ntokenFile == "" && defaultConfig != nil {
		if svcKeyFile == "" {
			svcKeyFile = defaultConfig.PrivateKey
		}
		if svcCertFile == "" {
			svcCertFile = defaultConfig.PublicCert
		}
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
		client, err = athenzutils.ZtsClient(ztsURL, svcKeyFile, svcCertFile, svcCACertFile, proxy)
	} else {
		client, err = ztsNtokenClient(ztsURL, ntoken, ntokenFile, hdr)
	}
	if err != nil {
		log.Fatalf("unable to create zts client: %v\n", err)
	}

	// zts timeout is in seconds, so we'll convert our value
	// if one is provided otherwise we'll pass nil to get the
	// server default timeout based token
	var ptrExpireTime *int32
	if expireTime > 0 {
		expireTimeMs := int32(expireTime * 60)
		ptrExpireTime = &expireTimeMs
	}

	// request a roletoken
	roleToken, err := client.GetRoleToken(zts.DomainName(domain), zts.EntityList(role), ptrExpireTime, ptrExpireTime, "")
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
		bytes, err := os.ReadFile(ntokenFile)
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
