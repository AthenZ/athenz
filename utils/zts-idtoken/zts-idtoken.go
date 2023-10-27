// Copyright The Athenz Authors
// Licensed under the terms of the Apache version 2.0 license. See LICENSE file for terms.

package main

import (
	"flag"
	"fmt"
	"github.com/AthenZ/athenz/libs/go/athenzconf"
	"github.com/AthenZ/athenz/libs/go/athenzutils"
	"gopkg.in/square/go-jose.v2"
	"gopkg.in/square/go-jose.v2/jwt"
	"log"
	"os"
)

var (
	// VERSION gets set by the build script via the LDFLAGS.
	VERSION string

	// BUILD_DATE gets set by the build script via the LDFLAGS.
	BUILD_DATE string
)

func usage() {
	fmt.Println("usage: zts-idtoken <credentials> -zts <ZTS url> -scope <scope> -redirect-uri <redirect-uri> -nonce <nonce> -client-id <client-id> -state <state> -key-type <RSA|EC> -format <token|kubectl> [-full-arn=true] [-role-in-aud-claim=true]")
	fmt.Println("           <credentials> := -svc-key-file <private-key-file> -svc-cert-file <service-cert-file> [-svc-cacert-file <ca-cert-file>]")
	fmt.Println("       zts-idtoken -validate -id-token <id-token> -conf <athenz-conf-path> [-claims]")
	os.Exit(1)
}

func printVersion() {
	if VERSION == "" {
		fmt.Println("zts-idtoken (development version)")
	} else {
		fmt.Println("zts-idtoken " + VERSION + " " + BUILD_DATE)
	}
}

func main() {
	var clientId, scope, state, redirectUri, nonce, svcKeyFile, svcCertFile, svcCACertFile, ztsURL, conf, idToken, keyType, format string
	var proxy, validate, claims, showVersion, fullArn, roleInAudClaim bool
	var expireTime int
	flag.StringVar(&clientId, "client-id", "", "client-id for the token")
	flag.StringVar(&redirectUri, "redirect-uri", "", "redirect uri registered for the client-id")
	flag.StringVar(&scope, "scope", "", "request scope")
	flag.StringVar(&nonce, "nonce", "", "request nonce - included as a claim in the id token")
	flag.StringVar(&state, "state", "", "state value for the request")
	flag.StringVar(&svcCACertFile, "svc-cacert-file", "", "CA Certificates file")
	flag.StringVar(&svcKeyFile, "svc-key-file", "", "service identity private key file")
	flag.StringVar(&svcCertFile, "svc-cert-file", "", "service identity certificate file")
	flag.StringVar(&ztsURL, "zts", "", "url of the ZTS Service")
	flag.BoolVar(&proxy, "proxy", true, "enable proxy mode for request")
	flag.BoolVar(&fullArn, "full-arn", false, "return full ARNs in group claim")
	flag.StringVar(&conf, "conf", "/home/athenz/conf/athenz.conf", "path to configuration file with public keys")
	flag.BoolVar(&validate, "validate", false, "validate id token")
	flag.BoolVar(&claims, "claims", false, "display all claims from id token")
	flag.StringVar(&idToken, "id-token", "", "id token to validate")
	flag.StringVar(&keyType, "key-type", "RSA", "signing key type: RSA or EC")
	flag.BoolVar(&showVersion, "version", false, "Show version")
	flag.StringVar(&format, "format", "token", "Output format: token | kubectl")
	flag.IntVar(&expireTime, "expire-time", 60, "token expire time in minutes")
	flag.BoolVar(&roleInAudClaim, "role-in-aud-claim", false, "include role name in aud claim")
	flag.Parse()

	if showVersion {
		printVersion()
		return
	}

	if validate {
		validateIdToken(idToken, conf, claims)
	} else {
		fetchIdToken(ztsURL, svcKeyFile, svcCertFile, svcCACertFile, clientId, scope, nonce, state, keyType, format, &fullArn, proxy, expireTime, &roleInAudClaim)
	}
}

func validateIdToken(idToken, conf string, showClaims bool) {
	if idToken == "" || conf == "" {
		usage()
	}
	athenzConf, err := athenzconf.ReadConf(conf)
	if err != nil {
		log.Fatalf("unable to parse configuration file %s, error %v\n", conf, err)
	}
	tok, err := jwt.ParseSigned(idToken)
	if err != nil {
		log.Fatalf("Unable to validate id token: %v\n", err)
	}
	publicKeyPEM, err := athenzConf.FetchZTSPublicKey(tok.Headers[0].KeyID)
	if err != nil {
		log.Fatalf("Public key fetch failure: %v\n", err)
	}
	publicKey, err := athenzutils.LoadPublicKey(publicKeyPEM)
	if err != nil {
		log.Fatalf("Public key load failure: %v\n", err)
	}
	jwks := &jose.JSONWebKeySet{
		Keys: []jose.JSONWebKey{
			{
				Key:       publicKey,
				Algorithm: tok.Headers[0].Algorithm,
				KeyID:     tok.Headers[0].KeyID,
			},
		},
	}
	var claims map[string]interface{}
	if err := tok.Claims(jwks, &claims); err != nil {
		log.Fatalf("Unable to validate id token: %v\n", err)
	}
	if showClaims {
		for k, v := range claims {
			fmt.Printf("claim[%s] value[%s]\n", k, v)
		}
	}
	fmt.Println("Id Token successfully validated")
}

func fetchIdToken(ztsURL, svcKeyFile, svcCertFile, svcCACertFile, clientId, scope, nonce, state, keyType, format string, fullArn *bool, proxy bool, expireTime int, roleInAudClaim *bool) {

	defaultConfig, _ := athenzutils.ReadDefaultConfig()
	// check to see if we need to use zts url from our default config file
	if ztsURL == "" && defaultConfig != nil {
		ztsURL = defaultConfig.Zts
	}
	if ztsURL == "" {
		usage()
	}

	// need to convert minutes into seconds
	expireTimeSecs := int32(expireTime) * 60

	idToken, err := athenzutils.FetchIdToken(ztsURL, svcKeyFile, svcCertFile, svcCACertFile, clientId, scope, nonce, state, keyType, fullArn, proxy, &expireTimeSecs, roleInAudClaim)
	if err != nil {
		log.Fatalf("unable to fetch id token: %v\n", err)
	}

	if format == "kubectl" {
		output, err := athenzutils.GetK8SClientAuthCredential(idToken)
		if err != nil {
			log.Fatalf("unable to generate kubectl supported output: %v\n", err)
		}
		fmt.Println(output)
	} else {
		fmt.Println(idToken)
	}
}
