// Copyright The Athenz Authors
// Licensed under the terms of the Apache version 2.0 license. See LICENSE file for terms.

package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"os"
	"strings"

	"github.com/AthenZ/athenz/clients/go/zts"
	"github.com/AthenZ/athenz/libs/go/athenzconf"
	"github.com/AthenZ/athenz/libs/go/athenzutils"
	"gopkg.in/square/go-jose.v2"
	"gopkg.in/square/go-jose.v2/jwt"
)

var (
	// VERSION gets set by the build script via the LDFLAGS.
	VERSION string

	// BUILD_DATE gets set by the build script via the LDFLAGS.
	BUILD_DATE string
)

func usage() {
	fmt.Println("usage: zts-accesstoken -domain <domain> [-roles <roles>] [-service <service>] <credentials> -zts <zts-server-url> [-expire-time <time-in-mins>] [-authorization-details <authz-details>] [-proxy-principal-spiffe-uris <spiffe-uris>]")
	fmt.Println("           <credentials> := -svc-key-file <private-key-file> -svc-cert-file <service-cert-file> [-svc-cacert-file <ca-cert-file>] | ")
	fmt.Println("           	             -ntoken-file <ntoken-file> [-hdr <auth-header-name>]")
	fmt.Println("       zts-accesstoken -validate -access-token <access-token> -conf <athenz-conf-path> [-claims]")
	os.Exit(1)
}

func printVersion() {
	if VERSION == "" {
		fmt.Println("zts-accesstoken (development version)")
	} else {
		fmt.Println("zts-accesstoken " + VERSION + " " + BUILD_DATE)
	}
}

func main() {
	var domain, service, svcKeyFile, svcCertFile, svcCACertFile, roles, ntokenFile, ztsURL, hdr, conf, accessToken, authzDetails, proxyPrincipalSpiffeUris string
	var expireTime int
	var proxy, validate, claims, tokenOnly, showVersion bool
	flag.StringVar(&domain, "domain", "", "name of provider domain")
	flag.StringVar(&service, "service", "", "name of provider service")
	flag.StringVar(&roles, "roles", "", "comma separated list of provider roles")
	flag.StringVar(&ntokenFile, "ntoken-file", "", "service identity token file")
	flag.StringVar(&svcCACertFile, "svc-cacert-file", "", "CA Certificates file")
	flag.StringVar(&svcKeyFile, "svc-key-file", "", "service identity private key file")
	flag.StringVar(&svcCertFile, "svc-cert-file", "", "service identity certificate file")
	flag.StringVar(&ztsURL, "zts", "", "url of the ZTS Service")
	flag.StringVar(&hdr, "hdr", "Athenz-Principal-Auth", "Header name")
	flag.IntVar(&expireTime, "expire-time", 0, "token expire time in minutes")
	flag.BoolVar(&proxy, "proxy", true, "enable proxy mode for request")
	flag.BoolVar(&validate, "validate", false, "validate role token")
	flag.BoolVar(&claims, "claims", false, "display all claims from access token")
	flag.StringVar(&accessToken, "access-token", "", "access token to validate")
	flag.StringVar(&conf, "conf", "/home/athenz/conf/athenz.conf", "path to configuration file with public keys")
	flag.StringVar(&authzDetails, "authorization-details", "", "Authorization Details (json document)")
	flag.StringVar(&proxyPrincipalSpiffeUris, "proxy-principal-spiffe-uris", "", "comm separated list of proxy principal spiffe uris")
	flag.BoolVar(&showVersion, "version", false, "Show version")
	flag.BoolVar(&tokenOnly, "token-only", false, "Display the access token only")
	flag.Parse()

	if showVersion {
		printVersion()
		return
	}

	if validate {
		validateAccessToken(accessToken, conf, claims)
	} else {
		fetchAccessToken(domain, service, roles, ztsURL, svcKeyFile, svcCertFile, svcCACertFile, ntokenFile, hdr, authzDetails, proxyPrincipalSpiffeUris, proxy, expireTime, tokenOnly)
	}
}

func validateAccessToken(accessToken, conf string, showClaims bool) {
	if accessToken == "" || conf == "" {
		usage()
	}
	athenzConf, err := athenzconf.ReadConf(conf)
	if err != nil {
		log.Fatalf("unable to parse configuration file %s, error %v\n", conf, err)
	}
	tok, err := jwt.ParseSigned(accessToken)
	if err != nil {
		log.Fatalf("Unable to validate access token: %v\n", err)
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
		log.Fatalf("Unable to validate access token: %v\n", err)
	}
	if showClaims {
		for k, v := range claims {
			fmt.Printf("claim[%s] value[%s]\n", k, v)
		}
	}
	fmt.Println("Access Token successfully validated")
}

func fetchAccessToken(domain, service, roles, ztsURL, svcKeyFile, svcCertFile, svcCACertFile, ntokenFile, hdr, authzDetails, proxyPrincipalSpiffeUris string, proxy bool, expireTime int, tokenOnly bool) {

	defaultConfig, _ := athenzutils.ReadDefaultConfig()
	// check to see if we need to use zts url from our default config file
	if ztsURL == "" && defaultConfig != nil {
		ztsURL = defaultConfig.Zts
	}

	if domain == "" || ztsURL == "" {
		usage()
	}

	// check to see if we need to use our key/cert from our default config file
	if ntokenFile == "" && defaultConfig != nil {
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
	} else if ntokenFile == "" {
		usage()
	}

	var client *zts.ZTSClient
	var err error
	if certCredentials {
		client, err = athenzutils.ZtsClient(ztsURL, svcKeyFile, svcCertFile, svcCACertFile, proxy)
	} else {
		client, err = ztsNtokenClient(ztsURL, ntokenFile, hdr)
	}
	if err != nil {
		log.Fatalf("unable to create zts client: %v\n", err)
	}

	// generate the scope for the request, convert time to seconds
	request := athenzutils.GenerateAccessTokenRequestString(domain, service, roles, authzDetails, proxyPrincipalSpiffeUris, "", expireTime*60)

	// request an access token
	accessTokenResponse, err := client.PostAccessTokenRequest(zts.AccessTokenRequest(request))
	if err != nil {
		log.Fatalln(err)
	}

	// check if we're asked only to return the access token
	if tokenOnly {
		fmt.Print(accessTokenResponse.Access_token)
		return
	}

	data, err := json.Marshal(accessTokenResponse)
	if err != nil {
		log.Fatalln(err)
	}

	fmt.Println(string(data))
}

func ztsNtokenClient(ztsURL, ntokenFile, hdr string) (*zts.ZTSClient, error) {
	// we need to load our ntoken from the given file
	bytes, err := os.ReadFile(ntokenFile)
	if err != nil {
		return nil, err
	}
	ntoken := strings.TrimSpace(string(bytes))

	// use the ntoken to talk to Athenz
	client := zts.NewClient(ztsURL, nil)
	client.AddCredentials(hdr, ntoken)
	return &client, nil
}
