// Copyright Athenz Authors
// Licensed under the terms of the Apache version 2.0 license. See LICENSE file for terms.

package main

import (
	"crypto/x509"
	"encoding/pem"
	"flag"
	"fmt"
	"github.com/AthenZ/athenz/clients/go/zts"
	"github.com/AthenZ/athenz/libs/go/athenzconf"
	"github.com/AthenZ/athenz/libs/go/athenzutils"
	"gopkg.in/square/go-jose.v2"
	"gopkg.in/square/go-jose.v2/jwt"
	"log"
	"os"
	"strings"
)

var (
	// VERSION gets set by the build script via the LDFLAGS.
	VERSION string

	// BUILD_DATE gets set by the build script via the LDFLAGS.
	BUILD_DATE string
)

func usage() {
	fmt.Println("usage: zts-idtoken <credentials> -zts <ZTS url> -scope <scope> -redirect-uri <redirect-uri> -nonce <nonce> -client-id <client-id> -state <state> -key-type <RSA|EC>")
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
	var clientId, scope, state, redirectUri, nonce, svcKeyFile, svcCertFile, svcCACertFile, ztsURL, conf, idToken, keyType string
	var proxy, validate, claims, showVersion bool
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
	flag.StringVar(&conf, "conf", "/home/athenz/conf/athenz.conf", "path to configuration file with public keys")
	flag.BoolVar(&validate, "validate", false, "validate id token")
	flag.BoolVar(&claims, "claims", false, "display all claims from id token")
	flag.StringVar(&idToken, "id-token", "", "id token to validate")
	flag.StringVar(&keyType, "key-type", "RSA", "signing key type: RSA or EC")
	flag.BoolVar(&showVersion, "version", false, "Show version")
	flag.Parse()

	if showVersion {
		printVersion()
		return
	}

	if validate {
		validateIdToken(idToken, conf, claims)
	} else {
		fetchIdToken(ztsURL, svcKeyFile, svcCertFile, svcCACertFile, clientId, redirectUri, scope, nonce, state, keyType, proxy)
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
	publicKey, err := loadPublicKey(publicKeyPEM)
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

func fetchIdToken(ztsURL, svcKeyFile, svcCertFile, svcCACertFile, clientId, redirectUri, scope, nonce, state, keyType string, proxy bool) {

	if ztsURL == "" {
		usage()
	}

	client, err := athenzutils.ZtsClient(ztsURL, svcKeyFile, svcCertFile, svcCACertFile, proxy)
	if err != nil {
		log.Fatalf("unable to create zts client: %v\n", err)
	}
	client.DisableRedirect = true

	// request an id token
	_, location, err := client.GetOIDCResponse("id_token", zts.ServiceName(clientId), redirectUri, scope, zts.EntityName(state), zts.EntityName(nonce), zts.SimpleName(keyType))
	if err != nil {
		log.Fatalln(err)
	}

	//the format of the location header is <redirect-uri>#id_token=<token>&state=<state>
	idTokenLabel := "#id_token="
	startIdx := strings.Index(location, idTokenLabel)
	if startIdx == -1 {
		log.Fatalln("Location header does not contain id_token field")
	}
	idToken := location[startIdx+len(idTokenLabel):]
	endIdx := strings.Index(idToken, "&state")
	if endIdx != -1 {
		idToken = idToken[:endIdx]
	}
	fmt.Println(idToken)
}

// NewVerifier creates an instance of Verifier using the given public key.
func loadPublicKey(publicKeyPEM []byte) (interface{}, error) {
	block, _ := pem.Decode(publicKeyPEM)
	if block == nil {
		return nil, fmt.Errorf("unable to load public key")
	}
	if !strings.HasSuffix(block.Type, "PUBLIC KEY") {
		return nil, fmt.Errorf("invalid public key type: %s", block.Type)
	}

	return x509.ParsePKIXPublicKey(block.Bytes)
}
