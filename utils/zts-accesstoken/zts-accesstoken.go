// Copyright The Athenz Authors
// Licensed under the terms of the Apache version 2.0 license. See LICENSE file for terms.

package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"net/url"
	"os"
	"strings"

	"github.com/AthenZ/athenz/clients/go/zts"
	"github.com/AthenZ/athenz/libs/go/athenzconf"
	"github.com/AthenZ/athenz/libs/go/athenzutils"
	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
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
	fmt.Println("")
	fmt.Println("  JAG Token Issue (external IdP ID Token -> ID-JAG):")
	fmt.Println("       zts-accesstoken -domain <domain> -roles <roles> -grant-type token-exchange -subject-token <id-token-file> -audience <audience> <credentials> -zts <zts-server-url>")
	fmt.Println("")
	fmt.Println("  Access Token Exchange (Access Token -> Access Token):")
	fmt.Println("       zts-accesstoken -domain <target-domain> [-roles <roles>] -grant-type token-exchange -requested-token-type access_token -subject-token <access-token-file> -subject-token-type access_token -audience <target-domain> [-actor-token <actor-token-file> -actor-token-type access_token] <credentials> -zts <zts-server-url>")
	fmt.Println("")
	fmt.Println("  JAG Token Exchange (ID-JAG -> Access Token):")
	fmt.Println("       zts-accesstoken -domain <domain> -roles <roles> -grant-type jwt-bearer -assertion <id-jag-file> <credentials> -zts <zts-server-url>")
	fmt.Println("")
	fmt.Println("  Validate:")
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
	var domain, service, actor, svcKeyFile, svcCertFile, svcCACertFile, roles, ntokenFile, ztsURL, hdr, conf, accessToken, authzDetails, proxyPrincipalSpiffeUris string
	var grantType, subjectToken, subjectTokenType, requestedTokenType, audience, assertion, actorToken, actorTokenType string
	var expireTime int
	var proxy, validate, claims, tokenOnly, showVersion, roleInAudClaim, openidIssuer bool
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
	flag.StringVar(&actor, "actor", "", "actor that may request on behalf of the principal")
	flag.BoolVar(&roleInAudClaim, "role-in-aud-claim", false, "include the role name in the audience claim when a single role is returned")
	flag.BoolVar(&openidIssuer, "openid-issuer", false, "use OpenID Connect issuer instead of default athenz issuer")
	flag.StringVar(&grantType, "grant-type", "", "grant type: token-exchange (for ID-JAG issue or access token exchange) or jwt-bearer (for JAG exchange)")
	flag.StringVar(&subjectToken, "subject-token", "", "file path to the subject token for token exchange")
	flag.StringVar(&subjectTokenType, "subject-token-type", "urn:ietf:params:oauth:token-type:id_token", "subject token type")
	flag.StringVar(&requestedTokenType, "requested-token-type", "urn:ietf:params:oauth:token-type:id-jag", "requested token type")
	flag.StringVar(&audience, "audience", "", "audience for the token request")
	flag.StringVar(&assertion, "assertion", "", "file path to the assertion token (ID-JAG) for jwt-bearer grant")
	flag.StringVar(&actorToken, "actor-token", "", "file path to the actor token for token exchange delegation")
	flag.StringVar(&actorTokenType, "actor-token-type", "", "actor token type")
	flag.Parse()

	if showVersion {
		printVersion()
		return
	}

	if validate {
		validateAccessToken(accessToken, conf, claims)
	} else if grantType == "token-exchange" {
		requestedTokenType = normalizeOAuthTokenType(requestedTokenType)
		subjectTokenType = normalizeOAuthTokenType(subjectTokenType)
		actorTokenType = normalizeOAuthTokenType(actorTokenType)
		if requestedTokenType == "urn:ietf:params:oauth:token-type:id-jag" {
			fetchJAGTokenIssue(domain, roles, ztsURL, svcKeyFile, svcCertFile, svcCACertFile, ntokenFile, hdr, subjectToken, subjectTokenType, requestedTokenType, audience, proxy, expireTime, tokenOnly)
		} else if requestedTokenType == "urn:ietf:params:oauth:token-type:access_token" || requestedTokenType == "" {
			fetchAccessTokenViaTokenExchange(domain, roles, ztsURL, svcKeyFile, svcCertFile, svcCACertFile, ntokenFile, hdr, subjectToken, subjectTokenType, requestedTokenType, audience, actorToken, actorTokenType, actor, proxy, expireTime, tokenOnly)
		} else {
			usage()
		}
	} else if grantType == "jwt-bearer" {
		fetchAccessTokenViaJAG(domain, roles, ztsURL, svcKeyFile, svcCertFile, svcCACertFile, ntokenFile, hdr, assertion, proxy, tokenOnly)
	} else {
		fetchAccessToken(domain, service, roles, ztsURL, svcKeyFile, svcCertFile, svcCACertFile, ntokenFile, hdr, authzDetails, proxyPrincipalSpiffeUris, actor, proxy, expireTime, tokenOnly, roleInAudClaim, openidIssuer)
	}
}

func normalizeOAuthTokenType(tokenType string) string {
	switch strings.ToLower(tokenType) {
	case "id-jag":
		return "urn:ietf:params:oauth:token-type:id-jag"
	case "id_token":
		return "urn:ietf:params:oauth:token-type:id_token"
	case "access_token":
		return "urn:ietf:params:oauth:token-type:access_token"
	case "jwt":
		return "urn:ietf:params:oauth:token-type:jwt"
	default:
		return tokenType
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
	signatureAlgorithms := []jose.SignatureAlgorithm{jose.RS256, jose.RS384, jose.RS512, jose.PS256, jose.PS384, jose.PS512, jose.ES256, jose.ES384, jose.ES512, jose.EdDSA}
	tok, err := jwt.ParseSigned(accessToken, signatureAlgorithms)
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

func fetchAccessToken(domain, service, roles, ztsURL, svcKeyFile, svcCertFile, svcCACertFile, ntokenFile, hdr, authzDetails, proxyPrincipalSpiffeUris, actor string, proxy bool, expireTime int, tokenOnly bool, roleInAudClaim bool, openidIssuer bool) {

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

	if actor != "" {
		params := url.Values{}
		params.Add("actor", actor)
		request += "&" + params.Encode()
	}

	if roleInAudClaim {
		params := url.Values{}
		params.Add("role_in_aud_claim", "true")
		request += "&" + params.Encode()
	}
	if openidIssuer {
		params := url.Values{}
		params.Add("openid_issuer", "true")
		request += "&" + params.Encode()
	}

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

func fetchJAGTokenIssue(domain, roles, ztsURL, svcKeyFile, svcCertFile, svcCACertFile, ntokenFile, hdr, subjectTokenFile, subjectTokenType, requestedTokenType, audience string, proxy bool, expireTime int, tokenOnly bool) {

	defaultConfig, _ := athenzutils.ReadDefaultConfig()
	if ztsURL == "" && defaultConfig != nil {
		ztsURL = defaultConfig.Zts
	}

	if domain == "" || roles == "" || audience == "" || subjectTokenFile == "" || ztsURL == "" {
		usage()
	}

	// read the subject token (ID token) from file
	subjectTokenBytes, err := os.ReadFile(subjectTokenFile)
	if err != nil {
		log.Fatalf("unable to read subject token file %s: %v\n", subjectTokenFile, err)
	}
	subjectToken := strings.TrimSpace(string(subjectTokenBytes))

	// use cert-based credentials for JAG token issue
	if defaultConfig != nil {
		if svcKeyFile == "" {
			svcKeyFile = defaultConfig.PrivateKey
		}
		if svcCertFile == "" {
			svcCertFile = defaultConfig.PublicCert
		}
	}

	if svcKeyFile == "" || svcCertFile == "" {
		log.Fatalln("service key and cert files are required for JAG token issue")
	}

	client, err := athenzutils.ZtsClient(ztsURL, svcKeyFile, svcCertFile, svcCACertFile, proxy)
	if err != nil {
		log.Fatalf("unable to create zts client: %v\n", err)
	}

	// build the JAG token issue request, convert time to seconds
	request := athenzutils.GenerateJAGTokenIssueRequestString(domain, roles, subjectToken, subjectTokenType, requestedTokenType, audience, expireTime*60)

	accessTokenResponse, err := client.PostAccessTokenRequest(zts.AccessTokenRequest(request))
	if err != nil {
		log.Fatalln(err)
	}

	if tokenOnly {
		fmt.Print(accessTokenResponse.Id_token)
		return
	}

	data, err := json.Marshal(accessTokenResponse)
	if err != nil {
		log.Fatalln(err)
	}

	fmt.Println(string(data))
}

func fetchAccessTokenViaTokenExchange(domain, roles, ztsURL, svcKeyFile, svcCertFile, svcCACertFile, ntokenFile, hdr, subjectTokenFile, subjectTokenType, requestedTokenType, audience, actorTokenFile, actorTokenType, actor string, proxy bool, expireTime int, tokenOnly bool) {

	defaultConfig, _ := athenzutils.ReadDefaultConfig()
	if ztsURL == "" && defaultConfig != nil {
		ztsURL = defaultConfig.Zts
	}

	if audience == "" {
		audience = domain
	}
	if domain == "" || audience == "" || subjectTokenFile == "" || subjectTokenType == "" || ztsURL == "" {
		usage()
	}

	subjectTokenBytes, err := os.ReadFile(subjectTokenFile)
	if err != nil {
		log.Fatalf("unable to read subject token file %s: %v\n", subjectTokenFile, err)
	}
	subjectToken := strings.TrimSpace(string(subjectTokenBytes))

	var actorToken string
	if actorTokenFile != "" {
		actorTokenBytes, err := os.ReadFile(actorTokenFile)
		if err != nil {
			log.Fatalf("unable to read actor token file %s: %v\n", actorTokenFile, err)
		}
		actorToken = strings.TrimSpace(string(actorTokenBytes))
		if actorTokenType == "" {
			log.Fatalln("actor token type is required when actor token is specified")
		}
	}

	if defaultConfig != nil {
		if ntokenFile == "" && svcKeyFile == "" {
			svcKeyFile = defaultConfig.PrivateKey
		}
		if ntokenFile == "" && svcCertFile == "" {
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
	if certCredentials {
		client, err = athenzutils.ZtsClient(ztsURL, svcKeyFile, svcCertFile, svcCACertFile, proxy)
	} else {
		client, err = ztsNtokenClient(ztsURL, ntokenFile, hdr)
	}
	if err != nil {
		log.Fatalf("unable to create zts client: %v\n", err)
	}

	request := athenzutils.GenerateTokenExchangeRequestString(domain, roles, subjectToken, subjectTokenType, requestedTokenType, audience, actorToken, actorTokenType, actor, expireTime*60)

	accessTokenResponse, err := client.PostAccessTokenRequest(zts.AccessTokenRequest(request))
	if err != nil {
		log.Fatalln(err)
	}

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

func fetchAccessTokenViaJAG(domain, roles, ztsURL, svcKeyFile, svcCertFile, svcCACertFile, ntokenFile, hdr, assertionFile string, proxy bool, tokenOnly bool) {

	defaultConfig, _ := athenzutils.ReadDefaultConfig()
	if ztsURL == "" && defaultConfig != nil {
		ztsURL = defaultConfig.Zts
	}

	if domain == "" || assertionFile == "" || ztsURL == "" {
		usage()
	}

	// read the assertion token (ID-JAG) from file
	assertionBytes, err := os.ReadFile(assertionFile)
	if err != nil {
		log.Fatalf("unable to read assertion token file %s: %v\n", assertionFile, err)
	}
	assertion := strings.TrimSpace(string(assertionBytes))

	// create the ZTS client
	if defaultConfig != nil {
		if ntokenFile == "" && svcKeyFile == "" {
			svcKeyFile = defaultConfig.PrivateKey
		}
		if ntokenFile == "" && svcCertFile == "" {
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
	if certCredentials {
		client, err = athenzutils.ZtsClient(ztsURL, svcKeyFile, svcCertFile, svcCACertFile, proxy)
	} else {
		client, err = ztsNtokenClient(ztsURL, ntokenFile, hdr)
	}
	if err != nil {
		log.Fatalf("unable to create zts client: %v\n", err)
	}

	// build the JAG token exchange request
	request := athenzutils.GenerateJAGTokenExchangeRequestString(assertion)

	// optionally add scope for downscoping
	if roles != "" {
		var scope string
		roleList := strings.Split(roles, ",")
		for idx, role := range roleList {
			if idx != 0 {
				scope += " "
			}
			scope += domain + ":role." + role
		}
		params, _ := url.ParseQuery(request)
		params.Add("scope", scope)
		request = params.Encode()
	}

	accessTokenResponse, err := client.PostAccessTokenRequest(zts.AccessTokenRequest(request))
	if err != nil {
		log.Fatalln(err)
	}

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
