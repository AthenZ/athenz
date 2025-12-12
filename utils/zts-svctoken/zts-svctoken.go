// Copyright The Athenz Authors
// Licensed under the terms of the Apache version 2.0 license. See LICENSE file for terms.

package main

import (
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"

	"github.com/AthenZ/athenz/clients/go/zts"
	"github.com/AthenZ/athenz/libs/go/athenzutils"
	"github.com/AthenZ/athenz/libs/go/tls/config"
)

var (
	// VERSION gets set by the build script via the LDFLAGS.
	VERSION string

	// BUILD_DATE gets set by the build script via the LDFLAGS.
	BUILD_DATE string
)

func printVersion() {
	if VERSION == "" {
		fmt.Println("zts-svctoken (development version)")
	} else {
		fmt.Println("zts-svctoken " + VERSION + " " + BUILD_DATE)
	}
}

func usage() {
	fmt.Println("zts-svctoken -zts <zts-server-url> -domain <domain-name> -service <service-name> -svc-key-file <private-key-file> -svc-cert-file <service-cert-file> [-cacert <ca-cert-file>] -audience <audience> -provider <provider-name> -instance <instance-id> -nonce <nonce> [-spiffe-uri <uri>] [-spiffe-svid]")
	os.Exit(1)
}

func main() {
	var ztsURL, domain, service, provider, instance, nonce string
	var svcKeyFile, svcCertFile, caCertFile, audience, spiffeUri, attestationDataFile string
	var spiffeSvid, showVersion bool
	var expiryTime int
	flag.StringVar(&attestationDataFile, "attestation-data", "", "Attestation Data File")
	flag.BoolVar(&spiffeSvid, "spiffe-svid", false, "include spiffe uri as the subject of the token")
	flag.StringVar(&spiffeUri, "spiffe-uri", "", "Spiffe URI to be included in the token")
	flag.StringVar(&audience, "audience", "", "audience for the token")
	flag.StringVar(&nonce, "nonce", "", "nonce for the token")
	flag.IntVar(&expiryTime, "expiry-time", 0, "expiry time in minutes")
	flag.StringVar(&caCertFile, "cacert", "", "CA certificate file")
	flag.StringVar(&domain, "domain", "", "domain of service (required)")
	flag.StringVar(&service, "service", "", "name of service (required)")
	flag.StringVar(&ztsURL, "zts", "", "url of the ZTS Service")
	flag.StringVar(&provider, "provider", "", "Athenz Provider")
	flag.StringVar(&instance, "instance", "", "Instance Id")
	flag.StringVar(&svcKeyFile, "svc-key-file", "", "service identity private key file")
	flag.StringVar(&svcCertFile, "svc-cert-file", "", "service identity certificate file")
	flag.BoolVar(&showVersion, "version", false, "Show version")
	flag.Parse()

	if showVersion {
		printVersion()
		return
	}

	defaultConfig, _ := athenzutils.ReadDefaultConfig()
	// check to see if we need to use zts url from our default config file
	if ztsURL == "" && defaultConfig != nil {
		ztsURL = defaultConfig.Zts
	}

	if ztsURL == "" || audience == "" || domain == "" || service == "" || provider == "" || instance == "" || svcKeyFile == "" || svcCertFile == "" || nonce == "" {
		log.Println("Error: missing required attributes. Run with -help for command line arguments")
		usage()
	}

	if spiffeSvid && spiffeUri == "" {
		log.Println("Error: spiffe-uri must be provided when spiffe-svid is set to true")
		usage()
	}

	// if we're given a certificate then we'll use that otherwise
	// we're going to generate a ntoken for our request unless
	// we're using copper argos which only uses tls and the attestation
	// data contains the authentication details

	client, err := certClient(ztsURL, svcKeyFile, svcCertFile, caCertFile)
	if err != nil {
		log.Fatalln(err)
	}

	attestationData := ""
	if attestationDataFile != "" {
		attestationDataBytes, err := os.ReadFile(attestationDataFile)
		if err != nil {
			log.Fatalln(err)
		}
		attestationData = string(attestationDataBytes)
	}

	expiryTime32 := int32(expiryTime)
	req := &zts.InstanceRegisterInformation{
		Provider:             zts.ServiceName(provider),
		Domain:               zts.DomainName(domain),
		Service:              zts.SimpleName(service),
		JwtSVIDInstanceId:    zts.PathElement(instance),
		JwtSVIDAudience:      audience,
		JwtSVIDNonce:         zts.EntityName(nonce),
		JwtSVIDSpiffe:        spiffeUri,
		JwtSVIDSpiffeSubject: &spiffeSvid,
		ExpiryTime:           &expiryTime32,
		AttestationData:      attestationData,
	}

	// request a jwt token for this service
	identity, _, err := client.PostInstanceRegisterInformation(req)
	if err != nil {
		log.Fatalln(err)
	}

	fmt.Println(identity.ServiceToken)
}

func certClient(ztsURL string, keyFile, certfile, caCertFile string) (*zts.ZTSClient, error) {

	keyPem, err := os.ReadFile(keyFile)
	if err != nil {
		return nil, err
	}
	certpem, err := os.ReadFile(certfile)
	if err != nil {
		return nil, err
	}
	var cacertpem []byte
	if caCertFile != "" {
		cacertpem, err = os.ReadFile(caCertFile)
		if err != nil {
			return nil, err
		}
	}

	tlsConfig, err := config.ClientTLSConfigFromPEM(keyPem, certpem, cacertpem)
	if err != nil {
		return nil, err
	}
	transport := &http.Transport{
		Proxy:           http.ProxyFromEnvironment,
		TLSClientConfig: tlsConfig,
	}
	client := zts.NewClient(ztsURL, transport)
	return &client, nil
}
