//
// Copyright The Athenz Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//

package main

import (
	"crypto/rand"
	"crypto/rsa"
	"flag"
	"github.com/AthenZ/athenz/clients/go/zts"
	"github.com/AthenZ/athenz/libs/go/sia/util"
	"github.com/AthenZ/athenz/provider/buildkite/sia-buildkite"
	"log"
	"os"
	"strconv"
	"strings"
)

// Following can be set by the build script using LDFLAGS

var Version string

func main() {

	var ztsURL, domain, service, spiffeTrustDomain, subjC, subjO, subjOU, provider string
	var caCertFile, keyFile, certFile, signerCertFile, dnsDomain string
	var oidcToken string
	var showVersion bool
	var expiryTime int
	flag.StringVar(&oidcToken, "build-kite-token", "", "BuildKite OIDC token")
	flag.StringVar(&keyFile, "key-file", "", "output private key file")
	flag.StringVar(&certFile, "cert-file", "", "output certificate file")
	flag.StringVar(&signerCertFile, "signer-cert-file", "", "output signer certificate file (optional)")
	flag.StringVar(&domain, "domain", "", "domain of service")
	flag.StringVar(&service, "service", "", "name of service")
	flag.StringVar(&ztsURL, "zts", "", "url of the ZTS Service")
	flag.StringVar(&dnsDomain, "dns-domain", "", "dns domain suffix to be included in the csr for sanDNS entries")
	flag.StringVar(&subjC, "subj-c", "US", "Subject C/Country field (optional)")
	flag.StringVar(&subjO, "subj-o", "", "Subject O/Organization field (optional)")
	flag.StringVar(&subjOU, "subj-ou", "Athenz", "Subject OU/OrganizationalUnit field (optional)")
	flag.StringVar(&provider, "provider", "sys.auth.build-kite", "Athenz Provider (optional)")
	flag.StringVar(&caCertFile, "cacert", "", "CA certificate file (optional)")
	flag.StringVar(&spiffeTrustDomain, "spiffe-trust-domain", "", "SPIFFE trust domain (optional)")
	flag.IntVar(&expiryTime, "expiry-time", 360, "expiry time in minutes (optional)")
	flag.BoolVar(&showVersion, "version", false, "Show version")
	flag.Parse()

	if showVersion {
		log.Printf("SIA BuildKite version: %s \n", Version)
		os.Exit(0)
	}

	// make sure all requires arguments are provided
	if oidcToken == "" || keyFile == "" || certFile == "" || domain == "" || service == "" || ztsURL == "" || dnsDomain == "" {
		log.Printf("missing required arguments\n")
		flag.Usage()
		os.Exit(1)
	}

	// get the oidc token for the BuildKite agent
	claims, err := sia.GetOIDCTokenClaims(oidcToken)
	if err != nil {
		log.Fatalf("unable to obtain oidc token claims from BuildKite: %v\n", err)
	}

	// construct the instance id from the claims, as <organization_slug>:<pipeline_slug>:<run_number>:<job_id>
	organizationSlug := claims["organization_slug"].(string)
	if organizationSlug == "" {
		log.Fatalf("unable to extract organization_slug from oidc token claims\n")
	}
	pipelineSlug := claims["pipeline_slug"].(string)
	if pipelineSlug == "" {
		log.Fatalf("unable to extract pipeline_slug from oidc token claims\n")
	}
	buildNumber := int(claims["build_number"].(float64))
	if buildNumber == 0 {
		log.Fatalf("unable to extract build_number from oidc token claims\n")
	}
	jobId := claims["job_id"].(string)
	if jobId == "" {
		log.Fatalf("unable to extract job_id from oidc token claims\n")
	}
	instanceId := strings.Join([]string{organizationSlug, pipelineSlug, strconv.Itoa(buildNumber), jobId}, ":")

	subject := claims["sub"].(string)
	if subject == "" {
		log.Fatalf("unable to extract subject from oidc token claims\n")
	}
	// the resource for the main service is on the form: organization:<org>:pipeline:<pipeline>:ref:refs/heads/<branch>:*
	// while the resource for the PR service omits the ref part: organization:<org>:pipeline:<pipeline>:*
	subjectParts := strings.Split(subject, ":")
	if len(subjectParts) < 6 {
		log.Fatalf("invalid subject format: %s\n", subject)
	}
	mainResource := strings.Join(subjectParts[:6], ":") + ":*"
	prResource := strings.Join(subjectParts[:4], ":") + ":*"

	// we're going to display the action and resource to be used in athenz policies
	log.Printf("Action:                    %s\n", "build-kite.build")
	log.Printf("Resource for main service: %s\n", domain+":"+mainResource)
	log.Printf("Resource for PR service:   %s\n", domain+":"+prResource)

	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		log.Fatalf("unable to generate rsa private key: %v\n", err)
	}

	// generate a csr for this service
	csrData, err := sia.GetCSRDetails(privateKey, domain, service, provider, instanceId, dnsDomain, spiffeTrustDomain, subjC, subjO, subjOU)
	if err != nil {
		log.Fatalf("unable to generate CSR: %v\n", err)
	}

	// we're using copper argos which only uses tls and the attestation
	// data contains the authentication details for the GitHub actions
	client, err := util.ZtsClient(ztsURL, "", "", "", caCertFile)
	if err != nil {
		log.Fatalf("unable to create zts client: %v\n", err)
	}
	client.AddCredentials("User-Agent", "SIA-BuildKite "+Version)

	certExpiryTime := int32(expiryTime)
	req := &zts.InstanceRegisterInformation{
		Provider:        zts.ServiceName(provider),
		Domain:          zts.DomainName(domain),
		Service:         zts.SimpleName(service),
		AttestationData: oidcToken,
		Csr:             csrData,
		ExpiryTime:      &certExpiryTime,
	}

	// request a tls certificate for this service
	identity, _, err := client.PostInstanceRegisterInformation(req)
	if err != nil {
		log.Fatalf("unable to register instance: %v\n", err)
	}

	err = os.WriteFile(keyFile, util.GetPEMBlock(privateKey), 0400)
	if err != nil {
		log.Fatalf("unable to write private key file: %s - error: %v\n", keyFile, err)
	}

	err = os.WriteFile(certFile, []byte(identity.X509Certificate), 0444)
	if err != nil {
		log.Fatalf("unable to write certificate file: %s - error: %v\n", certFile, err)
	}

	if signerCertFile != "" {
		err = os.WriteFile(signerCertFile, []byte(identity.X509CertificateSigner), 0444)
		if err != nil {
			log.Fatalf("unable to write signer certificate file: %s - error: %v\n", signerCertFile, err)
		}
	}
}
