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
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"flag"
	"fmt"
	"github.com/AthenZ/athenz/clients/go/zts"
	"github.com/AthenZ/athenz/libs/go/sia/util"
	"github.com/AthenZ/athenz/provider/harness/sia-harness"
	"log"
	"os"
	"strings"
)

// Following can be set by the build script using LDFLAGS

var Version string

func main() {

	var ztsURL, domain, service, spiffeTrustDomain, subjC, subjO, subjOU, provider, harnessUrl string
	var caCertFile, keyFile, certFile, signerCertFile, dnsDomain string
	var showVersion, stripNewLines bool
	var expiryTime int
	flag.IntVar(&expiryTime, "expiry-time", 360, "expiry time in minutes (optional)")
	flag.StringVar(&keyFile, "key-file", "", "output private key file")
	flag.StringVar(&certFile, "cert-file", "", "output certificate file")
	flag.StringVar(&signerCertFile, "signer-cert-file", "", "output signer certificate file (optional)")
	flag.StringVar(&domain, "domain", os.Getenv("ATHENZ_DOMAIN"), "domain of service")
	flag.StringVar(&service, "service", os.Getenv("ATHENZ_SERVICE"), "name of service")
	flag.StringVar(&ztsURL, "zts", "", "url of the ZTS Service")
	flag.StringVar(&harnessUrl, "harness", "", "url of the Harness OIDC Token Endpoint")
	flag.StringVar(&dnsDomain, "dns-domain", "", "dns domain suffix to be included in the csr for sanDNS entries")
	flag.StringVar(&subjC, "subj-c", "US", "Subject C/Country field (optional)")
	flag.StringVar(&subjO, "subj-o", "", "Subject O/Organization field (optional)")
	flag.StringVar(&subjOU, "subj-ou", "Athenz", "Subject OU/OrganizationalUnit field (optional)")
	flag.StringVar(&provider, "provider", "sys.auth.harness", "Athenz Provider (optional)")
	flag.StringVar(&caCertFile, "cacert", "", "CA certificate file (optional)")
	flag.StringVar(&spiffeTrustDomain, "spiffe-trust-domain", "", "SPIFFE trust domain (optional)")
	flag.BoolVar(&stripNewLines, "strip-new-lines", true, "Strip new lines from the key and certificate files")
	flag.BoolVar(&showVersion, "version", false, "Show version")
	flag.Parse()

	if showVersion {
		log.Printf("SIA Harness version: %s \n", Version)
		os.Exit(0)
	}

	// make sure all requires arguments are provided
	if keyFile == "" || certFile == "" || domain == "" || service == "" || ztsURL == "" || dnsDomain == "" || harnessUrl == "" {
		log.Printf("missing required arguments\n")
		flag.Usage()
		os.Exit(1)
	}

	// get the oidc token for the Harness Pipeline
	oidcToken, claims, err := sia.GetOIDCToken(ztsURL, harnessUrl)
	if err != nil {
		log.Fatalf("unable to obtain oidc token from Harness: %v\n", err)
	}

	// extract the instance id from the claims
	instanceId, err := getInstanceId(claims)
	if err != nil {
		log.Fatalf("unable to extract instance id from oidc token claims: %v\n", err)
	}

	// we're going to display the action and resource to be used in athenz policies
	context := claims["context"].(string)
	triggerType := extractFieldFromContext(context, "triggerType")
	triggerEvent := extractFieldFromContext(context, "triggerEvent")
	action := "harness." + triggerType
	if triggerEvent != "" && triggerEvent != "null" {
		action += "." + triggerEvent
	}
	log.Println("Action: " + strings.ToLower(action))
	log.Printf("Resource: %s\n", strings.ToLower(domain+":"+claims["sub"].(string)))

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
	// data contains the authentication details for the harness pipeline
	client, err := util.ZtsClient(ztsURL, "", "", "", caCertFile)
	if err != nil {
		log.Fatalf("unable to create zts client: %v\n", err)
	}
	client.AddCredentials("User-Agent", "SIA-Harness "+Version)

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

	var keyData []byte
	if stripNewLines {
		keyData = stripNewLinesFromFile(util.GetPEMBlock(privateKey))
	} else {
		keyData = util.GetPEMBlock(privateKey)
	}
	err = os.WriteFile(keyFile, keyData, 0400)
	if err != nil {
		log.Fatalf("unable to write private key file: %s - error: %v\n", keyFile, err)
	}

	var certData []byte
	if stripNewLines {
		certData = stripNewLinesFromFile([]byte(identity.X509Certificate))
	} else {
		certData = []byte(identity.X509Certificate)
	}
	err = os.WriteFile(certFile, certData, 0444)
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

func stripNewLinesFromFile(data []byte) []byte {
	return bytes.ReplaceAll(data, []byte("\n"), []byte("\\n"))
}

func getInstanceId(claims map[string]interface{}) (string, error) {
	// extract the run id from the claims which we're going to use as part of our instance id
	// the format of the run id is: <org>:<project>:<pipeline>

	orgId := extractValue(claims, "organization_id")
	if orgId == "" {
		return "", fmt.Errorf("unable to extract organization_id from oidc token claims")
	}
	projectId := extractValue(claims, "project_id")
	if projectId == "" {
		return "", fmt.Errorf("unable to extract project_id from oidc token claims")
	}
	pipelineId := extractValue(claims, "pipeline_id")
	if pipelineId == "" {
		return "", fmt.Errorf("unable to extract pipeline_id from oidc token claims")
	}
	context := extractValue(claims, "context")
	if context == "" {
		return "", fmt.Errorf("unable to extract context from oidc token claims")
	}
	sequenceId := extractFieldFromContext(context, "sequenceId")
	if sequenceId == "" {
		return "", fmt.Errorf("unable to extract sequenceId from context: %s", context)
	}
	instanceId := orgId + ":" + projectId + ":" + pipelineId + ":" + sequenceId
	return instanceId, nil
}

func extractValue(claims map[string]interface{}, key string) string {
	value, ok := claims[key]
	if !ok {
		return ""
	}
	return value.(string)
}

func extractFieldFromContext(context, field string) string {
	prefix := field + ":"
	fields := strings.Split(context, "/")
	for _, field := range fields {
		if strings.HasPrefix(field, prefix) {
			return field[len(prefix):]
		}
	}
	return ""
}
