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

package functions

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"fmt"
	"os"
	"strings"

	secretmanager "cloud.google.com/go/secretmanager/apiv1"
	"cloud.google.com/go/secretmanager/apiv1/secretmanagerpb"
	gcpa "github.com/AthenZ/athenz/libs/go/sia/gcp/attestation"
	gcpm "github.com/AthenZ/athenz/libs/go/sia/gcp/meta"
	"github.com/AthenZ/athenz/libs/go/sia/util"
)

const (
	gcpMetaDataServer = "http://metadata.google.internal"
)

// GetAthenzIdentity this method can be called from within a GCF (Google Cloud Function) - to get an Athenz certificate from ZTS.
// See https://cloud.google.com/functions/docs/writing/write-http-functions#http-example-go
func GetAthenzIdentity(athenzDomain, athenzService, athenzProvider, ztsUrl string, sanDNSDomains []string, spiffeTrustDomain string, csrSubjectFields util.CsrSubjectFields) (*util.SiaCertData, error) {

	athenzDomain = strings.ToLower(athenzDomain)
	athenzService = strings.ToLower(athenzService)
	athenzProvider = strings.ToLower(athenzProvider)

	// Get the project id from metadata
	gcpProjectId, err := gcpm.GetProject(gcpMetaDataServer)
	if err != nil {
		return nil, fmt.Errorf("unable to extract project id: %v", err)
	}

	// Get the function name https://cloud.google.com/functions/docs/configuring/env-var#newer_runtimes
	gcpFunctionName := os.Getenv("K_SERVICE")

	// if we don't have a function name then we'll use our project
	// id in its place to generate our instance id uri
	instanceId := "gcf-"
	if gcpFunctionName == "" {
		instanceId += gcpProjectId
	} else {
		instanceId += gcpProjectId + ":" + gcpFunctionName
	}

	// Get an identity-document for this GCF from GCP.

	attestationData, err := gcpa.New(gcpMetaDataServer, "", ztsUrl)
	if err != nil {
		return nil, fmt.Errorf("unable to get attestation data: %v", err)
	}

	// Create a private-key.
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, fmt.Errorf("unable to generate private key: %v", err)
	}

	return util.RegisterIdentity(athenzDomain, athenzService, athenzProvider, ztsUrl, instanceId, string(attestationData), spiffeTrustDomain, sanDNSDomains, csrSubjectFields, false, privateKey)
}

// StoreAthenzIdentityInSecretManager store the retrieved athenz identity in the
// specified secret. The secret is stored in the following json format:
//
//	{
//	   "<domain>.<service>.cert.pem":"<x509-cert-pem>,
//	   "<domain>.<service>.key.pem":"<pkey-pem>,
//	   "ca.cert.pem":"<ca-cert-pem>,
//	   "time": <utc-timestamp>
//	}
//
// The secret specified by the name must be pre-created and the service account
// that the function is invoked with must have been authorized to assume the
// "Secret Manager Secret Version Adder" role
func StoreAthenzIdentityInSecretManager(athenzDomain, athenzService, secretName string, siaCertData *util.SiaCertData) error {

	// Create the GCP secret-manager client.
	ctx := context.Background()
	secretManagerClient, err := secretmanager.NewClient(ctx)
	if err != nil {
		return fmt.Errorf("unable to create secret manager client: %v", err)
	}
	defer (func() {
		_ = secretManagerClient.Close()
	})()

	// generate our payload
	keyCertJson, err := util.GenerateSecretJsonData(athenzDomain, athenzService, siaCertData)
	if err != nil {
		return fmt.Errorf("unable to generate secret json data: %v", err)
	}

	// Get the project id from metadata
	gcpProjectId, err := gcpm.GetProject(gcpMetaDataServer)
	if err != nil {
		return fmt.Errorf("unable to extract project id: %v", err)
	}

	// Build the request
	addSecretVersionReq := &secretmanagerpb.AddSecretVersionRequest{
		Parent: "projects/" + gcpProjectId + "/secrets/" + secretName,
		Payload: &secretmanagerpb.SecretPayload{
			Data: keyCertJson,
		},
	}

	// Call the API.
	_, err = secretManagerClient.AddSecretVersion(ctx, addSecretVersionReq)
	return err
}
