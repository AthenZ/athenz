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
	"log"
	"os"
	"strings"

	certificatemanager "cloud.google.com/go/certificatemanager/apiv1"
	"cloud.google.com/go/certificatemanager/apiv1/certificatemanagerpb"
	secretmanager "cloud.google.com/go/secretmanager/apiv1"
	"cloud.google.com/go/secretmanager/apiv1/secretmanagerpb"
	gcpa "github.com/AthenZ/athenz/libs/go/sia/gcp/attestation"
	gcpm "github.com/AthenZ/athenz/libs/go/sia/gcp/meta"
	"github.com/AthenZ/athenz/libs/go/sia/util"
	"github.com/googleapis/gax-go/v2"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/fieldmaskpb"
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

	instanceId := getCloudFnInstance(gcpProjectId)
	return getInternalAthenzIdentity(athenzDomain, athenzService, instanceId, athenzProvider, ztsUrl, sanDNSDomains, spiffeTrustDomain, csrSubjectFields)
}

func getInternalAthenzIdentity(athenzDomain, athenzService, instanceId, athenzProvider, ztsUrl string, sanDNSDomains []string, spiffeTrustDomain string, csrSubjectFields util.CsrSubjectFields) (*util.SiaCertData, error) {
	// Get an identity-document for this GCF from GCP.
	attestationData, err := gcpa.New(gcpMetaDataServer, athenzService, ztsUrl)
	if err != nil {
		return nil, fmt.Errorf("unable to get attestation data: %v", err)
	}

	// Create a private-key.
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, fmt.Errorf("unable to generate private key: %v", err)
	}

	return util.RegisterIdentity(athenzDomain, athenzService, athenzProvider, ztsUrl, instanceId, attestationData, spiffeTrustDomain, sanDNSDomains, csrSubjectFields, false, privateKey)
}

// GetRoleCertificate retrieves a role certificate for the specified Athenz domain, service, provider, and role name.
// It requires service certificate to obtain role certificate, so Athenz service certificate needs to be obtained first and pass it here to get role certificate from ZTS.
// Finally, it returns a SiaCertData object containing the role certificate and private key.
func GetRoleCertificate(athenzDomain, athenzService, athenzProvider, roleName, ztsUrl string, expiryTime int64, sanDNSDomains []string, spiffeTrustDomain string, csrSubjectFields util.CsrSubjectFields, rolePrincipalEmail bool, svcTLSCert *util.SiaCertData) (*util.SiaCertData, error) {

	athenzDomain = strings.ToLower(athenzDomain)
	athenzService = strings.ToLower(athenzService)
	athenzProvider = strings.ToLower(athenzProvider)

	// Get the project id from metadata
	gcpProjectId, err := gcpm.GetProject(gcpMetaDataServer)
	if err != nil {
		return nil, fmt.Errorf("unable to extract project id: %v", err)
	}

	instanceId := getCloudFnInstance(gcpProjectId)
	if svcTLSCert == nil || svcTLSCert.X509CertificatePem == "" || svcTLSCert.PrivateKeyPem == "" || svcTLSCert.PrivateKey == nil {
		return nil, fmt.Errorf("invalid service TLS certificate data in SiaCertData")
	}
	return util.GetRoleCertificate(athenzDomain, athenzService, instanceId, athenzProvider, roleName, ztsUrl, expiryTime, sanDNSDomains, spiffeTrustDomain, csrSubjectFields, svcTLSCert, rolePrincipalEmail)

}

func getCloudFnInstance(gcpProjectId string) string {

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
	return instanceId
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
func StoreAthenzIdentityInSecretManager(athenzDomain, athenzService, secretName string, siaCertData *util.SiaCertData, isRoleCertificate bool) error {

	// Create the GCP secret-manager client.
	ctx := context.Background()

	// generate our payload
	keyCertJson, err := util.GenerateSecretJsonData(athenzDomain, athenzService, siaCertData, isRoleCertificate)
	if err != nil {
		return fmt.Errorf("unable to generate secret json data: %v", err)
	}

	secretManagerClient, err := secretmanager.NewClient(ctx)
	if err != nil {
		return fmt.Errorf("unable to create secret manager client: %v", err)
	}
	defer (func() {
		_ = secretManagerClient.Close()
	})()

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

// StoreAthenzIdentityInSecretManagerCustomFormat store the retrieved athenz identity in the
// specified secret. The secret is stored in the following json format:
//
//	{
//	   "<x509-cert-pem-key>":"<x509-cert-pem>,
//	   "<private-pem-key>":"<pkey-pem>,
//	   "<ca-cert-key>":"<ca-cert-pem>,
//	   "<time-key>": <utc-timestamp>
//	}
//
// It supports only 4 json fields 'cert_pem', 'key_pem', 'ca_pem' and 'time'.
// Out of 4 fields 'cert_pem' and 'key_pem' are mandatory, and resulted json will contain  X509CertificateSignerPem
// and timestamp only if the corresponding json field names are set.
//
// sample `jsonFieldMapper` map: [{"cert_pem": "certPem"}, {"key_pem": "keyPem"}], will result json like
//
//	{  "certPem":"<x509-cert-pem>, "keyPem":"<pkey-pem> }
//
// The secret specified by the name must be pre-created and the service account
// that the function is invoked with must have been authorized to assume the
// "Secret Manager Secret Version Adder" role
func StoreAthenzIdentityInSecretManagerCustomFormat(athenzDomain, athenzService, secretName string, siaCertData *util.SiaCertData, jsonFieldMapper map[string]string, isRoleCertificate bool) error {

	// Create the GCP secret-manager client.
	ctx := context.Background()

	var keyCertJson []byte
	var err error
	// generate our payload
	if nil == jsonFieldMapper {
		keyCertJson, err = util.GenerateSecretJsonData(athenzDomain, athenzService, siaCertData, isRoleCertificate)
	} else {
		keyCertJson, err = util.GenerateCustomSecretJsonData(siaCertData, jsonFieldMapper, isRoleCertificate)
	}

	if err != nil {
		return fmt.Errorf("unable to generate secret json data: %v", err)
	}

	secretManagerClient, err := secretmanager.NewClient(ctx)
	if err != nil {
		return fmt.Errorf("unable to create secret manager client: %v", err)
	}
	defer (func() {
		_ = secretManagerClient.Close()
	})()

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

// CertificateOperationInterface defines the interface for certificate operations
type CertificateOperationInterface interface {
	Name() string
	Wait(context.Context, ...gax.CallOption) (*certificatemanagerpb.Certificate, error)
}

// CertificateManagerClientInterface defines the interface for certificate manager client operations
type CertificateManagerClientInterface interface {
	CreateCertificate(context.Context, *certificatemanagerpb.CreateCertificateRequest, ...gax.CallOption) (CertificateOperationInterface, error)
	UpdateCertificate(context.Context, *certificatemanagerpb.UpdateCertificateRequest, ...gax.CallOption) (CertificateOperationInterface, error)
	Close() error
}

// certificateOperationAdapter adapts a concrete operation to the interface
type certificateOperationAdapter struct {
	createOp *certificatemanager.CreateCertificateOperation
	updateOp *certificatemanager.UpdateCertificateOperation
	isCreate bool
}

func (a *certificateOperationAdapter) Name() string {
	if a.isCreate {
		return a.createOp.Name()
	}
	return a.updateOp.Name()
}

func (a *certificateOperationAdapter) Wait(ctx context.Context, opts ...gax.CallOption) (*certificatemanagerpb.Certificate, error) {
	if a.isCreate {
		return a.createOp.Wait(ctx, opts...)
	}
	return a.updateOp.Wait(ctx, opts...)
}

// certificateManagerClientAdapter adapts the real client to the interface
type certificateManagerClientAdapter struct {
	client *certificatemanager.Client
}

func (a *certificateManagerClientAdapter) CreateCertificate(ctx context.Context, req *certificatemanagerpb.CreateCertificateRequest, opts ...gax.CallOption) (CertificateOperationInterface, error) {
	op, err := a.client.CreateCertificate(ctx, req, opts...)
	if err != nil {
		return nil, err
	}
	return &certificateOperationAdapter{createOp: op, isCreate: true}, nil
}

func (a *certificateManagerClientAdapter) UpdateCertificate(ctx context.Context, req *certificatemanagerpb.UpdateCertificateRequest, opts ...gax.CallOption) (CertificateOperationInterface, error) {
	op, err := a.client.UpdateCertificate(ctx, req, opts...)
	if err != nil {
		return nil, err
	}
	return &certificateOperationAdapter{updateOp: op, isCreate: false}, nil
}

func (a *certificateManagerClientAdapter) Close() error {
	return a.client.Close()
}

// MetadataProvider defines the interface for GCP metadata operations
type MetadataProvider interface {
	GetProject(metaEndpoint string) (string, error)
}

// DefaultMetadataProvider is the default implementation that uses the gcpm package
type DefaultMetadataProvider struct{}

// GetProject retrieves the GCP project ID from the metadata server
func (p *DefaultMetadataProvider) GetProject(metaEndpoint string) (string, error) {
	return gcpm.GetProject(metaEndpoint)
}

// StoreAthenzIdentityInCertificateManager store the retrieved athenz identity certificate
// in Google Certificate Manager. The certificate is stored as a self-managed certificate
// with the certificate and private key.
//
// The certificate specified by the certificateName must be pre-created and the service account
// that the function is invoked with must have been authorized to assume the
// "Certificate Manager Admin" role or equivalent permissions to create/update certificates.
//
// The location parameter specifies where the certificate should be created (e.g., "global").
// For regional certificates, specify the region (e.g., "us-central1").
func StoreAthenzIdentityInCertificateManager(certificateName, location string, siaCertData *util.SiaCertData, resourceLabels map[string]string) error {

	// Validate input
	if siaCertData == nil || siaCertData.X509CertificatePem == "" || siaCertData.PrivateKeyPem == "" {
		return fmt.Errorf("invalid certificate data: certificate and private key must be provided")
	}

	// Create the GCP certificate manager client.
	ctx := context.Background()

	certificateManagerClient, err := certificatemanager.NewClient(ctx)
	if err != nil {
		return fmt.Errorf("unable to create certificate manager client: %v", err)
	}
	defer (func() {
		_ = certificateManagerClient.Close()
	})()

	// Wrap the real client in an adapter to match the interface
	clientAdapter := &certificateManagerClientAdapter{client: certificateManagerClient}
	metadataProvider := &DefaultMetadataProvider{}
	return storeIdentityInCertificateManager(ctx, clientAdapter, metadataProvider, certificateName, location, siaCertData, resourceLabels)
}

func storeIdentityInCertificateManager(ctx context.Context, certificateManagerClient CertificateManagerClientInterface, metadataProvider MetadataProvider, certificateName, location string, siaCertData *util.SiaCertData, resourceLabels map[string]string) error {

	// Get the project id from metadata
	gcpProjectId, err := metadataProvider.GetProject(gcpMetaDataServer)
	if err != nil {
		return fmt.Errorf("unable to extract project id: %v", err)
	}

	// Build the parent path
	parent := fmt.Sprintf("projects/%s/locations/%s", gcpProjectId, location)

	// Build the certificate resource name
	certificateFullName := fmt.Sprintf("%s/certificates/%s", parent, certificateName)

	// Create the self-managed certificate request
	createCertificateReq := &certificatemanagerpb.CreateCertificateRequest{
		Parent:        parent,
		CertificateId: certificateName,
		Certificate: &certificatemanagerpb.Certificate{
			Name: certificateFullName,
			Type: &certificatemanagerpb.Certificate_SelfManaged{
				SelfManaged: &certificatemanagerpb.Certificate_SelfManagedCertificate{
					PemCertificate: siaCertData.X509CertificatePem,
					PemPrivateKey:  siaCertData.PrivateKeyPem,
				},
			},
			Labels: resourceLabels,
		},
	}

	// Try to create the certificate
	createOp, err := certificateManagerClient.CreateCertificate(ctx, createCertificateReq)
	if err == nil {
		log.Printf("Waiting for CreateCertificate operation %s to complete...\n", createOp.Name())
		_, err = createOp.Wait(ctx)
		if err != nil {
			log.Printf("CreateCertificate (wait) operation failed: %v\n", err)
		} else {
			log.Printf("CreateCertificate operation succeeded")
		}
		return err
	}

	// check if the error because the certificate already exists and as such
	// we just need to update the certificate instead

	st, ok := status.FromError(err)
	if !ok || st.Code() != codes.AlreadyExists {
		log.Printf("CreateCertificate operation failed: %v\n", err)
		return err
	}

	log.Println("Certificate already exists, we'll be updating it...")

	// Update the existing certificate
	updateCertificateReq := &certificatemanagerpb.UpdateCertificateRequest{
		Certificate: &certificatemanagerpb.Certificate{
			Name: certificateFullName,
			Type: &certificatemanagerpb.Certificate_SelfManaged{
				SelfManaged: &certificatemanagerpb.Certificate_SelfManagedCertificate{
					PemCertificate: siaCertData.X509CertificatePem,
					PemPrivateKey:  siaCertData.PrivateKeyPem,
				},
			},
			Labels: resourceLabels,
		},
		UpdateMask: &fieldmaskpb.FieldMask{
			Paths: []string{"self_managed", "labels"},
		},
	}

	updateOp, err := certificateManagerClient.UpdateCertificate(ctx, updateCertificateReq)
	if err == nil {
		log.Printf("Waiting for UpdateCertificate operation %s to complete...\n", updateOp.Name())
		_, err = updateOp.Wait(ctx)
		if err != nil {
			log.Printf("UpdateCertificate (wait) operation failed: %v\n", err)
		} else {
			log.Println("UpdateCertificate operation succeeded")
		}
	} else {
		log.Printf("UpdateCertificate operation failed: %v\n", err)
	}
	return err
}
