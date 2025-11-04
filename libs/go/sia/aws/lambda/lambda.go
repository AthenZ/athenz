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

package lambda

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"strings"

	"github.com/AthenZ/athenz/libs/go/sia/aws/attestation"
	"github.com/AthenZ/athenz/libs/go/sia/aws/meta"
	"github.com/AthenZ/athenz/libs/go/sia/aws/stssession"
	"github.com/AthenZ/athenz/libs/go/sia/util"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/acm"
	acmtypes "github.com/aws/aws-sdk-go-v2/service/acm/types"
	"github.com/aws/aws-sdk-go-v2/service/secretsmanager"
	"github.com/aws/aws-sdk-go-v2/service/ssm"
	ssmtypes "github.com/aws/aws-sdk-go-v2/service/ssm/types"
	"github.com/aws/aws-sdk-go-v2/service/sts"
)

// ACMClientInterface defines the interface for ACM client operations
type ACMClientInterface interface {
	ListCertificates(ctx context.Context, params *acm.ListCertificatesInput, optFns ...func(*acm.Options)) (*acm.ListCertificatesOutput, error)
	ListTagsForCertificate(ctx context.Context, params *acm.ListTagsForCertificateInput, optFns ...func(*acm.Options)) (*acm.ListTagsForCertificateOutput, error)
}

func getLambdaAttestationData(domain, service, account string) ([]byte, error) {
	data := &attestation.AttestationData{
		Role: fmt.Sprintf("%s.%s", domain, service),
	}
	stsClient, err := stssession.New(false, "")
	if err != nil {
		return nil, err
	}
	roleArn := fmt.Sprintf("arn:aws:iam::%s:role/%s", account, data.Role)
	tok, err := stsClient.AssumeRole(context.TODO(), &sts.AssumeRoleInput{
		RoleArn:         &roleArn,
		RoleSessionName: &data.Role,
	})
	if err != nil {
		return nil, err
	}
	data.Access = *tok.Credentials.AccessKeyId
	data.Secret = *tok.Credentials.SecretAccessKey
	data.Token = *tok.Credentials.SessionToken

	return json.Marshal(data)
}

func GetAthenzIdentity(athenzDomain, athenzService, athenzProvider, ztsUrl string, sanDNSDomains []string, spiffeTrustDomain string, csrSubjectFields util.CsrSubjectFields) (*util.SiaCertData, error) {
	awsAccount := meta.GetAccountId()
	athenzDomain = strings.ToLower(athenzDomain)
	athenzService = strings.ToLower(athenzService)
	athenzProvider = strings.ToLower(athenzProvider)

	return getInternalAthenzIdentity(athenzDomain, athenzService, athenzProvider, ztsUrl, awsAccount, sanDNSDomains, spiffeTrustDomain, csrSubjectFields, false)
}

// Deprecated: Use GetAthenzIdentity functions to get identity certificates
func GetAWSLambdaServiceCertificate(ztsUrl, athenzProvider, athenzDomain, service, awsAccount string, sanDNSDomains []string, instanceIdSanDNS bool) (tls.Certificate, error) {

	athenzDomain = strings.ToLower(athenzDomain)
	service = strings.ToLower(service)
	athenzProvider = strings.ToLower(athenzProvider)

	csrSubjectFields := util.CsrSubjectFields{
		Country:          "US",
		OrganizationUnit: athenzProvider,
	}
	siaCertData, err := getInternalAthenzIdentity(athenzDomain, service, athenzProvider, ztsUrl, awsAccount, sanDNSDomains, "", csrSubjectFields, instanceIdSanDNS)
	if err != nil {
		return tls.Certificate{}, err
	}

	return siaCertData.TLSCertificate, nil
}

func getInternalAthenzIdentity(athenzDomain, athenzService, athenzProvider, ztsUrl, awsAccount string, sanDNSDomains []string, spiffeTrustDomain string, csrSubjectFields util.CsrSubjectFields, instanceIdSanDNS bool) (*util.SiaCertData, error) {

	privateKey, err := util.GenerateKeyPair(2048)
	if err != nil {
		return nil, err
	}
	attestationData, err := getLambdaAttestationData(athenzDomain, athenzService, awsAccount)
	if err != nil {
		return nil, err
	}

	instanceId := getLambdaInstance(awsAccount, athenzService)
	return util.RegisterIdentity(athenzDomain, athenzService, athenzProvider, ztsUrl, instanceId, string(attestationData), spiffeTrustDomain, sanDNSDomains, csrSubjectFields, instanceIdSanDNS, privateKey)
}

// StoreAthenzIdentityInSecretManager store the retrieved athenz identity in the
// specified secret. The secret is stored in the following keys:
//
//	"<domain>.<service>.cert.pem":"<x509-cert-pem>,
//	"<domain>.<service>.key.pem":"<pkey-pem>,
//	"ca.cert.pem":"<ca-cert-pem>,
//	"time": <utc-timestamp>
//
// The secret specified by the name must be pre-created
func StoreAthenzIdentityInSecretManager(athenzDomain, athenzService, secretName string, siaCertData *util.SiaCertData, isRoleCertificate bool) error {
	return StoreAthenzIdentityInSecretManagerCustomFormat(athenzDomain, athenzService, secretName, siaCertData, nil, isRoleCertificate)
}

// StoreAthenzIdentityInSecretManagerCustomFormat store the retrieved athenz identity in the
// specified secret in custom json format. The secret is stored in the following keys:
//
//	"<x509-cert-pem-key>":"<x509-cert-pem>,
//	"<private-pem-key>":"<pkey-pem>,
//	"<ca-cert-key>":"<ca-cert-pem>,
//	"<time-key>": <utc-timestamp>
//
// It supports only 4 json fields 'cert_pem', 'key_pem', 'ca_pem' and 'time'.
// Out of 4 fields 'cert_pem' and 'key_pem' are mandatory, and resulted json will contain  X509CertificateSignerPem
// and timestamp only if the corresponding json field names are set.
//
// sample `jsonFieldMapper` map: [{"cert_pem": "certPem"}, {"key_pem": "keyPem"}], will result json like
//
//	{  "certPem":"<x509-cert-pem>, "keyPem":"<pkey-pem> }
//
// The secret specified by the name must be pre-created
func StoreAthenzIdentityInSecretManagerCustomFormat(athenzDomain, athenzService, secretName string, siaCertData *util.SiaCertData, jsonFieldMapper map[string]string, isRoleCertificate bool) error {

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
	cfg, err := config.LoadDefaultConfig(context.TODO())
	if err != nil {
		return err
	}
	svc := secretsmanager.NewFromConfig(cfg)
	input := &secretsmanager.PutSecretValueInput{
		SecretId:     aws.String(secretName),
		SecretString: aws.String(string(keyCertJson)),
	}
	_, err = svc.PutSecretValue(context.TODO(), input)
	return err
}

// StoreAthenzIdentityInParameterStore store the retrieved athenz identity in the
// specified parameter store as Secure String, without CA certificate. The secret is stored in the following keys:
//
//	"<domain>.<service>.cert.pem":"<x509-cert-pem>,
//	"<domain>.<service>.key.pem":"<pkey-pem>,
//	"time": <utc-timestamp>
//
// The parameter specified by the name must be pre-created
func StoreAthenzIdentityInParameterStore(athenzDomain, athenzService, parameterName, kmsId string, siaCertData *util.SiaCertData, isRoleCertificate bool) error {
	jsonFieldMapper := make(map[string]string)
	jsonFieldMapper[util.SiaYieldMapperX509CertPemKey] = fmt.Sprintf("%s.%s.cert.pem", athenzDomain, athenzService)
	jsonFieldMapper[util.SiaYieldMapperPvtPemKey] = fmt.Sprintf("%s.%s.key.pem", athenzDomain, athenzService)
	//do not set CA cert
	jsonFieldMapper[util.SiaYieldMapperIssueTimeKey] = "time"
	return storeAthenzIdentityInParameterStoreCustomFormat(parameterName, kmsId, siaCertData, jsonFieldMapper, isRoleCertificate)
}

// StoreAthenzIdentityInParameterStoreCustomFormat store the retrieved athenz identity in the
// specified parameter store as Secure String, without CA certificate. The secret is stored in the following keys
//
//	"<x509-cert-pem-key>":"<x509-cert-pem>,
//	"<private-pem-key>":"<pkey-pem>,
//	"<time-key>": <utc-timestamp>
//
// It supports only 3 json fields 'cert_pem', 'key_pem' and 'time', where 'cert_pem' and 'key_pem' are mandatory.
// The resulted json will contain timestamp only if the corresponding json field name is set. It will ignore 'ca_pem'
// even if it is set.
//
// sample `jsonFieldMapper` map: [{"cert_pem": "certPem"}, {"key_pem": "keyPem"}], will result json like
//
//	{  "certPem":"<x509-cert-pem>, "keyPem":"<pkey-pem> }
//
// The parameter specified by the name must be pre-created
func StoreAthenzIdentityInParameterStoreCustomFormat(parameterName, kmsId string, siaCertData *util.SiaCertData, jsonFieldMapper map[string]string, isRoleCertificate bool) error {
	// generate our payload
	if nil != jsonFieldMapper {
		_, ok := jsonFieldMapper[util.SiaYieldMapperCertSignerPemKey]
		if ok {
			// unset 'ca cert' field name
			jsonFieldMapper[util.SiaYieldMapperCertSignerPemKey] = ""
		}
	}
	return storeAthenzIdentityInParameterStoreCustomFormat(parameterName, kmsId, siaCertData, jsonFieldMapper, isRoleCertificate)
}

func storeAthenzIdentityInParameterStoreCustomFormat(parameterName, kmsId string, siaCertData *util.SiaCertData, jsonFieldMapper map[string]string, isRoleCertificate bool) error {
	// generate our payload
	keyCertJson, err := util.GenerateCustomSecretJsonData(siaCertData, jsonFieldMapper, isRoleCertificate)

	if err != nil {
		return fmt.Errorf("unable to generate secret json data: %v", err)
	}
	cfg, err := config.LoadDefaultConfig(context.TODO())
	if err != nil {
		return err
	}
	ssmClient := ssm.NewFromConfig(cfg)
	input := &ssm.PutParameterInput{
		Type:      ssmtypes.ParameterTypeSecureString,
		Name:      aws.String(parameterName),
		Value:     aws.String(string(keyCertJson)),
		Overwrite: aws.Bool(true),
		KeyId:     aws.String(kmsId),
	}
	_, err = ssmClient.PutParameter(context.TODO(), input)
	return err
}

// GetAWSLambdaRoleCertificate retrieves a role certificate for the specified Athenz domain, service, provider, and role name.
// It requires service certificate to obtain role certificate, so Athenz service certificate needs to be obtained first and pass it here to get role certificate from ZTS.
// Finally, it returns a SiaCertData object containing the role certificate and private key.
func GetAWSLambdaRoleCertificate(athenzDomain, athenzService, athenzProvider, roleName, ztsUrl string, expiryTime int64, sanDNSDomains []string, spiffeTrustDomain string, csrSubjectFields util.CsrSubjectFields, rolePrincipalEmail bool, svcTLSCert *util.SiaCertData) (*util.SiaCertData, error) {
	awsAccount := meta.GetAccountId()
	athenzDomain = strings.ToLower(athenzDomain)
	athenzService = strings.ToLower(athenzService)
	athenzProvider = strings.ToLower(athenzProvider)
	instanceId := getLambdaInstance(awsAccount, athenzService)

	if nil == svcTLSCert || "" == svcTLSCert.X509CertificatePem || "" == svcTLSCert.PrivateKeyPem || nil == svcTLSCert.PrivateKey {
		return nil, fmt.Errorf("invalid service TLS certificate data in SiaCertData")
	}
	return util.GetRoleCertificate(athenzDomain, athenzService, instanceId, athenzProvider, roleName, ztsUrl, expiryTime, sanDNSDomains, spiffeTrustDomain, csrSubjectFields, svcTLSCert, rolePrincipalEmail)
}

// StoreAthenzIdentityInACM stores the specified certificate in AWS ACM. If the certificate
// ARN is specified, the certificate will be updated in the given entry. If the ARN is not
// specified, then the caller can specify a tag key id and value pair and the function will
// try to locate the certificate arn that has the given tag configured. If no certificate is
// found, then a new one will be created with the given tag. If successful, the function will
// return the certificate arn that was either created or updated.
func StoreAthenzIdentityInACM(certArn, certTagIdKey, certTagIdValue string, siaCertData *util.SiaCertData, addlTags map[string]string) (string, error) {
	// Extract certificate components from SiaCertData
	certPem := siaCertData.X509CertificatePem
	keyPem := siaCertData.PrivateKeyPem

	// Validate that we have the required certificate and key
	if certPem == "" {
		return "", fmt.Errorf("certificate PEM is empty")
	}
	if keyPem == "" {
		return "", fmt.Errorf("private key PEM is empty")
	}
	if certArn == "" && (certTagIdKey == "" || certTagIdValue == "") {
		return "", fmt.Errorf("either certificate ARN or Tag ID Name/Value must be specified")
	}

	// Load AWS configuration
	cfg, err := config.LoadDefaultConfig(context.TODO())
	if err != nil {
		return "", fmt.Errorf("unable to load AWS config: %v", err)
	}

	// Create ACM client
	acmClient := acm.NewFromConfig(cfg)

	// Prepare the import certificate input
	input := &acm.ImportCertificateInput{
		Certificate: []byte(certPem),
		PrivateKey:  []byte(keyPem),
	}

	if certArn == "" {
		certArn, err = getCertificateArnByTag(context.TODO(), acmClient, certTagIdKey, certTagIdValue)
		if err != nil {
			log.Printf("unable to get certificate arn: %v\n", err)
			log.Println("will be importing the certificate as a new entry into ACM")
		}
	}

	// set up our tags based on given input
	var acmTags []acmtypes.Tag
	acmTags = append(acmTags, acmtypes.Tag{
		Key:   aws.String(certTagIdKey),
		Value: aws.String(certTagIdValue),
	})
	if len(addlTags) > 0 {
		for k, v := range addlTags {
			acmTags = append(acmTags, acmtypes.Tag{
				Key:   aws.String(k),
				Value: aws.String(v),
			})
		}
	}

	// If certificate ARN is provided, include it to reimport/update the existing certificate
	// additionally, setting tags during import api is only supported for the initial import
	// otherwise, when updating the certificate, we need to set the tags in a separate call

	if certArn != "" {
		input.CertificateArn = aws.String(certArn)
	} else {
		input.Tags = acmTags
	}

	// Import the certificate
	output, err := acmClient.ImportCertificate(context.TODO(), input)
	returnCertArn := ""
	if err == nil {
		if certArn == "" {
			returnCertArn = aws.ToString(output.CertificateArn)
			log.Printf("new certificate was imported into ACM: %s\n", returnCertArn)
		} else {
			returnCertArn = certArn
			log.Printf("certificate %s was updated in ACM\n", returnCertArn)

			// now we need to update the certificate tags
			tagInput := &acm.AddTagsToCertificateInput{
				CertificateArn: aws.String(returnCertArn),
				Tags:           acmTags,
			}
			_, err = acmClient.AddTagsToCertificate(context.TODO(), tagInput)
			if err != nil {
				log.Printf("failed to update tags to certificate: %v", err)
			}
		}
	}

	return returnCertArn, err
}

// getCertificateArnByTag finds an ACM certificate ARN that matches the given tag.
// It returns the first matching ARN found or an error if no match is found.
func getCertificateArnByTag(ctx context.Context, client ACMClientInterface, certTagIdKey, certTagIdValue string) (string, error) {

	// paginate through all certificates
	paginator := acm.NewListCertificatesPaginator(client, &acm.ListCertificatesInput{})

	for paginator.HasMorePages() {
		page, err := paginator.NextPage(ctx)
		if err != nil {
			return "", fmt.Errorf("failed to list certificates: %w", err)
		}

		for _, cert := range page.CertificateSummaryList {
			// for each certificate, get its tags
			tagsOutput, err := client.ListTagsForCertificate(ctx, &acm.ListTagsForCertificateInput{
				CertificateArn: cert.CertificateArn,
			})
			if err != nil {
				// Log the error but continue; we don't want one failed cert to stop the search
				log.Printf("warning: could not list tags for certificate %s: %v\n", *cert.CertificateArn, err)
				continue
			}

			// if the given tag value is present
			for _, tag := range tagsOutput.Tags {
				if tag.Value != nil && tag.Key != nil && certTagIdKey == *tag.Key && certTagIdValue == *tag.Value {
					return *cert.CertificateArn, nil
				}
			}
		}
	}

	return "", errors.New("no certificate found with the specified tag key/value pair")
}

func getLambdaInstance(awsAccount, athenzService string) string {
	return fmt.Sprintf("lambda-%s-%s", awsAccount, athenzService)
}
