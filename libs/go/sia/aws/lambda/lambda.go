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
	"fmt"
	"github.com/AthenZ/athenz/libs/go/sia/aws/attestation"
	"github.com/AthenZ/athenz/libs/go/sia/aws/meta"
	"github.com/AthenZ/athenz/libs/go/sia/aws/stssession"
	"github.com/AthenZ/athenz/libs/go/sia/util"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/secretsmanager"
	"github.com/aws/aws-sdk-go-v2/service/ssm"
	"github.com/aws/aws-sdk-go-v2/service/ssm/types"
	"github.com/aws/aws-sdk-go-v2/service/sts"
	"strings"
)

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
		Type:      types.ParameterTypeSecureString,
		Name:      aws.String(parameterName),
		Value:     aws.String(string(keyCertJson)),
		Overwrite: aws.Bool(true),
		KeyId:     aws.String(kmsId),
	}
	_, err = ssmClient.PutParameter(context.TODO(), input)
	return err
}

// GetAWSLambdaRoleCertificate retrieves a role certificate for the specified Athenz domain, service, provider, and role name.
// It is an expensive operation, because it needs to fetch the Athenz service certificate first, then using that certificate it will fetch role certificate from ZTS.
// Finally it returns a SiaCertData object containing the role certificate and private key.
func GetAWSLambdaRoleCertificate(athenzDomain, athenzService, athenzProvider, roleName, ztsUrl string, expiryTime int64, sanDNSDomains []string, spiffeTrustDomain string, csrSubjectFields util.CsrSubjectFields, rolePrincipalEmail bool) (*util.SiaCertData, error) {
	awsAccount := meta.GetAccountId()
	athenzDomain = strings.ToLower(athenzDomain)
	athenzService = strings.ToLower(athenzService)
	athenzProvider = strings.ToLower(athenzProvider)
	instanceId := getLambdaInstance(awsAccount, athenzService)

	tlsCert, err := getInternalAthenzIdentity(athenzDomain, athenzService, athenzProvider, ztsUrl, awsAccount, sanDNSDomains, spiffeTrustDomain, csrSubjectFields, false)
	if err != nil {
		return nil, err
	}
	return util.GetRoleCertificate(athenzDomain, athenzService, instanceId, athenzProvider, roleName, ztsUrl, expiryTime, sanDNSDomains, spiffeTrustDomain, csrSubjectFields, tlsCert, rolePrincipalEmail)
}

func getLambdaInstance(awsAccount, athenzService string) string {
	return fmt.Sprintf("lambda-%s-%s", awsAccount, athenzService)
}
