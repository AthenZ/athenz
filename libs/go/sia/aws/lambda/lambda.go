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
	"crypto/tls"
	"encoding/json"
	"fmt"
	"github.com/AthenZ/athenz/libs/go/sia/aws/attestation"
	"github.com/AthenZ/athenz/libs/go/sia/aws/meta"
	"github.com/AthenZ/athenz/libs/go/sia/util"
	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/secretsmanager"
	"github.com/aws/aws-sdk-go/service/sts"
	"strings"
)

func getLambdaAttestationData(domain, service, account string) ([]byte, error) {
	data := &attestation.AttestationData{
		Role: fmt.Sprintf("%s.%s", domain, service),
	}
	clientSession, err := session.NewSession()
	if err != nil {
		return nil, err
	}
	stsSession := sts.New(clientSession)
	roleArn := fmt.Sprintf("arn:aws:iam::%s:role/%s", account, data.Role)
	tok, err := stsSession.AssumeRole(&sts.AssumeRoleInput{
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
	return getInternalAthenzIdentity(athenzDomain, athenzService, athenzProvider, ztsUrl, awsAccount, sanDNSDomains, spiffeTrustDomain, csrSubjectFields, false)
}

// Deprecated: Use GetAthenzIdentity functions to get identity certificates
func GetAWSLambdaServiceCertificate(ztsUrl, athenzProvider, athenzDomain, service, awsAccount string, sanDNSDomains []string, instanceIdSanDNS bool) (tls.Certificate, error) {

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

	athenzDomain = strings.ToLower(athenzDomain)
	athenzService = strings.ToLower(athenzService)
	athenzProvider = strings.ToLower(athenzProvider)

	privateKey, err := util.GenerateKeyPair(2048)
	if err != nil {
		return nil, err
	}
	attestationData, err := getLambdaAttestationData(athenzDomain, athenzService, awsAccount)
	if err != nil {
		return nil, err
	}

	instanceId := fmt.Sprintf("lambda-%s-%s", awsAccount, athenzService)
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
func StoreAthenzIdentityInSecretManager(athenzDomain, athenzService, secretName string, siaCertData *util.SiaCertData) error {

	// generate our payload
	keyCertJson, err := util.GenerateSecretJsonData(athenzDomain, athenzService, siaCertData)
	if err != nil {
		return fmt.Errorf("unable to generate secret json data: %v", err)
	}
	clientSession, err := session.NewSession()
	if err != nil {
		return err
	}
	svc := secretsmanager.New(clientSession)
	input := &secretsmanager.PutSecretValueInput{
		SecretId:     aws.String(secretName),
		SecretString: aws.String(string(keyCertJson)),
	}
	_, err = svc.PutSecretValue(input)
	return err
}
