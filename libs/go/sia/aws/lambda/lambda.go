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
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/sts"
	"log"
	"net/url"
	"strings"

	"github.com/AthenZ/athenz/clients/go/zts"
	"github.com/AthenZ/athenz/libs/go/sia/aws/attestation"
	"github.com/AthenZ/athenz/libs/go/sia/util"
)

func getLambdaAttestationData(domain, service, account string) (*attestation.AttestationData, error) {
	data := &attestation.AttestationData{
		Role: fmt.Sprintf("%s.%s", domain, service),
	}
	stsSession := sts.New(session.New())
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
	return data, nil
}

func GetAWSLambdaServiceCertificate(ztsUrl, provider, domain, service, account string, ztsDomains []string, instanceIdSanDNS bool) (tls.Certificate, error) {
	key, err := util.GenerateKeyPair(2048)
	if err != nil {
		return tls.Certificate{}, err
	}

	var csrDetails util.CertReqDetails
	csrDetails.CommonName = fmt.Sprintf("%s.%s", domain, service)
	csrDetails.Country = "US"
	csrDetails.OrgUnit = provider
	hyphenDomain := strings.Replace(domain, ".", "-", -1)
	csrDetails.HostList = []string{}
	for _, ztsDomain := range ztsDomains {
		host := fmt.Sprintf("%s.%s.%s", service, hyphenDomain, ztsDomain)
		csrDetails.HostList = append(csrDetails.HostList, host)
	}
	csrDetails.URIs = []*url.URL{}
	spiffeUri := fmt.Sprintf("spiffe://%s/sa/%s", domain, service)
	csrDetails.URIs = util.AppendUri(csrDetails.URIs, spiffeUri)

	// athenz://instanceid/<provider>/<instance-id>
	instanceIdUri := fmt.Sprintf("athenz://instanceid/%s/lambda-%s-%s", provider, account, service)
	csrDetails.URIs = util.AppendUri(csrDetails.URIs, instanceIdUri)
	// for backward compatibility a sanDNS entry with instance id in the hostname if requested
	if instanceIdSanDNS {
		instanceIdHost := fmt.Sprintf("lambda-%s-%s.instanceid.athenz.%s", account, service, ztsDomains[0])
		csrDetails.HostList = append(csrDetails.HostList, instanceIdHost)
	}

	csr, err := util.GenerateX509CSR(key, csrDetails)
	if err != nil {
		return tls.Certificate{}, err
	}

	data, err := getLambdaAttestationData(domain, service, account)
	if err != nil {
		return tls.Certificate{}, err
	}

	client, err := util.ZtsClient(ztsUrl, "", "", "", "")
	if err != nil {
		return tls.Certificate{}, err
	}

	var info zts.InstanceRegisterInformation
	info.Provider = zts.ServiceName(provider)
	info.Domain = zts.DomainName(domain)
	info.Service = zts.SimpleName(service)
	info.Csr = csr

	attestData, err := json.Marshal(data)
	if err != nil {
		return tls.Certificate{}, err
	}
	info.AttestationData = string(attestData)

	identity, _, err := client.PostInstanceRegisterInformation(&info)
	if err != nil {
		log.Printf("Unable to do PostInstanceRegisterInformation, err: %v\n", err)
		return tls.Certificate{}, err
	}

	return tls.X509KeyPair([]byte(identity.X509Certificate), util.GetPEMBlock(key))
}
