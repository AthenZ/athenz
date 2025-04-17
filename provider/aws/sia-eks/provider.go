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

package sia

import (
	"crypto"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"net"
	"net/url"

	"github.com/AthenZ/athenz/libs/go/sia/aws/attestation"
	"github.com/AthenZ/athenz/libs/go/sia/host/ip"
	"github.com/AthenZ/athenz/libs/go/sia/host/provider"
	"github.com/AthenZ/athenz/libs/go/sia/host/signature"
	"github.com/AthenZ/athenz/libs/go/sia/host/utils"
)

type EKSProvider struct {
	Name string
}

// GetName returns the name of the current provider
func (eks EKSProvider) GetName() string {
	return eks.Name
}

// GetHostname returns the hostname as per the provider
func (eks EKSProvider) GetHostname(fqdn bool) string {
	return utils.GetHostname(fqdn)
}

func (eks EKSProvider) AttestationData(_ string, _ crypto.PrivateKey, _ *signature.SignatureInfo) (string, error) {
	return "", fmt.Errorf("not implemented")
}

func (eks EKSProvider) PrepareKey(_ string) (crypto.PrivateKey, error) {
	return "", fmt.Errorf("not implemented")
}

func (eks EKSProvider) GetCsrDn() pkix.Name {
	return pkix.Name{}
}

func (eks EKSProvider) GetSanDns(_ string, _ bool, _ bool, _ []string) []string {
	return nil
}

func (eks EKSProvider) GetSanUri(_ string, _ ip.Opts, _, _ string) []*url.URL {
	return nil
}

func (eks EKSProvider) GetEmail(_ string) []string {
	return nil
}

func (eks EKSProvider) GetRoleDnsNames(_ *x509.Certificate, _ string) []string {
	return nil
}

func (eks EKSProvider) GetSanIp(_ map[string]bool, _ []net.IP, _ ip.Opts) []net.IP {
	return nil
}

func (eks EKSProvider) GetSuffixes() []string {
	return []string{}
}

func (eks EKSProvider) CloudAttestationData(request *provider.AttestationRequest) (string, error) {
	return attestation.New(request.Domain, request.Service, request.Region, request.Account, request.EC2Document, request.EC2Signature, request.UseRegionalSTS, request.OmitDomain)
}

func (eks EKSProvider) GetAccountDomainServiceFromMeta(_ string) (string, string, string, error) {
	return "", "", "", fmt.Errorf("not implemented")
}

func (eks EKSProvider) GetAccessManagementProfileFromMeta(_ string) (string, error) {
	return "", fmt.Errorf("not implemented")
}

func (eks EKSProvider) GetAdditionalSshHostPrincipals(_ string) (string, error) {
	return "", nil
}

func (tp EKSProvider) GetInstanceAttributeValueFromMeta(string, string) (string, error) {
	return "", nil
}
