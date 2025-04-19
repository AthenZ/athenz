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

	gcpa "github.com/AthenZ/athenz/libs/go/sia/gcp/attestation"
	"github.com/AthenZ/athenz/libs/go/sia/gcp/meta"
	"github.com/AthenZ/athenz/libs/go/sia/host/ip"
	"github.com/AthenZ/athenz/libs/go/sia/host/provider"
	"github.com/AthenZ/athenz/libs/go/sia/host/signature"
	"github.com/AthenZ/athenz/libs/go/sia/host/utils"
)

type GCPRunProvider struct {
	Name string
}

// GetName returns the name of the current provider
func (gcprun GCPRunProvider) GetName() string {
	return gcprun.Name
}

// GetHostname returns the hostname as per the provider
func (gcprun GCPRunProvider) GetHostname(fqdn bool) string {
	return utils.GetHostname(fqdn)
}

func (gcprun GCPRunProvider) AttestationData(_ string, _ crypto.PrivateKey, _ *signature.SignatureInfo) (string, error) {
	result, err := meta.GetData("http://169.254.169.254", "/computeMetadata/v1/instance/service-accounts/default/identity?audience=https://zts.athenz.io&format=full")
	if err == nil {
		return string(result), nil
	}
	return "", fmt.Errorf("error while retriveing attestation data")
}

func (gcprun GCPRunProvider) PrepareKey(_ string) (crypto.PrivateKey, error) {
	return "", fmt.Errorf("not implemented")
}

func (gcprun GCPRunProvider) GetCsrDn() pkix.Name {
	return pkix.Name{}
}

func (gcprun GCPRunProvider) GetSanDns(_ string, _ bool, _ bool, _ []string) []string {
	return nil
}

func (gcprun GCPRunProvider) GetSanUri(_ string, _ ip.Opts, _, _ string) []*url.URL {
	return nil
}

func (gcprun GCPRunProvider) GetEmail(_ string) []string {
	return nil
}

func (gcprun GCPRunProvider) GetRoleDnsNames(_ *x509.Certificate, _ string) []string {
	return nil
}

func (gcprun GCPRunProvider) GetSanIp(_ map[string]bool, _ []net.IP, _ ip.Opts) []net.IP {
	return nil
}

func (gcprun GCPRunProvider) GetSuffixes() []string {
	return []string{}
}

func (gcprun GCPRunProvider) CloudAttestationData(request *provider.AttestationRequest) (string, error) {
	return gcpa.New(request.MetaEndPoint, request.Service, request.ZTSUrl)
}

func (gcprun GCPRunProvider) GetAccountDomainServiceFromMeta(base string) (string, string, string, error) {
	account, err := meta.GetProject(base)
	if err != nil {
		return "", "", "", err
	}
	domain, err := meta.GetDomain(base)
	if err != nil {
		return account, "", "", err
	}
	service, err := meta.GetService(base)
	if err != nil {
		return account, domain, "", err
	}
	return account, domain, service, nil
}

func (gcprun GCPRunProvider) GetAccessManagementProfileFromMeta(base string) (string, error) {
	return "", fmt.Errorf("not implemented")
}

func (gcprun GCPRunProvider) GetAdditionalSshHostPrincipals(base string) (string, error) {
	return "", nil
}

func (tp GCPRunProvider) GetInstanceAttributeValueFromMeta(string, string) (string, error) {
	return "", nil
}
