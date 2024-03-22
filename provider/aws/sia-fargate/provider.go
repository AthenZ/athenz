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
	"github.com/AthenZ/athenz/libs/go/sia/host/ip"
	"github.com/AthenZ/athenz/libs/go/sia/host/signature"
	"net"
	"net/url"
)

type FargateProvider struct {
	Name string
}

// GetName returns the name of the current provider
func (fargate FargateProvider) GetName() string {
	return fargate.Name
}

// GetHostname returns the hostname as per the provider
func (fargate FargateProvider) GetHostname(_ bool) string {
	return ""
}

func (fargate FargateProvider) AttestationData(_ string, _ crypto.PrivateKey, _ *signature.SignatureInfo) (string, error) {
	return "", fmt.Errorf("not implemented")
}

func (fargate FargateProvider) PrepareKey(_ string) (crypto.PrivateKey, error) {
	return "", fmt.Errorf("not implemented")
}

func (fargate FargateProvider) GetCsrDn() pkix.Name {
	return pkix.Name{}
}

func (fargate FargateProvider) GetSanDns(_ string, _ bool, _ bool, _ []string) []string {
	return nil
}

func (fargate FargateProvider) GetSanUri(_ string, _ ip.Opts, _, _ string) []*url.URL {
	return nil
}

func (fargate FargateProvider) GetEmail(_ string) []string {
	return nil
}

func (fargate FargateProvider) GetRoleDnsNames(_ *x509.Certificate, _ string) []string {
	return nil
}

func (fargate FargateProvider) GetSanIp(_ map[string]bool, _ []net.IP, _ ip.Opts) []net.IP {
	return nil
}

func (fargate FargateProvider) GetSuffixes() []string {
	return []string{}
}

func (fargate FargateProvider) CloudAttestationData(_, _, _ string) (string, error) {
	return "", fmt.Errorf("not implemented")
}

func (fargate FargateProvider) GetAccountDomainServiceFromMeta(_ string) (string, string, string, error) {
	return "", "", "", fmt.Errorf("not implemented")
}

func (fargate FargateProvider) GetAccessManagementProfileFromMeta(_ string) (string, error) {
	return "", fmt.Errorf("not implemented")
}

func (fargate FargateProvider) GetAdditionalSshHostPrincipals(_ string) (string, error) {
	return "", nil
}
