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
func (fargate FargateProvider) GetHostname(fqdn bool) string {
	return ""
}

func (fargate FargateProvider) AttestationData(svc string, key crypto.PrivateKey, sigInfo *signature.SignatureInfo) (string, error) {
	return "", fmt.Errorf("not implemented")
}

func (fargate FargateProvider) PrepareKey(file string) (crypto.PrivateKey, error) {
	return "", fmt.Errorf("not implemented")
}

func (fargate FargateProvider) GetCsrDn() pkix.Name {
	return pkix.Name{}
}

func (fargate FargateProvider) GetSanDns(service string, includeHost bool, wildcard bool, cnames []string) []string {
	return nil
}

func (fargate FargateProvider) GetSanUri(svc string, opts ip.Opts) []*url.URL {
	return nil
}

func (fargate FargateProvider) GetEmail(service string) []string {
	return nil
}

func (fargate FargateProvider) GetRoleDnsNames(cert *x509.Certificate, service string) []string {
	return nil
}

func (fargate FargateProvider) GetSanIp(docIp map[string]bool, ips []net.IP, opts ip.Opts) []net.IP {
	return nil
}

func (fargate FargateProvider) GetSuffix() string {
	return ""
}

func (eks FargateProvider) CloudAttestationData(base, svc, ztSserverName string) (string, error) {
	return "", fmt.Errorf("not implemented")
}

func (eks FargateProvider) GetAccountDomainServiceFromMeta(base string) (string, string, string, error) {
	return "", "", "", fmt.Errorf("not implemented")
}

func (tp FargateProvider) GetAccessManagementProfileFromMeta(base string) (string, error) {
	return "", fmt.Errorf("not implemented")
}
