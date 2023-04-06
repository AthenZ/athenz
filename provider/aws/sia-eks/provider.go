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
	"log"
	"net"
	"net/url"
	"os"
)

type EKSProvider struct {
	Name string
}

// GetName returns the name of the current provider
func (eks EKSProvider) GetName() string {
	return eks.Name
}

// GetHostname returns the hostname as per the provider
func (eks EKSProvider) GetHostname() string {
	hostname, err := os.Hostname()
	if err != nil {
		log.Printf("Unable to obtain os hostname: %v\n", err)
		return os.Getenv("HOSTNAME")
	}
	return hostname
}

func (eks EKSProvider) AttestationData(svc string, key crypto.PrivateKey, sigInfo *signature.SignatureInfo) (string, error) {
	return "", fmt.Errorf("not implemented")
}

func (eks EKSProvider) PrepareKey(file string) (crypto.PrivateKey, error) {
	return "", fmt.Errorf("not implemented")
}

func (eks EKSProvider) GetCsrDn() pkix.Name {
	return pkix.Name{}
}

func (eks EKSProvider) GetSanDns(service string, includeHost bool, wildcard bool, cnames []string) []string {
	return nil
}

func (eks EKSProvider) GetSanUri(svc string, opts ip.Opts) []*url.URL {
	return nil
}

func (eks EKSProvider) GetEmail(service string) []string {
	return nil
}

func (eks EKSProvider) GetRoleDnsNames(cert *x509.Certificate, service string) []string {
	return nil
}

func (eks EKSProvider) GetSanIp(docIp map[string]bool, ips []net.IP, opts ip.Opts) []net.IP {
	return nil
}

func (eks EKSProvider) GetSuffix() string {
	return ""
}

func (eks EKSProvider) CloudAttestationData(base, svc, ztSserverName string) (string, error) {
	return "", fmt.Errorf("not implemented")
}

func (eks EKSProvider) GetAccountDomainServiceFromMeta(base string) (string, string, string, error) {
	return "", "", "", fmt.Errorf("not implemented")
}

func (tp EKSProvider) GetAccessManagementProfileFromMeta(base string) (string, error) {
	return "", fmt.Errorf("not implemented")
}
