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
	"github.com/AthenZ/athenz/libs/go/sia/host/utils"
	"log"
	"net"
	"net/url"
)

type EC2Provider struct {
	Name            string
	SSHCertPublicIP bool
}

// GetName returns the name of the current provider
func (ec2 EC2Provider) GetName() string {
	return ec2.Name
}

// GetHostname returns the hostname as per the provider
func (ec2 EC2Provider) GetHostname(fqdn bool) string {
	return utils.GetHostname(fqdn)
}

func (ec2 EC2Provider) AttestationData(_ string, _ crypto.PrivateKey, _ *signature.SignatureInfo) (string, error) {
	return "", fmt.Errorf("not implemented")
}

func (ec2 EC2Provider) PrepareKey(_ string) (crypto.PrivateKey, error) {
	return "", fmt.Errorf("not implemented")
}

func (ec2 EC2Provider) GetCsrDn() pkix.Name {
	return pkix.Name{}
}

func (ec2 EC2Provider) GetSanDns(_ string, _ bool, _ bool, _ []string) []string {
	return nil
}

func (ec2 EC2Provider) GetSanUri(_ string, _ ip.Opts, _, _ string) []*url.URL {
	return nil
}

func (ec2 EC2Provider) GetEmail(_ string) []string {
	return nil
}

func (ec2 EC2Provider) GetRoleDnsNames(_ *x509.Certificate, _ string) []string {
	return nil
}

func (ec2 EC2Provider) GetSanIp(_ map[string]bool, _ []net.IP, _ ip.Opts) []net.IP {
	return nil
}

func (ec2 EC2Provider) GetSuffixes() []string {
	return []string{}
}

func (ec2 EC2Provider) CloudAttestationData(_, _, _ string) (string, error) {
	return "", fmt.Errorf("not implemented")
}

func (ec2 EC2Provider) GetAccountDomainServiceFromMeta(_ string) (string, string, string, error) {
	return "", "", "", fmt.Errorf("not implemented")
}

func (ec2 EC2Provider) GetAccessManagementProfileFromMeta(_ string) (string, error) {
	return "", fmt.Errorf("not implemented")
}

// GetAdditionalSshHostPrincipals returns the additional ssh host principals
func (ec2 EC2Provider) GetAdditionalSshHostPrincipals(base string) (string, error) {
	// we're going to use our instance id as the additional ssh host principal
	_, _, _, instanceId, _, _, _, err := GetEC2DocumentDetails(base)
	if err != nil {
		log.Printf("unable to extract instance id for ssh host principal: %v\n", err)
	}
	// we're going to use our public ip as the additional ssh host principal if enabled
	publicIP := ""
	if ec2.SSHCertPublicIP {
		publicIP, err = GetEC2PublicIP(base)
		if err != nil {
			log.Printf("unable to extract public ip for ssh host principal: %v\n", err)
		}
	}
	if instanceId == "" {
		return publicIP, nil
	} else if publicIP == "" {
		return instanceId, nil
	} else {
		return fmt.Sprintf("%s,%s", instanceId, publicIP), nil
	}
}
