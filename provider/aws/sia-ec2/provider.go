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

type EC2Provider struct {
	Name string
}

// GetName returns the name of the current provider
func (ec2 EC2Provider) GetName() string {
	return ec2.Name
}

// GetHostname returns the hostname as per the provider
func (ec2 EC2Provider) GetHostname() string {
	hostname, err := os.Hostname()
	if err != nil {
		log.Printf("Unable to obtain os hostname: %v\n", err)
		return ""
	}
	return hostname
}

func (ec2 EC2Provider) AttestationData(svc string, key crypto.PrivateKey, sigInfo *signature.SignatureInfo) (string, error) {
	return "", fmt.Errorf("not implemented")
}

func (ec2 EC2Provider) PrepareKey(file string) (crypto.PrivateKey, error) {
	return "", fmt.Errorf("not implemented")
}

func (ec2 EC2Provider) GetCsrDn() pkix.Name {
	return pkix.Name{}
}

func (ec2 EC2Provider) GetSanDns(service string, includeHost bool, wildcard bool, cnames []string) []string {
	return nil
}

func (ec2 EC2Provider) GetSanUri(svc string, opts ip.Opts) []*url.URL {
	return nil
}

func (ec2 EC2Provider) GetEmail(service string) []string {
	return nil
}

func (ec2 EC2Provider) GetRoleDnsNames(cert *x509.Certificate, service string) []string {
	return nil
}

func (ec2 EC2Provider) GetSanIp(docIp map[string]bool, ips []net.IP, opts ip.Opts) []net.IP {
	return nil
}

func (ec2 EC2Provider) GetSuffix() string {
	return ""
}
