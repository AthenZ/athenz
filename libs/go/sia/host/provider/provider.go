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

package provider

import (
	"crypto"
	"crypto/x509"
	"crypto/x509/pkix"
	"net"
	"net/url"

	"github.com/AthenZ/athenz/libs/go/sia/host/ip"
	"github.com/AthenZ/athenz/libs/go/sia/host/signature"
)

// Provider is the interface which wraps various Providers known to ZTS
// It has methods for providing attestationdata depending on provider type
// and generating sub-parts of DN to be including in the CSR and San DNS and URI entries
type Provider interface {
	// PrepareKey creates/setup up a private key for use with the provider
	PrepareKey(string) (crypto.PrivateKey, error)

	// AttestationData returns the attestation data that can be used in the ZTS api
	AttestationData(string, crypto.PrivateKey, *signature.SignatureInfo) (string, error)

	// GetName returns the name of the current provider
	GetName() string

	// GetHostname returns the name of the hostname as recognized by the provider
	GetHostname(bool) string

	// GetCsrDn returns the x.509 Distinguished Name for use in the CSR
	GetCsrDn() pkix.Name

	// GetSanDns returns an array of provider specific SAN DNS entries
	GetSanDns(string, bool, bool, []string) []string

	// GetSanUri returns an array of provider specific SAN URI entries
	GetSanUri(string, ip.Opts, string, string) []*url.URL

	// GetEmail retuns an array of one email which can be used to identify the principal
	GetEmail(string) []string

	// GetRoleDnsNames returns an array of SanDNS entries that can be used for Role Cert
	GetRoleDnsNames(*x509.Certificate, string) []string

	// GetSanIp returns an array of IPs that can be included in San IPs from the list of IPs found on the box
	GetSanIp(map[string]bool, []net.IP, ip.Opts) []net.IP

	// GetSuffixes returns a list of suffixes for the current provider
	GetSuffixes() []string

	// CloudAttestationData gets the attestation data to prove the identity from metadata of the respective cloud
	CloudAttestationData(string, string, string) (string, error)

	// GetAccountDomainServiceFromMeta gets the account, domain and service info from the respective cloud
	GetAccountDomainServiceFromMeta(string) (string, string, string, error)

	// GetAccessManagementProfileFromMeta gets the profile info from the respective cloud
	GetAccessManagementProfileFromMeta(string) (string, error)

	// GetAdditionalSshHostPrincipals returns additional provider specific principals to be added in ssh host cert
	GetAdditionalSshHostPrincipals(string) (string, error)
}
