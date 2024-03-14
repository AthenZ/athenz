package options

import (
	"crypto"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"fmt"
	"net"
	"net/url"

	"github.com/AthenZ/athenz/libs/go/sia/gcp/attestation"
	"github.com/AthenZ/athenz/libs/go/sia/host/ip"
	"github.com/AthenZ/athenz/libs/go/sia/host/signature"
)

type MockGCPProvider struct {
	Name     string
	Hostname string
}

// GetName returns the name of the current provider
func (tp MockGCPProvider) GetName() string {
	return tp.Name
}

// GetHostname returns the hostname as per the provider
func (tp MockGCPProvider) GetHostname() string {
	return tp.Hostname
}

func (tp MockGCPProvider) AttestationData(svc string, key crypto.PrivateKey, sigInfo *signature.SignatureInfo) (string, error) {
	return "", fmt.Errorf("not implemented")
}

func (tp MockGCPProvider) PrepareKey(file string) (crypto.PrivateKey, error) {
	return "", fmt.Errorf("not implemented")
}

func (tp MockGCPProvider) GetCsrDn() pkix.Name {
	return pkix.Name{}
}

func (tp MockGCPProvider) GetSanDns(service string, includeHost bool, wildcard bool, cnames []string) []string {
	return nil
}

func (tp MockGCPProvider) GetSanUri(svc string, opts ip.Opts, spiffeTrustDomain, spiffeNamespace string) []*url.URL {
	return nil
}

func (tp MockGCPProvider) GetEmail(service string) []string {
	return nil
}

func (tp MockGCPProvider) GetRoleDnsNames(cert *x509.Certificate, service string) []string {
	return nil
}

func (tp MockGCPProvider) GetSanIp(docIp map[string]bool, ips []net.IP, opts ip.Opts) []net.IP {
	return nil
}

func (tp MockGCPProvider) GetSuffixes() []string {
	return []string{}
}

func (tp MockGCPProvider) CloudAttestationData(base, svc, ztsServerName string) (string, error) {
	a, _ := json.Marshal(&attestation.GoogleAttestationData{
		IdentityToken: "abc",
	})

	return string(a), nil
}

func (tp MockGCPProvider) GetAccountDomainServiceFromMeta(base string) (string, string, string, error) {
	return "mockGCPProject", "mockAthenzDomain", "mockAthenzService", nil
}

func (tp MockGCPProvider) GetAccessManagementProfileFromMeta(base string) (string, error) {
	return "testProf", nil
}

func (tp MockGCPProvider) GetAdditionalSshHostPrincipals(base string) (string, error) {
	return "my-vm,compute.1234567890000,my-vm.c.my-gcp-project.internal", nil
}
