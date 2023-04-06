package options

import (
	"crypto"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"fmt"
	"github.com/AthenZ/athenz/libs/go/sia/aws/attestation"
	"github.com/AthenZ/athenz/libs/go/sia/host/ip"
	"github.com/AthenZ/athenz/libs/go/sia/host/signature"
	"net"
	"net/url"
)

type MockAWSProvider struct {
	Name     string
	Hostname string
}

// GetName returns the name of the current provider
func (tp MockAWSProvider) GetName() string {
	return tp.Name
}

// GetHostname returns the hostname as per the provider
func (tp MockAWSProvider) GetHostname() string {
	return tp.Hostname
}

func (tp MockAWSProvider) AttestationData(svc string, key crypto.PrivateKey, sigInfo *signature.SignatureInfo) (string, error) {
	return "", fmt.Errorf("not implemented")
}

func (tp MockAWSProvider) PrepareKey(file string) (crypto.PrivateKey, error) {
	return "", fmt.Errorf("not implemented")
}

func (tp MockAWSProvider) GetCsrDn() pkix.Name {
	return pkix.Name{}
}

func (tp MockAWSProvider) GetSanDns(service string, includeHost bool, wildcard bool, cnames []string) []string {
	return nil
}

func (tp MockAWSProvider) GetSanUri(svc string, opts ip.Opts) []*url.URL {
	return nil
}

func (tp MockAWSProvider) GetEmail(service string) []string {
	return nil
}

func (tp MockAWSProvider) GetRoleDnsNames(cert *x509.Certificate, service string) []string {
	return nil
}

func (tp MockAWSProvider) GetSanIp(docIp map[string]bool, ips []net.IP, opts ip.Opts) []net.IP {
	return nil
}

func (tp MockAWSProvider) GetSuffix() string {
	return ""
}

func (tp MockAWSProvider) CloudAttestationData(base, svc, ztsServerName string) (string, error) {
	a, _ := json.Marshal(&attestation.AttestationData{
		Role: "athenz.hockey",
	})

	return string(a), nil
}

func (tp MockAWSProvider) GetAccountDomainServiceFromMeta(base string) (string, string, string, error) {
	return "mockAWSAccount", "mockAthenzDomain", "mockAthenzService", nil
}

func (tp MockAWSProvider) GetAccessManagementProfileFromMeta(base string) (string, error) {
	return "testProf", nil
}
