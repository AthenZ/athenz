package options

import (
	"crypto"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"fmt"
	"net"
	"net/url"

	"github.com/AthenZ/athenz/libs/go/sia/aws/attestation"
	"github.com/AthenZ/athenz/libs/go/sia/host/ip"
	"github.com/AthenZ/athenz/libs/go/sia/host/signature"
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
func (tp MockAWSProvider) GetHostname(bool) string {
	return tp.Hostname
}

func (tp MockAWSProvider) AttestationData(string, crypto.PrivateKey, *signature.SignatureInfo) (string, error) {
	return "", fmt.Errorf("not implemented")
}

func (tp MockAWSProvider) PrepareKey(string) (crypto.PrivateKey, error) {
	return "", fmt.Errorf("not implemented")
}

func (tp MockAWSProvider) GetCsrDn() pkix.Name {
	return pkix.Name{}
}

func (tp MockAWSProvider) GetSanDns(string, bool, bool, []string) []string {
	return nil
}

func (tp MockAWSProvider) GetSanUri(string, ip.Opts, string, string) []*url.URL {
	return nil
}

func (tp MockAWSProvider) GetEmail(string) []string {
	return nil
}

func (tp MockAWSProvider) GetRoleDnsNames(*x509.Certificate, string) []string {
	return nil
}

func (tp MockAWSProvider) GetSanIp(map[string]bool, []net.IP, ip.Opts) []net.IP {
	return nil
}

func (tp MockAWSProvider) GetSuffixes() []string {
	return []string{}
}

func (tp MockAWSProvider) CloudAttestationData(string, string, string) (string, error) {
	a, _ := json.Marshal(&attestation.AttestationData{
		Role: "athenz.hockey",
	})

	return string(a), nil
}

func (tp MockAWSProvider) GetAccountDomainServiceFromMeta(string) (string, string, string, error) {
	return "mockAWSAccount", "mockAthenzDomain", "mockAthenzService", nil
}

func (tp MockAWSProvider) GetAccessManagementProfileFromMeta(string) (string, error) {
	return "testProf", nil
}

func (tp MockAWSProvider) GetAdditionalSshHostPrincipals(string) (string, error) {
	return "i-1234edt22", nil
}
