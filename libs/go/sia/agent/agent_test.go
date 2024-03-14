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

package agent

import (
	"crypto"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"log"
	"net"
	"net/url"
	"os"
	"testing"
	"time"

	"k8s.io/utils/strings/slices"

	"github.com/AthenZ/athenz/libs/go/sia/access/config"
	"github.com/AthenZ/athenz/libs/go/sia/agent/devel/ztsmock"
	"github.com/AthenZ/athenz/libs/go/sia/host/ip"
	"github.com/AthenZ/athenz/libs/go/sia/host/signature"
	"github.com/AthenZ/athenz/libs/go/sia/options"
	"github.com/AthenZ/athenz/libs/go/sia/ssh/hostkey"
	"github.com/AthenZ/athenz/libs/go/sia/util"

	"github.com/stretchr/testify/assert"
)

func setup() {
	go ztsmock.StartZtsServer("127.0.0.1:5084")
	time.Sleep(3 * time.Second)
}

func teardown() {}

func TestMain(m *testing.M) {
	setup()
	code := m.Run()
	teardown()
	os.Exit(code)
}

type TestProvider struct {
	Name     string
	Hostname string
}

// GetName returns the name of the current provider
func (tp TestProvider) GetName() string {
	return tp.Name
}

// GetHostname returns the hostname as per the provider
func (tp TestProvider) GetHostname(bool) string {
	return tp.Hostname
}

func (tp TestProvider) AttestationData(string, crypto.PrivateKey, *signature.SignatureInfo) (string, error) {
	return "", fmt.Errorf("not implemented")
}

func (tp TestProvider) PrepareKey(string) (crypto.PrivateKey, error) {
	return "", fmt.Errorf("not implemented")
}

func (tp TestProvider) GetCsrDn() pkix.Name {
	return pkix.Name{}
}

func (tp TestProvider) GetSanDns(string, bool, bool, []string) []string {
	return nil
}

func (tp TestProvider) GetSanUri(string, ip.Opts, string, string) []*url.URL {
	return nil
}

func (tp TestProvider) GetEmail(string) []string {
	return nil
}

func (tp TestProvider) GetRoleDnsNames(*x509.Certificate, string) []string {
	return nil
}

func (tp TestProvider) GetSanIp(map[string]bool, []net.IP, ip.Opts) []net.IP {
	return nil
}

func (tp TestProvider) GetSuffixes() []string {
	return []string{}
}

func (tp TestProvider) CloudAttestationData(string, string, string) (string, error) {
	return "abc", nil
}

func (tp TestProvider) GetAccountDomainServiceFromMeta(string) (string, string, string, error) {
	return "testAcct", "testDom", "testSvc", nil
}

func (tp TestProvider) GetAccessManagementProfileFromMeta(string) (string, error) {
	return "testProf", nil
}

func (tp TestProvider) GetAdditionalSshHostPrincipals(string) (string, error) {
	return "my-vm,my-instance-id", nil
}

func TestUpdateFileNew(test *testing.T) {
	testInternalUpdateFileNew(test, true)
	testInternalUpdateFileNew(test, false)
}

func testInternalUpdateFileNew(test *testing.T, fileDirectUpdate bool) {

	//make sure our temp file does not exist
	timeNano := time.Now().UnixNano()
	fileName := fmt.Sprintf("sia-test.tmp%d", timeNano)
	_ = os.Remove(fileName)
	testContents := "sia-unit-test"
	err := util.UpdateFile(fileName, []byte(testContents), util.ExecIdCommand("-u"), util.ExecIdCommand("-g"), 0644, fileDirectUpdate, true)
	if err != nil {
		test.Errorf("Cannot create new file: %v", err)
		return
	}
	data, err := os.ReadFile(fileName)
	if err != nil {
		test.Errorf("Cannot read new created file: %v", err)
		_ = os.Remove(fileName)
		return
	}
	if string(data) != testContents {
		test.Errorf("Read %s data not the same as stored %s data", data, testContents)
		_ = os.Remove(fileName)
		return
	}
	_ = os.Remove(fileName)
}

func TestUpdateFileExisting(test *testing.T) {
	testInternalUpdateFileExisting(test, true)
	testInternalUpdateFileExisting(test, false)
}

func testInternalUpdateFileExisting(test *testing.T, fileDirectUpdate bool) {

	//create our temporary file
	timeNano := time.Now().UnixNano()
	fileName := fmt.Sprintf("sia-test.tmp%d", timeNano)
	testContents := "sia-unit-test"
	err := os.WriteFile(fileName, []byte(testContents), 0644)
	if err != nil {
		test.Errorf("Cannot create new file: %v", err)
		return
	}
	testNewContents := "sia-unit"
	err = util.UpdateFile(fileName, []byte(testNewContents), util.ExecIdCommand("-u"), util.ExecIdCommand("-g"), 0644, fileDirectUpdate, true)
	if err != nil {
		test.Errorf("Cannot create new file: %v", err)
		return
	}
	data, err := os.ReadFile(fileName)
	if err != nil {
		test.Errorf("Cannot read new created file: %v", err)
		_ = os.Remove(fileName)
		return
	}
	if string(data) != testNewContents {
		test.Errorf("Read %s data not the same as stored %s data", data, testNewContents)
		_ = os.Remove(fileName)
		return
	}
	_ = os.Remove(fileName)
}

func TestRegisterInstance(test *testing.T) {

	siaDir := test.TempDir()

	keyFile := fmt.Sprintf("%s/athenz.hockey.key.pem", siaDir)
	certFile := fmt.Sprintf("%s/athenz.hockey.cert.pem", siaDir)
	caCertFile := fmt.Sprintf("%s/ca.cert.pem", siaDir)

	tp := TestProvider{
		Name: "athenz.aws.us-west-2",
	}
	opts := &options.Options{
		Domain: "athenz",
		Services: []options.Service{
			{
				Name: "hockey",
				Uid:  util.ExecIdCommand("-u"),
				Gid:  util.ExecIdCommand("-g"),
			},
		},
		KeyDir:           siaDir,
		CertDir:          siaDir,
		AthenzCACertFile: caCertFile,
		ZTSAWSDomains:    []string{"zts-aws-cloud"},
		Region:           "us-west-2",
		InstanceId:       "pod-1234",
		Provider:         tp,
		SanDnsHostname:   true,
	}

	err := RegisterInstance("http://127.0.0.1:5084/zts/v1", opts, false)
	assert.Nil(test, err, "unable to register instance")

	if err != nil {
		test.Errorf("Unable to register instance: %v", err)
		return
	}
	_, err = os.Stat(keyFile)
	if err != nil {
		test.Errorf("Unable to validate private key file: %v", err)
	}
	_, err = os.Stat(certFile)
	if err != nil {
		test.Errorf("Unable to validate x509 certificate file: %v", err)
	}
	_, err = os.Stat(caCertFile)
	if err != nil {
		test.Errorf("Unable to validate CA certificate file: %v", err)
	}
}

func copyFile(src, dst string) error {
	data, err := os.ReadFile(src)
	if err != nil {
		return err
	}
	return os.WriteFile(dst, data, 0644)
}

func refreshServiceCertSetup(test *testing.T) (*options.Options, string) {

	siaDir := test.TempDir()

	keyFile := fmt.Sprintf("%s/athenz.hockey.key.pem", siaDir)
	certFile := fmt.Sprintf("%s/athenz.hockey.cert.pem", siaDir)
	caCertFile := fmt.Sprintf("%s/ca.cert.pem", siaDir)

	err := copyFile("devel/data/key.pem", keyFile)
	if err != nil {
		test.Errorf("Unable to copy file %s to %s - %v\n", "devel/data/key.pem", keyFile, err)
		return nil, ""
	}
	err = copyFile("devel/data/cert.pem", certFile)
	if err != nil {
		test.Errorf("Unable to copy file %s to %s - %v\n", "devel/data/cert.pem", certFile, err)
		return nil, ""
	}
	err = copyFile("devel/data/ca.cert.pem", caCertFile)
	if err != nil {
		test.Errorf("Unable to copy file %s to %s - %v\n", "devel/data/ca.cert..pem", caCertFile, err)
		return nil, ""
	}

	tp := TestProvider{
		Name: "athenz.aws.us-west-2",
	}
	opts := &options.Options{
		Domain: "athenz",
		Services: []options.Service{
			{
				Name:     "hockey",
				Uid:      util.ExecIdCommand("-u"),
				Gid:      util.ExecIdCommand("-g"),
				FileMode: 0400,
			},
		},
		KeyDir:           siaDir,
		CertDir:          siaDir,
		AthenzCACertFile: caCertFile,
		Provider:         tp,
		ZTSAWSDomains:    []string{"zts-aws-cloud"},
		Region:           "us-west-2",
		InstanceId:       "pod-1234",
	}

	return opts, certFile
}

func TestRefreshInstance(test *testing.T) {

	opts, certFile := refreshServiceCertSetup(test)
	if opts == nil {
		test.Errorf("Certificate setup was not completed successfully")
		return
	}

	err := RefreshInstance("http://127.0.0.1:5084/zts/v1", opts)
	assert.Nil(test, err, fmt.Sprintf("unable to refresh instance: %v", err))

	oldCert, _ := os.ReadFile("devel/data/cert.pem")
	newCert, _ := os.ReadFile(certFile)
	if string(oldCert) == string(newCert) {
		test.Errorf("Certificate was not refreshed")
		return
	}
}

func TestRoleCertificateRequest(test *testing.T) {

	siaDir := test.TempDir()

	keyFile := fmt.Sprintf("%s/athenz.hockey.key.pem", siaDir)
	certFile := fmt.Sprintf("%s/athenz.hockey.cert.pem", siaDir)
	caCertFile := fmt.Sprintf("%s/ca.cert.pem", siaDir)
	roleCertFile := fmt.Sprintf("%s/testrole.cert.pem", siaDir)

	err := copyFile("devel/data/key.pem", keyFile)
	if err != nil {
		test.Errorf("Unable to copy file %s to %s - %v\n", "devel/data/key.pem", keyFile, err)
		return
	}
	err = copyFile("devel/data/cert.pem", certFile)
	if err != nil {
		test.Errorf("Unable to copy file %s to %s - %v\n", "devel/data/cert.pem", certFile, err)
		return
	}
	err = copyFile("devel/data/ca.cert.pem", caCertFile)
	if err != nil {
		test.Errorf("Unable to copy file %s to %s - %v\n", "devel/data/ca.cert..pem", caCertFile, err)
		return
	}

	tp := TestProvider{
		Name: "athenz.aws.us-west-2",
	}
	opts := &options.Options{
		Domain: "athenz",
		Services: []options.Service{
			{
				Name:     "hockey",
				Uid:      util.ExecIdCommand("-u"),
				Gid:      util.ExecIdCommand("-g"),
				FileMode: 0400,
			},
		},
		Roles: []options.Role{
			{
				Name:             "athenz:role.writers",
				Service:          "hockey",
				Uid:              util.ExecIdCommand("-u"),
				Gid:              util.ExecIdCommand("-g"),
				RoleCertFilename: roleCertFile,
				FileMode:         0400,
			},
		},
		KeyDir:           siaDir,
		CertDir:          siaDir,
		AthenzCACertFile: caCertFile,
		ZTSAWSDomains:    []string{"zts-aws-cloud"},
		Provider:         tp,
	}

	_, failures := GetRoleCertificates("http://127.0.0.1:5084/zts/v1", opts)
	if failures != 0 {
		test.Errorf("Unable to get role certificate: %v", err)
		return
	}

	_, err = os.Stat(roleCertFile)
	if err != nil {
		test.Errorf("Unable to validate role certificate file: %v", err)
	}
}

func TestShouldSkipRegister(test *testing.T) {
	startTime := time.Now()
	opts := &options.Options{
		EC2StartTime: &startTime,
	}
	//current time is valid
	if shouldSkipRegister(opts) {
		test.Errorf("Current time is considered expired incorrectly")
	}
	//generate time stamp 29 mins ago - valid
	startTime = time.Now().Add(time.Minute * 29 * -1)
	opts.EC2StartTime = &startTime
	if shouldSkipRegister(opts) {
		test.Errorf("29 mins ago time is considered expired incorrectly")
	}
	//generate time stamp 31 mins ago - expired
	startTime = time.Now().Add(time.Minute * 31 * -1)
	opts.EC2StartTime = &startTime
	if !shouldSkipRegister(opts) {
		test.Errorf("31 mins ago time is considered not expired incorrectly")
	}
}

func TestHostCertificateLinePresent(test *testing.T) {
	tests := []struct {
		name     string
		data     string
		certFile string
		result   bool
	}{
		{"valid-start", "HostCertificate /sshd.config", "/sshd.config", true},
		{"valid-mid", "PermitTunnel no\nHostCertificate /sshd.config\nUseDNS no", "/sshd.config", true},
		{"valid-mid-space", "PermitTunnel no\n  HostCertificate /sshd.config\nUseDNS no", "/sshd.config", true},
		{"valid-mid-tab", "PermitTunnel no\n\tHostCertificate /sshd.config\nUseDNS no", "/sshd.config", true},
		{"valid-mid-mix", "PermitTunnel no\n \t HostCertificate /sshd.config\nUseDNS no", "/sshd.config", true},
		{"valid-end", "PermitTunnel no\nHostCertificate /sshd.config", "/sshd.config", true},
		{"valid-commented", "PermitTunnel no\n#HostCertificate /sshd.config\nUseDNS no", "/sshd.config", false},
		{"valid-not-present1", "PermitTunnel no\nHostCertificateOther /sshd.config\nUseDNS no", "/sshd.config", false},
		{"valid-not-present2", "PermitTunnel no\nHostCertificate/sshd.config\nUseDNS no", "/sshd.config", false},
		{"valid-not-present3", "PermitTunnel no\n\nUseDNS no\n", "/sshd.config", false},
		{"valid-not-present3", "PermitTunnel no\nHostCertificate /sshd2.config\nUseDNS no\n", "/sshd.config", false},
	}
	for _, tt := range tests {
		test.Run(tt.name, func(t *testing.T) {
			tmpFile, err := os.CreateTemp(os.TempDir(), "sia-agent-test-")
			if err != nil {
				log.Fatal("Cannot create temporary file", err)
			}
			defer os.Remove(tmpFile.Name())
			os.WriteFile(tmpFile.Name(), []byte(tt.data), 644)
			result, _ := hostCertificateLinePresent(tmpFile.Name(), tt.certFile)
			if result != tt.result {
				test.Errorf("%s: invalid value returned - expected: %v, received %v", tt.name, tt.result, result)
			}
		})
	}
}

func TestUpdateSSHConfigFile(test *testing.T) {
	tests := []struct {
		name   string
		data   string
		result string
	}{
		{"test1", "PermitTunnel no\nUseDNS no", "PermitTunnel no\nUseDNS no\nHostCertificate /sshd.config\n"},
		{"test2", "PermitTunnel no\n#HostCertificate /sshd.config\nUseDNS no\n", "PermitTunnel no\n#HostCertificate /sshd.config\nUseDNS no\n\nHostCertificate /sshd.config\n"},
	}
	for _, tt := range tests {
		test.Run(tt.name, func(t *testing.T) {
			tmpFile, err := os.CreateTemp(os.TempDir(), "sia-agent-test-")
			if err != nil {
				log.Fatal("Cannot create temporary file", err)
			}
			defer os.Remove(tmpFile.Name())
			os.WriteFile(tmpFile.Name(), []byte(tt.data), 644)
			err = updateSSHConfigFile(tmpFile.Name(), "/sshd.config")
			if err != nil {
				test.Errorf("%s: unable to update file %s - error: %v", tt.name, tmpFile.Name(), err)
			}
			data, _ := os.ReadFile(tmpFile.Name())
			if tt.result != string(data) {
				test.Errorf("%s: invalid value returned - expected: %v, received %v", tt.name, tt.result, string(data))
			}
		})
	}
}

func TestNilTokenOptions(test *testing.T) {
	opts := &options.Options{
		Domain: "athenz",
	}
	token, err := tokenOptions(opts, "")
	assert.Nil(test, token, "should not create token")
	assert.NotNil(test, err, "token is not presented")
}

func TestTokenStoreOptions(test *testing.T) {
	opts := &options.Options{
		Domain: "athenz",
		AccessTokens: []config.AccessToken{
			{
				FileName: "reader",
				Domain:   "athenz",
				Service:  "api",
			},
		},
		TokenDir:  "/tmp",
		CertDir:   "/tmp",
		KeyDir:    "/tmp",
		BackupDir: "/tmp",
	}
	token, err := tokenOptions(opts, "")
	assert.Nil(test, err)
	assert.Equal(test, token.StoreOptions, config.AccessTokenProp)

	// set the token option value
	tokenOption := 2
	opts.StoreTokenOption = &tokenOption

	token, err = tokenOptions(opts, "")
	assert.Nil(test, err)
	assert.Equal(test, token.StoreOptions, config.AccessTokenWithoutQuotesProp)
}

func TestGetServiceHostname(test *testing.T) {
	tests := []struct {
		name             string
		sanDnsHostname   bool
		providerHostname string
		hostnameSuffix   string
		service          string
		domain           string
		result           string
	}{
		{"disabled", false, "unknown", "unknown", "api", "sports", ""},
		{"no hostname", true, "", "unknown", "api", "sports", ""},
		{"valid hostname", true, "zts.athenz.cloud", "unknown", "api", "sports", "zts.athenz.cloud"},
		{"no suffix", true, "zts", "", "api", "athenz", ""},
		{"autogenerated - top domain", true, "zts", "athenz.cloud", "api", "sports", "zts.api.sports.athenz.cloud"},
		{"autogenerated - subdomain", true, "zts", "athenz.cloud", "api", "sports.prod", "zts.api.sports-prod.athenz.cloud"},
	}
	for _, tt := range tests {
		test.Run(tt.name, func(t *testing.T) {
			provider := TestProvider{
				Name:     "testProvider",
				Hostname: tt.providerHostname,
			}
			opts := options.Options{
				SanDnsHostname: tt.sanDnsHostname,
				HostnameSuffix: tt.hostnameSuffix,
				Domain:         tt.domain,
				Provider:       provider,
			}
			svc := options.Service{
				Name: tt.service,
			}
			hostname := getServiceHostname(&opts, svc, false)
			if tt.result != hostname {
				test.Errorf("%s: invalid value returned - expected: %v, received %v", tt.name, tt.result, hostname)
			}
		})
	}
}

func TestServiceAlreadyRegistered(test *testing.T) {

	keyDir := test.TempDir()
	certDir := test.TempDir()
	opts := options.Options{
		KeyDir:  keyDir,
		CertDir: certDir,
		Domain:  "athenz",
	}
	keyFile := fmt.Sprintf("%s/athenz.hockey.key.pem", keyDir)
	certFile := fmt.Sprintf("%s/athenz.hockey.cert.pem", certDir)
	err := copyFile("devel/data/key.pem", keyFile)
	if err != nil {
		test.Errorf("Unable to copy file %s to %s - %v\n", "devel/data/key.pem", keyFile, err)
		return
	}
	err = copyFile("devel/data/cert.pem", certFile)
	if err != nil {
		test.Errorf("Unable to copy file %s to %s - %v\n", "devel/data/cert.pem", certFile, err)
		return
	}
	tests := []struct {
		name         string
		keyFileName  string
		certFileName string
		result       bool
	}{
		{"both-valid", keyFile, certFile, true},
		{"key-valid-only", keyFile, "", false},
		{"cert-valid only", "", certFile, false},
		{"both-invalid", "", "", false},
	}
	for _, tt := range tests {
		test.Run(tt.name, func(t *testing.T) {
			svc := options.Service{
				Name:         "api",
				KeyFilename:  tt.keyFileName,
				CertFilename: tt.certFileName,
			}
			serviceRegistered := serviceAlreadyRegistered(&opts, svc)
			if tt.result != serviceRegistered {
				test.Errorf("%s: invalid value returned - expected: %v, received %v", tt.name, tt.result, serviceRegistered)
			}
		})
	}
}

func TestGenerateSshRequest(test *testing.T) {

	tp := TestProvider{
		Name: "athenz.aws.us-west-2",
	}
	opts := options.Options{
		Ssh:      false,
		Provider: tp,
	}
	// ssh option false we should get success with nils and empty csr
	sshReq, sshCsr, err := generateSshRequest(&opts, "backend", "hostname.athenz.io")
	assert.Nil(test, sshReq)
	assert.Equal(test, "", sshCsr)
	assert.Nil(test, err)
	// ssh enabled but not for primary service we should get success with nils and empty csr
	opts.Ssh = true
	opts.Services = []options.Service{
		{
			Name: "api",
		},
	}
	sshReq, sshCsr, err = generateSshRequest(&opts, "backend", "hostname.athenz.io")
	assert.Nil(test, sshReq)
	assert.Equal(test, "", sshCsr)
	assert.Nil(test, err)
	// ssh enabled with primary service and key type is rsa - null cert request but valid csr
	opts.SshPubKeyFile = "devel/data/cert.pem"
	opts.Domain = "athenz"
	opts.ZTSAWSDomains = []string{"athenz.io"}
	opts.SshHostKeyType = hostkey.Rsa
	sshReq, sshCsr, err = generateSshRequest(&opts, "api", "hostname.athenz.io")
	assert.Nil(test, sshReq)
	assert.NotEmpty(test, sshCsr)
	assert.Nil(test, err)
	// ssh enabled with primary service and key type is ecdsa - empty csr but not-nil cert request
	opts.SshHostKeyType = hostkey.Ecdsa
	sshReq, sshCsr, err = generateSshRequest(&opts, "api", "hostname.athenz.io")
	assert.NotNil(test, sshReq)
	assert.Equal(test, 3, len(sshReq.CertRequestData.Principals))
	assert.True(test, slices.Contains(sshReq.CertRequestData.Principals, "my-vm"))
	assert.True(test, slices.Contains(sshReq.CertRequestData.Principals, "my-instance-id"))
	assert.Empty(test, sshCsr)
	assert.Nil(test, err)
	// ssh enabled with primary service and key type is ecdsa - empty csr but not-nil cert request, opts defines sshPrincipals
	opts.SshHostKeyType = hostkey.Ecdsa
	opts.SshPrincipals = "cname.athenz.io"
	sshReq, sshCsr, err = generateSshRequest(&opts, "api", "hostname.athenz.io")
	assert.NotNil(test, sshReq)
	assert.Equal(test, 4, len(sshReq.CertRequestData.Principals))
	assert.True(test, slices.Contains(sshReq.CertRequestData.Principals, "hostname.athenz.io"))
	assert.True(test, slices.Contains(sshReq.CertRequestData.Principals, "cname.athenz.io"))
	assert.True(test, slices.Contains(sshReq.CertRequestData.Principals, "my-vm"))
	assert.True(test, slices.Contains(sshReq.CertRequestData.Principals, "my-instance-id"))
	assert.Empty(test, sshCsr)
	assert.Nil(test, err)
}

func TestShouldExitRightAwayCountsOnly(test *testing.T) {

	opts := &options.Options{
		FailCountForExit: 2,
	}

	assert.True(test, shouldExitRightAway(2, opts))
	assert.True(test, shouldExitRightAway(3, opts))
	assert.False(test, shouldExitRightAway(0, opts))
	assert.False(test, shouldExitRightAway(1, opts))
}

func TestShouldExitRightAwayCertificate(test *testing.T) {

	opts, _ := refreshServiceCertSetup(test)
	if opts == nil {
		test.Errorf("Certificate setup was not completed successfully")
		return
	}

	err := RefreshInstance("http://127.0.0.1:5084/zts/v1", opts)
	assert.Nil(test, err, fmt.Sprintf("unable to refresh instance: %v", err))

	// our certs are valid for 30 days, so we'll set the refresh
	// interval to 31 days, it should fail, but if we set it
	// to 28 days, it should be ok

	opts.FailCountForExit = 2
	opts.RefreshInterval = 28 * 24 * 60
	assert.False(test, shouldExitRightAway(1, opts))

	opts.RefreshInterval = 31 * 24 * 60
	assert.True(test, shouldExitRightAway(1, opts))
}
