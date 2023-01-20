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
	"fmt"
	"os"
	"testing"
	"time"

	"github.com/AthenZ/athenz/libs/go/sia/util"
	"github.com/AthenZ/athenz/provider/azure/sia-vm/data/attestation"
	"github.com/AthenZ/athenz/provider/azure/sia-vm/devel/ztsmock"
	"github.com/AthenZ/athenz/provider/azure/sia-vm/options"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func setup() {
	go ztsmock.StartZtsServer("127.0.0.1:5085")
	time.Sleep(3 * time.Second)
}

func teardown() {}

func TestMain(m *testing.M) {
	setup()
	code := m.Run()
	teardown()
	os.Exit(code)
}

func TestGetProviderName(test *testing.T) {
	name := getProviderName("azure.provider", "uswest2")
	if name != "azure.provider" {
		test.Errorf("Unable to verify provider with azure.provider name: %s", name)
		return
	}
	name = getProviderName("", "uswest2")
	if name != "athenz.azure.uswest2" {
		test.Errorf("Unable to verify provider with uswest2 region name: %s", name)
		return
	}
}

func TestRegisterInstance(test *testing.T) {
	siaDir := test.TempDir()

	keyFile := fmt.Sprintf("%s/athenz.hockey.key.pem", siaDir)
	certFile := fmt.Sprintf("%s/athenz.hockey.cert.pem", siaDir)
	caCertFile := fmt.Sprintf("%s/ca.cert.pem", siaDir)

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
		ZTSAzureDomains:  []string{"zts-azure-domain"},
	}

	a := &attestation.Data{
		Location:          "west2",
		Name:              "athenz.syncer",
		ResourceGroupName: "Athenz",
		SubscriptionId:    "12345",
		VmId:              "12345-vm",
		Token:             "attestation-token",
	}

	identityDocument := attestation.IdentityDocument{
		Location:          "west2",
		Name:              "athenz",
		ResourceGroupName: "athenz-rg",
		SubscriptionId:    "123456789012",
		VmId:              "123456789012-vmid",
		OsType:            "Linux",
		Tags:              "athenz:athenz.api",
		PrivateIp:         "10.0.0.1",
		PublicIp:          "",
		Document:          nil,
	}

	err := RegisterInstance([]*attestation.Data{a}, "http://127.0.0.1:5085/zts/v1", &identityDocument, opts)
	assert.Nil(test, err, "unable to regster instance")

	_, err = os.Stat(keyFile)
	assert.Nil(test, err, fmt.Sprintf("unable to find private key:%q", keyFile))

	_, err = os.Stat(certFile)
	assert.Nil(test, err, fmt.Sprintf("unable to find x509 cert: %q", certFile))

	_, err = os.Stat(caCertFile)
	assert.Nil(test, err, fmt.Sprintf("unable to find ca cert: %q", caCertFile))
}

func TestRegisterInstanceMultiple(test *testing.T) {
	siaDir := test.TempDir()

	caCertFile := fmt.Sprintf("%s/ca.cert.pem", siaDir)

	opts := &options.Options{
		Domain: "athenz",
		Services: []options.Service{
			{Name: "hockey",
				Uid: util.ExecIdCommand("-u"),
				Gid: util.ExecIdCommand("-g"),
			},
			{
				Name: "soccer",
				Uid:  util.ExecIdCommand("-u"),
				Gid:  util.ExecIdCommand("-g"),
			},
		},
		KeyDir:           siaDir,
		CertDir:          siaDir,
		AthenzCACertFile: caCertFile,
		ZTSAzureDomains:  []string{"zts-azure-domain"},
	}

	data := []*attestation.Data{
		{},
		{},
	}

	identityDocument := attestation.IdentityDocument{
		Location:          "west2",
		Name:              "athenz",
		ResourceGroupName: "athenz-rg",
		SubscriptionId:    "123456789012",
		VmId:              "123456789012-vmid",
		OsType:            "Linux",
		Tags:              "athenz:athenz.api",
		PrivateIp:         "10.0.0.1",
		PublicIp:          "",
		Document:          nil,
	}

	err := RegisterInstance(data, "http://127.0.0.1:5085/zts/v1", &identityDocument, opts)
	assert.Nil(test, err, "unable to register instance")

	// Verify the first service
	keyFile := fmt.Sprintf("%s/athenz.hockey.key.pem", siaDir)
	certFile := fmt.Sprintf("%s/athenz.hockey.cert.pem", siaDir)

	_, err = os.Stat(keyFile)
	assert.Nil(test, err, fmt.Sprintf("unable to find private key:%q", keyFile))

	_, err = os.Stat(certFile)
	assert.Nil(test, err, fmt.Sprintf("unable to find x509 cert: %q", certFile))

	_, err = os.Stat(caCertFile)
	assert.Nil(test, err, fmt.Sprintf("unable to find ca cert: %q", caCertFile))

	// Verify the second service
	keyFile = fmt.Sprintf("%s/athenz.soccer.key.pem", siaDir)
	certFile = fmt.Sprintf("%s/athenz.soccer.cert.pem", siaDir)

	_, err = os.Stat(keyFile)
	assert.Nil(test, err, fmt.Sprintf("unable to find private key:%q", keyFile))

	_, err = os.Stat(certFile)
	assert.Nil(test, err, fmt.Sprintf("unable to find x509 cert: %q", certFile))
}

func copyFile(src, dst string) error {
	data, err := os.ReadFile(src)
	if err != nil {
		return err
	}
	return os.WriteFile(dst, data, 0644)
}

func TestRefreshInstance(test *testing.T) {
	siaDir := test.TempDir()

	keyFile := fmt.Sprintf("%s/athenz.hockey.key.pem", siaDir)
	certFile := fmt.Sprintf("%s/athenz.hockey.cert.pem", siaDir)
	caCertFile := fmt.Sprintf("%s/ca.cert.pem", siaDir)

	err := copyFile("devel/data/unit_test_key.pem", keyFile)
	require.Nil(test, err, fmt.Sprintf("unable to copy file: %q to %q, error: %v", "devel/data/unit_test_key.pem", keyFile, err))

	err = copyFile("devel/data/cert.pem", certFile)
	require.Nil(test, err, fmt.Sprintf("unable to copy file: %q to %q, error: %v", "devel/data/cert.pem", certFile, err))

	err = copyFile("devel/data/ca.cert.pem", caCertFile)
	require.Nil(test, err, fmt.Sprintf("unable to copy file: %q to %q, error: %v", "devel/data/cert.pem", caCertFile, err))

	opts := options.Options{
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
		ZTSAzureDomains:  []string{"zts-azure-domain"},
	}

	a := &attestation.Data{
		Token: "token",
	}

	identityDocument := attestation.IdentityDocument{
		Location:          "west2",
		Name:              "athenz",
		ResourceGroupName: "athenz-rg",
		SubscriptionId:    "123456789012",
		VmId:              "123456789012-vmid",
		OsType:            "Linux",
		Tags:              "athenz:athenz.api",
		PrivateIp:         "10.0.0.1",
		PublicIp:          "",
		Document:          nil,
	}

	err = RefreshInstance([]*attestation.Data{a}, "http://127.0.0.1:5085/zts/v1", &identityDocument, &opts)
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

	err := copyFile("devel/data/unit_test_key.pem", keyFile)
	require.Nil(test, err, fmt.Sprintf("unable to copy file: %q to %q, error: %v", "devel/data/unit_test_key.pem", keyFile, err))

	err = copyFile("devel/data/cert.pem", certFile)
	require.Nil(test, err, fmt.Sprintf("unable to copy file: %q to %q, error: %v", "devel/data/cert.pem", certFile, err))

	err = copyFile("devel/data/ca.cert.pem", caCertFile)
	require.Nil(test, err, fmt.Sprintf("unable to copy file: %q to %q, error: %v", "devel/data/cert.pem", caCertFile, err))

	opts := &options.Options{
		Domain: "athenz",
		Services: []options.Service{
			{
				Name: "hockey",
				Uid:  util.ExecIdCommand("-u"),
				Gid:  util.ExecIdCommand("-g"),
			},
		},
		Roles: map[string]options.ConfigRole{
			"athenz:role.writers": {
				Filename: roleCertFile,
			},
		},
		KeyDir:           siaDir,
		CertDir:          siaDir,
		AthenzCACertFile: caCertFile,
		ZTSAzureDomains:  []string{"zts-azure-domain"},
	}

	result := GetRoleCertificate("http://127.0.0.1:5085/zts/v1", keyFile, certFile, opts)
	if !result {
		test.Errorf("Unable to get role certificate")
		return
	}

	_, err = os.Stat(roleCertFile)
	if err != nil {
		test.Errorf("Unable to validate role certificate file: %v", err)
	}
}

func TestExtractProviderFromCertInvalidFile(test *testing.T) {
	if extractProviderFromCert("invalid-file") != "" {
		test.Error("Invalid file returned valid provider")
	}
}

func TestExtractProviderFromCertWithoutOU(test *testing.T) {
	if extractProviderFromCert("devel/data/cert_wout_ou.pem") != "" {
		test.Error("Provider returned from cert_wout_ou.pem")
	}
}

func TestExtractProviderFromCert(test *testing.T) {
	if extractProviderFromCert("devel/data/cert.pem") != "Athenz" {
		test.Error("Unable to extract Athenz ou provider from cert.pem")
	}
}
