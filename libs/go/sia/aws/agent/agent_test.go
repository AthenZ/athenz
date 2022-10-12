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
	"fmt"
	"log"
	"os"
	"testing"
	"time"

	"github.com/AthenZ/athenz/libs/go/sia/aws/agent/devel/ztsmock"
	"github.com/AthenZ/athenz/libs/go/sia/aws/attestation"
	"github.com/AthenZ/athenz/libs/go/sia/aws/options"
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

func TestUpdateFileNew(test *testing.T) {

	//make sure our temp file does not exist
	timeNano := time.Now().UnixNano()
	fileName := fmt.Sprintf("sia-test.tmp%d", timeNano)
	_ = os.Remove(fileName)
	testContents := "sia-unit-test"
	err := util.UpdateFile(fileName, []byte(testContents), util.ExecIdCommand("-u"), util.ExecIdCommand("-g"), 0644)
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
	err = util.UpdateFile(fileName, []byte(testNewContents), util.ExecIdCommand("-u"), util.ExecIdCommand("-g"), 0644)
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
		Provider:         "athenz.aws.us-west-2",
	}

	a := &attestation.AttestationData{
		Role: "athenz.hockey",
	}

	err := RegisterInstance([]*attestation.AttestationData{a}, "http://127.0.0.1:5084/zts/v1", opts, false)
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

func TestRefreshInstance(test *testing.T) {

	siaDir := test.TempDir()

	keyFile := fmt.Sprintf("%s/athenz.hockey.key.pem", siaDir)
	certFile := fmt.Sprintf("%s/athenz.hockey.cert.pem", siaDir)
	caCertFile := fmt.Sprintf("%s/ca.cert.pem", siaDir)

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
		Provider:         "athenz.aws.us-west-2",
		ZTSAWSDomains:    []string{"zts-aws-cloud"},
		Region:           "us-west-2",
		InstanceId:       "pod-1234",
	}

	a := &attestation.AttestationData{
		Role: "athenz.hockey",
	}

	err = RefreshInstance([]*attestation.AttestationData{a}, "http://127.0.0.1:5084/zts/v1", opts)
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

	opts := &options.Options{
		Domain: "athenz",
		Services: []options.Service{
			{
				Name: "hockey",
				Uid:  util.ExecIdCommand("-u"),
				Gid:  util.ExecIdCommand("-g"),
			},
		},
		Roles: []options.Role{
			{
				Name:     "athenz:role.writers",
				Service:  "hockey",
				Uid:      util.ExecIdCommand("-u"),
				Gid:      util.ExecIdCommand("-g"),
				Filename: roleCertFile,
			},
		},
		KeyDir:           siaDir,
		CertDir:          siaDir,
		AthenzCACertFile: caCertFile,
		ZTSAWSDomains:    []string{"zts-aws-cloud"},
		Provider:         "athenz.aws.us-west-2",
	}

	result := GetRoleCertificates("http://127.0.0.1:5084/zts/v1", opts)
	if !result {
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
		name   string
		data   string
		result bool
	}{
		{"valid-start", "HostCertificate /sshd.config", true},
		{"valid-mid", "PermitTunnel no\nHostCertificate /sshd.config\nUseDNS no", true},
		{"valid-mid-space", "PermitTunnel no\n  HostCertificate /sshd.config\nUseDNS no", true},
		{"valid-mid-tab", "PermitTunnel no\n\tHostCertificate /sshd.config\nUseDNS no", true},
		{"valid-mid-mix", "PermitTunnel no\n \t HostCertificate /sshd.config\nUseDNS no", true},
		{"valid-end", "PermitTunnel no\nHostCertificate /sshd.config", true},
		{"valid-commented", "PermitTunnel no\n#HostCertificate /sshd.config\nUseDNS no", false},
		{"valid-not-present1", "PermitTunnel no\nHostCertificateOther /sshd.config\nUseDNS no", false},
		{"valid-not-present2", "PermitTunnel no\nHostCertificate/sshd.config\nUseDNS no", false},
		{"valid-not-present3", "PermitTunnel no\n\nUseDNS no\n", false},
	}
	for _, tt := range tests {
		test.Run(tt.name, func(t *testing.T) {
			tmpFile, err := os.CreateTemp(os.TempDir(), "sia-agent-test-")
			if err != nil {
				log.Fatal("Cannot create temporary file", err)
			}
			defer os.Remove(tmpFile.Name())
			os.WriteFile(tmpFile.Name(), []byte(tt.data), 644)
			result, _ := hostCertificateLinePresent(tmpFile.Name())
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
