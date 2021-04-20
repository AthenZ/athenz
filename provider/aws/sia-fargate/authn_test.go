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
	"github.com/AthenZ/athenz/libs/go/sia/aws/attestation"
	"github.com/AthenZ/athenz/provider/aws/sia-ec2/options"
	"github.com/AthenZ/athenz/provider/aws/sia-ec2/util"
	"github.com/AthenZ/athenz/provider/aws/sia-fargate/devel/metamock"
	"github.com/AthenZ/athenz/provider/aws/sia-fargate/devel/ztsmock"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"io"
	"io/ioutil"
	"log"
	"log/syslog"
	"os"
	"testing"
	"time"
)

func setup() {

	os.Setenv("ECS_CONTAINER_METADATA_URI_V4", "http://127.0.0.1:5080")

	go metamock.StartMetaServer("127.0.0.1:5080")
	go ztsmock.StartZtsServer("127.0.0.1:5081")
}

func teardown() {}

func TestMain(m *testing.M) {
	setup()
	code := m.Run()
	teardown()
	os.Exit(code)
}

func TestUpdateFileNew(test *testing.T) {

	var sysLogger io.Writer
	sysLogger, err := syslog.New(syslog.LOG_INFO|syslog.LOG_DAEMON, "siad")
	if err != nil {
		log.Printf("Unable to create sys logger: %v\n", err)
		sysLogger = os.Stdout
	}

	//make sure our temp file does not exist
	timeNano := time.Now().UnixNano()
	fileName := fmt.Sprintf("sia-test.tmp%d", timeNano)
	defer os.Remove(fileName)

	testContents := "sia-unit-test"
	err = util.UpdateFile(fileName, testContents, 0, 0, 0644, sysLogger)
	if err != nil {
		test.Errorf("Cannot create new file: %v", err)
		return
	}
	data, err := ioutil.ReadFile(fileName)
	if err != nil {
		test.Errorf("Cannot read new created file: %v", err)
		return
	}
	if string(data) != testContents {
		test.Errorf("Read %s data not the same as stored %s data", data, testContents)
		return
	}
}

func TestUpdateFileExisting(test *testing.T) {

	var sysLogger io.Writer
	sysLogger, err := syslog.New(syslog.LOG_INFO|syslog.LOG_DAEMON, "siad")
	if err != nil {
		log.Printf("Unable to create sys logger: %v\n", err)
		sysLogger = os.Stdout
	}

	//create our temporary file
	timeNano := time.Now().UnixNano()
	fileName := fmt.Sprintf("sia-test.tmp%d", timeNano)

	defer os.Remove(fileName)

	testContents := "sia-unit-test"
	err = ioutil.WriteFile(fileName, []byte(testContents), 0644)
	if err != nil {
		test.Errorf("Cannot create new file: %v", err)
		return
	}
	testNewContents := "sia-unit"
	err = util.UpdateFile(fileName, testNewContents, 0, 0, 0644, sysLogger)
	if err != nil {
		test.Errorf("Cannot create new file: %v", err)
		return
	}
	data, err := ioutil.ReadFile(fileName)
	if err != nil {
		test.Errorf("Cannot read new created file: %v", err)
		return
	}
	if string(data) != testNewContents {
		test.Errorf("Read %s data not the same as stored %s data", data, testNewContents)
		return
	}
}

func TestRegisterInstance(test *testing.T) {

	siaDir, err := ioutil.TempDir("", "sia.")
	require.Nil(test, err)
	defer os.RemoveAll(siaDir)

	keyFile := fmt.Sprintf("%s/athenz.hockey.key.pem", siaDir)
	certFile := fmt.Sprintf("%s/athenz.hockey.cert.pem", siaDir)
	caCertFile := fmt.Sprintf("%s/ca.cert.pem", siaDir)

	require.Nil(test, err)

	opts := &options.Options{
		Domain: "athenz",
		Services: []options.Service{
			{
				Name: "hockey",
			},
		},
		KeyDir:           siaDir,
		CertDir:          siaDir,
		AthenzCACertFile: caCertFile,
	}

	a := &attestation.AttestationData{
		Role:   "athenz.hockey",
		TaskId: "task-1234",
	}

	err = RegisterInstance([]*attestation.AttestationData{a}, "http://127.0.0.1:5081/zts/v1", opts, "us-west-2", os.Stdout)
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
	data, err := ioutil.ReadFile(src)
	if err != nil {
		return err
	}
	return ioutil.WriteFile(dst, data, 0644)
}

func TestRefreshInstance(test *testing.T) {

	siaDir, err := ioutil.TempDir("", "sia.")
	require.Nil(test, err)
	defer os.RemoveAll(siaDir)

	keyFile := fmt.Sprintf("%s/athenz.hockey.key.pem", siaDir)
	certFile := fmt.Sprintf("%s/athenz.hockey.cert.pem", siaDir)
	caCertFile := fmt.Sprintf("%s/ca.cert.pem", siaDir)

	err = copyFile("devel/data/key.pem", keyFile)
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
			},
		},
		KeyDir:           siaDir,
		CertDir:          siaDir,
		AthenzCACertFile: caCertFile,
		Provider:         "athenz.aws",
	}

	a := &attestation.AttestationData{
		Role:   "athenz.hockey",
		TaskId: "task-1234",
	}

	err = RefreshInstance([]*attestation.AttestationData{a}, "http://127.0.0.1:5081/zts/v1", opts, "us-west-2", os.Stdout)
	assert.Nil(test, err, fmt.Sprintf("unable to refresh instance: %v", err))

	oldCert, _ := ioutil.ReadFile("devel/data/cert.pem")
	newCert, _ := ioutil.ReadFile(certFile)
	if string(oldCert) == string(newCert) {
		test.Errorf("Certificate was not refreshed")
		return
	}
}

func TestRoleCertificateRequest(test *testing.T) {

	siaDir, err := ioutil.TempDir("", "sia.")
	require.Nil(test, err)
	defer os.RemoveAll(siaDir)

	keyFile := fmt.Sprintf("%s/athenz.hockey.key.pem", siaDir)
	certFile := fmt.Sprintf("%s/athenz.hockey.cert.pem", siaDir)
	caCertFile := fmt.Sprintf("%s/ca.cert.pem", siaDir)
	roleCertFile := fmt.Sprintf("%s/testrole.cert.pem", siaDir)

	err = copyFile("devel/data/key.pem", keyFile)
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
	}

	result := GetRoleCertificate("http://127.0.0.1:5081/zts/v1", keyFile, certFile, opts, os.Stdout)
	if !result {
		test.Errorf("Unable to get role certificate: %v", err)
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
func TestGetMetadata(test *testing.T) {

	// "TaskARN": "arn:aws:ecs:us-west-2:012345678910:task/9781c248-0edd-4cdb-9a93-f63cb662a5d3",
	account, taskId, region, err := GetECSFargateData("http://127.0.0.1:5080")
	if err != nil {
		test.Errorf("Unable to get account, task id from fargate: %v", err)
	}
	if account != "012345678910" {
		test.Errorf("Account number mismatch %s vs 012345678910", account)
	}
	if taskId != "9781c248-0edd-4cdb-9a93-f63cb662a5d3" {
		test.Errorf("Task Id mismatch %s vs 9781c248-0edd-4cdb-9a93-f63cb662a5d3", taskId)
	}
	if region != "us-west-2" {
		test.Errorf("Region mismatch %s vs us-west-2", region)
	}
}
