//
// Copyright 2020 Verizon Media
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
	"encoding/json"
	"fmt"
	"github.com/AthenZ/athenz/provider/aws/sia-ec2/data/attestation"
	"github.com/AthenZ/athenz/provider/aws/sia-ec2/devel/metamock"
	"github.com/AthenZ/athenz/provider/aws/sia-ec2/devel/ztsmock"
	"github.com/AthenZ/athenz/provider/aws/sia-ec2/internal/driver"
	"github.com/AthenZ/athenz/provider/aws/sia-ec2/internal/testserver"
	"github.com/AthenZ/athenz/provider/aws/sia-ec2/options"
	"github.com/dimfeld/httptreemux"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"io"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"testing"
	"time"
)

var (
	instanceIdentityJson = `{
		"devpayProductCodes" : null,
		"privateIp" : "172.31.30.74",
		"availabilityZone" : "us-west-2a",
		"version" : "2010-08-31",
		"instanceId" : "i-03d1ae7035f931a90",
		"billingProducts" : null,
		"instanceType" : "t2.micro",
		"accountId" : "000000000000",
		"imageId" : "ami-527b8832",
		"pendingTime" : "2016-05-02T22:23:14Z",
		"architecture" : "x86_64",
		"kernelId" : null,
		"ramdiskId" : null,
		"region" : "us-west-2"
    }`
)

const ztsBaseUrl = "zts/v1"

var caKeyStr, caCertStr string

const (
	metaEndPoint = "http://127.0.0.1:5080"
)

func setup() {
	go metamock.StartMetaServer("127.0.0.1:5080")
	go ztsmock.StartZtsServer("127.0.0.1:5081")
	caKeyStr, caCertStr = driver.SetupCA()
}

func teardown() {}

func TestMain(m *testing.M) {
	setup()
	code := m.Run()
	teardown()
	os.Exit(code)
}

func TestGetProviderName(test *testing.T) {
	name, ec2Provider := getProviderName("aws.provider", "us-west-2", "", "")
	if name != "aws.provider" {
		test.Errorf("Unable to verify provider with aws.provider name: %s", name)
		return
	}
	if ec2Provider {
		test.Errorf("Given provider incorrectly identified as ec2 provider")
	}
	name, ec2Provider = getProviderName("", "us-west-2", "", "athenz")
	if name != "athenz.aws.us-west-2" {
		test.Errorf("Unable to verify provider with us-west-2 region name: %s", name)
		return
	}
	if !ec2Provider {
		test.Errorf("EC2 provider incorrectly not identified as ec2 provider")
	}
	name, ec2Provider = getProviderName("aws.provider", "us-west-2", "12345", "")
	if name != "aws.provider" {
		test.Errorf("Unable to verify ecs provider with aws.provider name: %s", name)
		return
	}
	if ec2Provider {
		test.Errorf("Given provider with task id incorrectly identified as ec2 provider")
	}
	name, ec2Provider = getProviderName("", "us-west-2", "12345", "athenz")
	if name != "athenz.aws-ecs.us-west-2" {
		test.Errorf("Unable to verify ecs provider with us-west-2 region name: %s", name)
		return
	}
	if ec2Provider {
		test.Errorf("ECS provider incorrectly identified as ec2 provider")
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
			options.Service{
				Name: "hockey",
			},
		},
		KeyDir:               siaDir,
		CertDir:              siaDir,
		AthenzCACertFile:     caCertFile,
		ProviderParentDomain: "athenz",
	}

	var docMap map[string]string
	json.Unmarshal([]byte(instanceIdentityJson), &docMap)
	docMap["pendingTime"] = time.Now().Format(time.RFC3339)
	attestDataDoc, err := json.Marshal(docMap)

	a := &attestation.AttestationData{
		Document: string(attestDataDoc),
		Role:     "athenz.hockey",
	}

	// Mock ZTS PostInstanceRegistrationInformation for creation of certs
	ztsRouter := httptreemux.New()
	ztsRouter.POST("/zts/v1/instance", func(w http.ResponseWriter, r *http.Request, params map[string]string) {
		log.Printf("Called /zts/v1/instance")
		w.WriteHeader(http.StatusCreated)
		io.WriteString(w, driver.GenerateRegisterIdentity(r, caKeyStr, caCertStr))
	})

	ztsServer := &testserver.S{}
	ztsServer.Start(ztsRouter)
	defer ztsServer.Stop()

	err = RegisterInstance([]*attestation.AttestationData{a}, attestDataDoc, ztsServer.BaseUrl(ztsBaseUrl), opts, true, os.Stdout)
	assert.Nil(test, err, "unable to regster instance")

	_, err = os.Stat(keyFile)
	assert.Nil(test, err, fmt.Sprintf("unable to find private key:%q", keyFile))

	_, err = os.Stat(certFile)
	assert.Nil(test, err, fmt.Sprintf("unable to find x509 cert: %q", certFile))

	_, err = os.Stat(caCertFile)
	assert.Nil(test, err, fmt.Sprintf("unable to find ca cert: %q", caCertFile))
}

func TestRegisterInstanceMultiple(test *testing.T) {
	siaDir, err := ioutil.TempDir("", "sia.")
	require.Nil(test, err)
	defer os.RemoveAll(siaDir)

	caCertFile := fmt.Sprintf("%s/ca.cert.pem", siaDir)

	require.Nil(test, err)

	opts := &options.Options{
		Domain: "athenz",
		Services: []options.Service{
			options.Service{Name: "hockey"},
			options.Service{Name: "soccer"},
		},
		KeyDir:               siaDir,
		CertDir:              siaDir,
		AthenzCACertFile:     caCertFile,
		ProviderParentDomain: "athenz",
	}

	var docMap map[string]string
	json.Unmarshal([]byte(instanceIdentityJson), &docMap)
	docMap["pendingTime"] = time.Now().Format(time.RFC3339)
	attestDataDoc, err := json.Marshal(docMap)

	data := []*attestation.AttestationData{
		&attestation.AttestationData{Document: string(attestDataDoc), Role: "athenz.hockey"},
		&attestation.AttestationData{Document: string(attestDataDoc), Role: "athenz.soccer"},
	}

	// Mock ZTS PostInstanceRegistrationInformation for creation of certs
	ztsRouter := httptreemux.New()
	ztsRouter.POST("/zts/v1/instance", func(w http.ResponseWriter, r *http.Request, params map[string]string) {
		log.Printf("Called /zts/v1/instance")
		w.WriteHeader(http.StatusCreated)
		io.WriteString(w, driver.GenerateRegisterIdentity(r, caKeyStr, caCertStr))
	})

	ztsServer := &testserver.S{}
	ztsServer.Start(ztsRouter)
	defer ztsServer.Stop()

	err = RegisterInstance(data, attestDataDoc, ztsServer.BaseUrl(ztsBaseUrl), opts, true, os.Stdout)
	assert.Nil(test, err, "unable to regster instance")

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
	domain := "athenz"
	service := "hockey"

	err = copyFile("devel/data/unit_test_key.pem", keyFile)
	require.Nil(test, err, fmt.Sprintf("unable to copy file: %q to %q, error: %v", "devel/data/unit_test_key.pem", keyFile, err))

	err = copyFile("devel/data/cert.pem", certFile)
	require.Nil(test, err, fmt.Sprintf("unable to copy file: %q to %q, error: %v", "devel/data/cert.pem", certFile, err))

	err = copyFile("devel/data/ca.cert.pem", caCertFile)
	require.Nil(test, err, fmt.Sprintf("unable to copy file: %q to %q, error: %v", "devel/data/cert.pem", caCertFile, err))

	opts := &options.Options{
		Domain: domain,
		Services: []options.Service{
			options.Service{
				Name: service,
			},
		},
		KeyDir:               siaDir,
		CertDir:              siaDir,
		AthenzCACertFile:     caCertFile,
		ProviderParentDomain: "athenz",
	}

	var docMap map[string]string
	json.Unmarshal([]byte(instanceIdentityJson), &docMap)
	docMap["pendingTime"] = time.Now().Format(time.RFC3339)
	attestDataDoc, err := json.Marshal(docMap)

	a := &attestation.AttestationData{
		Document: string(attestDataDoc),
		Role:     fmt.Sprintf("%s.%s", domain, service),
	}

	// Mock ZTS PostInstanceRegistrationInformation for creation of certs
	ztsRouter := httptreemux.New()
	ztsRouter.POST(fmt.Sprintf("/zts/v1/instance/athenz.aws.us-west-2/%s/%s/i-03d1ae7035f931a90", domain, service), func(w http.ResponseWriter, r *http.Request, params map[string]string) {
		log.Printf("Called /zts/v1/instance")
		w.WriteHeader(http.StatusOK)
		io.WriteString(w, driver.GenerateRefreshIdentity(r, domain, service, caKeyStr, caCertStr))
	})

	ztsServer := &testserver.S{}
	ztsServer.Start(ztsRouter)
	defer ztsServer.Stop()

	err = RefreshInstance([]*attestation.AttestationData{a}, ztsServer.BaseUrl(ztsBaseUrl), opts, os.Stdout)
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

	err = copyFile("devel/data/unit_test_key.pem", keyFile)
	require.Nil(test, err, fmt.Sprintf("unable to copy file: %q to %q, error: %v", "devel/data/unit_test_key.pem", keyFile, err))

	err = copyFile("devel/data/cert.pem", certFile)
	require.Nil(test, err, fmt.Sprintf("unable to copy file: %q to %q, error: %v", "devel/data/cert.pem", certFile, err))

	err = copyFile("devel/data/ca.cert.pem", caCertFile)
	require.Nil(test, err, fmt.Sprintf("unable to copy file: %q to %q, error: %v", "devel/data/cert.pem", caCertFile, err))

	opts := &options.Options{
		Domain: "athenz",
		Services: []options.Service{
			options.Service{
				Name: "hockey",
			},
		},
		Roles: map[string]options.ConfigRole{
			"athenz:role.writers": {
				Filename: roleCertFile,
			},
		},
		KeyDir:               siaDir,
		CertDir:              siaDir,
		AthenzCACertFile:     caCertFile,
		ProviderParentDomain: "athenz",
	}

	ztsRouter := httptreemux.New()
	ztsRouter.POST("/zts/v1/domain/athenz/role/writers/token", func(w http.ResponseWriter, r *http.Request, params map[string]string) {
		log.Printf("Called /zts/v1/instance")
		w.WriteHeader(http.StatusOK)
		io.WriteString(w, driver.GenerateRoleCertificate(r, caKeyStr, caCertStr))
	})

	ztsServer := &testserver.S{}
	ztsServer.Start(ztsRouter)
	defer ztsServer.Stop()

	result := GetRoleCertificate(ztsServer.BaseUrl(ztsBaseUrl), keyFile, certFile, opts, os.Stdout)
	if !result {
		test.Errorf("Unable to get role certificate: %v", err)
		return
	}

	_, err = os.Stat(roleCertFile)
	if err != nil {
		test.Errorf("Unable to validate role certificate file: %v", err)
	}
}

func TestGetInstanceId(test *testing.T) {
	data := &attestation.AttestationData{}
	data.TaskId = "task1234"
	docMap := make(map[string]interface{})
	id := getInstanceId(data, docMap)
	if id != "task1234" {
		test.Errorf("Unable to verify task id value")
		return
	}
	data.TaskId = ""
	docMap["instanceId"] = "ec2"
	id = getInstanceId(data, docMap)
	if id != "ec2" {
		test.Errorf("Unable to verify ec2 id value")
		return
	}
}

func TestIsDocumentExpired(test *testing.T) {
	var docMap map[string]interface{}
	//current time is valid
	jsonDoc := fmt.Sprintf("{\"privateIp\" : \"172.31.30.74\",\n\"pendingTime\" : \"%s\"}", time.Now().Format(time.RFC3339))
	json.Unmarshal([]byte(jsonDoc), &docMap)
	if isDocumentExpired(docMap) {
		test.Errorf("Current time is considered expired incorrectly")
	}
	//generate time stamp 29 mins ago - valid
	jsonDoc = fmt.Sprintf("{\"privateIp\" : \"172.31.30.74\",\n\"pendingTime\" : \"%s\"}", time.Now().Add(time.Minute*29*-1).Format(time.RFC3339))
	json.Unmarshal([]byte(jsonDoc), &docMap)
	if isDocumentExpired(docMap) {
		test.Errorf("29 mins ago time is considered expired incorrectly")
	}
	//generate time stamp 31 mins ago - expired
	jsonDoc = fmt.Sprintf("{\"privateIp\" : \"172.31.30.74\",\n\"pendingTime\" : \"%s\"}", time.Now().Add(time.Minute*31*-1).Format(time.RFC3339))
	json.Unmarshal([]byte(jsonDoc), &docMap)
	if !isDocumentExpired(docMap) {
		test.Errorf("31 mins ago time is considered not expired incorrectly")
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

func TestGenerateRolePrivKey(test *testing.T) {
	privKey, err := RoleKey(true, "")
	assert.Nil(test, err, "should not be an error creating private key")
	assert.NotNil(test, privKey, "should successfully create private key")
}

func TestLoadRoleKeyFromFile(test *testing.T) {
	keyDir, err := ioutil.TempDir("", "keyDir.")
	require.Nil(test, err)
	defer os.RemoveAll(keyDir)

	keyFile := fmt.Sprintf("%s/athenz.role.key.pem", keyDir)

	err = copyFile("devel/data/unit_test_key.pem", keyFile)
	require.Nil(test, err, fmt.Sprintf("unable to copy file: %q to %q, error: %v", "devel/data/unit_test_key", keyFile, err))

	privKey, err := RoleKey(false, keyFile)
	assert.Nil(test, err, "should not be an error loading private key from file")
	assert.NotNil(test, privKey, "should successfully load private key from file")
}

func TestFailLoadRoleKeyFromFile(test *testing.T) {
	keyDir, err := ioutil.TempDir("", "keyDir.")
	require.Nil(test, err)
	defer os.RemoveAll(keyDir)

	keyFile := fmt.Sprintf("%s/athenz.role.key.pem", keyDir)
	_, err = RoleKey(false, keyFile)
	assert.NotNil(test, err, "should throw an error loading private key from file")
}

func TestGenerateRoleKey(test *testing.T) {
	siaDir, err := ioutil.TempDir("", "sia.")
	require.Nil(test, err)
	defer os.RemoveAll(siaDir)

	keyFile := fmt.Sprintf("%s/athenz.hockey.key.pem", siaDir)
	certFile := fmt.Sprintf("%s/athenz.hockey.cert.pem", siaDir)
	caCertFile := fmt.Sprintf("%s/ca.cert.pem", siaDir)
	roleFileName := "athenz:role.writers"
	roleCertFile := fmt.Sprintf("%s/%s.cert.pem", siaDir, roleFileName)
	roleKeyFile := fmt.Sprintf("%s/%s.key.pem", siaDir, roleFileName)

	err = copyFile("devel/data/unit_test_key.pem", keyFile)
	require.Nil(test, err, fmt.Sprintf("unable to copy file: %q to %q, error: %v", "devel/data/unit_test_key.pem", keyFile, err))

	err = copyFile("devel/data/cert.pem", certFile)
	require.Nil(test, err, fmt.Sprintf("unable to copy file: %q to %q, error: %v", "devel/data/cert.pem", certFile, err))

	err = copyFile("devel/data/unit_test_key.pem", roleKeyFile)
	require.Nil(test, err, fmt.Sprintf("unable to copy file: %q to %q, error: %v", "devel/data/unit_test_key.pem", roleKeyFile, err))

	err = copyFile("devel/data/cert.pem", roleCertFile)
	require.Nil(test, err, fmt.Sprintf("unable to copy file: %q to %q, error: %v", "devel/data/cert.pem", roleCertFile, err))

	err = copyFile("devel/data/ca.cert.pem", caCertFile)
	require.Nil(test, err, fmt.Sprintf("unable to copy file: %q to %q, error: %v", "devel/data/cert.pem", caCertFile, err))

	opts := &options.Options{
		Domain: "athenz",
		Services: []options.Service{
			options.Service{
				Name: "hockey",
			},
		},
		Roles: map[string]options.ConfigRole{
			"athenz:role.writers": {},
		},
		KeyDir:               siaDir,
		CertDir:              siaDir,
		AthenzCACertFile:     caCertFile,
		GenerateRoleKey:      true,
		ProviderParentDomain: "athenz",
	}

	ztsRouter := httptreemux.New()
	ztsRouter.POST("/zts/v1/domain/athenz/role/writers/token", func(w http.ResponseWriter, r *http.Request, params map[string]string) {
		log.Printf("Called /zts/v1/instance")
		w.WriteHeader(http.StatusOK)
		io.WriteString(w, driver.GenerateRoleCertificate(r, caKeyStr, caCertStr))
	})

	ztsServer := &testserver.S{}
	ztsServer.Start(ztsRouter)
	defer ztsServer.Stop()

	result := GetRoleCertificate(ztsServer.BaseUrl(ztsBaseUrl), keyFile, certFile, opts, os.Stdout)
	if !result {
		test.Errorf("Unable to get role certificate: %v", err)
		return
	}

	_, err = os.Stat(roleCertFile)
	if err != nil {
		test.Errorf("Unable to validate role certificate file: %v", err)
	}

	_, err = os.Stat(roleKeyFile)
	if err != nil {
		test.Errorf("Unable to validate role key file: %v", err)
	}
}

func TestGenerateRoleKeyWithFileName(test *testing.T) {
	siaDir, err := ioutil.TempDir("", "sia.")
	require.Nil(test, err)
	defer os.RemoveAll(siaDir)

	keyFile := fmt.Sprintf("%s/athenz.hockey.key.pem", siaDir)
	certFile := fmt.Sprintf("%s/athenz.hockey.cert.pem", siaDir)
	caCertFile := fmt.Sprintf("%s/ca.cert.pem", siaDir)
	roleFileName := "testrole"
	roleCertFile := fmt.Sprintf("%s/%s.cert.pem", siaDir, roleFileName)
	roleKeyFile := fmt.Sprintf("%s/%s.key.pem", siaDir, roleFileName)

	err = copyFile("devel/data/unit_test_key.pem", keyFile)
	require.Nil(test, err, fmt.Sprintf("unable to copy file: %q to %q, error: %v", "devel/data/unit_test_key.pem", keyFile, err))

	err = copyFile("devel/data/cert.pem", certFile)
	require.Nil(test, err, fmt.Sprintf("unable to copy file: %q to %q, error: %v", "devel/data/cert.pem", certFile, err))

	err = copyFile("devel/data/unit_test_key.pem", roleKeyFile)
	require.Nil(test, err, fmt.Sprintf("unable to copy file: %q to %q, error: %v", "devel/data/unit_test_key.pem", roleKeyFile, err))

	err = copyFile("devel/data/cert.pem", roleCertFile)
	require.Nil(test, err, fmt.Sprintf("unable to copy file: %q to %q, error: %v", "devel/data/cert.pem", roleCertFile, err))

	err = copyFile("devel/data/ca.cert.pem", caCertFile)
	require.Nil(test, err, fmt.Sprintf("unable to copy file: %q to %q, error: %v", "devel/data/cert.pem", caCertFile, err))

	opts := &options.Options{
		Domain: "athenz",
		Services: []options.Service{
			options.Service{
				Name: "hockey",
			},
		},
		Roles: map[string]options.ConfigRole{
			"athenz:role.writers": {
				Filename: fmt.Sprintf("%s.cert.pem", roleFileName),
			},
		},
		KeyDir:               siaDir,
		CertDir:              siaDir,
		AthenzCACertFile:     caCertFile,
		GenerateRoleKey:      true,
		ProviderParentDomain: "athenz",
	}

	ztsRouter := httptreemux.New()
	ztsRouter.POST("/zts/v1/domain/athenz/role/writers/token", func(w http.ResponseWriter, r *http.Request, params map[string]string) {
		log.Printf("Called /zts/v1/instance")
		w.WriteHeader(http.StatusOK)
		io.WriteString(w, driver.GenerateRoleCertificate(r, caKeyStr, caCertStr))
	})

	ztsServer := &testserver.S{}
	ztsServer.Start(ztsRouter)
	defer ztsServer.Stop()

	result := GetRoleCertificate(ztsServer.BaseUrl(ztsBaseUrl), keyFile, certFile, opts, os.Stdout)
	if !result {
		test.Errorf("Unable to get role certificate: %v", err)
		return
	}

	_, err = os.Stat(roleCertFile)
	if err != nil {
		test.Errorf("Unable to validate role certificate file: %v", err)
	}

	_, err = os.Stat(roleKeyFile)
	if err != nil {
		test.Errorf("Unable to validate role key file: %v", err)
	}
}

func TestRotateRoleKey(test *testing.T) {
	siaDir, err := ioutil.TempDir("", "sia.")
	require.Nil(test, err)
	defer os.RemoveAll(siaDir)

	keyFile := fmt.Sprintf("%s/athenz.hockey.key.pem", siaDir)
	certFile := fmt.Sprintf("%s/athenz.hockey.cert.pem", siaDir)
	caCertFile := fmt.Sprintf("%s/ca.cert.pem", siaDir)
	roleFileName := "testrole"
	roleCertFile := fmt.Sprintf("%s/%s.cert.pem", siaDir, roleFileName)
	roleKeyFile := fmt.Sprintf("%s/%s.key.pem", siaDir, roleFileName)

	err = copyFile("devel/data/unit_test_key.pem", keyFile)
	require.Nil(test, err, fmt.Sprintf("unable to copy file: %q to %q, error: %v", "devel/data/unit_test_key.pem", keyFile, err))

	err = copyFile("devel/data/cert.pem", certFile)
	require.Nil(test, err, fmt.Sprintf("unable to copy file: %q to %q, error: %v", "devel/data/cert.pem", certFile, err))

	err = copyFile("devel/data/unit_test_key.pem", roleKeyFile)
	require.Nil(test, err, fmt.Sprintf("unable to copy file: %q to %q, error: %v", "devel/data/unit_test_key.pem", roleKeyFile, err))

	err = copyFile("devel/data/cert.pem", roleCertFile)
	require.Nil(test, err, fmt.Sprintf("unable to copy file: %q to %q, error: %v", "devel/data/cert.pem", roleCertFile, err))

	err = copyFile("devel/data/ca.cert.pem", caCertFile)
	require.Nil(test, err, fmt.Sprintf("unable to copy file: %q to %q, error: %v", "devel/data/cert.pem", caCertFile, err))

	opts := &options.Options{
		Domain: "athenz",
		Services: []options.Service{
			{
				Name: "hockey",
			},
		},
		Roles: map[string]options.ConfigRole{
			"athenz:role.writers": {
				Filename: fmt.Sprintf("%s.cert.pem", roleFileName),
			},
		},
		KeyDir:               siaDir,
		CertDir:              siaDir,
		BackUpDir:            siaDir,
		AthenzCACertFile:     caCertFile,
		GenerateRoleKey:      true,
		RotateKey:            true,
		ProviderParentDomain: "athenz",
	}

	// Mock ZTS PostInstanceRegistrationInformation for creation of certs
	ztsRouter := httptreemux.New()
	ztsRouter.POST("/zts/v1/domain/athenz/role/writers/token", func(w http.ResponseWriter, r *http.Request, params map[string]string) {
		log.Printf("Called /zts/v1/instance")
		w.WriteHeader(http.StatusOK)
		io.WriteString(w, driver.GenerateRoleCertificate(r, caKeyStr, caCertStr))
	})

	ztsServer := &testserver.S{}
	ztsServer.Start(ztsRouter)
	defer ztsServer.Stop()

	result := GetRoleCertificate(ztsServer.BaseUrl(ztsBaseUrl), keyFile, certFile, opts, os.Stdout)
	if !result {
		test.Errorf("Unable to get role certificate: %v", err)
		return
	}

	_, err = os.Stat(roleCertFile)
	if err != nil {
		test.Errorf("Unable to validate role certificate file: %v", err)
	}

	_, err = os.Stat(roleKeyFile)
	if err != nil {
		test.Errorf("Unable to validate role key file: %v", err)
	}

	oldCert, _ := ioutil.ReadFile(roleCertFile)
	oldKey, _ := ioutil.ReadFile(roleKeyFile)

	result = GetRoleCertificate(ztsServer.BaseUrl(ztsBaseUrl), keyFile, certFile, opts, os.Stdout)
	if !result {
		test.Errorf("Unable to get role certificate: %v", err)
		return
	}

	_, err = os.Stat(roleCertFile)
	if err != nil {
		test.Errorf("Unable to validate role certificate file: %v", err)
	}

	_, err = os.Stat(roleKeyFile)
	if err != nil {
		test.Errorf("Unable to validate role key file: %v", err)
	}

	newCert, _ := ioutil.ReadFile(roleCertFile)
	newKey, _ := ioutil.ReadFile(roleKeyFile)

	if string(oldCert) == string(newCert) {
		test.Errorf("Certificate was not refreshed")
		return
	}

	if string(oldKey) == string(newKey) {
		test.Errorf("Key was not rotated")
		return
	}
}

func TestRefreshInstanceWithRotateKey(test *testing.T) {
	siaDir, err := ioutil.TempDir("", "sia.")
	require.Nil(test, err)
	defer os.RemoveAll(siaDir)

	keyFile := fmt.Sprintf("%s/athenz.hockey.key.pem", siaDir)
	certFile := fmt.Sprintf("%s/athenz.hockey.cert.pem", siaDir)
	caCertFile := fmt.Sprintf("%s/ca.cert.pem", siaDir)
	domain := "athenz"
	service := "hockey"

	err = copyFile("devel/data/unit_test_key.pem", keyFile)
	require.Nil(test, err, fmt.Sprintf("unable to copy file: %q to %q, error: %v", "devel/data/unit_test_key.pem", keyFile, err))

	err = copyFile("devel/data/cert.pem", certFile)
	require.Nil(test, err, fmt.Sprintf("unable to copy file: %q to %q, error: %v", "devel/data/cert.pem", certFile, err))

	err = copyFile("devel/data/ca.cert.pem", caCertFile)
	require.Nil(test, err, fmt.Sprintf("unable to copy file: %q to %q, error: %v", "devel/data/cert.pem", caCertFile, err))

	opts := &options.Options{
		Domain: domain,
		Services: []options.Service{
			options.Service{
				Name:     service,
				FileMode: 0440,
			},
		},
		KeyDir:               siaDir,
		CertDir:              siaDir,
		BackUpDir:            siaDir,
		AthenzCACertFile:     caCertFile,
		RotateKey:            true,
		ProviderParentDomain: "athenz",
	}

	var docMap map[string]string
	json.Unmarshal([]byte(instanceIdentityJson), &docMap)
	docMap["pendingTime"] = time.Now().Format(time.RFC3339)
	attestDataDoc, err := json.Marshal(docMap)

	a := &attestation.AttestationData{
		Document: string(attestDataDoc),
		Role:     "athenz.hockey",
	}

	// Mock ZTS PostInstanceRegistrationInformation for creation of certs
	ztsRouter := httptreemux.New()
	ztsRouter.POST(fmt.Sprintf("/zts/v1/instance/athenz.aws.us-west-2/%s/%s/i-03d1ae7035f931a90", domain, service), func(w http.ResponseWriter, r *http.Request, params map[string]string) {
		log.Printf("Called /zts/v1/instance")
		w.WriteHeader(http.StatusOK)
		io.WriteString(w, driver.GenerateRefreshIdentity(r, domain, service, caKeyStr, caCertStr))
	})

	ztsServer := &testserver.S{}
	ztsServer.Start(ztsRouter)
	defer ztsServer.Stop()

	err = RefreshInstance([]*attestation.AttestationData{a}, ztsServer.BaseUrl(ztsBaseUrl), opts, os.Stdout)
	assert.Nil(test, err, fmt.Sprintf("unable to refresh instance: %v", err))

	oldCert, _ := ioutil.ReadFile("devel/data/cert.pem")
	newCert, _ := ioutil.ReadFile(certFile)
	if string(oldCert) == string(newCert) {
		test.Errorf("Certificate was not refreshed")
		return
	}

	oldKey, _ := ioutil.ReadFile("devel/data/key.pem")
	newKey, _ := ioutil.ReadFile(keyFile)
	if string(oldKey) == string(newKey) {
		test.Errorf("Key was not rotated")
		return
	}
}
