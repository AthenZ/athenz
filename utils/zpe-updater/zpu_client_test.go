// Copyright 2017 Yahoo Holdings, Inc.
// Licensed under the terms of the Apache version 2.0 license. See LICENSE file for terms.

package zpu

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"testing"
	"time"

	"github.com/AthenZ/athenz/clients/go/zts"
	"github.com/AthenZ/athenz/libs/go/zmssvctoken"
	"github.com/AthenZ/athenz/utils/zpe-updater/devel"
	"github.com/AthenZ/athenz/utils/zpe-updater/util"
	"github.com/ardielle/ardielle-go/rdl"
	"github.com/stretchr/testify/assert"
)

const (
	ConfPath        = "/tmp"
	PoliciesDir     = "/tmp/zpu"
	TempPoliciesDir = "/tmp/zpe"
	MetricDir       = "/tmp/zpu_metrics"
	Domain          = "test"
)

var testConfig *ZpuConfiguration
var ztsClient zts.ZTSClient
var port string

var ecdsaPrivateKeyPEM = []byte(`-----BEGIN EC PRIVATE KEY-----
MIGkAgEBBDA27vlziu7AYNJo/aaG3mS4XPK2euiTLQDxzUoDkiMpVHRXLxSbX897
Gz7dQNFo3UWgBwYFK4EEACKhZANiAARBr6GWO6EGIV09DGInLfC/JSvPOKc26mZu
jpEdar4FkJ02OsHdtZ6AM7HgLASSBETL13Mhk8LL9qfRo+PEwLcyJnvWlDsMa3eh
Pji5iP4d9rQEOm/G9PXZ3/ZZEz5DuYs=
-----END EC PRIVATE KEY-----
`)

var ecdsaPublicKeyPEM = []byte(`-----BEGIN PUBLIC KEY-----
MHYwEAYHKoZIzj0CAQYFK4EEACIDYgAEQa+hljuhBiFdPQxiJy3wvyUrzzinNupm
bo6RHWq+BZCdNjrB3bWegDOx4CwEkgREy9dzIZPCy/an0aPjxMC3MiZ71pQ7DGt3
oT44uYj+Hfa0BDpvxvT12d/2WRM+Q7mL
-----END PUBLIC KEY-----
`)

func TestMain(m *testing.M) {
	setUp()
	code := m.Run()
	cleanUp()
	os.Exit(code)
}

func getTestConfiguration() (*ZpuConfiguration, error) {
	zmsURL := fmt.Sprintf("http://localhost:%s/zms/v1", port)
	ztsURL := fmt.Sprintf("http://localhost:%s/zts/v1", port)
	athenzConf := `{"zmsURL":"` + zmsURL + `","ztsURL":"` + ztsURL + `","ztsPublicKeys":[{"id":"0","key":"LS0tLS1CRUdJTiBQVUJMSUMgS0VZLS0tLS0KTUZ3d0RRWUpLb1pJaHZjTkFRRUJCUUFEU3dBd1NBSkJBTHpmU09UUUpmRW0xZW00TDNza3lOVlEvYngwTU9UcQphK1J3T0gzWmNNS3lvR3hPSm85QXllUmE2RlhNbXZKSkdZczVQMzRZc3pGcG5qMnVBYmkyNG5FQ0F3RUFBUT09Ci0tLS0tRU5EIFBVQkxJQyBLRVktLS0tLQo-"}],"zmsPublicKeys":[{"id":"0","key":"LS0tLS1CRUdJTiBQVUJMSUMgS0VZLS0tLS0KTUZ3d0RRWUpLb1pJaHZjTkFRRUJCUUFEU3dBd1NBSkJBTHpmU09UUUpmRW0xZW00TDNza3lOVlEvYngwTU9UcQphK1J3T0gzWmNNS3lvR3hPSm85QXllUmE2RlhNbXZKSkdZczVQMzRZc3pGcG5qMnVBYmkyNG5FQ0F3RUFBUT09Ci0tLS0tRU5EIFBVQkxJQyBLRVktLS0tLQo-"}]}`
	_ = devel.CreateFile(ConfPath+"/athenz.conf", athenzConf)
	zpuConf := `{"domains":"test"}`
	_ = devel.CreateFile(ConfPath+"/zpu.conf", zpuConf)
	config, err := NewZpuConfiguration("", ConfPath+"/athenz.conf", ConfPath+"/zpu.conf")
	config.PolicyFileDir = PoliciesDir
	config.TempPolicyFileDir = TempPoliciesDir
	config.MetricsDir = MetricDir
	if err != nil {
		return nil, fmt.Errorf("failed to return test configuration object, Error:%v", err)
	}
	return config, nil
}

func setUp() error {
	var err error
	testConfig, err = getTestConfiguration()
	if err != nil {
		return err
	}
	err = os.MkdirAll(PoliciesDir, 0755)
	if err != nil {
		return fmt.Errorf("failed to create directory for policy files, Error:%v", err)
	}
	err = os.MkdirAll(TempPoliciesDir, 0755)
	if err != nil {
		return fmt.Errorf("failed to create temporary directory for policy files, Error:%v", err)
	}
	err = os.MkdirAll(MetricDir, 0755)
	if err != nil {
		return fmt.Errorf("failed to create directory for metric files, Error:%v", err)
	}
	ztsClient = zts.NewClient((*testConfig).Zts, nil)
	return nil
}

func cleanUp() error {
	err := os.RemoveAll(PoliciesDir)
	if err != nil {
		return fmt.Errorf("failed to delete directory for policy files, Error:%v", err)
	}
	err = os.RemoveAll(TempPoliciesDir)
	if err != nil {
		return fmt.Errorf("failed to delete temporary directory for policy files, Error:%v", err)
	}
	err = os.RemoveAll(MetricDir)
	if err != nil {
		return fmt.Errorf("failed to delete directory for metric files, Error:%v", err)
	}
	err = os.Remove(ConfPath + "/athenz.conf")
	if err != nil {
		return fmt.Errorf("failed to delete athenz conf file, Error:%v", err)
	}
	err = os.Remove(ConfPath + "/zpu.conf")
	if err != nil {
		return fmt.Errorf("failed to delete zpu conf file, Error:%v", err)
	}
	return nil
}

func TestWritePolicies(t *testing.T) {
	a := assert.New(t)
	policyJSON, _ := ioutil.ReadFile("test_data/data_domain.json")
	err := WritePolicies(testConfig, policyJSON, Domain)
	a.Nil(err)
	policyFile := fmt.Sprintf("%s/%s.pol", PoliciesDir, Domain)
	tempPolicyFile := fmt.Sprintf("%s/%s.tmp", TempPoliciesDir, Domain)
	a.Equal(util.Exists(tempPolicyFile), false)
	a.Equal(util.Exists(policyFile), true)
	data, err := ioutil.ReadFile(policyFile)
	a.Nil(err)
	a.Equal(string(data), string(policyJSON))
	err = os.Remove(policyFile)
	a.Nil(err)
}

func TestWritePoliciesEmptyPolicyDir(t *testing.T) {
	a := assert.New(t)
	policyJSON, _ := ioutil.ReadFile("test_data/data_domain.json")
	testConfig.PolicyFileDir = "/random"
	err := WritePolicies(testConfig, policyJSON, Domain)
	fmt.Print(err)
	a.NotNil(err)
	testConfig.PolicyFileDir = PoliciesDir
}

func TestGetEtagForExistingPolicyJson(test *testing.T) {

	tests := []struct {
		name         string
		expiryOffset float64
		forceRefresh bool
		response     bool
	}{
		{"valid-test", 3600 * 60, false, true},
		{"expired-test", 1200 * 60, false, false},
		{"forced-refresh-test", 3600 * 60, true, false},
	}
	for _, tt := range tests {
		test.Run(tt.name, func(t *testing.T) {
			a := assert.New(test)
			ztsClient := zts.NewClient((*testConfig).Zts, nil)
			testConfig.JWSPolicySupport = false
			testConfig.CheckZMSSignature = true
			testConfig.ForceRefresh = tt.forceRefresh

			//Correct Policy File Exist - expiry check is 2880 * 60, so we'll use 3600 * 60
			policyData, err := devel.GenerateSignedPolicyData("./test_data/data_domain.json", ecdsaPrivateKeyPEM, "0", tt.expiryOffset)
			a.Nil(err)
			policyJSON, err := json.Marshal(policyData)
			a.Nil(err)
			err = ioutil.WriteFile(PoliciesDir+"/test.pol", policyJSON, 0755)
			a.Nil(err)

			testConfig.PutZtsPublicKey("0", string(ecdsaPublicKeyPEM))
			testConfig.PutZmsPublicKey("0", string(ecdsaPublicKeyPEM))
			etag := GetEtagForExistingPolicy(testConfig, ztsClient, "test")
			_, err = ValidateSignedPolicies(testConfig, ztsClient, policyData)
			a.Nil(err)
			if tt.response {
				a.NotEmpty(etag)
			} else {
				a.Empty(etag)
			}
			err = os.Remove(PoliciesDir + "/test.pol")
			a.Nil(err)
		})
	}
}

func TestGetEtagForExistingPolicyJws(test *testing.T) {

	tests := []struct {
		name         string
		expiryOffset float64
		forceRefresh bool
		response     bool
	}{
		{"valid-test", 3600 * 60, false, true},
		{"expired-test", 1200 * 60, false, false},
		{"forced-refresh-test", 3600 * 60, true, false},
	}
	for _, tt := range tests {
		test.Run(tt.name, func(t *testing.T) {
			a := assert.New(t)
			ztsClient := zts.NewClient((*testConfig).Zts, nil)
			testConfig.JWSPolicySupport = true
			testConfig.ForceRefresh = tt.forceRefresh

			//Correct Policy File Exist - expiry check is 2880 * 60, so we'll use 3600 * 60
			policyData, err := devel.GenerateJWSPolicyData("./test_data/data_domain.json", ecdsaPrivateKeyPEM, "0", "ES384", tt.expiryOffset)
			a.Nil(err)
			policyJSON, err := json.Marshal(policyData)
			a.Nil(err)
			err = ioutil.WriteFile(PoliciesDir+"/test.pol", policyJSON, 0755)
			a.Nil(err)

			testConfig.PutZtsPublicKey("0", string(ecdsaPublicKeyPEM))
			etag := GetEtagForExistingPolicy(testConfig, ztsClient, "test")
			_, err = ValidateJWSPolicies(testConfig, ztsClient, policyData)
			a.Nil(err)
			if tt.response {
				a.NotEmpty(etag)
			} else {
				a.Empty(etag)
			}
			err = os.Remove(PoliciesDir + "/test.pol")
			a.Nil(err)
		})
	}
}

func TestPolicyUpdaterEmptyDomain(t *testing.T) {
	a := assert.New(t)
	conf := &ZpuConfiguration{
		Zts:        "zts_url",
		DomainList: "",
	}
	err := PolicyUpdater(conf)
	a.NotNil(err)
}

func TestPolicyUpdaterWrongzts(t *testing.T) {
	a := assert.New(t)
	conf := &ZpuConfiguration{
		Zts:        "zts_url",
		DomainList: "test",
		MetricsDir: "/policy",
	}
	err := PolicyUpdater(conf)
	a.NotNil(err)
}

func TestExpired(t *testing.T) {
	a := assert.New(t)
	current := time.Now()
	future := rdl.NewTimestamp(current.AddDate(0, 0, 2))
	past := rdl.NewTimestamp(current.AddDate(0, 0, -2))
	expireFlag := expired(past, 0)
	a.Equal(expireFlag, true, "The date is in past")
	expireFlag = expired(future, 0)
	a.Equal(expireFlag, false, "The date is in future")
	// We're going to pass offset longer than the 2 days
	// in the future thus making the future date to be
	// considered expired
	expireFlag = expired(future, 2*86400+10)
	a.Equal(expireFlag, true, "With offset the date is in past")
}

func TestVerifierPositiveTest(t *testing.T) {
	a := assert.New(t)
	publicKey := "LS0tLS1CRUdJTiBQVUJMSUMgS0VZLS0tLS0KTUZ3d0RRWUpLb1pJaHZjTkFRRUJCUUFEU3dBd1NBSkJBTHpmU09UUUpmRW0xZW00TDNza3lOVlEvYngwTU9UcQphK1J3T0gzWmNNS3lvR3hPSm85QXllUmE2RlhNbXZKSkdZczVQMzRZc3pGcG5qMnVBYmkyNG5FQ0F3RUFBUT09Ci0tLS0tRU5EIFBVQkxJQyBLRVktLS0tLQo-"
	input := `{"expires":"2017-06-09T06:11:12.125Z","modified":"2017-06-02T06:11:12.125Z","policyData":{"domain":"sys.auth","policies":[{"assertions":[{"action":"*","effect":"ALLOW","resource":"*","role":"sys.auth:role.admin"},{"action":"*","effect":"DENY","resource":"*","role":"sys.auth:role.non-admin"}],"name":"sys.auth:policy.admin"}]},"zmsKeyId":"0","zmsSignature":"Y2HuXmgL86PL1WnleGFHwPmNEqUdWgDxmmIsDnF5f5oqakacqTtwt9JNqDV9nuJ7LnKl3zsZoDQSAtcHMu4IGA--"}`
	signature := "XJnQ4t33D4yr7NtUjLaWhXULFr76z.z0p3QV4uCkA5KR9L4liVRmICYwVmnXxvHAlImKlKLv7sbIHNsjBfGfCw--"
	key, err := new(zmssvctoken.YBase64).DecodeString(publicKey)
	if err != nil {
		log.Fatalf("failed to decode key to verify data , Error:%v", err)
	}
	err = verify(input, signature, string(key))
	a.Nil(err, "Verifier failed for valid data")
}

func TestVerifierTamperedInput(t *testing.T) {
	a := assert.New(t)
	publicKey := "LS0tLS1CRUdJTiBQVUJMSUMgS0VZLS0tLS0KTUZ3d0RRWUpLb1pJaHZjTkFRRUJCUUFEU3dBd1NBSkJBTHpmU09UUUpmRW0xZW00TDNza3lOVlEvYngwTU9UcQphK1J3T0gzWmNNS3lvR3hPSm85QXllUmE2RlhNbXZKSkdZczVQMzRZc3pGcG5qMnVBYmkyNG5FQ0F3RUFBUT09Ci0tLS0tRU5EIFBVQkxJQyBLRVktLS0tLQo-"
	input := `{"expires":"2017-06-09T06:11:12.125Z","modified" : "2017-06-02T06:11:12.125Z","policyData":{"domain":"sys.auth","policies":[{"assertions":[{"action":"*","effect":"ALLOW","resource":"*","role":"sys.auth:role.admin"},{"action":"*","effect":"DENY","resource":"*","role":"sys.auth:role.non-admin"}],"name":"sys.auth:policy.admin"}]},"zmsKeyId":"0","zmsSignature":"Y2HuXmgL86PL1WnleGFHwPmNEqUdWgDxmmIsDnF5f5oqakacqTtwt9JNqDV9nuJ7LnKl3zsZoDQSAtcHMu4IGA--"}`
	signature := "XJnQ4t33D4yr7NtUjLaWhXULFr76z.z0p3QV4uCkA5KR9L4liVRmICYwVmnXxvHAlImKlKLv7sbIHNsjBfGfCw--"
	key, err := new(zmssvctoken.YBase64).DecodeString(publicKey)
	a.Nil(err)
	err = verify(input, signature, string(key))
	a.NotNil(err, "Verifier validated for invalid data")
}

func TestVerifierTamperedKey(t *testing.T) {
	a := assert.New(t)
	publicKey := "LS1tLS1CRUdJTiBQVUJMSUMgS0VZLS0tLS0KTUZ3d0RRWUpLb1pJaHZjTkFRRUJCUUFEU3dBd1NBSkJBTHpmU09UUUpmRW0xZW00TDNza3lOVlEvYngwTU9UcQphK1J3T0gzWmNNS3lvR3hPSm85QXllUmE2RlhNbXZKSkdZczVQMzRZc3pGcG5qMnVBYmkyNG5FQ0F3RUFBUT09Ci0tLS0tRU5EIFBVQkxJQyBLRVktLS0tLQo-"
	input := `{"expires":"2017-06-09T06:11:12.125Z","modified":"2017-06-02T06:11:12.125Z","policyData":{"domain":"sys.auth","policies":[{"assertions":[{"action":"*","effect":"ALLOW","resource":"*","role":"sys.auth:role.admin"},{"action":"*","effect":"DENY","resource":"*","role":"sys.auth:role.non-admin"}],"name":"sys.auth:policy.admin"}]},"zmsKeyId":"0","zmsSignature":"Y2HuXmgL86PL1WnleGFHwPmNEqUdWgDxmmIsDnF5f5oqakacqTtwt9JNqDV9nuJ7LnKl3zsZoDQSAtcHMu4IGA--"}`
	signature := "XJn4t33D4yr7NtUjLaWhXULFr76z.z0p3QV4uCkA5KR9L4liVRmICYwVmnXxvHAlImKlKLv7sbIHNsjBfGfCw--"
	key, err := new(zmssvctoken.YBase64).DecodeString(publicKey)
	a.Nil(err)
	err = verify(input, signature, string(key))
	a.NotNil(err, "Verifier validated data with tampered key")
}

func TestVerifierTamperedSignature(t *testing.T) {
	a := assert.New(t)
	publicKey := "LS0tLS1CRUdJTiBQVUJMSUMgS0VZLS0tLS0KTUZ3d0RRWUpLb1pJaHZjTkFRRUJCUUFEU3dBd1NBSkJBTHpmU09UUUpmRW0xZW00TDNza3lOVlEvYngwTU9UcQphK1J3T0gzWmNNS3lvR3hPSm85QXllUmE2RlhNbXZKSkdZczVQMzRZc3pGcG5qMnVBYmkyNG5FQ0F3RUFBUT09Ci0tLS0tRU5EIFBVQkxJQyBLRVktLS0tLQo-"
	input := `{"expires":"2017-06-09T06:11:12.125Z","modified":"2017-06-02T06:11:12.125Z","policyData":{"domain":"sys.auth","policies":[{"assertions":[{"action":"*","effect":"ALLOW","resource":"*","role":"sys.auth:role.admin"},{"action":"*","effect":"DENY","resource":"*","role":"sys.auth:role.non-admin"}],"name":"sys.auth:policy.admin"}]},"zmsKeyId":"0","zmsSignature":"Y2HuXmgL86PL1WnleGFHwPmNEqUdWgDxmmIsDnF5f5oqakacqTtwt9JNqDV9nuJ7LnKl3zsZoDQSAtcHMu4IGA--"}`
	signature := "XJpQ4t33D4yr7NtUjLaWhXULFr76z.z0p3QV4uCkA5KR9L4liVRmICYwVmnXxvHAlImKlKLv7sbIHNsjBfGfCw--"
	key, err := new(zmssvctoken.YBase64).DecodeString(publicKey)
	a.Nil(err)
	err = verify(input, signature, string(key))
	a.NotNil(err, "Verifier validated data with tampered signature")
}

func TestFormatUrl(t *testing.T) {
	a := assert.New(t)
	url := formatURL("ztsURL/", "zts/v1")
	a.Equal(url, "ztsURL/zts/v1")
	url = formatURL("ztsURL", "zts/v1")
	a.Equal(url, "ztsURL/zts/v1")

	url = formatURL("zmsURL/", "zms/v1")
	a.Equal(url, "zmsURL/zms/v1")
	url = formatURL("zmsURL", "zms/v1")
	a.Equal(url, "zmsURL/zms/v1")
}
