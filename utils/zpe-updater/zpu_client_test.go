// Copyright The Athenz Authors
// Licensed under the terms of the Apache version 2.0 license. See LICENSE file for terms.

package zpu

import (
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/AthenZ/athenz/libs/go/athenz-common/log"
	siautil "github.com/AthenZ/athenz/libs/go/sia/util"
	"github.com/dimfeld/httptreemux"
	"github.com/stretchr/testify/require"

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

type testServer struct {
	listener net.Listener
	addr     string
}

func (t *testServer) start(h http.Handler) {
	listener, err := net.Listen("tcp", ":0")
	if err != nil {
		log.Fatalf("Unable to serve on randomly assigned port")
	}
	s := &http.Server{Handler: h}
	t.listener = listener
	t.addr = listener.Addr().String()

	go func() {
		s.Serve(listener)
	}()
}

func (t *testServer) stop() {
	t.listener.Close()
}

func (t *testServer) baseUrl(version string) string {
	return "http://" + t.addr + "/" + version
}

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

var rsaPublicKeyPEM = []byte(`-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAxq83nCd8AqH5n40dEBME
lbaJd2gFWu6bjhNzyp9562dpf454BUSN0uF+g3i1yzcwdvADTiuExKN1u/IoGURx
VCa0JTzAPJw6/JIoyOZnHZCoarcgQQqZ56/udkSQ2NssrwGSQjOwxMrgIdH6XeLg
GqVN4BoEEI+gpaQZa7rSytU5RFSGOnZWO2Vwgs1OBxiOiYg1gzA1spJXQhxcBWw/
v+YrUFtjxBKsG1UrWbnHbgciiN5U2v51Yztjo8A1T+o9eIG90jVo3EhS2qhbzd8m
LAsEhjV1sP8GItjfdfwXpXT7q2QG99W3PM75+HdwGLvJIrkED7YRj4CpMkz6F1et
awIDAQAB
-----END PUBLIC KEY-----
`)

var rsaPublicKeyJwk = []byte(`{"kty":"RSA","e":"AQAB","kid":"c6e34b18-fb1c-43bb-9de7-7edc8981b14d","n":"xq83nCd8AqH5n40dEBMElbaJd2gFWu6bjhNzyp9562dpf454BUSN0uF-g3i1yzcwdvADTiuExKN1u_IoGURxVCa0JTzAPJw6_JIoyOZnHZCoarcgQQqZ56_udkSQ2NssrwGSQjOwxMrgIdH6XeLgGqVN4BoEEI-gpaQZa7rSytU5RFSGOnZWO2Vwgs1OBxiOiYg1gzA1spJXQhxcBWw_v-YrUFtjxBKsG1UrWbnHbgciiN5U2v51Yztjo8A1T-o9eIG90jVo3EhS2qhbzd8mLAsEhjV1sP8GItjfdfwXpXT7q2QG99W3PM75-HdwGLvJIrkED7YRj4CpMkz6F1etaw"}`)

var ecPublicKeyPEM = []byte(`-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAESVqB4JcUD6lsfvqMr+OKUNUphdNn
64Eay60978ZlL76V/S7SkyPiUYDNmLHm7gKbkIxAiAw2mTDLXrfC0phUog==
-----END PUBLIC KEY-----
`)

var ecPublicKeyJwk = []byte(`{
  "kid" : "FdFYFzERwC2uCBB46pZQi4GG85LujR8obt-KWRBICVQ",
  "kty" : "EC",
  "crv" : "P-256",
  "x"   : "SVqB4JcUD6lsfvqMr-OKUNUphdNn64Eay60978ZlL74",
  "y"   : "lf0u0pMj4lGAzZix5u4Cm5CMQIgMNpkwy163wtKYVKI",
  "d"   : "0g5vAEKzugrXaRbgKG0Tj2qJ5lMP4Bezds1_sTybkfk"
}`)

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
	config, err := NewZpuConfiguration("", ConfPath+"/athenz.conf", ConfPath+"/zpu.conf", ConfPath)
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
	policyJSON, _ := os.ReadFile("test_data/data_domain.json")
	err := WritePolicies(testConfig, policyJSON, Domain)
	a.Nil(err)
	policyFile := fmt.Sprintf("%s/%s.pol", PoliciesDir, Domain)
	tempPolicyFile := fmt.Sprintf("%s/%s.tmp", TempPoliciesDir, Domain)
	a.Equal(util.Exists(tempPolicyFile), false)
	a.Equal(util.Exists(policyFile), true)
	data, err := os.ReadFile(policyFile)
	a.Nil(err)
	a.Equal(string(data), string(policyJSON))
	err = os.Remove(policyFile)
	a.Nil(err)
}

func TestWritePoliciesEmptyPolicyDir(t *testing.T) {
	a := assert.New(t)
	policyJSON, _ := os.ReadFile("test_data/data_domain.json")
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
			err = os.WriteFile(PoliciesDir+"/test.pol", policyJSON, 0755)
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
			err = os.WriteFile(PoliciesDir+"/test.pol", policyJSON, 0755)
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

func TestRSAJwkToPem(t *testing.T) {

	var ztsJwk zts.JWK
	err := json.Unmarshal(rsaPublicKeyJwk, &ztsJwk)
	require.Nil(t, err, "should be able to convert json to zts.JWK")

	jwkAsPem, err := jwkToPem(&ztsJwk)
	require.Nil(t, err, "should be able to convert zts.JWK to pem")

	require.Equal(t, jwkAsPem, rsaPublicKeyPEM)

}

func TestECJwkToPem(t *testing.T) {

	var ztsJwk zts.JWK
	err := json.Unmarshal(ecPublicKeyJwk, &ztsJwk)
	require.Nil(t, err, "should be able to convert json to zts.JWK")

	jwkAsPem, err := jwkToPem(&ztsJwk)
	require.Nil(t, err, "should be able to convert zts.JWK to pem")

	require.Equal(t, jwkAsPem, ecPublicKeyPEM)

}

func TestPolicyUpdaterJwkOnInit(t *testing.T) {
	a := assert.New(t)
	ztsRouter := httptreemux.New()

	siaDir, err := os.MkdirTemp("", "sia")
	if err != nil {
		a.Nil(err)
	}
	defer os.RemoveAll(siaDir)

	// left here the PEM public key for debugging purpose
	// pub := "LS0tLS1CRUdJTiBQVUJMSUMgS0VZLS0tLS0KTUZ3d0RRWUpLb1pJaHZjTkFRRUJCUUFEU3dBd1NBSkJBTHpmU09UUUpmRW0xZW00TDNza3lOVlEvYngwTU9UcQphK1J3T0gzWmNNS3lvR3hPSm85QXllUmE2RlhNbXZKSkdZczVQMzRZc3pGcG5qMnVBYmkyNG5FQ0F3RUFBUT09Ci0tLS0tRU5EIFBVQkxJQyBLRVktLS0tLQo-"
	// pubkey, _ := new(zmssvctoken.YBase64).DecodeString(pub)
	// log.Printf("pubkey: [%s]", pubKey)

	signedPolicy := `{"expires":"2017-06-09T06:11:12.125Z","modified":"2017-06-02T06:11:12.125Z","policyData":{"domain":"sys.auth","policies":[{"assertions":[{"action":"*","effect":"ALLOW","resource":"*","role":"sys.auth:role.admin"},{"action":"*","effect":"DENY","resource":"*","role":"sys.auth:role.non-admin"}],"name":"sys.auth:policy.admin"}]},"zmsKeyId":"0","zmsSignature":"Y2HuXmgL86PL1WnleGFHwPmNEqUdWgDxmmIsDnF5f5oqakacqTtwt9JNqDV9nuJ7LnKl3zsZoDQSAtcHMu4IGA--"}`
	pubJwk := "{\"kty\":\"RSA\",\"e\":\"AQAB\",\"kid\":\"0\",\"n\":\"vN9I5NAl8SbV6bgveyTI1VD9vHQw5Opr5HA4fdlwwrKgbE4mj0DJ5FroVcya8kkZizk_fhizMWmePa4BuLbicQ\"}"
	signature := "XJnQ4t33D4yr7NtUjLaWhXULFr76z.z0p3QV4uCkA5KR9L4liVRmICYwVmnXxvHAlImKlKLv7sbIHNsjBfGfCw--"

	// Mock GetDomainSignedPolicyData
	ztsRouter.GET("/zts/v1/domain/sys.auth/signed_policy_data", func(w http.ResponseWriter, r *http.Request, params map[string]string) {
		log.Printf("Called /domain/sys.auth/signed_policy_data")
		policyData, _ := devel.SignPolicy([]byte(signedPolicy), signature, "0")
		pd, _ := json.Marshal(policyData)
		io.WriteString(w, string(pd))
	})

	ztsServer := &testServer{}
	ztsServer.start(ztsRouter)
	defer ztsServer.stop()

	zmsKeysmap := make(map[string]string)
	zmsKeysmap["0"] = "previous value"
	log.Debug = true

	conf := ZpuConfiguration{
		Zts:               ztsServer.baseUrl("zts/v1"),
		DomainList:        "sys.auth",
		SiaDir:            siaDir,
		ZmsKeysmap:        zmsKeysmap,
		ZtsKeysmap:        make(map[string]string),
		MetricsDir:        MetricDir,
		PolicyFileDir:     PoliciesDir,
		TempPolicyFileDir: TempPoliciesDir,
		CheckZMSSignature: true,
		ExpiredFunc: func(rdl.Timestamp) bool {
			return false
		},
	}

	writeAthenzJwkConf(pubJwk, &conf)
	conf.loadAthenzJwks()
	err = PolicyUpdater(&conf)
	a.Nil(err)
	policyFile := fmt.Sprintf("%s/%s.pol", PoliciesDir, "sys.auth")
	a.Equal(util.Exists(policyFile), true)
}

func TestPolicyUpdaterJwkOnZtsCall(t *testing.T) {
	a := assert.New(t)
	ztsRouter := httptreemux.New()
	ztsRouter.EscapeAddedRoutes = true

	siaDir, err := os.MkdirTemp("", "sia")
	if err != nil {
		a.Nil(err)
	}
	defer os.RemoveAll(siaDir)

	signedPolicy := `{"expires":"2017-06-09T06:11:12.125Z","modified":"2017-06-02T06:11:12.125Z","policyData":{"domain":"sys.auth","policies":[{"assertions":[{"action":"*","effect":"ALLOW","resource":"*","role":"sys.auth:role.admin"},{"action":"*","effect":"DENY","resource":"*","role":"sys.auth:role.non-admin"}],"name":"sys.auth:policy.admin"}]},"zmsKeyId":"0","zmsSignature":"Y2HuXmgL86PL1WnleGFHwPmNEqUdWgDxmmIsDnF5f5oqakacqTtwt9JNqDV9nuJ7LnKl3zsZoDQSAtcHMu4IGA--"}`
	pubJwk := "{\"kty\":\"RSA\",\"e\":\"AQAB\",\"kid\":\"0\",\"n\":\"vN9I5NAl8SbV6bgveyTI1VD9vHQw5Opr5HA4fdlwwrKgbE4mj0DJ5FroVcya8kkZizk_fhizMWmePa4BuLbicQ\"}"
	signature := "XJnQ4t33D4yr7NtUjLaWhXULFr76z.z0p3QV4uCkA5KR9L4liVRmICYwVmnXxvHAlImKlKLv7sbIHNsjBfGfCw--"

	// Mock GetDomainSignedPolicyData
	ztsRouter.GET("/zts/v1/domain/sys.auth/signed_policy_data", func(w http.ResponseWriter, r *http.Request, params map[string]string) {
		log.Printf("Called /domain/sys.auth/signed_policy_data")
		policyData, _ := devel.SignPolicy([]byte(signedPolicy), signature, "0")
		pd, _ := json.Marshal(policyData)
		io.WriteString(w, string(pd))
	})

	jwkConf := athenzJwkFromString(pubJwk)
	// Mock GetJWKList
	ztsRouter.GET("/zts/v1/oauth2/keys", func(w http.ResponseWriter, r *http.Request, params map[string]string) {
		log.Printf("Called /zts/v1/oauth2/keys")
		ztsKeys, _ := json.Marshal(jwkConf.Zts)
		io.WriteString(w, string(ztsKeys))
	})

	ztsServer := &testServer{}
	ztsServer.start(ztsRouter)
	defer ztsServer.stop()

	conf := ZpuConfiguration{
		Zts:               ztsServer.baseUrl("zts/v1"),
		DomainList:        "sys.auth",
		SiaDir:            siaDir,
		ZmsKeysmap:        make(map[string]string),
		ZtsKeysmap:        make(map[string]string),
		MetricsDir:        MetricDir,
		PolicyFileDir:     PoliciesDir,
		TempPolicyFileDir: TempPoliciesDir,
		CheckZMSSignature: false,
		ExpiredFunc: func(rdl.Timestamp) bool {
			return false
		},
	}

	err = PolicyUpdater(&conf)
	a.Nil(err)
	policyFile := fmt.Sprintf("%s/%s.pol", PoliciesDir, "sys.auth")
	a.Equal(util.Exists(policyFile), true)
}

func writeAthenzJwkConf(pubJwk string, zpuConf *ZpuConfiguration) {

	jwkConf := athenzJwkFromString(pubJwk)

	bytes, err := json.MarshalIndent(jwkConf, "", "    ")
	if err != nil {
		log.Fatalf("error: %v", err)
	}

	confFile := filepath.Join(zpuConf.SiaDir, siautil.JwkConfFile)
	if err := os.WriteFile(confFile, bytes, 0600); err != nil {
		log.Fatalf("Unable to create the file %q: %v", confFile, err)
	}
}

func athenzJwkFromString(pubJwk string) *zts.AthenzJWKConfig {
	jwkKey := func() *zts.JWKList {

		var jwkKey = zts.JWK{}
		json.Unmarshal([]byte(pubJwk), &jwkKey)

		keysArr := []*zts.JWK{
			&jwkKey,
		}

		return &zts.JWKList{
			Keys: keysArr,
		}
	}

	now := rdl.TimestampNow()
	jwkConf := zts.AthenzJWKConfig{
		Modified: &now,
		Zms:      jwkKey(),
		Zts:      jwkKey(),
	}
	return &jwkConf
}

func TestCanFetchLatestJwksFromZts(t *testing.T) {
	lastZtsJwkFetchTime = time.Time{}
	a := assert.New(t)
	conf := ZpuConfiguration{
		MinutesBetweenZtsCalls: 1,
	}

	a.True(canFetchLatestJwksFromZts(&conf), "should be able to fetch keys from zts")

	// now set the last fetch time and try again
	lastZtsJwkFetchTime = time.Now()
	a.False(canFetchLatestJwksFromZts(&conf), "should not be able to fetch keys from zts")
}
