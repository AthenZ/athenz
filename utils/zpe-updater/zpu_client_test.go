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

	"github.com/ardielle/ardielle-go/rdl"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/yahoo/athenz/clients/go/zts"
	"github.com/yahoo/athenz/libs/go/zmssvctoken"
	"github.com/yahoo/athenz/utils/zpe-updater/devel"
	"github.com/yahoo/athenz/utils/zpe-updater/test_data"
	"github.com/yahoo/athenz/utils/zpe-updater/util"
)

const (
	CONF_PATH         = "/tmp"
	POLICIES_DIR      = "/tmp/zpu"
	TEMP_POLICIES_DIR = "/tmp/zpe"
	METRIC_DIR        = "/tmp/zpu_metrics"
	DOMAIN            = "test"
)

var testConfig *ZpuConfiguration
var ztsClient zts.ZTSClient
var port string

func TestMain(m *testing.M) {

	address := devel.StartMockServer(test_data.EndPoints, test_data.MetricEndPoints)
	port = address[5:]
	log.Printf("The port assigned to test server is; %v", port)
	err := setUp()
	if err != nil {
		log.Fatalf("Failed to set up test environment, Error:%v", err)
	}
	exitCode := m.Run()
	err = cleanUp()
	if err != nil {
		exitCode = 2
	}
	os.Exit(exitCode)
}

func TestWritePolicies(t *testing.T) {
	a := assert.New(t)
	policyData, _, err := ztsClient.GetDomainSignedPolicyData(zts.DomainName(DOMAIN), "")
	a.Nil(err)
	policyJSON, err := json.Marshal(policyData)
	a.Nil(err)

	err = WritePolicies(testConfig, policyJSON, DOMAIN, POLICIES_DIR)
	a.Nil(err)
	policyFile := fmt.Sprintf("%s/%s.pol", POLICIES_DIR, DOMAIN)
	tempPolicyFile := fmt.Sprintf("%s/%s.tmp", TEMP_POLICIES_DIR, DOMAIN)
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
	policyData, _, err := ztsClient.GetDomainSignedPolicyData(zts.DomainName(DOMAIN), "")
	a.Nil(err)
	policyJSON, err := json.Marshal(policyData)
	a.Nil(err)
	err = WritePolicies(testConfig, policyJSON, DOMAIN, "/random")
	fmt.Print(err)
	a.NotNil(err)
}

func TestGetEtagForExistingPolicy(t *testing.T) {
	a := assert.New(t)
	ztsClient := zts.NewClient((*testConfig).Zts, nil)

	//Policy File does not exist
	etag := GetEtagForExistingPolicy(testConfig, ztsClient, DOMAIN, POLICIES_DIR)
	a.Empty(etag, "Empty Etag should be returned")

	//Correct Policy File Exist
	policyData, _, err := ztsClient.GetDomainSignedPolicyData(zts.DomainName(DOMAIN), "")
	a.Nil(err)
	policyJSON, err := json.Marshal(policyData)
	a.Nil(err)
	err = ioutil.WriteFile(POLICIES_DIR+"/test.pol", policyJSON, 0755)
	a.Nil(err)
	etag = GetEtagForExistingPolicy(testConfig, ztsClient, "test", POLICIES_DIR)
	_, errv := ValidateSignedPolicies(testConfig, ztsClient, policyData)
	if errv != nil {
		a.Empty(etag)
	} else {
		a.NotEmpty(etag)
	}
	err = os.Remove(POLICIES_DIR + "/test.pol")
	a.Nil(err)
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
		log.Fatalf("Failed to decode key to verify data , Error:%v", err)
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

func TestAggregateAllDomainMetrics(t *testing.T) {
	a := assert.New(t)
	agg, dec := aggregateAllDomainMetrics(METRIC_DIR)
	a.Nil(dec)
	a.Nil(agg)
	data1 := `{"ONE":1,"TWO":0,"THREE":0}`
	data2 := `{"ONE":0,"TWO":1,"THREE":0}`
	data3 := `{"ONE":0,"TWO":0,"THREE":1}`
	err := ioutil.WriteFile(METRIC_DIR+"/test_000.json", []byte(data1), 0755)
	a.Nil(err)
	err = ioutil.WriteFile(METRIC_DIR+"/test_001.json", []byte(data1), 0755)
	a.Nil(err)
	err = ioutil.WriteFile(METRIC_DIR+"/test1_000.json", []byte(data2), 0755)
	a.Nil(err)
	err = ioutil.WriteFile(METRIC_DIR+"/test1_001.json", []byte(data2), 0755)
	a.Nil(err)
	err = ioutil.WriteFile(METRIC_DIR+"/test2_000.json", []byte(data3), 0755)
	a.Nil(err)
	err = ioutil.WriteFile(METRIC_DIR+"/test2_001.json", []byte(data3), 0755)
	a.Nil(err)
	aggregate, err := aggregateAllDomainMetrics(METRIC_DIR)
	a.Nil(err, "Valid metric files shold be aggregated")
	m := map[string]map[string]int{"test": map[string]int{"ONE": 2, "TWO": 0, "THREE": 0}, "test1": map[string]int{"ONE": 0, "TWO": 2, "THREE": 0}, "test2": map[string]int{"ONE": 0, "TWO": 0, "THREE": 2}}
	a.Equal(len(aggregate), 3)
	a.Equal(aggregate["test"], m["test"])
	a.Equal(aggregate["test1"], m["test1"])
	a.Equal(aggregate["test2"], m["test2"])
	err = os.Remove(METRIC_DIR + "/test_000.json")
	a.Nil(err)
	err = os.Remove(METRIC_DIR + "/test_001.json")
	a.Nil(err)
	err = os.Remove(METRIC_DIR + "/test1_000.json")
	a.Nil(err)
	err = os.Remove(METRIC_DIR + "/test1_001.json")
	a.Nil(err)
	err = os.Remove(METRIC_DIR + "/test2_000.json")
	a.Nil(err)
	err = os.Remove(METRIC_DIR + "/test2_001.json")
	a.Nil(err)
}

func TestBuildDomainMetric(t *testing.T) {
	a := assert.New(t)
	m := map[string]int{"ACCESS_ALLOWED_TOKEN_CACHE_FAILURE": 1, "LOAD_FILE_GOOD": 0, "ACCESS_ALLOWED_DENY_NO_MATCH": 2}
	data, err := buildDomainMetrics("test", m)
	a.Nil(err)
	metricJSON, err := json.Marshal(data)
	a.Nil(err)
	a.Equal(string(metricJSON), `{"domainName":"test","metricList":[{"metricType":"ACCESS_ALLOWED_DENY_NO_MATCH","metricVal":2},{"metricType":"ACCESS_ALLOWED_TOKEN_CACHE_FAILURE","metricVal":1},{"metricType":"LOAD_FILE_GOOD","metricVal":0}]}`)
}

func TestDeleteDomainFiles(t *testing.T) {
	a := assert.New(t)

	err := ioutil.WriteFile(METRIC_DIR+"/test_000.json", []byte("test"), 0755)
	a.Nil(err)
	err = ioutil.WriteFile(METRIC_DIR+"/test_001.json", []byte("test"), 0755)
	a.Nil(err)
	err = ioutil.WriteFile(METRIC_DIR+"/test1_000.json", []byte("test"), 0755)
	a.Nil(err)
	err = ioutil.WriteFile(METRIC_DIR+"/test2_000.json", []byte("test"), 0755)
	a.Nil(err)
	deleteDomainMetricFiles(METRIC_DIR, "test")
	a.Equal(util.Exists(METRIC_DIR+"/test_000.json"), false)
	a.Equal(util.Exists(METRIC_DIR+"/test_001.json"), false)
	a.Equal(util.Exists(METRIC_DIR+"/test1_000.json"), true)
	a.Equal(util.Exists(METRIC_DIR+"/test2_000.json"), true)
	deleteDomainMetricFiles(METRIC_DIR, "test1")
	a.Equal(util.Exists(METRIC_DIR+"/test1_000.json"), false)
	deleteDomainMetricFiles(METRIC_DIR, "test2")
	a.Equal(util.Exists(METRIC_DIR+"/test2_000.json"), false)
}

func TestPostAllDomainMetric(t *testing.T) {
	a := assert.New(t)
	err := ioutil.WriteFile(METRIC_DIR+"/test_000.json", []byte(`{"ACCESS_ALLOWED_TOKEN_CACHE_FAILURE":1,"LOAD_FILE_GOOD":0,"ACCESS_ALLOWED_DENY_NO_MATCH":2}`), 0755)
	a.Nil(err)
	err = ioutil.WriteFile(METRIC_DIR+"/test_001.json", []byte(`{"ACCESS_ALLOWED_TOKEN_CACHE_FAILURE":0,"LOAD_FILE_GOOD":1,"ACCESS_ALLOWED_DENY_NO_MATCH":0}`), 0755)
	a.Nil(err)
	err = ioutil.WriteFile(METRIC_DIR+"/test1_000.json", []byte(`{"ACCESS_ALLOWED_TOKEN_CACHE_FAILURE":0,"LOAD_FILE_GOOD":1,"ACCESS_ALLOWED_DENY_NO_MATCH":1}`), 0755)
	a.Nil(err)
	err = ioutil.WriteFile(METRIC_DIR+"/test1_001.json", []byte(`{"ACCESS_ALLOWED_TOKEN_CACHE_FAILURE":0,"LOAD_FILE_GOOD":0,"ACCESS_ALLOWED_DENY_NO_MATCH":2}`), 0755)
	a.Nil(err)
	err = PostAllDomainMetric(ztsClient, METRIC_DIR)
	require.Nil(t, err, "Metrics for all domains should be posted")
	a.Equal(util.Exists(METRIC_DIR+"/test_000.json"), false)
	a.Equal(util.Exists(METRIC_DIR+"/test_001.json"), false)
	a.Equal(util.Exists(METRIC_DIR+"/test1_000.json"), false)
	a.Equal(util.Exists(METRIC_DIR+"/test1_001.json"), false)

	//No Domain Metric Files
	err = PostAllDomainMetric(ztsClient, METRIC_DIR)
	require.Nil(t, err, "No metric files to read")
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

func setUp() error {
	var err error
	testConfig, err = getTestConfiguration()
	if err != nil {
		return err
	}
	err = os.MkdirAll(POLICIES_DIR, 0755)
	if err != nil {
		return fmt.Errorf("Failed to create directory for policy files, Error:%v", err)
	}
	err = os.MkdirAll(TEMP_POLICIES_DIR, 0755)
	if err != nil {
		return fmt.Errorf("Failed to create temporary directory for policy files, Error:%v", err)
	}
	err = os.MkdirAll(METRIC_DIR, 0755)
	if err != nil {
		return fmt.Errorf("Failed to create directory for metric files, Error:%v", err)
	}
	ztsClient = zts.NewClient((*testConfig).Zts, nil)
	return nil
}

func cleanUp() error {
	err := os.RemoveAll(POLICIES_DIR)
	if err != nil {
		return fmt.Errorf("Failed to delete directory for policy files, Error:%v", err)
	}
	err = os.RemoveAll(TEMP_POLICIES_DIR)
	if err != nil {
		return fmt.Errorf("Failed to delete temporary directory for policy files, Error:%v", err)
	}
	err = os.RemoveAll(METRIC_DIR)
	if err != nil {
		return fmt.Errorf("Failed to delete directory for metric files, Error:%v", err)
	}
	err = os.Remove(CONF_PATH + "/athenz.conf")
	if err != nil {
		return fmt.Errorf("Failed to delete athenz conf file, Error:%v", err)
	}
	err = os.Remove(CONF_PATH + "/zpu.conf")
	if err != nil {
		return fmt.Errorf("Failed to delete zpu conf file, Error:%v", err)
	}
	return nil
}

func getTestConfiguration() (*ZpuConfiguration, error) {
	zmsURL := fmt.Sprintf("http://localhost:%s/zms/v1", port)
	ztsURL := fmt.Sprintf("http://localhost:%s/zts/v1", port)
	athenzConf := `{"zmsURL":"` + zmsURL + `","ztsURL":"` + ztsURL + `","ztsPublicKeys":[{"id":"0","key":"LS0tLS1CRUdJTiBQVUJMSUMgS0VZLS0tLS0KTUZ3d0RRWUpLb1pJaHZjTkFRRUJCUUFEU3dBd1NBSkJBTHpmU09UUUpmRW0xZW00TDNza3lOVlEvYngwTU9UcQphK1J3T0gzWmNNS3lvR3hPSm85QXllUmE2RlhNbXZKSkdZczVQMzRZc3pGcG5qMnVBYmkyNG5FQ0F3RUFBUT09Ci0tLS0tRU5EIFBVQkxJQyBLRVktLS0tLQo-"}],"zmsPublicKeys":[{"id":"0","key":"LS0tLS1CRUdJTiBQVUJMSUMgS0VZLS0tLS0KTUZ3d0RRWUpLb1pJaHZjTkFRRUJCUUFEU3dBd1NBSkJBTHpmU09UUUpmRW0xZW00TDNza3lOVlEvYngwTU9UcQphK1J3T0gzWmNNS3lvR3hPSm85QXllUmE2RlhNbXZKSkdZczVQMzRZc3pGcG5qMnVBYmkyNG5FQ0F3RUFBUT09Ci0tLS0tRU5EIFBVQkxJQyBLRVktLS0tLQo-"}]}`
	devel.CreateFile(CONF_PATH+"/athenz.conf", athenzConf)
	zpuConf := `{"domains":"test"}`
	devel.CreateFile(CONF_PATH+"/zpu.conf", zpuConf)
	config, err := NewZpuConfiguration("", CONF_PATH+"/athenz.conf", CONF_PATH+"/zpu.conf")
	if err != nil {
		return nil, fmt.Errorf("Failed to return test configuration object, Error:%v", err)
	}
	return config, nil
}
