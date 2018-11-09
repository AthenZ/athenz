// Copyright 2017 Yahoo Holdings, Inc.
// Licensed under the terms of the Apache version 2.0 license. See LICENSE file for terms.

package zpu

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/ardielle/ardielle-go/rdl"
	"github.com/yahoo/athenz/clients/go/zts"
	"github.com/yahoo/athenz/libs/go/athenzutils"
	"github.com/yahoo/athenz/libs/go/zmssvctoken"
	"github.com/yahoo/athenz/utils/zpe-updater/util"
)

func PolicyUpdater(config *ZpuConfiguration) error {
	if config == nil {
		return errors.New("Nil configuration")
	}
	if config.DomainList == "" {
		return errors.New("No domain list to process from configuration")
	}
	if config.Zts == "" {
		return errors.New("Empty Zts url in configuration")
	}
	success := true
	domains := strings.Split(config.DomainList, ",")

	ztsURL := formatURL(config.Zts, "zts/v1")
	var ztsClient zts.ZTSClient
	if config.PrivateKeyFile != "" && config.CertFile != "" {
		ztsCli, err := athenzutils.ZtsClient(ztsURL, config.PrivateKeyFile, config.CertFile, config.CaCertFile, config.Proxy)
		if err != nil {
			return fmt.Errorf("Failed to create Zts Client, Error:%v", err)
		}
		ztsClient = *ztsCli
	} else if config.PrivateKeyFile == "" && config.CertFile != "" {
		return errors.New("Both private key and cert file are required, missing private key file")
	} else if config.PrivateKeyFile != "" && config.CertFile == "" {
		return errors.New("Both private key and cert file are required, missing certificate file")
	} else {
		ztsClient = zts.NewClient(ztsURL, nil)
	}

	policyFileDir := config.PolicyFileDir

	failedDomains := ""
	for _, domain := range domains {
		err := GetPolicies(config, ztsClient, policyFileDir, domain)
		if err != nil {
			if success {
				success = false
			}
			failedDomains += `"`
			failedDomains += domain
			failedDomains += `" `
			log.Printf("Failed to get policies for domain: %v, Error:%v", domain, err)
		}
	}
	metricFilesPath := config.MetricsDir
	if metricFilesPath != "" {
		err := PostAllDomainMetric(ztsClient, metricFilesPath)
		if err != nil {
			log.Printf("Posting of metrics to Zts failed, Error:%v", err)
		}
	}
	if !success {
		return fmt.Errorf("Failed to get policies for domains: %v", failedDomains)
	}
	return nil
}

func GetPolicies(config *ZpuConfiguration, ztsClient zts.ZTSClient, policyFileDir, domain string) error {
	log.Printf("Getting policies for domain: %v", domain)
	etag := GetEtagForExistingPolicy(config, ztsClient, domain, policyFileDir)
	data, _, err := ztsClient.GetDomainSignedPolicyData(zts.DomainName(domain), etag)
	if err != nil {
		return fmt.Errorf("Failed to get domain signed policy data for domain: %v, Error:%v", domain, err)
	}

	if data == nil {
		if etag != "" {
			log.Printf("Policies not updated since last fetch for domain: %v", domain)
			return nil
		}
		return fmt.Errorf("Empty policies data returned for domain: %v", domain)
	}
	// validate data using zts public key and signature
	bytes, err := ValidateSignedPolicies(config, ztsClient, data)
	if err != nil {
		return fmt.Errorf("Failed to validate policy data for domain: %v, Error: %v", domain, err)
	}
	err = WritePolicies(config, bytes, domain, policyFileDir)
	if err != nil {
		return fmt.Errorf("Unable to write Policies for domain:\"%v\" to file, Error:%v", domain, err)
	}
	log.Printf("Policies for domain: %v successfully written", domain)
	return nil
}

func GetEtagForExistingPolicy(config *ZpuConfiguration, ztsClient zts.ZTSClient, domain, policyFileDir string) string {
	var etag string
	var domainSignedPolicyData *zts.DomainSignedPolicyData

	policyFile := fmt.Sprintf("%s/%s.pol", policyFileDir, domain)

	// If Policies file is not found, return empty etag the first time.
	// Otherwise load the file contents, if data has expired return empty etag,
	// else construct etag from modified field in JSON.
	exists := util.Exists(policyFile)
	if !exists {
		return ""
	}

	readFile, err := os.OpenFile(policyFile, os.O_RDONLY, 0444)
	defer readFile.Close()
	if err != nil {
		return ""
	}
	err = json.NewDecoder(readFile).Decode(&domainSignedPolicyData)
	if err != nil {
		return ""
	}
	_, err = ValidateSignedPolicies(config, ztsClient, domainSignedPolicyData)
	if err != nil {
		return ""
	}
	expires := domainSignedPolicyData.SignedPolicyData.Expires
	// We are going to see if we should consider the policy expired
	// and retrieve the latest policy. We're going to take the current
	// expiry timestamp from the policy file, subtract the expected
	// expiry check time (default 2 days) and then see if the date we
	// get should be considered as expired.
	if expired(expires, config.ExpiryCheck) {
		return ""
	}
	modified := domainSignedPolicyData.SignedPolicyData.Modified
	if !modified.IsZero() {
		etag = "\"" + string(modified.String()) + "\""
	}
	return etag
}

func ValidateSignedPolicies(config *ZpuConfiguration, ztsClient zts.ZTSClient, data *zts.DomainSignedPolicyData) ([]byte, error) {
	expires := data.SignedPolicyData.Expires
	if expired(expires, 0) {
		return nil, fmt.Errorf("The policy data is expired on %v", expires)
	}
	signedPolicyData := data.SignedPolicyData
	ztsSignature := data.Signature
	ztsKeyID := data.KeyId

	ztsPublicKey := config.GetZtsPublicKey(ztsKeyID)
	if ztsPublicKey == "" {
		key, err := ztsClient.GetPublicKeyEntry("sys.auth", "zts", ztsKeyID)
		if err != nil {
			return nil, fmt.Errorf("Unable to get the Zts public key with id:\"%v\" to verify data", ztsKeyID)
		}
		decodedKey, err := new(zmssvctoken.YBase64).DecodeString(key.Key)
		if err != nil {
			return nil, fmt.Errorf("Unable to decode the Zts public key with id:\"%v\" to verify data", ztsKeyID)
		}
		ztsPublicKey = string(decodedKey)
	}
	input, err := util.ToCanonicalString(signedPolicyData)
	if err != nil {
		return nil, err
	}
	err = verify(input, ztsSignature, ztsPublicKey)
	if err != nil {
		return nil, fmt.Errorf("Verification of data with zts key having id:\"%v\" failed, Error :%v", ztsKeyID, err)
	}
	//generate canonical json output so that properties
	//can validate the signatures if not using athenz
	//provided libraries for authorization
	bytes := []byte("{\"signedPolicyData\":" + input + ",\"keyId\":\"" + ztsKeyID + "\",\"signature\":\"" + ztsSignature + "\"}")
	zmsSignature := data.SignedPolicyData.ZmsSignature
	zmsKeyID := data.SignedPolicyData.ZmsKeyId
	zmsPublicKey := config.GetZmsPublicKey(zmsKeyID)
	if zmsPublicKey == "" {
		key, err := ztsClient.GetPublicKeyEntry("sys.auth", "zms", zmsKeyID)
		if err != nil {
			return nil, fmt.Errorf("Unable to get the Zms public key with id:\"%v\" to verify data", zmsKeyID)
		}
		decodedKey, err := new(zmssvctoken.YBase64).DecodeString(key.Key)
		if err != nil {
			return nil, fmt.Errorf("Unable to decode the Zms public key with id:\"%v\" to verify data", zmsKeyID)
		}
		zmsPublicKey = string(decodedKey)
	}
	policyData := data.SignedPolicyData.PolicyData
	input, err = util.ToCanonicalString(policyData)
	if err != nil {
		return nil, err
	}
	err = verify(input, zmsSignature, zmsPublicKey)
	if err != nil {
		return nil, fmt.Errorf("Verification of data with zms key with id:\"%v\" failed, Error :%v", zmsKeyID, err)
	}
	return bytes, nil
}

func verify(input, signature, publicKey string) error {
	verifier, err := zmssvctoken.NewVerifier([]byte(publicKey))
	if err != nil {
		return err
	}
	err = verifier.Verify(input, signature)
	return err
}

func expired(expires rdl.Timestamp, offset int) bool {
	expiryCheck := rdl.NewTimestamp(expires.Time.Add(-1 * time.Duration(int64(offset)) * time.Second))
	return rdl.TimestampNow().Millis() > expiryCheck.Millis()
}

// If domain policy file is not found, create the policy file and write policies in it.
// Else delete the existing file and write the modified policies to new file.
func WritePolicies(config *ZpuConfiguration, bytes []byte, domain, policyFileDir string) error {
	tempPolicyFileDir := config.TempPolicyFileDir
	if tempPolicyFileDir == "" || bytes == nil {
		return errors.New("Empty parameters are not valid arguments")
	}
	policyFile := fmt.Sprintf("%s/%s.pol", policyFileDir, domain)
	tempPolicyFile := fmt.Sprintf("%s/%s.tmp", tempPolicyFileDir, domain)
	if util.Exists(tempPolicyFile) {
		err := os.Remove(tempPolicyFile)
		if err != nil {
			return err
		}
	}
	err := verifyTmpDirSetup(tempPolicyFileDir)
	if err != nil {
		return err
	}
	err = ioutil.WriteFile(tempPolicyFile, bytes, 0755)
	if err != nil {
		return err
	}
	err = os.Rename(tempPolicyFile, policyFile)
	return err
}

func verifyTmpDirSetup(TempPolicyFileDir string) error {
	if util.Exists(TempPolicyFileDir) {
		return nil
	}
	err := os.MkdirAll(TempPolicyFileDir, 0755)
	return err
}

func PostAllDomainMetric(ztsClient zts.ZTSClient, metricFilePath string) error {
	m, err := aggregateAllDomainMetrics(metricFilePath)
	if err != nil {
		return err
	}
	if m != nil {
		for key, value := range m {

			data, err := buildDomainMetrics(key, value)
			if err != nil {
				return err
			}
			log.Printf("Posting Domain metric for domain %v to Zts", key)
			data, err = ztsClient.PostDomainMetrics(zts.DomainName(key), data)
			if err != nil {
				log.Printf("Failed to post metrics for domain %v to Zts", key)
				return err
			}
			deleteDomainMetricFiles(metricFilePath, key)
		}
	}
	return nil
}

func aggregateAllDomainMetrics(metricFilePath string) (map[string]map[string]int, error) {
	var m = make(map[string]map[string]int)
	var fileMap = make(map[string]int)

	files, err := ioutil.ReadDir(metricFilePath)
	if err != nil {
		return nil, err
	}
	if len(files) == 0 {
		return nil, nil
	}
	for _, f := range files {
		data, err := ioutil.ReadFile(metricFilePath + "/" + f.Name())
		if err != nil {
			return nil, fmt.Errorf("Failed to read metric  file : %v, Error:%v", f.Name(), err)
		}
		fileMap = map[string]int{}
		err = json.Unmarshal(data, &fileMap)
		if err != nil {
			return nil, fmt.Errorf("Unmarshalling Error:%v for file : %v", err, f.Name())
		}
		domain := strings.Split(f.Name(), "_")
		if _, exists := m[domain[0]]; exists {
			domainMap := m[domain[0]]
			for key, value := range fileMap {
				if _, exists := domainMap[key]; exists {
					val := domainMap[key]
					val += value
					domainMap[key] = val
				} else {
					domainMap[key] = value
				}

			}
		} else {
			m[domain[0]] = fileMap
		}

	}
	return m, nil
}

func buildDomainMetrics(key string, value map[string]int) (*zts.DomainMetrics, error) {
	var data *zts.DomainMetrics
	counter := 1
	metricJSON := `{"domainName":"` + key + `","metricList":[`
	valuekeys := []string{}
	for k := range value {
		valuekeys = append(valuekeys, k)
	}
	sort.Strings(valuekeys)
	for _, innerKey := range valuekeys {
		size := len(value)
		if counter == size {
			metricJSON += `{"metricType":"` + innerKey + `","metricVal":` + strconv.Itoa(value[innerKey]) + `}`
		} else {
			metricJSON += `{"metricType":"` + innerKey + `","metricVal":` + strconv.Itoa(value[innerKey]) + `},`
		}
		counter++
	}
	metricJSON += `]}`
	err := json.Unmarshal([]byte(metricJSON), &data)
	if err != nil {
		return nil, err
	}
	return data, err
}

func deleteDomainMetricFiles(path, domainName string) {
	files, err := ioutil.ReadDir(path)
	if err != nil {
		log.Printf("Failed to get metric files at path for deletion: %v", path)
		return
	}
	for _, f := range files {
		domain := strings.Split(f.Name(), "_")
		if domain[0] == domainName {
			err := os.Remove(path + "/" + f.Name())
			if err != nil {
				log.Printf("Failed to delete file : % v for domain : %v", f.Name(), domainName)
			}
		}
	}
}

func formatURL(url, suffix string) string {
	if !strings.HasSuffix(url, suffix) {
		if strings.LastIndex(url, "/") != len(url)-1 {
			url += "/"
		}
		url += suffix
	}
	return url
}
