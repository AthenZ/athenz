// Copyright 2017 Yahoo Holdings, Inc.
// Licensed under the terms of the Apache version 2.0 license. See LICENSE file for terms.

package zpu

import (
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"strings"
	"time"

	"github.com/AthenZ/athenz/clients/go/zts"
	"github.com/AthenZ/athenz/libs/go/athenzutils"
	"github.com/AthenZ/athenz/libs/go/zmssvctoken"
	"github.com/AthenZ/athenz/utils/zpe-updater/util"
	"github.com/ardielle/ardielle-go/rdl"

	"gopkg.in/square/go-jose.v2"
)

func PolicyUpdater(config *ZpuConfiguration) error {
	if config == nil {
		return errors.New("nil configuration")
	}
	if config.DomainList == "" {
		return errors.New("no domain list to process from configuration")
	}
	if config.Zts == "" {
		return errors.New("empty Zts url in configuration")
	}
	success := true
	domains := strings.Split(config.DomainList, ",")

	ztsURL := formatURL(config.Zts, "zts/v1")
	var ztsClient zts.ZTSClient
	if config.PrivateKeyFile != "" && config.CertFile != "" {
		ztsCli, err := athenzutils.ZtsClient(ztsURL, config.PrivateKeyFile, config.CertFile, config.CaCertFile, config.Proxy)
		if err != nil {
			return fmt.Errorf("failed to create Zts Client, Error:%v", err)
		}
		ztsClient = *ztsCli
	} else if config.PrivateKeyFile == "" && config.CertFile != "" {
		return errors.New("both private key and cert file are required, missing private key file")
	} else if config.PrivateKeyFile != "" && config.CertFile == "" {
		return errors.New("both private key and cert file are required, missing certificate file")
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
			log.Printf("failed to get policies for domain: %v, Error:%v", domain, err)
		}
	}
	if !success {
		return fmt.Errorf("failed to get policies for domains: %v", failedDomains)
	}
	return nil
}

func GetPolicies(config *ZpuConfiguration, ztsClient zts.ZTSClient, policyFileDir, domain string) error {
	if config.JWSPolicySupport {
		return GetJWSPolicies(config, ztsClient, policyFileDir, domain)
	} else {
		return GetSignedPolicies(config, ztsClient, policyFileDir, domain)
	}
}

func GetJWSPolicies(config *ZpuConfiguration, ztsClient zts.ZTSClient, policyFileDir, domain string) error {
	log.Printf("Getting policies for domain: %v", domain)
	etag := GetEtagForExistingPolicy(config, ztsClient, domain, policyFileDir)
	signedPolicyRequest := zts.SignedPolicyRequest{
		PolicyVersions: config.PolicyVersions,
		SignatureP1363Format: true,
	}
	data, _, err := ztsClient.PostSignedPolicyRequest(zts.DomainName(domain), &signedPolicyRequest, etag)
	if err != nil {
		return fmt.Errorf("failed to get domain jws policy data for domain: %v, Error:%v", domain, err)
	}

	if data == nil {
		if etag != "" {
			log.Printf("Policies not updated since last fetch for domain: %v", domain)
			return nil
		}
		return fmt.Errorf("empty policies data returned for domain: %v", domain)
	}
	// validate data using zts public key and signature
	bytes, err := ValidateJWSPolicies(config, ztsClient, data)
	if err != nil {
		return fmt.Errorf("failed to validate policy data for domain: %v, Error: %v", domain, err)
	}
	err = WritePolicies(config, bytes, domain, policyFileDir)
	if err != nil {
		return fmt.Errorf("unable to write Policies for domain:\"%v\" to file, Error:%v", domain, err)
	}
	log.Printf("Policies for domain: %v successfully written", domain)
	return nil
}

func GetSignedPolicies(config *ZpuConfiguration, ztsClient zts.ZTSClient, policyFileDir, domain string) error {
	log.Printf("Getting policies for domain: %v", domain)
	etag := GetEtagForExistingPolicy(config, ztsClient, domain, policyFileDir)
	data, _, err := ztsClient.GetDomainSignedPolicyData(zts.DomainName(domain), etag)
	if err != nil {
		return fmt.Errorf("failed to get domain signed policy data for domain: %v, Error:%v", domain, err)
	}

	if data == nil {
		if etag != "" {
			log.Printf("Policies not updated since last fetch for domain: %v", domain)
			return nil
		}
		return fmt.Errorf("empty policies data returned for domain: %v", domain)
	}
	// validate data using zts public key and signature
	bytes, err := ValidateSignedPolicies(config, ztsClient, data)
	if err != nil {
		return fmt.Errorf("failed to validate policy data for domain: %v, Error: %v", domain, err)
	}
	err = WritePolicies(config, bytes, domain, policyFileDir)
	if err != nil {
		return fmt.Errorf("unable to write Policies for domain:\"%v\" to file, Error:%v", domain, err)
	}
	log.Printf("Policies for domain: %v successfully written", domain)
	return nil
}

func GetSignedPolicyDataFromJson(config *ZpuConfiguration, ztsClient zts.ZTSClient, readFile *os.File) (*zts.SignedPolicyData, error){
	var domainSignedPolicyData *zts.DomainSignedPolicyData
	err := json.NewDecoder(readFile).Decode(&domainSignedPolicyData)
	if err != nil {
		return nil, err
	}
	_, err = ValidateSignedPolicies(config, ztsClient, domainSignedPolicyData)
	if err != nil {
		return nil, err
	}
	return domainSignedPolicyData.SignedPolicyData, nil
}

func GetSignedPolicyDataFromJws(config *ZpuConfiguration, ztsClient zts.ZTSClient, readFile *os.File) (*zts.SignedPolicyData, error){
	var jwsPolicyData *zts.JWSPolicyData
	err := json.NewDecoder(readFile).Decode(&jwsPolicyData)
	if err != nil {
		return nil, err
	}
	_, err = ValidateJWSPolicies(config, ztsClient, jwsPolicyData)
	if err != nil {
		return nil, err
	}
	signedPolicyBytes, err := base64.RawURLEncoding.DecodeString(jwsPolicyData.Payload)
	if err != nil {
		return nil, err
	}
	var signedPolicyData *zts.SignedPolicyData
	err = json.Unmarshal(signedPolicyBytes, &signedPolicyData)
	if err != nil {
		return nil, err
	}
	return signedPolicyData, nil
}

func GetEtagForExistingPolicy(config *ZpuConfiguration, ztsClient zts.ZTSClient, domain, policyFileDir string) string {
	var etag string
	var err error
	policyFile := fmt.Sprintf("%s/%s.pol", policyFileDir, domain)

	// If Policies file is not found, return empty etag the first time.
	// Otherwise, load the file contents, if data has expired return empty etag,
	// else construct etag from modified field in JSON.
	exists := util.Exists(policyFile)
	if !exists {
		return ""
	}

	readFile, err := os.OpenFile(policyFile, os.O_RDONLY, 0444)
	if err != nil {
		return ""
	}
	defer readFile.Close()

	var signedPolicyData *zts.SignedPolicyData
	if config.JWSPolicySupport {
		signedPolicyData, err = GetSignedPolicyDataFromJws(config, ztsClient, readFile)
	} else {
		signedPolicyData, err = GetSignedPolicyDataFromJson(config, ztsClient, readFile)
	}
	if err != nil {
		return ""
	}
	// We are going to see if we should consider the policy expired
	// and retrieve the latest policy. We're going to take the current
	// expiry timestamp from the policy file, subtract the expected
	// expiry check time (default 2 days) and then see if the date we
	// get should be considered as expired.
	expires := signedPolicyData.Expires
	if expired(expires, config.ExpiryCheck) {
		return ""
	}
	modified := signedPolicyData.Modified
	if !modified.IsZero() {
		etag = "\"" + string(modified.String()) + "\""
	}
	return etag
}

func getZtsPublicKey(config *ZpuConfiguration, ztsClient zts.ZTSClient, ztsKeyID string) (string, error) {
	ztsPublicKey := config.GetZtsPublicKey(ztsKeyID)
	if ztsPublicKey == "" {
		key, err := ztsClient.GetPublicKeyEntry("sys.auth", "zts", ztsKeyID)
		if err != nil {
			return "", fmt.Errorf("unable to get the Zts public key with id:\"%v\" to verify data", ztsKeyID)
		}
		decodedKey, err := new(zmssvctoken.YBase64).DecodeString(key.Key)
		if err != nil {
			return "", fmt.Errorf("unable to decode the Zts public key with id:\"%v\" to verify data", ztsKeyID)
		}
		ztsPublicKey = string(decodedKey)
	}
	return ztsPublicKey, nil
}

func ValidateSignedPolicies(config *ZpuConfiguration, ztsClient zts.ZTSClient, data *zts.DomainSignedPolicyData) ([]byte, error) {
	expires := data.SignedPolicyData.Expires
	if expired(expires, 0) {
		return nil, fmt.Errorf("policy data is expired on %v", expires)
	}
	signedPolicyData := data.SignedPolicyData
	ztsSignature := data.Signature
	ztsKeyID := data.KeyId

	ztsPublicKey, err := getZtsPublicKey(config, ztsClient, ztsKeyID)
	if err != nil {
		return nil, err
	}

	input, err := util.ToCanonicalString(signedPolicyData)
	if err != nil {
		return nil, err
	}
	err = verify(input, ztsSignature, ztsPublicKey)
	if err != nil {
		return nil, fmt.Errorf("verification of data with zts key having id:\"%v\" failed, Error :%v", ztsKeyID, err)
	}
	//generate canonical json output so that properties
	//can validate the signatures if not using athenz
	//provided libraries for authorization
	bytes := []byte("{\"signedPolicyData\":" + input + ",\"keyId\":\"" + ztsKeyID + "\",\"signature\":\"" + ztsSignature + "\"}")
	if config.CheckZMSSignature {
		zmsSignature := data.SignedPolicyData.ZmsSignature
		zmsKeyID := data.SignedPolicyData.ZmsKeyId
		zmsPublicKey := config.GetZmsPublicKey(zmsKeyID)
		if zmsPublicKey == "" {
			key, err := ztsClient.GetPublicKeyEntry("sys.auth", "zms", zmsKeyID)
			if err != nil {
				return nil, fmt.Errorf("unable to get the Zms public key with id:\"%v\" to verify data", zmsKeyID)
			}
			decodedKey, err := new(zmssvctoken.YBase64).DecodeString(key.Key)
			if err != nil {
				return nil, fmt.Errorf("unable to decode the Zms public key with id:\"%v\" to verify data", zmsKeyID)
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
			return nil, fmt.Errorf("verification of data with zms key with id:\"%v\" failed, Error :%v", zmsKeyID, err)
		}
	}
	return bytes, nil
}

func ValidateJWSPolicies(config *ZpuConfiguration, ztsClient zts.ZTSClient, jwsPolicyData *zts.JWSPolicyData) ([]byte, error) {
	// Parse the serialized, protected JWS object. An error would indicate that
	// the given input did not represent a valid message.
	jwsPolicyBytes, err := json.Marshal(jwsPolicyData)
	if err != nil {
		return nil, err
	}
	object, err := jose.ParseSigned(string(jwsPolicyBytes))
	if err != nil {
		return nil, err
	}
	ztsPublicKey, err := getZtsPublicKey(config, ztsClient, object.Signatures[0].Protected.KeyID)
	if err != nil {
		return nil, err
	}
	publicKey, err := loadPublicKey([]byte(ztsPublicKey))
	if err != nil {
		return nil, err
	}
	// Now we can verify the signature on the payload. An error here would
	// indicate that the message failed to verify, e.g. because the signature was
	// broken or the message was tampered with.
	_, err = object.Verify(publicKey)
	if err != nil {
		return nil, err
	}
	return jwsPolicyBytes, nil
}

func loadPublicKey(publicKeyPEM []byte) (interface{}, error) {
	block, _ := pem.Decode(publicKeyPEM)
	if block == nil {
		return nil, fmt.Errorf("unable to load public key")
	}
	if !strings.HasSuffix(block.Type, "PUBLIC KEY") {
		return nil, fmt.Errorf("invalid public key type: %s", block.Type)
	}

	return x509.ParsePKIXPublicKey(block.Bytes)
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

// WritePolicies If domain policy file is not found, create the policy file and write policies in it.
// Else delete the existing file and write the modified policies to new file.
func WritePolicies(config *ZpuConfiguration, bytes []byte, domain, policyFileDir string) error {
	tempPolicyFileDir := config.TempPolicyFileDir
	if tempPolicyFileDir == "" || bytes == nil {
		return errors.New("empty parameters are not valid arguments")
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

func formatURL(url, suffix string) string {
	if !strings.HasSuffix(url, suffix) {
		if strings.LastIndex(url, "/") != len(url)-1 {
			url += "/"
		}
		url += suffix
	}
	return url
}
