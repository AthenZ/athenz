// Copyright The Athenz Authors
// Licensed under the terms of the Apache version 2.0 license. See LICENSE file for terms.

package zpu

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/AthenZ/athenz/libs/go/athenz-common/log"
	"github.com/AthenZ/athenz/utils/zpe-updater/metrics"
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

var lastZtsJwkFetchTime = time.Time{}

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

	ztsClient, err := getZTSClient(config)
	if err != nil {
		return err
	}

	failedDomains := ""
	for _, domain := range domains {
		err := GetPolicies(config, ztsClient, domain)
		if err != nil {
			success = false
			failedDomains += `"` + domain + `" `
			log.Printf("failed to get policies for domain: %v, Error:%v\n", domain, err)
		}
	}
	if !success {
		return fmt.Errorf("failed to get policies for domains: %v", failedDomains)
	}
	return nil
}

func getZTSClient(config *ZpuConfiguration) (zts.ZTSClient, error) {
	ztsURL := formatURL(config.Zts, "zts/v1")
	var ztsClient zts.ZTSClient
	if config.PrivateKeyFile != "" && config.CertFile != "" {
		ztsCli, err := athenzutils.ZtsClient(ztsURL, config.PrivateKeyFile, config.CertFile, config.CaCertFile, config.Proxy)
		if err != nil {
			return ztsClient, fmt.Errorf("failed to create Zts Client, Error:%v", err)
		}
		ztsClient = *ztsCli
	} else if config.PrivateKeyFile == "" && config.CertFile != "" {
		return ztsClient, errors.New("both private key and cert file are required, missing private key file")
	} else if config.PrivateKeyFile != "" && config.CertFile == "" {
		return ztsClient, errors.New("both private key and cert file are required, missing certificate file")
	} else {
		ztsClient = zts.NewClient(ztsURL, nil)
	}
	return ztsClient, nil
}

func GetPolicies(config *ZpuConfiguration, ztsClient zts.ZTSClient, domain string) error {
	if config.JWSPolicySupport {
		return GetJWSPolicies(config, ztsClient, domain)
	} else {
		return GetSignedPolicies(config, ztsClient, domain)
	}
}

func GetJWSPolicies(config *ZpuConfiguration, ztsClient zts.ZTSClient, domain string) error {
	log.Printf("Getting policies for domain: %v\n", domain)
	etag := GetEtagForExistingPolicy(config, ztsClient, domain)
	signedPolicyRequest := zts.SignedPolicyRequest{
		PolicyVersions:       config.PolicyVersions,
		SignatureP1363Format: true,
	}
	data, _, err := ztsClient.PostSignedPolicyRequest(zts.DomainName(domain), &signedPolicyRequest, etag)
	if err != nil {
		return fmt.Errorf("failed to get domain jws policy data for domain: %v, Error:%v", domain, err)
	}

	if data == nil {
		if etag != "" {
			log.Printf("Policies not updated since last fetch for domain: %v\n", domain)
			return nil
		}
		return fmt.Errorf("empty policies data returned for domain: %v", domain)
	}
	// validate data using zts public key and signature
	bytes, err := ValidateJWSPolicies(config, ztsClient, data)
	if err != nil {
		return fmt.Errorf("failed to validate policy data for domain: %v, Error: %v", domain, err)
	}
	err = WritePolicies(config, bytes, domain)
	if err != nil {
		return fmt.Errorf("unable to write Policies for domain:\"%v\" to file, Error:%v", domain, err)
	}
	log.Printf("Policies for domain: %v successfully written\n", domain)
	return nil
}

func GetSignedPolicies(config *ZpuConfiguration, ztsClient zts.ZTSClient, domain string) error {
	log.Printf("Getting policies for domain: %v\n", domain)
	etag := GetEtagForExistingPolicy(config, ztsClient, domain)
	data, _, err := ztsClient.GetDomainSignedPolicyData(zts.DomainName(domain), etag)
	if err != nil {
		return fmt.Errorf("failed to get domain signed policy data for domain: %v, Error:%v", domain, err)
	}

	if data == nil {
		if etag != "" {
			log.Printf("Policies not updated since last fetch for domain: %v\n", domain)
			return nil
		}
		return fmt.Errorf("empty policies data returned for domain: %v", domain)
	}
	// validate data using zts public key and signature
	bytes, err := ValidateSignedPolicies(config, ztsClient, data)
	if err != nil {
		return fmt.Errorf("failed to validate policy data for domain: %v, Error: %v", domain, err)
	}
	err = WritePolicies(config, bytes, domain)
	if err != nil {
		return fmt.Errorf("unable to write Policies for domain:\"%v\" to file, Error:%v", domain, err)
	}
	log.Printf("Policies for domain: %v successfully written\n", domain)
	return nil
}

func GetSignedPolicyDataFromJson(config *ZpuConfiguration, ztsClient zts.ZTSClient, readFile *os.File) (*zts.SignedPolicyData, error) {
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

func GetSignedPolicyDataFromJws(config *ZpuConfiguration, ztsClient zts.ZTSClient, readFile *os.File) (*zts.SignedPolicyData, error) {
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

func GetEtagForExistingPolicy(config *ZpuConfiguration, ztsClient zts.ZTSClient, domain string) string {
	var etag string
	var err error
	policyFile := fmt.Sprintf("%s/%s.pol", config.PolicyFileDir, domain)

	// First check if we're asked to force refresh the policy
	if config.ForceRefresh {
		return ""
	}

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
		// first, reload athenz jwks from disk and try again
		log.Debugf("key id: [%s] does not exist in public keys map, reload athenz jwks from disk", ztsKeyID)
		config.loadAthenzJwks()
		ztsPublicKey = config.GetZtsPublicKey(ztsKeyID)

		if ztsPublicKey != "" {
			return ztsPublicKey, nil
		}
		if canFetchLatestJwksFromZts(config) {
			//  fetch all zts jwk keys and update config
			log.Debugf("key id: [%s] does not exist in also after reloading athenz jwks from disk, about to fetch directly from zts", ztsKeyID)
			rfc := true
			ztsJwkList, err := ztsClient.GetJWKList(&rfc)
			if err != nil {
				return "", fmt.Errorf("unable to get the zts jwk keys, err: %v", err)
			}
			config.updateZtsJwks(ztsJwkList)
			lastZtsJwkFetchTime = time.Now()

			// after fetching all jwks from zts, try again
			ztsPublicKey = config.GetZtsPublicKey(ztsKeyID)
		} else {
			log.Printf("not allowed to fetch jwks from zts, last fetch time: %v", lastZtsJwkFetchTime)
		}
		if ztsPublicKey == "" {
			return "", fmt.Errorf("unable to get the zts public key with id:\"%v\" to verify data", ztsKeyID)
		}
	}
	return ztsPublicKey, nil
}

func canFetchLatestJwksFromZts(config *ZpuConfiguration) bool {
	minutesBetweenZtsCalls := 30
	if config.MinutesBetweenZtsCalls > 0 {
		minutesBetweenZtsCalls = config.MinutesBetweenZtsCalls
	}
	now := time.Now()
	minDiff := int(now.Sub(lastZtsJwkFetchTime).Minutes())
	return minDiff > minutesBetweenZtsCalls
}

func getZmsPublicKey(config *ZpuConfiguration, ztsClient zts.ZTSClient, zmsKeyID string) (string, error) {
	zmsPublicKey := config.GetZmsPublicKey(zmsKeyID)
	if zmsPublicKey == "" {

		// first, reload athenz jwks from disk and try again
		log.Debugf("key id: [%s] does not exist in public keys map, reload athenz jwks from disk", zmsKeyID)
		config.loadAthenzJwks()
		zmsPublicKey = config.GetZmsPublicKey(zmsKeyID)

		// if we didn't succeed, retrieve it from zts
		if zmsPublicKey == "" {
			log.Debugf("key id: [%s] does not exist in also after reloading athenz jwks from disk, about to fetch directly from zts", zmsKeyID)
			key, err := ztsClient.GetPublicKeyEntry("sys.auth", "zms", zmsKeyID)
			if err != nil {
				return "", fmt.Errorf("unable to get the Zms public key with id:\"%v\" to verify data", zmsKeyID)
			}
			decodedKey, err := new(zmssvctoken.YBase64).DecodeString(key.Key)
			if err != nil {
				return "", fmt.Errorf("unable to decode the Zms public key with id:\"%v\" to verify data", zmsKeyID)
			}
			zmsPublicKey = string(decodedKey)
		}
	}
	return zmsPublicKey, nil
}

func isExpired(config *ZpuConfiguration, expires *rdl.Timestamp) bool {
	if config.ExpiredFunc != nil {
		return config.ExpiredFunc(*expires)
	} else {
		return expired(*expires, 0)
	}
}

func ValidateSignedPolicies(config *ZpuConfiguration, ztsClient zts.ZTSClient, data *zts.DomainSignedPolicyData) ([]byte, error) {
	expires := data.SignedPolicyData.Expires
	if isExpired(config, &expires) {
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
		zmsPublicKey, err := getZmsPublicKey(config, ztsClient, zmsKeyID)
		if err != nil {
			return nil, err
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

	publicKey, err := athenzutils.LoadPublicKey([]byte(ztsPublicKey))
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
func WritePolicies(config *ZpuConfiguration, bytes []byte, domain string) error {
	tempPolicyFileDir := config.TempPolicyFileDir
	if tempPolicyFileDir == "" || bytes == nil {
		return errors.New("empty parameters are not valid arguments")
	}
	policyFile := fmt.Sprintf("%s/%s.pol", config.PolicyFileDir, domain)
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
	err = os.WriteFile(tempPolicyFile, bytes, 0755)
	if err != nil {
		return err
	}
	return os.Rename(tempPolicyFile, policyFile)
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

func PolicyView(config *ZpuConfiguration, domainName string) error {
	if config == nil {
		return errors.New("nil configuration")
	}

	ztsClient, err := getZTSClient(config)
	if err != nil {
		return err
	}

	policyFile := fmt.Sprintf("%s/%s.pol", config.PolicyFileDir, domainName)

	// If Policies file is not found, return empty etag the first time.
	// Otherwise, load the file contents, if data has expired return empty etag,
	// else construct etag from modified field in JSON.
	exists := util.Exists(policyFile)
	if !exists {
		return errors.New("domain policy file does not exist")
	}

	readFile, err := os.OpenFile(policyFile, os.O_RDONLY, 0444)
	if err != nil {
		return err
	}
	defer readFile.Close()

	var signedPolicyData *zts.SignedPolicyData
	if config.JWSPolicySupport {
		signedPolicyData, err = GetSignedPolicyDataFromJws(config, ztsClient, readFile)
	} else {
		signedPolicyData, err = GetSignedPolicyDataFromJson(config, ztsClient, readFile)
	}
	if err != nil {
		return errors.New("unable to get domain policy data")
	}
	jsonPolicyBytes, err := json.MarshalIndent(signedPolicyData, "", "  ")
	if err != nil {
		return err
	}
	fmt.Print(string(jsonPolicyBytes))
	return nil
}

func CheckState(config *ZpuConfiguration) ([]metrics.PolicyStatus, []error) {
	var errorsMessages []error
	if config == nil {
		errorsMessages = append(errorsMessages, errors.New("nil configuration"))
		return nil, errorsMessages
	}
	if config.DomainList == "" {
		errorsMessages = append(errorsMessages, errors.New("no domain list to process from configuration"))
		return nil, errorsMessages
	}
	if config.Zts == "" {
		errorsMessages = append(errorsMessages, errors.New("empty Zts url in configuration"))
		return nil, errorsMessages
	}

	ztsClient, err := getZTSClient(config)
	if err != nil {
		errorsMessages = append(errorsMessages, errors.New("failed to generate Zts client: "+err.Error()))
		return nil, errorsMessages
	}
	domains := strings.Split(config.DomainList, ",")

	var checkedPolicis []metrics.PolicyStatus
	for _, domainName := range domains {

		checkedPolicy := metrics.PolicyStatus{
			DomainName: domainName,
			FileExists: false,
		}

		policyFile := fmt.Sprintf("%s/%s.pol", config.PolicyFileDir, domainName)
		exists := util.Exists(policyFile)
		if !exists {
			errorsMessages = append(errorsMessages, errors.New("policy file doesn't exist for domain "+domainName))
			checkedPolicis = append(checkedPolicis, checkedPolicy)
			continue
		}
		readFile, err := os.OpenFile(policyFile, os.O_RDONLY, 0444)
		if err != nil {
			errorsMessages = append(errorsMessages, errors.New("failed to read policy file for domain "+domainName+": "+err.Error()))
			checkedPolicis = append(checkedPolicis, checkedPolicy)
			continue
		}
		checkedPolicy.FileExists = true
		defer readFile.Close()

		var signedPolicyData *zts.SignedPolicyData
		if config.JWSPolicySupport {
			signedPolicyData, err = GetSignedPolicyDataFromJws(config, ztsClient, readFile)
		} else {
			signedPolicyData, err = GetSignedPolicyDataFromJson(config, ztsClient, readFile)
		}
		if err != nil {
			errorsMessages = append(errorsMessages, errors.New("failed to validate policy file signature for domain "+domainName+": "+err.Error()))
			checkedPolicy.ValidSignature = false
			checkedPolicis = append(checkedPolicis, checkedPolicy)
			continue
		}
		checkedPolicy.ValidSignature = true

		expiryCheck := rdl.NewTimestamp(signedPolicyData.Expires.Time.Add(-1 * time.Duration(int64(config.ExpiryCheck)) * time.Second))
		checkedPolicy.Expiry = expiryCheck.Sub(rdl.TimestampNow().Time)
		if checkedPolicy.Expiry.Milliseconds() <= 0 {
			errorsMessages = append(errorsMessages, errors.New("policy file expired for domain "+domainName))
		}
		checkedPolicis = append(checkedPolicis, checkedPolicy)
	}
	return checkedPolicis, errorsMessages
}
