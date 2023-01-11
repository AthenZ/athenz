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

package util

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"time"

	"github.com/ardielle/ardielle-go/rdl"

	"github.com/AthenZ/athenz/clients/go/zts"
	"github.com/AthenZ/athenz/libs/go/sia/futil"
)

type CertReqDetails struct {
	CommonName string
	Country    string
	Province   string
	Locality   string
	Org        string
	OrgUnit    string
	IpList     []string
	HostList   []string
	EmailList  []string
	URIs       []*url.URL
}

// SSHKeyReq - congruent with certsign-rdl/certsign.rdl
type SSHKeyReq struct {
	Principals []string `json:"principals"`
	Ips        []string `json:"ips,omitempty" rdl:"optional"`
	Pubkey     string   `json:"pubkey"`
	Reqip      string   `json:"reqip"`
	Requser    string   `json:"requser"`
	Certtype   string   `json:"certtype"`
	Transid    string   `json:"transid"`
	Command    string   `json:"command,omitempty" rdl:"optional"`
}

const JwkConfFile = "athenz.conf"

func SplitRoleName(roleName string) (string, string, error) {
	tmp := strings.Split(roleName, ":role.")
	if len(tmp) != 2 {
		return "", "", fmt.Errorf("invalid role name: '%s', expected format {domain}:role.{role}", roleName)
	}
	if len(tmp[0]) == 0 || len(tmp[1]) == 0 {
		return "", "", fmt.Errorf("invalid role name: '%s', expected format {domain}:role.{role}", roleName)
	}
	return tmp[0], tmp[1], nil
}

func SplitDomain(domain string) (string, string) {
	i := strings.LastIndex(domain, ".")
	if i < 0 {
		return "", ""
	}
	return domain[0:i], domain[i+1:]
}

func ZtsHostName(identity, ztsAwsDomain string) string {
	domain, service := SplitDomain(identity)
	hyphenDomain := strings.Replace(domain, ".", "-", -1)
	return fmt.Sprintf("%s.%s.%s", service, hyphenDomain, ztsAwsDomain)
}

func ZtsClient(ztsUrl, ztsServerName string, keyFile, certFile, caCertFile string) (*zts.ZTSClient, error) {
	log.Printf("ZTS Client: url: %s\n", ztsUrl)
	if strings.HasPrefix(ztsUrl, "http://") {
		client := zts.NewClient(ztsUrl, &http.Transport{Proxy: http.ProxyFromEnvironment})
		return &client, nil
	} else {
		if keyFile != "" {
			log.Printf("ZTS Client: private key file: %s\n", keyFile)
		}
		if certFile != "" {
			log.Printf("ZTS Client: certificate file: %s\n", certFile)
		}
		if caCertFile != "" {
			log.Printf("ZTS Client: CA certificate file: %s\n", caCertFile)
		}
		config, err := tlsConfiguration(keyFile, certFile, caCertFile)
		if err != nil {
			return nil, err
		}
		if ztsServerName != "" {
			log.Printf("ZTS Client: Server Name: %s\n", ztsServerName)
			config.ServerName = ztsServerName
		}
		tr := &http.Transport{
			TLSClientConfig: config,
			Proxy:           http.ProxyFromEnvironment,
		}
		client := zts.NewClient(ztsUrl, tr)
		return &client, nil
	}
}

func tlsConfiguration(keyfile, certfile, cafile string) (*tls.Config, error) {
	var capem []byte
	var keypem []byte
	var certpem []byte
	var err error
	if cafile != "" {
		capem, err = os.ReadFile(cafile)
		if err != nil {
			return nil, err
		}
	}
	if keyfile != "" && certfile != "" {
		keypem, err = os.ReadFile(keyfile)
		if err != nil {
			return nil, err
		}
		certpem, err = os.ReadFile(certfile)
		if err != nil {
			return nil, err
		}
	}
	return tlsConfigurationFromPEM(keypem, certpem, capem)
}

func tlsConfigurationFromPEM(keypem, certpem, capem []byte) (*tls.Config, error) {
	config := &tls.Config{}

	if capem != nil {
		certPool := x509.NewCertPool()
		if !certPool.AppendCertsFromPEM(capem) {
			return nil, fmt.Errorf("failed to append certs to pool")
		}
		config.RootCAs = certPool
	}

	if certpem != nil && keypem != nil {
		mycert, err := tls.X509KeyPair(certpem, keypem)
		if err != nil {
			return nil, err
		}
		config.Certificates = make([]tls.Certificate, 1)
		config.Certificates[0] = mycert
	}
	return config, nil
}

func GenerateX509CSR(key *rsa.PrivateKey, csrDetails CertReqDetails) (string, error) {
	//note: RFC 6125 states that if the SAN (Subject Alternative Name)
	//exists, it is used, not the CN. So, we will always put the Athenz
	//name in the CN (it is *not* a DNS domain name), and put the host
	//name into the SAN.
	subj := pkix.Name{CommonName: csrDetails.CommonName}
	if csrDetails.Country != "" {
		subj.Country = []string{csrDetails.Country}
	}
	if csrDetails.Province != "" {
		subj.Province = []string{csrDetails.Province}
	}
	if csrDetails.Locality != "" {
		subj.Locality = []string{csrDetails.Locality}
	}
	if csrDetails.Org != "" {
		subj.Organization = []string{csrDetails.Org}
	}
	if csrDetails.OrgUnit != "" {
		subj.OrganizationalUnit = []string{csrDetails.OrgUnit}
	}
	template := x509.CertificateRequest{
		Subject:            subj,
		SignatureAlgorithm: x509.SHA256WithRSA,
	}
	if len(csrDetails.IpList) != 0 {
		template.IPAddresses = make([]net.IP, 0)
		for _, ip := range csrDetails.IpList {
			template.IPAddresses = append(template.IPAddresses, net.ParseIP(ip))
		}
	}
	template.DNSNames = csrDetails.HostList
	template.EmailAddresses = csrDetails.EmailList
	template.URIs = csrDetails.URIs
	csr, err := x509.CreateCertificateRequest(rand.Reader, &template, key)
	if err != nil {
		return "", fmt.Errorf("cannot create CSR: %v", err)
	}
	block := &pem.Block{
		Type:  "CERTIFICATE REQUEST",
		Bytes: csr,
	}
	var buf bytes.Buffer
	err = pem.Encode(&buf, block)
	if err != nil {
		return "", fmt.Errorf("cannot encode CSR to PEM: %v", err)
	}
	return buf.String(), nil
}

func GenerateKeyPair(bits int) (*rsa.PrivateKey, error) {
	log.Println("Generating RSA 2048 bit private key...")
	return rsa.GenerateKey(rand.Reader, bits)
}

func GetPEMBlock(privateKey *rsa.PrivateKey) []byte {
	block := &pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(privateKey),
	}
	return pem.EncodeToMemory(block)
}

func PrivatePem(privateKey *rsa.PrivateKey) string {
	block := GetPEMBlock(privateKey)
	return string(block)
}

func FileExists(path string) bool {
	if _, err := os.Stat(path); os.IsNotExist(err) {
		return false
	}
	return true
}

func PrivateKeyFromFile(filename string) (*rsa.PrivateKey, error) {
	log.Printf("Reading private key from %s...\n", filename)
	pemBytes, err := os.ReadFile(filename)
	if err != nil {
		return nil, err
	}
	block, _ := pem.Decode(pemBytes)
	if block == nil {
		return nil, fmt.Errorf("no PEM block found")
	}
	return x509.ParsePKCS1PrivateKey(block.Bytes)
}

func GenerateSvcCertCSR(key *rsa.PrivateKey, countryName, orgName, domain, service, commonName, instanceId, provider string, ztsDomains []string, wildCardDnsName, instanceIdSanDNS bool) (string, error) {

	log.Println("Generating X.509 Service Certificate CSR...")

	//note: RFC 6125 states that if the SAN (Subject Alternative Name) exists,
	//it is used, not the CN. So, we will always put the Athenz name in the CN
	//(it is *not* a DNS domain name), and put the host name into the SAN.

	var csrDetails CertReqDetails
	csrDetails.CommonName = commonName
	csrDetails.Country = countryName
	csrDetails.Org = orgName
	csrDetails.OrgUnit = provider

	hyphenDomain := strings.Replace(domain, ".", "-", -1)
	csrDetails.HostList = []string{}
	for _, ztsDomain := range ztsDomains {
		host := fmt.Sprintf("%s.%s.%s", service, hyphenDomain, ztsDomain)
		csrDetails.HostList = append(csrDetails.HostList, host)
		if wildCardDnsName {
			host = fmt.Sprintf("*.%s.%s.%s", service, hyphenDomain, ztsDomain)
			csrDetails.HostList = append(csrDetails.HostList, host)
		}
	}
	// for backward compatibility a sanDNS entry with instance id in the hostname
	if instanceIdSanDNS {
		instanceIdHost := fmt.Sprintf("%s.instanceid.athenz.%s", instanceId, ztsDomains[0])
		csrDetails.HostList = append(csrDetails.HostList, instanceIdHost)
	}

	csrDetails.URIs = []*url.URL{}
	// spiffe uri must always be the first one
	spiffeUri := fmt.Sprintf("spiffe://%s/sa/%s", domain, service)
	csrDetails.URIs = AppendUri(csrDetails.URIs, spiffeUri)

	// athenz://instanceid/<provider>/<instance-id>
	instanceIdUri := fmt.Sprintf("athenz://instanceid/%s/%s", provider, instanceId)
	csrDetails.URIs = AppendUri(csrDetails.URIs, instanceIdUri)

	return GenerateX509CSR(key, csrDetails)
}

func GenerateRoleCertCSR(key *rsa.PrivateKey, countryName, orgName, domain, service, roleName, instanceId, provider, emailDomain string) (string, error) {

	log.Println("Generating Role Certificate CSR...")

	// for role certificates we're putting the role name in the CN
	var csrDetails CertReqDetails
	csrDetails.CommonName = roleName
	csrDetails.Country = countryName
	csrDetails.Org = orgName
	csrDetails.OrgUnit = provider

	csrDetails.URIs = []*url.URL{}
	// spiffe uri must always be the first one
	domainNameRequest, roleNameRequest, err := SplitRoleName(roleName)
	if err != nil {
		return "", err
	}
	spiffeUri := fmt.Sprintf("spiffe://%s/ra/%s", domainNameRequest, roleNameRequest)
	csrDetails.URIs = AppendUri(csrDetails.URIs, spiffeUri)

	// athenz://instanceid/<provider>/<instance-id>
	instanceIdUri := fmt.Sprintf("athenz://instanceid/%s/%s", provider, instanceId)
	csrDetails.URIs = AppendUri(csrDetails.URIs, instanceIdUri)

	// include an uri for athenz principal
	principalUri := fmt.Sprintf("athenz://principal/%s.%s", domain, service)
	csrDetails.URIs = AppendUri(csrDetails.URIs, principalUri)

	// for backward compatibility an email with the principal as the local part
	if emailDomain != "" {
		email := fmt.Sprintf("%s.%s@%s", domain, service, emailDomain)
		csrDetails.EmailList = []string{email}
	}

	return GenerateX509CSR(key, csrDetails)
}

func GenerateSSHHostCSR(sshPubKeyFile string, domain, service, ip string, ztsAwsDomains []string) (string, error) {

	log.Println("Generating SSH Host Certificate CSR...")

	pubkey, err := os.ReadFile(sshPubKeyFile)
	if err != nil {
		log.Printf("Skipping SSH CSR Request - Unable to read SSH Public Key File: %v\n", err)
		return "", nil
	}
	identity := domain + "." + service
	transId := fmt.Sprintf("%x", time.Now().Unix())
	hyphenDomain := strings.Replace(domain, ".", "-", -1)
	principals := []string{}
	for _, ztsDomain := range ztsAwsDomains {
		host := fmt.Sprintf("%s.%s.%s", service, hyphenDomain, ztsDomain)
		principals = append(principals, host)
	}
	req := &SSHKeyReq{
		Principals: principals,
		Pubkey:     string(pubkey),
		Reqip:      ip,
		Requser:    identity,
		Certtype:   "host",
		Transid:    transId,
	}
	csr, err := json.Marshal(req)
	if err != nil {
		return "", err
	}
	return string(csr), err
}

func AppendUri(uriList []*url.URL, uriValue string) []*url.URL {
	uri, err := url.Parse(uriValue)
	if err == nil {
		uriList = append(uriList, uri)
	}
	return uriList
}

func GetRoleCertFileName(certDir, fileName, certName string) string {
	switch {
	case fileName == "":
		return fmt.Sprintf("%s/%s.cert.pem", certDir, certName)
	case fileName[0] == '/':
		return fileName
	default:
		return fmt.Sprintf("%s/%s", certDir, fileName)
	}
}

func GetSvcCertFileName(certDir, fileName, domain, service string) string {
	switch {
	case fileName == "":
		return fmt.Sprintf("%s/%s.%s.cert.pem", certDir, domain, service)
	case fileName[0] == '/':
		return fileName
	default:
		return fmt.Sprintf("%s/%s", certDir, fileName)
	}
}

func ExtractServiceName(arn, comp string) (string, string, error) {
	//expected format "arn:aws:iam::<account-id><comp>{domain}.{service}-service"
	//<comp> could be :instance-profile/ or :role/ depending on container
	if !strings.HasSuffix(arn, "-service") {
		return "", "", fmt.Errorf("cannot determine role from arn: %s", arn)
	}
	idx := strings.Index(arn, comp)
	if idx < 0 {
		return "", "", fmt.Errorf("cannot determine role from arn: %s", arn)
	}
	profile := arn[idx+len(comp) : len(arn)-8]
	idx = strings.LastIndex(profile, ".")
	if idx < 0 {
		return "", "", fmt.Errorf("cannot determine domain/service from arn: %s", arn)
	}
	return profile[:idx], profile[idx+1:], nil
}

func PrivateKey(keyFile string, rotateKey bool) (*rsa.PrivateKey, error) {
	if rotateKey == true || !FileExists(keyFile) {
		key, err := GenerateKeyPair(2048)
		if err != nil {
			return nil, fmt.Errorf("cannot generate private key err: %v", err)
		}
		return key, err
	}
	key, err := PrivateKeyFromFile(keyFile)
	if err != nil {
		log.Printf("Unable to read private key from %s, err: %v\n", keyFile, err)
		return nil, err
	}
	return key, err
}

func EnsureBackUpDir(backUpDir string) error {
	if !FileExists(backUpDir) {
		err := os.MkdirAll(backUpDir, 0755)
		if err != nil {
			return err
		}
	}
	return nil
}

func Copy(sourceFile, destFile string, perm os.FileMode) error {
	sourceBytes, err := os.ReadFile(sourceFile)
	if err != nil {
		return err
	}
	if FileExists(destFile) {
		if err := os.Remove(destFile); err != nil {
			log.Printf("Unable to delete file %s\n", destFile)
		}
	}
	return os.WriteFile(destFile, sourceBytes, perm)
}

func CopyCertKeyFile(srcKey, destKey, srcCert, destCert string, keyPerm int) error {
	if err := Copy(srcCert, destCert, 0444); err != nil {
		return err
	}
	return Copy(srcKey, destKey, os.FileMode(keyPerm))
}

func UpdateKey(keyFile string, uid, gid int) {
	if uid != 0 || gid != 0 {
		// Change the ownership on keyfile
		log.Printf("Changing file %s ownership to %d:%d...\n", keyFile, uid, gid)
		err := os.Chown(keyFile, uid, gid)
		if err != nil {
			log.Fatalf("Cannot chown file %s to %d:%d, err: %v", keyFile, uid, gid, err)
		}
	}
	if gid != 0 {
		log.Printf("Changing file %s permission to 0440\n", keyFile)
		err := os.Chmod(keyFile, 0440)
		if err != nil {
			log.Fatalf("Cannot chmod file %s to 0440, err: %v", keyFile, err)
		}
	}
}

func ParseAssumedRoleArn(roleArn, serviceSuffix, accessProfileSeparator string) (string, string, string, string, error) {
	//arn:aws:sts::123456789012:assumed-role/athenz.zts-service@sia-profile/i-0662a0226f2d9dc2b
	if !strings.HasPrefix(roleArn, "arn:aws:sts:") {
		return "", "", "", "", fmt.Errorf("unable to parse role arn (prefix): %s", roleArn)
	}
	arn := strings.Split(roleArn, ":")
	// make sure we have correct number of components
	if len(arn) < 6 {
		return "", "", "", "", fmt.Errorf("unable to parse role arn (number of components): %s", roleArn)
	}
	// our role part as 3 components separated by /
	roleComps := strings.Split(arn[5], "/")
	if len(roleComps) != 3 {
		return "", "", "", "", fmt.Errorf("unable to parse role arn (role components): %s", roleArn)
	}
	// the first component must be assumed-role
	if roleComps[0] != "assumed-role" {
		return "", "", "", "", fmt.Errorf("unable to parse role arn (assumed-role): %s", roleArn)
	}
	// second component is our athenz service name with the requested service suffix
	// if the service suffix is empty then we don't need any parsing of the requested
	// domain/service values, and we'll just parse the values as is
	var domain, service, profile string
	if serviceSuffix == "" {
		roleName := roleComps[1]
		if accessProfileSeparator != "" && strings.Contains(roleName, accessProfileSeparator) {
			roleData := strings.Split(roleName, accessProfileSeparator)
			profile = roleData[1]
			roleName = roleData[0]
		}
		idx := strings.LastIndex(roleName, ".")
		if idx > 0 {
			domain = roleName[:idx]
			service = roleName[idx+1:]
		}
	} else {
		serviceData := roleComps[1]
		if accessProfileSeparator != "" && strings.Contains(roleComps[1], accessProfileSeparator) {
			roleData := strings.Split(roleComps[1], accessProfileSeparator)
			profile = roleData[1]
			serviceData = roleData[0]
		}
		if !strings.HasSuffix(serviceData, serviceSuffix) {
			return "", "", "", "", fmt.Errorf("service name does not have '%s' suffix: %s", serviceSuffix, roleArn)
		}
		roleName := serviceData[0 : len(serviceData)-len(serviceSuffix)]
		idx := strings.LastIndex(roleName, ".")
		if idx < 0 {
			return "", "", "", "", fmt.Errorf("cannot determine domain/service from arn: %s", roleArn)
		}
		domain = roleName[:idx]
		service = roleName[idx+1:]
	}
	account := arn[4]
	return account, domain, service, profile, nil
}

func ParseTaskArn(taskArn string) (string, string, string, error) {
	// fargate task arn has the following format (old and new):
	// arn:aws:ecs:us-west-2:012345678910:task/9781c248-0edd-4cdb-9a93-f63cb662a5d3
	// arn:aws:ecs:us-west-2:012345678910:task/cluster-name/9781c248-0edd-4cdb-9a93-f63cb662a5d3
	if !strings.HasPrefix(taskArn, "arn:aws:ecs:") {
		return "", "", "", fmt.Errorf("unable to parse task arn (ecs prefix error): %s", taskArn)
	}
	arn := strings.Split(taskArn, ":")
	if len(arn) < 6 {
		return "", "", "", fmt.Errorf("unable to parse task arn (number of components): %s", taskArn)
	}
	region := arn[3]
	account := arn[4]
	taskComps := strings.Split(arn[5], "/")
	if taskComps[0] != "task" {
		return "", "", "", fmt.Errorf("unable to parse task arn (task prefix): %s", taskArn)
	}
	var taskId string
	lenComps := len(taskComps)
	if lenComps == 2 || lenComps == 3 {
		taskId = taskComps[lenComps-1]
	} else {
		return "", "", "", fmt.Errorf("unable to parse task arn (task prefix): %s", taskArn)
	}
	return account, taskId, region, nil
}

func ParseRoleArn(roleArn, rolePrefix, roleSuffix, profileSeparator string) (string, string, string, string, error) {
	//arn:aws:iam::123456789012:role/athenz.zts
	//arn:aws:iam::123456789012:instance-profile/athenz.zts
	//arn:aws:iam::123456789012:instance-profile/athenz.zts@access-profile

	if !strings.HasPrefix(roleArn, "arn:aws:iam:") {
		return "", "", "", "", fmt.Errorf("unable to parse role arn (prefix): %s", roleArn)
	}
	arn := strings.Split(roleArn, ":")
	// make sure we have correct number of components
	if len(arn) != 6 {
		return "", "", "", "", fmt.Errorf("unable to parse role arn (number of components): %s", roleArn)
	}
	// our role part must start with role/
	if !strings.HasPrefix(arn[5], rolePrefix) {
		return "", "", "", "", fmt.Errorf("role name does not have '%s' prefix: %s", rolePrefix, roleArn)
	}

	roleName := arn[5][len(rolePrefix):]
	profile := ""
	serviceRole := roleName

	if profileSeparator != "" && strings.Contains(arn[5], profileSeparator) {
		data := strings.Split(roleName, profileSeparator)

		serviceRole = data[0]
		profile = data[1]

		if profile == "" {
			return "", "", "", "", fmt.Errorf("cannot determine profile from arn: %s", roleArn)
		}
	}

	if roleSuffix != "" && !strings.HasSuffix(serviceRole, roleSuffix) {
		return "", "", "", "", fmt.Errorf("role name does not have '%s' suffix: %s", roleSuffix, roleArn)
	}

	// get service details without suffix
	serviceData := serviceRole[:len(serviceRole)-len(roleSuffix)]
	idx := strings.LastIndex(serviceData, ".")
	if idx < 0 {
		return "", "", "", "", fmt.Errorf("cannot determine domain/service from arn: %s", roleArn)
	}
	domain := serviceData[:idx]
	service := serviceData[idx+1:]
	account := arn[4]
	return account, domain, service, profile, nil
}

func ParseEnvBooleanFlag(varName string) bool {
	value := os.Getenv(varName)
	return value == "true" || value == "1"
}

func ParseEnvIntFlag(varName string, defaultValue int) int {
	varStr := os.Getenv(varName)
	if varStr == "" {
		return defaultValue
	}
	value, err := strconv.Atoi(varStr)
	if err != nil {
		return defaultValue
	}
	return value
}

func ParseEnvFloatFlag(varName string, defaultValue float64) float64 {
	varStr := os.Getenv(varName)
	if varStr == "" {
		return defaultValue
	}
	value, err := strconv.ParseFloat(varStr, 64)
	if err != nil {
		return defaultValue
	}
	return value
}

func getCertKeyFileName(file, keyDir, certDir, keyPrefix, certPrefix string) (string, string) {
	if file != "" && file[0] == '/' {
		return file, fmt.Sprintf("%s/%s.key.pem", keyDir, keyPrefix)
	} else {
		return fmt.Sprintf("%s/%s.cert.pem", certDir, certPrefix), fmt.Sprintf("%s/%s.key.pem", keyDir, keyPrefix)
	}
}

func SaveCertKey(key, cert []byte, file, keyPrefix, certPrefix string, uid, gid, fileMode int, createKey, rotateKey bool, keyDir, certDir, backupDir string) error {

	certFile, keyFile := getCertKeyFileName(file, keyDir, certDir, keyPrefix, certPrefix)

	// perform validation of x509KeyPair pair match before writing to disk
	x509KeyPair, err := tls.X509KeyPair(cert, key)
	if err != nil {
		return fmt.Errorf("x509KeyPair and key for: %s do not match, error: %v", keyPrefix, err)
	}
	_, err = x509.ParseCertificate(x509KeyPair.Certificate[0])
	if err != nil {
		return fmt.Errorf("x509KeyPair and key for: %s unable to parse cert, error: %v", keyPrefix, err)
	}

	backUpKeyFile := fmt.Sprintf("%s/%s.key.pem", backupDir, keyPrefix)
	backUpCertFile := fmt.Sprintf("%s/%s.cert.pem", backupDir, certPrefix)

	if rotateKey {
		err = EnsureBackUpDir(backupDir)
		if err != nil {
			return err
		}
		// taking back up of key and cert
		log.Printf("taking back up of cert: %s to %s and key: %s to %s\n", certFile, backUpCertFile, keyFile, backUpKeyFile)
		err = CopyCertKeyFile(keyFile, backUpKeyFile, certFile, backUpCertFile, 0400)
		if err != nil {
			return err
		}
		//write the new key and x509KeyPair to disk
		log.Printf("writing new key file: %s to disk\n", keyFile)
		err = UpdateFile(keyFile, key, uid, gid, os.FileMode(fileMode))
		if err != nil {
			return err
		}
	} else if createKey && !FileExists(keyFile) {
		//write the new key and x509KeyPair to disk
		log.Printf("writing new key file: %s to disk\n", keyFile)
		err = UpdateFile(keyFile, key, uid, gid, os.FileMode(fileMode))
		if err != nil {
			return err
		}
	} else if FileExists(keyFile) {
		UpdateKey(keyFile, uid, gid)
	}

	err = UpdateFile(certFile, cert, uid, gid, os.FileMode(0444))
	if err != nil {
		return err
	}

	// perform 2nd validation of x509KeyPair pair match after writing to disk
	x509KeyPair, err = tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		log.Printf("x509KeyPair: %s, key: %s do not match, error: %v\n", certFile, keyFile, err)
		err = CopyCertKeyFile(backUpKeyFile, keyFile, backUpCertFile, certFile, fileMode)
		if err != nil {
			return err
		}
	}

	_, err = x509.ParseCertificate(x509KeyPair.Certificate[0])
	if err != nil {
		log.Printf("x509KeyPair: %s, key: %s, unable to parse cert, error: %v\n", certFile, keyFile, err)
		err = CopyCertKeyFile(backUpKeyFile, keyFile, backUpCertFile, certFile, fileMode)
		if err != nil {
			return err
		}
	}

	return nil
}

func ParseServiceSpiffeUri(uri string) (string, string) {
	return parseSpiffeUri(uri, "/sa/")
}

func ParseRoleSpiffeUri(uri string) (string, string) {
	return parseSpiffeUri(uri, "/ra/")
}

func ParseCASpiffeUri(uri string) (string, string) {
	return parseSpiffeUri(uri, "/ca/")
}

func parseSpiffeUri(uri, objType string) (string, string) {
	if !strings.HasPrefix(uri, "spiffe://") {
		return "", ""
	}
	comp := uri[9:]
	idx := strings.Index(comp, objType)
	if idx == -1 {
		return "", ""
	}
	comp1 := comp[0:idx]
	comp2 := comp[idx+len(objType):]
	if comp1 == "" || comp2 == "" {
		return "", ""
	}
	return comp1, comp2
}

func Nonce() (string, error) {
	b := make([]byte, 4)
	_, err := rand.Read(b)
	if err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

func ExecIdCommand(arg string) int {
	out, err := exec.Command(GetUtilPath("id"), arg).Output()
	if err != nil {
		log.Fatalf("Cannot exec 'id %s': %v", arg, err)
	}
	s := strings.Trim(string(out), "\n\r ")
	id, err := strconv.Atoi(s)
	if err != nil {
		log.Fatalf("Unexpected UID/GID format in user record: %s", string(out))
	}
	return id
}

func EnvOrDefault(name string, defaultValue string) string {
	v := os.Getenv(name)
	if v == "" {
		return defaultValue
	}
	return v
}

func WriteAthenzJWKFile(athenzJwk *zts.AthenzJWKConfig, siaDir string, uid int, gid int) error {
	confJson, err := json.MarshalIndent(athenzJwk, "", "  ")
	if err != nil {
		return err
	}
	jwkConfFile := fmt.Sprintf("%s/"+JwkConfFile, siaDir)
	err = UpdateFile(jwkConfFile, confJson, uid, gid, 0444)
	if err != nil {
		return err
	}
	return nil
}

func GetAthenzJwkConfModTime(siaDir string) rdl.Timestamp {
	jwkConfFile := fmt.Sprintf("%s/"+JwkConfFile, siaDir)
	jwkConfObj := zts.AthenzJWKConfig{}
	err := ReadAthenzJwkConf(jwkConfFile, &jwkConfObj)
	if err != nil {
		log.Print(err.Error())
		return rdl.TimestampFromEpoch(0)
	}
	return *jwkConfObj.Modified
}

func ReadAthenzJwkConf(jwkConfFile string, jwkConfObj *zts.AthenzJWKConfig) error {
	jwkConfStr, err := os.ReadFile(jwkConfFile)
	if err != nil {
		return fmt.Errorf("athenz.conf does not exist in [%s], err: %v", jwkConfFile, err)
	}
	err = json.Unmarshal(jwkConfStr, jwkConfObj)
	if err != nil {
		return fmt.Errorf("failed to unmarshal athenz.conf: [%s], err: %v", jwkConfFile, err)
	}
	return nil
}

func GetUtilPath(command string) string {
	path := "/usr/bin/" + command
	if futil.Exists(path) {
		return path
	}
	path = "/bin/" + command
	if futil.Exists(path) {
		return path
	} else {
		return command
	}
}
