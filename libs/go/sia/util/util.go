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
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/AthenZ/athenz/clients/go/zts"
	"github.com/AthenZ/athenz/libs/go/sia/futil"
	"github.com/AthenZ/athenz/libs/go/tls/config"
	"github.com/ardielle/ardielle-go/rdl"
	"github.com/google/shlex"
)

// CertReqDetails - struct with details to generate a certificate CSR
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

// SvcCertReqOptions - struct with details to generate a service certificate CSR
type SvcCertReqOptions struct {
	Country           string
	OrgName           string
	Domain            string
	Service           string
	CommonName        string
	Account           string
	InstanceName      string
	InstanceId        string
	Provider          string
	Hostname          string
	SpiffeTrustDomain string
	SpiffeNamespace   string
	AddlSanDNSEntries []string
	ZtsDomains        []string
	WildCardDnsName   bool
	InstanceIdSanDNS  bool
}

// RoleCertReqOptions - struct with details to generate a role certificate CSR
type RoleCertReqOptions struct {
	Country           string
	OrgName           string
	Domain            string
	Service           string
	RoleName          string
	InstanceId        string
	Provider          string
	EmailDomain       string
	SpiffeTrustDomain string
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

func SanDNSHostname(domain, service, cloudDomain string) string {
	hyphenDomain := strings.Replace(domain, ".", "-", -1)
	return fmt.Sprintf("%s.%s.%s", service, hyphenDomain, cloudDomain)
}

func SanURIInstanceId(athenzProvider, instanceId string) string {
	return "athenz://instanceid/" + athenzProvider + "/" + instanceId
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
		tlsConfig, err := tlsConfiguration(keyFile, certFile, caCertFile)
		if err != nil {
			return nil, err
		}
		if ztsServerName != "" {
			log.Printf("ZTS Client: Server Name: %s\n", ztsServerName)
			tlsConfig.ServerName = ztsServerName
		}
		tr := &http.Transport{
			TLSClientConfig: tlsConfig,
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
	return config.ClientTLSConfigFromPEM(keypem, certpem, capem)
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

func ParseCertificate(certPem string) (*x509.Certificate, error) {
	// Decode the certificate from PEM format.
	x509CertificateBlock, _ := pem.Decode([]byte(certPem))
	if x509CertificateBlock == nil || x509CertificateBlock.Type != "CERTIFICATE" {
		return nil, fmt.Errorf("failed to decode PEM block containing the certificate")
	}
	return x509.ParseCertificate(x509CertificateBlock.Bytes)
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

func GenerateSvcCertCSR(key *rsa.PrivateKey, options *SvcCertReqOptions) (string, error) {

	log.Println("Generating X.509 Service Certificate CSR...")

	//note: RFC 6125 states that if the SAN (Subject Alternative Name) exists,
	//it is used, not the CN. So, we will always put the Athenz name in the CN
	//(it is *not* a DNS domain name), and put the host name into the SAN.

	var csrDetails CertReqDetails
	csrDetails.CommonName = options.CommonName
	csrDetails.Country = options.Country
	csrDetails.Org = options.OrgName
	csrDetails.OrgUnit = options.Provider

	hyphenDomain := strings.Replace(options.Domain, ".", "-", -1)
	csrDetails.HostList = []string{}
	for _, ztsDomain := range options.ZtsDomains {
		host := fmt.Sprintf("%s.%s.%s", options.Service, hyphenDomain, ztsDomain)
		csrDetails.HostList = AppendHostname(csrDetails.HostList, host)
		if options.WildCardDnsName {
			host = fmt.Sprintf("*.%s.%s.%s", options.Service, hyphenDomain, ztsDomain)
			csrDetails.HostList = AppendHostname(csrDetails.HostList, host)
		}
	}
	// include hostname if requested
	if options.Hostname != "" {
		csrDetails.HostList = AppendHostname(csrDetails.HostList, options.Hostname)
	}
	if len(options.AddlSanDNSEntries) > 0 {
		for _, host := range options.AddlSanDNSEntries {
			csrDetails.HostList = AppendHostname(csrDetails.HostList, host)
		}
	}
	// for backward compatibility a sanDNS entry with instance id in the hostname
	if options.InstanceIdSanDNS {
		instanceIdHost := fmt.Sprintf("%s.instanceid.athenz.%s", options.InstanceId, options.ZtsDomains[0])
		csrDetails.HostList = AppendHostname(csrDetails.HostList, instanceIdHost)
	}

	csrDetails.URIs = []*url.URL{}
	// spiffe uri must always be the first one
	spiffeUri := GetSvcSpiffeUri(options.SpiffeTrustDomain, options.SpiffeNamespace, options.Domain, options.Service)
	csrDetails.URIs = AppendUri(csrDetails.URIs, spiffeUri)

	// athenz://instanceid/<provider>/<instance-id>
	instanceIdUri := fmt.Sprintf("athenz://instanceid/%s/%s", options.Provider, options.InstanceId)
	csrDetails.URIs = AppendUri(csrDetails.URIs, instanceIdUri)

	// athenz://instancename/<account>/<instance-name>
	if options.Account != "" && options.InstanceName != "" {
		instanceNameUri := fmt.Sprintf("athenz://instancename/%s/%s", options.Account, options.InstanceName)
		csrDetails.URIs = AppendUri(csrDetails.URIs, instanceNameUri)
	}

	return GenerateX509CSR(key, csrDetails)
}

func GetSvcSpiffeUri(trustDomain, namespace, domain, service string) string {
	var uriStr string
	if trustDomain != "" && namespace != "" {
		uriStr = fmt.Sprintf("spiffe://%s/ns/%s/sa/%s.%s", trustDomain, namespace, domain, service)
	} else {
		uriStr = fmt.Sprintf("spiffe://%s/sa/%s", domain, service)
	}
	return uriStr
}

func GetRoleSpiffeUri(trustDomain, domain, role string) string {
	var uriStr string
	if trustDomain != "" {
		uriStr = fmt.Sprintf("spiffe://%s/ns/%s/ra/%s", trustDomain, domain, role)
	} else {
		uriStr = fmt.Sprintf("spiffe://%s/ra/%s", domain, role)
	}
	return uriStr
}

func GenerateRoleCertCSR(key *rsa.PrivateKey, options *RoleCertReqOptions) (string, error) {

	log.Println("Generating Role Certificate CSR...")

	// for role certificates we're putting the role name in the CN
	var csrDetails CertReqDetails
	csrDetails.CommonName = options.RoleName
	csrDetails.Country = options.Country
	csrDetails.Org = options.OrgName
	csrDetails.OrgUnit = options.Provider

	csrDetails.URIs = []*url.URL{}
	// spiffe uri must always be the first one
	domainNameRequest, roleNameRequest, err := SplitRoleName(options.RoleName)
	if err != nil {
		return "", err
	}
	spiffeUri := GetRoleSpiffeUri(options.SpiffeTrustDomain, domainNameRequest, roleNameRequest)
	csrDetails.URIs = AppendUri(csrDetails.URIs, spiffeUri)

	// athenz://instanceid/<provider>/<instance-id>
	instanceIdUri := fmt.Sprintf("athenz://instanceid/%s/%s", options.Provider, options.InstanceId)
	csrDetails.URIs = AppendUri(csrDetails.URIs, instanceIdUri)

	// include an uri for athenz principal
	principalUri := fmt.Sprintf("athenz://principal/%s.%s", options.Domain, options.Service)
	csrDetails.URIs = AppendUri(csrDetails.URIs, principalUri)

	// for backward compatibility an email with the principal as the local part
	if options.EmailDomain != "" {
		email := fmt.Sprintf("%s.%s@%s", options.Domain, options.Service, options.EmailDomain)
		csrDetails.EmailList = []string{email}
	}

	return GenerateX509CSR(key, csrDetails)
}

func GenerateSSHHostCSR(sshPubKeyFile string, domain, service, ip string, ztsCloudDomains []string) (string, error) {

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
	for _, ztsDomain := range ztsCloudDomains {
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

func GenerateSSHHostRequest(sshPubKeyFile string, domain, service, hostname, ip, instanceId, sshPrincipals string, ztsCloudDomains []string) (*zts.SSHCertRequest, error) {

	log.Println("Generating SSH Host Certificate Request...")

	pubkey, err := os.ReadFile(sshPubKeyFile)
	if err != nil {
		log.Printf("Unable to read SSH Public Key File: %v\n", err)
		return nil, err
	}
	identity := domain + "." + service
	hyphenDomain := strings.Replace(domain, ".", "-", -1)
	var principals []string
	if hostname != "" {
		principals = append(principals, hostname)
	}
	if sshPrincipals != "" {
		principals = append(principals, strings.Split(sshPrincipals, ",")...)
	}
	if ip != "" {
		principals = append(principals, ip)
	}
	for _, ztsDomain := range ztsCloudDomains {
		host := fmt.Sprintf("%s.%s.%s", service, hyphenDomain, ztsDomain)
		principals = append(principals, host)
	}
	pubKeyAlgo := int32(x509.ECDSA)
	dataRequest := &zts.SSHCertRequestData{
		Principals:   principals,
		PublicKey:    string(pubkey),
		CaPubKeyAlgo: &pubKeyAlgo,
	}
	metaRequest := &zts.SSHCertRequestMeta{
		TransId:       fmt.Sprintf("%x", time.Now().Unix()),
		Requestor:     identity,
		AthenzService: zts.EntityName(identity),
		Origin:        ip,
		InstanceId:    zts.PathElement(instanceId),
		CertType:      "host",
	}
	req := &zts.SSHCertRequest{
		CertRequestData: dataRequest,
		CertRequestMeta: metaRequest,
	}
	return req, nil
}

func AppendUri(uriList []*url.URL, uriValue string) []*url.URL {
	uri, err := url.Parse(uriValue)
	if err == nil {
		uriList = append(uriList, uri)
	}
	return uriList
}

func AppendHostname(hostList []string, hostname string) []string {
	for _, host := range hostList {
		if host == hostname {
			return hostList
		}
	}
	return append(hostList, hostname)
}

func GetRoleCertFileName(certDir, fileName, roleName string) string {
	switch {
	case fileName == "":
		return fmt.Sprintf("%s/%s.cert.pem", certDir, roleName)
	case fileName[0] == '/':
		return fileName
	default:
		return fmt.Sprintf("%s/%s", certDir, fileName)
	}
}

func GetRoleKeyFileName(keyDir, fileName, roleName string, generateRoleKey bool) string {
	// if we're not asked to generate a separate role key then we're
	// going to use the service key file thus no need to return a role key file
	if !generateRoleKey {
		return ""
	}
	keyPrefix := roleName
	if fileName != "" {
		keyPrefix = strings.TrimSuffix(fileName, ".cert.pem")
	}
	return fmt.Sprintf("%s/%s.key.pem", keyDir, keyPrefix)
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

func GetSvcKeyFileName(keyDir, fileName, domain, service string) string {
	switch {
	case fileName == "":
		return fmt.Sprintf("%s/%s.%s.key.pem", keyDir, domain, service)
	case fileName[0] == '/':
		return fileName
	default:
		return fmt.Sprintf("%s/%s", keyDir, fileName)
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
	if rotateKey || !FileExists(keyFile) {
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
	if FileExists(sourceFile) {
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
	// source file does not exist to take backup of so no error
	return nil
}

func CopyCertKeyFile(srcKey, destKey, srcCert, destCert string, keyFileMode os.FileMode, fileDirectUpdate bool) error {
	certFileMode := requiredFilePerm(0444, fileDirectUpdate)
	if err := Copy(srcCert, destCert, certFileMode); err != nil {
		return err
	}
	keyFileMode = requiredFilePerm(keyFileMode, fileDirectUpdate)
	return Copy(srcKey, destKey, keyFileMode)
}

func UpdateKeyOwnership(keyFile string, uid, gid int, fileMode os.FileMode, fileDirectUpdate bool) {
	if uid != 0 || gid != 0 {
		// Change the ownership on keyfile
		log.Printf("Changing file %s ownership to %d:%d...\n", keyFile, uid, gid)
		err := os.Chown(keyFile, uid, gid)
		if err != nil {
			log.Fatalf("Cannot chown file %s to %d:%d, err: %v", keyFile, uid, gid, err)
		}
	}
	if gid != 0 {
		fileMode = requiredFilePerm(fileMode, fileDirectUpdate)
		log.Printf("Changing file %s permission to %v\n", keyFile, fileMode)
		err := os.Chmod(keyFile, fileMode)
		if err != nil {
			log.Fatalf("Cannot chmod file %s to %v, err: %v", keyFile, fileMode, err)
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

func ParseRoleArn(roleArn, rolePrefix, roleSuffix, profileSeparator string, roleServiceNameOnly bool) (string, string, string, string, error) {
	// supported formats are
	//  arn:aws:iam::123456789012:role/athenz.zts
	//  arn:aws:iam::123456789012:instance-profile/athenz.zts
	//  arn:aws:iam::123456789012:instance-profile/athenz.zts@access-profile
	// if roleServiceNameOnly option is true then we also support
	//  arn:aws:iam::123456789012:instance-profile/zts
	// where domain name can be derived server side from the account number

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
	var domain, service string
	if idx < 0 {
		if !roleServiceNameOnly {
			return "", "", "", "", fmt.Errorf("cannot determine domain/service from arn: %s", roleArn)
		} else {
			service = serviceData
		}
	} else {
		domain = serviceData[:idx]
		service = serviceData[idx+1:]
	}
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

func GetRoleCertKeyPaths(domainName, roleName, roleFilename, roleService, roleServiceKeyFilename, keyDir string, generateRoleKey bool) (string, string, string) {
	certPrefix := roleName
	if roleFilename != "" {
		certPrefix = strings.TrimSuffix(roleFilename, ".cert.pem")
	}
	svcKeyFile := ""
	keyPrefix := fmt.Sprintf("%s.%s", domainName, roleService)
	if generateRoleKey {
		keyPrefix = roleName
		if roleFilename != "" {
			keyPrefix = strings.TrimSuffix(roleFilename, ".cert.pem")
		}
	} else {
		svcKeyFile = GetSvcKeyFileName(keyDir, roleServiceKeyFilename, domainName, roleService)
	}
	return keyPrefix, certPrefix, svcKeyFile
}

func getCertKeyFileName(keyFile, certFile, keyDir, certDir, keyPrefix, certPrefix string) (string, string) {
	if keyFile == "" {
		keyFile = fmt.Sprintf("%s/%s.key.pem", keyDir, keyPrefix)
	}
	if certFile != "" {
		if certFile[0] == '/' {
			return keyFile, certFile
		} else {
			return keyFile, fmt.Sprintf("%s/%s", certDir, certFile)
		}
	} else {
		return keyFile, fmt.Sprintf("%s/%s.cert.pem", certDir, certPrefix)
	}
}

func SaveRoleCertKey(key, cert []byte, keyFile, certFile, svcKeyFile, roleName string, uid, gid, fileMode int, createKey, rotateKey bool, backupDir string, fileDirectUpdate bool) error {

	// perform validation of x509KeyPair pair match before writing to disk
	x509KeyPair, err := tls.X509KeyPair(cert, key)
	if err != nil {
		return fmt.Errorf("x509KeyPair and key for: %s do not match, error: %v", roleName, err)
	}
	_, err = x509.ParseCertificate(x509KeyPair.Certificate[0])
	if err != nil {
		return fmt.Errorf("x509KeyPair and key for: %s unable to parse cert, error: %v", roleName, err)
	}

	backUpKeyFile := fmt.Sprintf("%s/%s.key.pem", backupDir, roleName)
	backUpCertFile := fmt.Sprintf("%s/%s.cert.pem", backupDir, roleName)

	// if we're not given a role key file, it means we're re-using our service private key
	// thus there is no need to update any files
	filesBackedUp := false
	if keyFile != "" {
		if rotateKey {
			err = EnsureBackUpDir(backupDir)
			if err != nil {
				return err
			}
			// taking backup of key and cert
			if FileExists(keyFile) || FileExists(certFile) {
				log.Printf("taking backup of cert: %s to %s and key: %s to %s\n", certFile, backUpCertFile, keyFile, backUpKeyFile)
				err = CopyCertKeyFile(keyFile, backUpKeyFile, certFile, backUpCertFile, os.FileMode(fileMode), fileDirectUpdate)
				if err != nil {
					log.Printf("Error while taking backup %v\n", err)
					return err
				}
				filesBackedUp = true
			}
			//write the new key and x509KeyPair to disk
			log.Printf("writing new key file: %s to disk\n", keyFile)
			err = UpdateFile(keyFile, key, uid, gid, os.FileMode(fileMode), fileDirectUpdate, true)
			if err != nil {
				log.Printf("Error while writing key file during rotate %v\n", err)
				return err
			}
		} else if createKey && !FileExists(keyFile) {
			//write the new key and x509KeyPair to disk
			log.Printf("writing new key file: %s to disk\n", keyFile)
			err = UpdateFile(keyFile, key, uid, gid, os.FileMode(fileMode), fileDirectUpdate, true)
			if err != nil {
				log.Printf("Error while writing key file during create %v\n", err)
				return err
			}
		} else if FileExists(keyFile) {
			log.Printf("Updating existing key file %s ownership only", keyFile)
			UpdateKeyOwnership(keyFile, uid, gid, os.FileMode(fileMode), fileDirectUpdate)
		}
	} else {
		// since we're using our service key file, let's set the key file as such,
		// so we can load and validate the x509KeyPair later in this method
		keyFile = svcKeyFile
	}

	log.Printf("Updating the cert file %s", certFile)
	err = UpdateFile(certFile, cert, uid, gid, os.FileMode(0444), fileDirectUpdate, true)
	if err != nil {
		log.Printf("Error while writing cert file %v\n", err)
		return err
	}

	// perform 2nd validation of x509KeyPair pair match after writing to disk
	x509KeyPair, err = tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		log.Printf("x509KeyPair: %s, key: %s do not match, error: %v\n", certFile, keyFile, err)
		// restore the original contents only if we had successfully backed up the files
		if filesBackedUp {
			err = CopyCertKeyFile(backUpKeyFile, keyFile, backUpCertFile, certFile, os.FileMode(fileMode), fileDirectUpdate)
		}
		return err
	}

	_, err = x509.ParseCertificate(x509KeyPair.Certificate[0])
	if err != nil {
		log.Printf("x509KeyPair: %s, key: %s, unable to parse cert, error: %v\n", certFile, keyFile, err)
		// restore the original contents only if we had successfully backed up the files
		if filesBackedUp {
			err = CopyCertKeyFile(backUpKeyFile, keyFile, backUpCertFile, certFile, os.FileMode(fileMode), fileDirectUpdate)
		}
		return err
	}

	return nil
}

// SaveServiceCertKey writes the key and cert to disk and takes backup of existing key and cert if rotateKey is true
// this method is only called when we're refreshing the service certificate. during service registration we directly
// update key/cert/ca-cert files
func SaveServiceCertKey(key, cert []byte, keyFile, certFile, serviceName string, uid, gid, fileMode int, rotateKey bool, backupDir string, fileDirectUpdate bool) error {
	// perform validation of x509KeyPair pair match before writing to disk
	x509KeyPair, err := tls.X509KeyPair(cert, key)
	if err != nil {
		return fmt.Errorf("x509KeyPair and key for: %s do not match, error: %v", serviceName, err)
	}
	_, err = x509.ParseCertificate(x509KeyPair.Certificate[0])
	if err != nil {
		return fmt.Errorf("x509KeyPair and key for: %s unable to parse cert, error: %v", serviceName, err)
	}

	backUpKeyFile := fmt.Sprintf("%s/%s.key.pem", backupDir, serviceName)
	backUpCertFile := fmt.Sprintf("%s/%s.cert.pem", backupDir, serviceName)

	filesBackedUp := false
	if rotateKey {
		err = EnsureBackUpDir(backupDir)
		if err != nil {
			return err
		}
		// taking backup of key and cert
		if FileExists(keyFile) || FileExists(certFile) {
			log.Printf("taking backup of cert: %s to %s and key: %s to %s\n", certFile, backUpCertFile, keyFile, backUpKeyFile)
			err = CopyCertKeyFile(keyFile, backUpKeyFile, certFile, backUpCertFile, os.FileMode(fileMode), fileDirectUpdate)
			if err != nil {
				log.Printf("Error while taking backup %v\n", err)
				return err
			}
			filesBackedUp = true
		}
		//write the new key and x509KeyPair to disk
		log.Printf("writing new key file: %s to disk\n", keyFile)
		err = UpdateFile(keyFile, key, uid, gid, os.FileMode(fileMode), fileDirectUpdate, true)
		if err != nil {
			log.Printf("Error while writing key file during rotate %v\n", err)
			return err
		}
	} else if FileExists(keyFile) {
		log.Printf("Updating existing key file %s ownership only", keyFile)
		UpdateKeyOwnership(keyFile, uid, gid, os.FileMode(fileMode), fileDirectUpdate)
	}
	log.Printf("Updating the cert file %s", certFile)
	err = UpdateFile(certFile, cert, uid, gid, os.FileMode(0444), fileDirectUpdate, true)
	if err != nil {
		log.Printf("Error while writing cert file %v\n", err)
		return err
	}

	// perform 2nd validation of x509KeyPair pair match after writing to disk
	x509KeyPair, err = tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		log.Printf("x509KeyPair: %s, key: %s do not match, error: %v\n", certFile, keyFile, err)
		// restore the original contents only if we had successfully backed up the files
		if filesBackedUp {
			err = CopyCertKeyFile(backUpKeyFile, keyFile, backUpCertFile, certFile, os.FileMode(fileMode), fileDirectUpdate)
		}
		return err
	}

	_, err = x509.ParseCertificate(x509KeyPair.Certificate[0])
	if err != nil {
		log.Printf("x509KeyPair: %s, key: %s, unable to parse cert, error: %v\n", certFile, keyFile, err)
		// restore the original contents only if we had successfully backed up the files
		if filesBackedUp {
			err = CopyCertKeyFile(backUpKeyFile, keyFile, backUpCertFile, certFile, os.FileMode(fileMode), fileDirectUpdate)
		}
		return err
	}

	return nil
}

func ParseServiceSpiffeUri(uri string) (string, string, string, string) {
	//  spiffe://<athenz-domain>/sa/<athenz-service>
	//   e.g. spiffe://sports/sa/api
	//  spiffe://<trust-domain>/ns/<namespace>/sa/<athenz-domain>.<athenz-service>
	//   e.g. spiffe://athenz.io/ns/default/sa/sports.api
	idx := strings.Index(uri, "/ns/")
	if idx == -1 {
		domain, service := parseSpiffeUriWithoutNamespace(uri, "/sa/")
		return "", "", domain, service
	} else {
		trustDomain, namespace, athenzService := parseSpiffeUriWithNamespace(uri, "/sa/")
		idx = strings.LastIndex(athenzService, ".")
		if idx < 0 {
			return "", "", "", ""
		} else {
			return trustDomain, namespace, athenzService[0:idx], athenzService[idx+1:]
		}
	}
}

func ParseRoleSpiffeUri(uri string) (string, string) {
	//  spiffe://<athenz-domain>/ra/<athenz-role>
	return parseSpiffeUriWithoutNamespace(uri, "/ra/")
}

func ParseCASpiffeUri(uri string) (string, string, string) {
	//  spiffe://<trust-domain>/ns/<namespace>/ca/<athenz-cluster>
	idx := strings.Index(uri, "/ns/")
	if idx == -1 {
		return "", "", ""
	} else {
		return parseSpiffeUriWithNamespace(uri, "/ca/")
	}
}

func parseSpiffeUriWithoutNamespace(uri, objType string) (string, string) {
	if !strings.HasPrefix(uri, "spiffe://") {
		return "", ""
	}
	comp := uri[9:]
	//supported formats:
	//  spiffe://<athenz-domain>/sa/<athenz-service>
	//  spiffe://<athenz-domain>/ra/<athenz-role>
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

func parseSpiffeUriWithNamespace(uri, objType string) (string, string, string) {
	if !strings.HasPrefix(uri, "spiffe://") {
		return "", "", ""
	}
	comp := uri[9:]
	//supported formats:
	//  spiffe://<trust-domain>/ns/<namespace>/sa/<athenz-domain>.<athenz-service>
	//  spiffe://<trust-domain>/ns/<namespace>/ca/<athenz-cluster>
	idx := strings.Index(comp, "/ns/")
	trustDomain := comp[0:idx]
	nsComp := comp[idx+4:]
	idx = strings.Index(nsComp, objType)
	if idx == -1 {
		return "", "", ""
	}
	return trustDomain, nsComp[0:idx], nsComp[idx+len(objType):]
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
	err = UpdateFile(jwkConfFile, confJson, uid, gid, 0444, false, true)
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

func UpdateFileContents(fileName string, contents []byte, perm os.FileMode, fileDirectUpdate, verbose bool) error {
	// verify we have valid contents otherwise we're just
	// going to skip and return success without doing anything
	if len(contents) == 0 {
		if verbose {
			log.Printf("Contents is empty. Skipping writing to file %s\n", fileName)
		}
		return nil
	}
	// if the file direct update flag is enabled then we need to make
	// sure the permissions for the file include write option set
	perm = requiredFilePerm(perm, fileDirectUpdate)
	// if the original file does not exist then we
	// just write the contents to the given file
	// directly
	_, err := os.Stat(fileName)
	if err != nil && os.IsNotExist(err) {
		if verbose {
			log.Printf("Updating file %s...\n", fileName)
		}
		err = os.WriteFile(fileName, contents, perm)
		if err != nil {
			log.Printf("Unable to write new file %s, err: %v\n", fileName, err)
			return err
		}
	} else {
		if fileDirectUpdate {
			err = updateFileDirectly(fileName, contents, perm, verbose)
		} else {
			err = updateFileUsingRename(fileName, contents, perm, verbose)
		}
		if err != nil {
			return err
		}
	}
	return nil
}

func updateFileUsingRename(fileName string, contents []byte, perm os.FileMode, verbose bool) error {
	timeNano := time.Now().UnixNano()
	// write the new contents to a temporary file
	newFileName := fmt.Sprintf("%s.tmp%d", fileName, timeNano)
	if verbose {
		log.Printf("Writing contents to temporary file %s...\n", newFileName)
	}
	err := os.WriteFile(newFileName, contents, perm)
	if err != nil {
		log.Printf("Unable to write new file %s, err: %v\n", newFileName, err)
		return err
	}
	// move the contents of the old file to a backup file
	bakFileName := fmt.Sprintf("%s.bak%d", fileName, timeNano)
	if verbose {
		log.Printf("Renaming original file %s to backup file %s...\n", fileName, bakFileName)
	}
	err = os.Rename(fileName, bakFileName)
	if err != nil {
		log.Printf("Unable to rename file %s to %s, err: %v\n", fileName, bakFileName, err)
		return err
	}
	// move the new contents to the original location
	if verbose {
		log.Printf("Renaming temporary file %s to requested file %s...\n", newFileName, fileName)
	}
	err = os.Rename(newFileName, fileName)
	if err != nil {
		log.Printf("Unable to rename file %s to %s, err: %v\n", newFileName, fileName, err)
		// before returning try to restore the original file
		_ = os.Rename(bakFileName, fileName)
		return err
	}
	// remove the temporary backup file
	if verbose {
		log.Printf("Removing backup file %s...\n", bakFileName)
	}
	_ = os.Remove(bakFileName)
	return nil
}

func updateFileDirectly(fileName string, contents []byte, perm os.FileMode, verbose bool) error {
	timeNano := time.Now().UnixNano()
	// move the contents of the old file to a backup file
	bakFileName := fmt.Sprintf("%s.bak%d", fileName, timeNano)
	if verbose {
		log.Printf("Copying original file %s to backup file %s...\n", fileName, bakFileName)
	}
	origContents, err := os.ReadFile(fileName)
	if err != nil {
		log.Printf("Unable to read original file %s contents, err: %v\n", fileName, err)
		return err
	}
	err = os.WriteFile(bakFileName, origContents, perm)
	if err != nil {
		log.Printf("Unable to write original file %s contents to %s, err: %v\n", fileName, bakFileName, err)
		return err
	}
	// write the new contents to the original location
	if verbose {
		log.Printf("Writing new contents to the original file %s...\n", fileName)
	}
	err = os.WriteFile(fileName, contents, perm)
	if err != nil {
		log.Printf("Unable to write new file %s, err: %v\n", fileName, err)
		_ = os.Rename(bakFileName, fileName)
		return err
	}
	// remove the temporary backup file
	if verbose {
		log.Printf("Removing backup file %s...\n", bakFileName)
	}
	_ = os.Remove(bakFileName)
	return nil
}

func SetupSIADir(siaDir string, ownerUid, ownerGid int) error {
	// Create the requested sia directory, if it doesn't exist
	if !FileExists(siaDir) {
		err := os.MkdirAll(siaDir, 0755)
		if err != nil {
			return fmt.Errorf("unable to create sia dir: %q, error: %v", siaDir, err)
		}
	}

	// update our main and then subdirectories
	setupDirOwnership(siaDir, ownerUid, ownerGid)
	return nil
}

func requiredFilePerm(defaultPerm os.FileMode, directUpdateRequested bool) os.FileMode {
	// if the direct update option is not requested then we'll
	// return the default perm as specified, otherwise, we need
	// to enable the write flag for the owner
	if directUpdateRequested {
		return defaultPerm | 0200
	} else {
		return defaultPerm
	}
}

// ParseScriptArguments parses a script path with arguments using shlex
// and constructs an array of string with name and arguments
func ParseScriptArguments(script string) []string {
	if script == "" {
		return []string{}
	}
	parts, err := shlex.Split(script)
	if err != nil {
		log.Printf("invalid script: %q, err: %v\n", script, err)
		return []string{}
	}
	if !validateScriptArguments(parts) {
		return []string{}
	}

	// Clean application path
	if len(parts) != 0 {
		parts[0] = filepath.Clean(parts[0])
	}
	return parts
}

// ExecuteScript executes a script along with the provided
// arguments while blocking the agent
func ExecuteScript(script []string, addlDetail string, runAfterFailExit bool) error {
	// execute run after script (if provided)
	if len(script) == 0 {
		return nil
	}
	if addlDetail != "" {
		script = append(script, addlDetail)
	}
	log.Printf("executing run after hook for: %v", script)
	err := exec.Command(script[0], script[1:]...).Run()
	if err != nil {
		log.Printf("unable to execute: %q, err: %v", script, err)
		if runAfterFailExit {
			os.Exit(1)
		}
	}
	return err
}

// ExecuteScriptWithoutBlock executes a script along with the provided
// arguments in a go subroutine without blocking the agent
func ExecuteScriptWithoutBlock(script []string, addlDetail string, runAfterFailExit bool) {
	go func() {
		ExecuteScript(script, addlDetail, runAfterFailExit)
	}()
}

// ParseSiaCmd parses the sia command and returns the command and a boolean
// indicating whether the command should skip errors or not. The format
// of the command is sia-command[:skip-errors]. If the command includes
// additional arguments separated by colon, then those are ignored.
func ParseSiaCmd(siaCmd string) (string, bool) {
	parts := strings.Split(siaCmd, ":")
	if len(parts) == 1 {
		return parts[0], false
	} else {
		return parts[0], parts[1] == "skip-errors"
	}
}

// NotifySystemdReadyForCommand sends a notification to systemd that the
// service is ready if the clientCmd argument matches to the notifyCmd
func NotifySystemdReadyForCommand(clientCmd, notifyCmd string) error {
	// if our client command is not the requested value
	// then we're going to skip the notification
	if clientCmd != notifyCmd {
		return nil
	}
	err := NotifySystemdReady()
	if err != nil {
		log.Printf("failed to notify systemd: %v", err)
	}
	return err
}

// NotifySystemdReady sends a notification to systemd that the service is ready
func NotifySystemdReady() error {
	notifySocket := os.Getenv("NOTIFY_SOCKET")
	if notifySocket == "" {
		return fmt.Errorf("notify socket is not set")
	}
	socketAddr := &net.UnixAddr{
		Name: notifySocket,
		Net:  "unixgram",
	}
	conn, err := net.DialUnix(socketAddr.Net, nil, socketAddr)
	if err != nil {
		return err
	}
	defer conn.Close()
	_, err = conn.Write([]byte("READY=1"))
	return err
}

// TouchDoneFile creates an empty file if it doesn't exist and updates the
// access and modification times to the current time. The name of the file
// is constructed by joining the directory and file name with a separator
// plus the .done extension.
func TouchDoneFile(fileDir, fileName string) error {
	doneFilePath := filepath.Join(fileDir, fileName+".done")
	f, err := os.OpenFile(doneFilePath, os.O_CREATE, 0644)
	if err != nil {
		log.Printf("unable to touch '%s' file: %v\n", doneFilePath, err)
		return err
	}
	f.Close()
	currentTime := time.Now().Local()
	return os.Chtimes(doneFilePath, currentTime, currentTime)
}
