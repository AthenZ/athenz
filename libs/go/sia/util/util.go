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

package util

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"github.com/AthenZ/athenz/clients/go/zts"
	"github.com/AthenZ/athenz/libs/go/sia/logutil"
	"io"
	"io/ioutil"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
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

func ZtsClient(ztsUrl, ztsServerName string, keyFile, certFile, caCertFile string, sysLogger io.Writer) (*zts.ZTSClient, error) {
	logutil.LogInfo(sysLogger, "ZTS Client: url: %s\n", ztsUrl)
	if strings.HasPrefix(ztsUrl, "http://") {
		client := zts.NewClient(ztsUrl, &http.Transport{Proxy: http.ProxyFromEnvironment})
		return &client, nil
	} else {
		if keyFile != "" {
			logutil.LogInfo(sysLogger, "ZTS Client: private key file: %s\n", keyFile)
		}
		if certFile != "" {
			logutil.LogInfo(sysLogger, "ZTS Client: certificate file: %s\n", certFile)
		}
		if caCertFile != "" {
			logutil.LogInfo(sysLogger, "ZTS Client: CA certificate file: %s\n", caCertFile)
		}
		config, err := tlsConfiguration(keyFile, certFile, caCertFile)
		if err != nil {
			return nil, err
		}
		if ztsServerName != "" {
			logutil.LogInfo(sysLogger, "ZTS Client: Server Name: %s\n", ztsServerName)
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
		capem, err = ioutil.ReadFile(cafile)
		if err != nil {
			return nil, err
		}
	}
	if keyfile != "" && certfile != "" {
		keypem, err = ioutil.ReadFile(keyfile)
		if err != nil {
			return nil, err
		}
		certpem, err = ioutil.ReadFile(certfile)
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
	pemBytes, err := ioutil.ReadFile(filename)
	if err != nil {
		return nil, err
	}
	block, _ := pem.Decode(pemBytes)
	if block == nil {
		return nil, fmt.Errorf("no PEM block found")
	}
	return x509.ParsePKCS1PrivateKey(block.Bytes)
}

func GenerateCSR(key *rsa.PrivateKey, countryName, orgName, domain, service, commonName, instanceId, provider, spiffeUri, ztsDomain string, principalEmail bool) (string, error) {
	//note: RFC 6125 states that if the SAN (Subject Alternative Name) exists,
	//it is used, not the CN. So, we will always put the Athenz name in the CN
	//(it is *not* a DNS domain name), and put the host name into the SAN.

	var csrDetails CertReqDetails
	csrDetails.CommonName = commonName
	csrDetails.Country = countryName
	csrDetails.Org = orgName
	csrDetails.OrgUnit = provider

	hyphenDomain := strings.Replace(domain, ".", "-", -1)
	host := fmt.Sprintf("%s.%s.%s", service, hyphenDomain, ztsDomain)
	csrDetails.HostList = []string{host}
	csrDetails.URIs = []*url.URL{}
	// spiffe uri must always be the first one
	if spiffeUri != "" {
		csrDetails.URIs = appendUri(csrDetails.URIs, spiffeUri)
	}
	if instanceId != "" {
		// athenz://instanceid/<provider>/<instance-id>
		instanceIdUri := fmt.Sprintf("athenz://instanceid/%s/%s", provider, instanceId)
		csrDetails.URIs = appendUri(csrDetails.URIs, instanceIdUri)
	}
	if principalEmail {
		email := fmt.Sprintf("%s.%s@%s", domain, service, ztsDomain)
		csrDetails.EmailList = []string{email}
	}
	return GenerateX509CSR(key, csrDetails)
}

func appendUri(uriList []*url.URL, uriValue string) []*url.URL {
	uri, err := url.Parse(uriValue)
	if err == nil {
		uriList = append(uriList, uri)
	}
	return uriList
}

func GetRoleCertFileName(certDir, fileName, certName string) string {
	if fileName == "" {
		return certDir + certName + ".cert.pem"
	}
	if fileName[0] == '/' {
		return fileName
	} else {
		return certDir + fileName
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
	sourceBytes, err := ioutil.ReadFile(sourceFile)
	if err != nil {
		return err
	}
	if FileExists(destFile) {
		if err := os.Remove(destFile); err != nil {
			log.Printf("Unable to delete file %s", destFile)
		}
	}
	return ioutil.WriteFile(destFile, sourceBytes, perm)
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

func UidGidForUserGroup(username, groupname string, sysLogger io.Writer) (int, int) {
	// Get uid and gid for the username.
	uid, gid := uidGidForUser(username, sysLogger)

	// Override the group id if user explicitly specified the group.
	ggid := -1
	if groupname != "" {
		ggid = gidForGroup(groupname, sysLogger)
	}
	// if the group is not specified or invalid then we'll default
	// to our unix group name called athenz
	if ggid == -1 {
		ggid = gidForGroup(siaUnixGroup, sysLogger)
	}
	// if we have a valid value then update the gid
	// otherwise use the user group id value
	if ggid != -1 {
		gid = ggid
	}
	return uid, gid
}
