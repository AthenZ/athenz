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
	"github.com/yahoo/athenz/clients/go/zts"
	"github.com/yahoo/athenz/provider/azure/sia-vm/logutil"
	"io"
	"io/ioutil"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"time"
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

const siaUnixGroup = "athenz"

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

func ZtsHostName(identity, ztsAzureDomain string) string {
	domain, service := SplitDomain(identity)
	hyphenDomain := strings.Replace(domain, ".", "-", -1)
	return fmt.Sprintf("%s.%s.%s", service, hyphenDomain, ztsAzureDomain)
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

func getPEMBlock(privateKey *rsa.PrivateKey) []byte {
	block := &pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(privateKey),
	}
	return pem.EncodeToMemory(block)
}

func PrivatePem(privateKey *rsa.PrivateKey) string {
	block := getPEMBlock(privateKey)
	return string(block)
}

func UpdateFile(fileName, contents string, uid, gid int, perm os.FileMode, sysLogger io.Writer) error {
	// verify we have valid contents otherwise we're just
	// going to skip and return success without doing anything
	if contents == "" {
		logutil.LogInfo(sysLogger, "Contents is empty. Skipping writing to file %s\n", fileName)
		return nil
	}
	// if the original file does not exists then we
	// we just write the contents to the given file
	// directly
	_, err := os.Stat(fileName)
	if err != nil && os.IsNotExist(err) {
		logutil.LogInfo(sysLogger, "Updating file %s...\n", fileName)
		err = ioutil.WriteFile(fileName, []byte(contents), perm)
		if err != nil {
			logutil.LogInfo(sysLogger, "Unable to write new file %s, err: %v\n", fileName, err)
			return err
		}
	} else {
		timeNano := time.Now().UnixNano()
		// write the new contents to a temporary file
		newFileName := fmt.Sprintf("%s.tmp%d", fileName, timeNano)
		logutil.LogInfo(sysLogger, "Writing contents to temporary file %s...\n", newFileName)
		err = ioutil.WriteFile(newFileName, []byte(contents), perm)
		if err != nil {
			logutil.LogInfo(sysLogger, "Unable to write new file %s, err: %v\n", newFileName, err)
			return err
		}
		// move the contents of the old file to a backup file
		bakFileName := fmt.Sprintf("%s.bak%d", fileName, timeNano)
		logutil.LogInfo(sysLogger, "Renaming original file %s to backup file %s...\n", fileName, bakFileName)
		err = os.Rename(fileName, bakFileName)
		if err != nil {
			logutil.LogInfo(sysLogger, "Unable to rename file %s to %s, err: %v\n", fileName, bakFileName, err)
			return err
		}
		// move the new contents to the original location
		logutil.LogInfo(sysLogger, "Renaming temporary file %s to requested file %s...\n", newFileName, fileName)
		err = os.Rename(newFileName, fileName)
		if err != nil {
			logutil.LogInfo(sysLogger, "Unable to rename file %s to %s, err: %v\n", newFileName, fileName, err)
			// before returning try to restore the original file
			_ = os.Rename(bakFileName, fileName)
			return err
		}
		// remove the temporary backup file
		logutil.LogInfo(sysLogger, "Removing backup file %s...\n", bakFileName)
		_ = os.Remove(bakFileName)
	}
	if uid != 0 || gid != 0 {
		logutil.LogInfo(sysLogger, "Changing file %s ownership to %d:%d...\n", fileName, uid, gid)
		err = os.Chown(fileName, uid, gid)
		if err != nil {
			logutil.LogInfo(sysLogger, "Cannot chown file %s to %d:%d, err: %v\n", fileName, uid, gid, err)
			return err
		}
	}
	return nil
}

func FileExists(path string) bool {
	if _, err := os.Stat(path); os.IsNotExist(err) {
		return false
	}
	return true
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

func gidForGroup(groupname string, sysLogger io.Writer) int {
	//shelling out to id is used here because the os/user package
	//requires cgo, which doesn't cross-compile. we can use getent group
	//command but instead we opted for a simple grep for /etc/group
	cmdStr := fmt.Sprintf("^%s:", groupname)
	out, err := exec.Command("grep", cmdStr, "/etc/group").Output()
	if err != nil {
		logutil.LogInfo(sysLogger, "Cannot exec 'grep %s '/etc/group': %v\n", groupname, err)
		return -1
	}
	s := strings.Trim(string(out), "\n\r ")
	comps := strings.Split(string(out), ":")
	if len(comps) < 3 {
		logutil.LogInfo(sysLogger, "Invalid response from grep group command: %s\n", s)
		return -1
	}
	//the group id should be the third value: 'group_name:password:group_id:group_list'
	id, err := strconv.Atoi(comps[2])
	if err != nil {
		logutil.LogInfo(sysLogger, "Invalid response from getent group command: %s\n", s)
		return -1
	}
	return id
}

func idCommand(username, arg string, sysLogger io.Writer) int {
	//shelling out to id is used here because the os/user package
	//requires cgo, which doesn't cross-compile
	out, err := exec.Command("id", arg, username).Output()
	if err != nil {
		logutil.LogFatal(sysLogger, "Cannot exec 'id %s %s': %v\n", arg, username, err)
	}
	s := strings.Trim(string(out), "\n\r ")
	id, err := strconv.Atoi(s)
	if err != nil {
		logutil.LogFatal(sysLogger, "Unexpected UID/GID format in user record: %s\n", string(out))
	}
	return id
}

func uidGidForUser(username string, sysLogger io.Writer) (int, int) {
	if username == "" {
		return 0, 0
	}
	uid := idCommand(username, "-u", sysLogger)
	gid := idCommand(username, "-g", sysLogger)
	return uid, gid
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

func GenerateCSR(key *rsa.PrivateKey, countryName, domain, service, commonName, instanceId, provider, spiffeUri, ztsAzureDomain string, principalEmail bool) (string, error) {
	//note: RFC 6125 states that if the SAN (Subject Alternative Name) exists,
	//it is used, not the CN. So, we will always put the Athenz name in the CN
	//(it is *not* a DNS domain name), and put the host name into the SAN.

	var csrDetails CertReqDetails
	csrDetails.CommonName = commonName
	csrDetails.Country = countryName
	csrDetails.OrgUnit = provider

	hyphenDomain := strings.Replace(domain, ".", "-", -1)
	host := fmt.Sprintf("%s.%s.%s", service, hyphenDomain, ztsAzureDomain)
	csrDetails.HostList = []string{host}
	csrDetails.URIs = []*url.URL{}
	if instanceId != "" {
		// athenz://instanceid/<provider>/<instance-id>
		instanceIdUri := fmt.Sprintf("athenz://instanceid/%s/%s", provider, instanceId)
		csrDetails.URIs = appendUri(csrDetails.URIs, instanceIdUri)
	}
	if spiffeUri != "" {
		csrDetails.URIs = appendUri(csrDetails.URIs, spiffeUri)
	}
	if principalEmail {
		email := fmt.Sprintf("%s.%s@%s", domain, service, ztsAzureDomain)
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

func SetupSIADirs(siaMainDir, siaLinkDir string, sysLogger io.Writer) error {
	// Create the certs directory, if it doesn't exist
	certDir := fmt.Sprintf("%s/certs", siaMainDir)
	if !FileExists(certDir) {
		err := os.MkdirAll(certDir, 0755)
		if err != nil {
			return fmt.Errorf("unable to create certs dir: %q, error: %v", certDir, err)
		}
	}

	// Create the keys directory, if it doesn't exist
	keyDir := fmt.Sprintf("%s/keys", siaMainDir)
	if !FileExists(keyDir) {
		err := os.MkdirAll(keyDir, 0755)
		if err != nil {
			return fmt.Errorf("unable to create keys dir: %q, error: %v", keyDir, err)
		}
	}

	//make sure the link directory exists as well
	if siaLinkDir != "" && !FileExists(siaLinkDir) {
		err := os.Symlink(siaMainDir, siaLinkDir)
		if err != nil {
			logutil.LogInfo(sysLogger, "Unable to symlink SIA directory '%s': %v\n", siaLinkDir, err)
			return nil
		}
	}
	return nil
}

func ExtractServiceName(tagValues string) (string, string, error) {
	tags := strings.Split(tagValues, ";")
	for _, tag := range tags {
		if strings.HasPrefix(tag, "athenz:") {
			fullServiceName := tag[7:]
			idx := strings.LastIndex(fullServiceName, ".")
			if idx == -1 {
				return "", "", fmt.Errorf("invalid service name: %s", fullServiceName)
			}
			return fullServiceName[:idx], fullServiceName[idx+1:], nil
		}
	}
	return "", "", fmt.Errorf("missing Athenz tag value: %s", tagValues)
}
