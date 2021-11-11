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
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"testing"
	"time"
)

func TestSplitRoleName(test *testing.T) {

	domain, role, err := SplitRoleName("role")
	if err == nil {
		test.Errorf("Invalid role was parsed successfully")
		return
	}

	domain, role, err = SplitRoleName("role:role2:role3")
	if err == nil {
		test.Errorf("Invalid role was parsed successfully")
		return
	}

	domain, role, err = SplitRoleName("role:test")
	if err == nil {
		test.Errorf("Invalid role was parsed successfully")
		return
	}

	domain, role, err = SplitRoleName("role:role.")
	if err == nil {
		test.Errorf("Invalid role was parsed successfully")
		return
	}

	domain, role, err = SplitRoleName("domain:role.test.role")
	if err != nil {
		test.Errorf("Unable to parse valid role name successfully")
		return
	}
	if domain != "domain" {
		test.Errorf("Domain field is not expected domain value")
		return
	}
	if role != "test.role" {
		test.Errorf("Role field is not expected test.role value")
		return
	}
}

func TestSplitDomain(test *testing.T) {

	domain, service := SplitDomain("domain")
	if domain != "" {
		test.Errorf("Domain is not empty")
		return
	}
	if service != "" {
		test.Errorf("Service is not empty")
		return
	}

	domain, service = SplitDomain("athenz.storage")
	if domain != "athenz" {
		test.Errorf("Domain is not athenz")
		return
	}
	if service != "storage" {
		test.Errorf("Service is not storage")
		return
	}

	domain, service = SplitDomain("athenz.ci.storage")
	if domain != "athenz.ci" {
		test.Errorf("Domain is not athenz.ci")
		return
	}
	if service != "storage" {
		test.Errorf("Service is not storage")
		return
	}
}

func TestZtsHostName(test *testing.T) {

	host := ZtsHostName("athenz.storage", "athenz.cloud")
	if host != "storage.athenz.athenz.cloud" {
		test.Errorf("Host is not expected storage.athenz.athenz.cloud value")
		return
	}

	host = ZtsHostName("athenz.ci.storage", "athenz.cloud")
	if host != "storage.athenz-ci.athenz.cloud" {
		test.Errorf("Host is not expected storage.athenz-ci.athenz.cloud value")
		return
	}

	host = ZtsHostName("athenz", "athenz.cloud")
	if host != "..athenz.cloud" {
		test.Errorf("Host is not expected ..athenz.cloud value")
		return
	}
}

func TestUpdateFileNew(test *testing.T) {

	sysLogger := os.Stdout

	//make sure our temp file does not exist
	timeNano := time.Now().UnixNano()
	fileName := fmt.Sprintf("sia-test.tmp%d", timeNano)
	os.Remove(fileName)
	testContents := "sia-unit-test"
	err := UpdateFile(fileName, []byte(testContents), 0, 0, 0644, sysLogger)
	if err != nil {
		test.Errorf("Cannot create new file: %v", err)
		return
	}
	data, err := ioutil.ReadFile(fileName)
	if err != nil {
		test.Errorf("Cannot read new created file: %v", err)
		os.Remove(fileName)
		return
	}
	if string(data) != testContents {
		test.Errorf("Read %s data not the same as stored %s data", data, testContents)
		os.Remove(fileName)
		return
	}
	os.Remove(fileName)
}

func TestUpdateFileExisting(test *testing.T) {

	sysLogger := os.Stdout

	//create our temporary file
	timeNano := time.Now().UnixNano()
	fileName := fmt.Sprintf("sia-test.tmp%d", timeNano)
	testContents := "sia-unit-test"
	err := ioutil.WriteFile(fileName, []byte(testContents), 0644)
	if err != nil {
		test.Errorf("Cannot create new file: %v", err)
		return
	}
	testNewContents := "sia-unit"
	err = UpdateFile(fileName, []byte(testNewContents), 0, 0, 0644, sysLogger)
	if err != nil {
		test.Errorf("Cannot create new file: %v", err)
		return
	}
	data, err := ioutil.ReadFile(fileName)
	if err != nil {
		test.Errorf("Cannot read new created file: %v", err)
		os.Remove(fileName)
		return
	}
	if string(data) != testNewContents {
		test.Errorf("Read %s data not the same as stored %s data", data, testNewContents)
		os.Remove(fileName)
		return
	}
	os.Remove(fileName)
}

func TestPrivateKeySupport(test *testing.T) {

	sysLogger := os.Stdout

	key, err := GenerateKeyPair(2048)
	if err != nil {
		test.Errorf("Unable to generate private key pair %v", err)
		return
	}
	timeNano := time.Now().UnixNano()
	fileName := fmt.Sprintf("sia-test.tmp%d", timeNano)
	uid := localIdCommand("-u")
	gid := localIdCommand("-g")
	err = UpdateFile(fileName, []byte(PrivatePem(key)), uid, gid, 0644, sysLogger)
	if err != nil {
		test.Errorf("Unable to save private key file - %v", err)
		return
	}
	key, err = PrivateKeyFromFile(fileName)
	os.Remove(fileName)
	if err != nil {
		test.Errorf("Unable to read private key file - %v", err)
		return
	}
}

func localIdCommand(arg string) int {
	out, err := exec.Command("id", arg).Output()
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

func TestGenerateCSR(test *testing.T) {

	key, err := GenerateKeyPair(2048)
	if err != nil {
		test.Errorf("Cannot generate private key: %v", err)
		return
	}

	csr, err := GenerateCSR(key, "US", "", "domain", "service", "domain.service", "instance001", "Athenz", "spiffe://domain/sa/service", []string{"athenz.cloud"}, false, true)
	if err != nil {
		test.Errorf("Cannot create CSR: %v", err)
		return
	}

	block, _ := pem.Decode([]byte(csr))
	parsedcertreq, err := x509.ParseCertificateRequest(block.Bytes)
	if err != nil {
		test.Errorf("Cannot parse CSR: %v", err)
		return
	}

	if parsedcertreq.EmailAddresses[0] != "domain.service@athenz.cloud" {
		test.Errorf("CSR does not have expected email address: %s", parsedcertreq.EmailAddresses[0])
		return
	}
	if len(parsedcertreq.DNSNames) != 1 {
		test.Errorf("CSR has more than 1 san dns name: %d", len(parsedcertreq.DNSNames))
		return
	}
	if len(parsedcertreq.DNSNames) != 1 {
		test.Errorf("CSR does not have a single dns name")
		return
	}
	if parsedcertreq.DNSNames[0] != "service.domain.athenz.cloud" {
		test.Errorf("CSR does not have expected dns name: %s", parsedcertreq.DNSNames[0])
		return
	}
	if parsedcertreq.URIs[0].String() != "spiffe://domain/sa/service" {
		test.Errorf("CSR does not have expected spiffe uri: %s", parsedcertreq.URIs[0].String())
		return
	}
	if parsedcertreq.URIs[1].String() != "athenz://instanceid/Athenz/instance001" {
		test.Errorf("CSR does not have expected instance uri: %s", parsedcertreq.URIs[1].String())
		return
	}
	if parsedcertreq.URIs[2].String() != "athenz://principal/domain.service" {
		test.Errorf("CSR does not have expected role principal uri: %s", parsedcertreq.URIs[2].String())
		return
	}
	if parsedcertreq.Subject.CommonName != "domain.service" {
		test.Errorf("CSR does not have expected common name: %s", parsedcertreq.Subject.CommonName)
		return
	}
	if parsedcertreq.Subject.OrganizationalUnit[0] != "Athenz" {
		test.Errorf("CSR does not have expected org unit: %s", parsedcertreq.Subject.OrganizationalUnit)
		return
	}
	if parsedcertreq.Subject.Organization != nil {
		test.Errorf("CSR does not have expected org")
		return
	}
}

func TestGenerateCSRWithWildCardHostname(test *testing.T) {

	key, err := GenerateKeyPair(2048)
	if err != nil {
		test.Errorf("Cannot generate private key: %v", err)
		return
	}
	csr, err := GenerateCSR(key, "US", "", "domain", "service", "domain.service", "", "Athenz", "spiffe://domain/sa/service", []string{"athenz.cloud"}, true, false)
	if err != nil {
		test.Errorf("Cannot create CSR: %v", err)
		return
	}

	block, _ := pem.Decode([]byte(csr))
	parsedcertreq, err := x509.ParseCertificateRequest(block.Bytes)
	if err != nil {
		test.Errorf("Cannot parse CSR: %v", err)
		return
	}
	if len(parsedcertreq.DNSNames) != 2 {
		test.Errorf("CSR does not have 2 expected san dns names: %d", len(parsedcertreq.DNSNames))
		return
	}
	if parsedcertreq.DNSNames[0] != "service.domain.athenz.cloud" {
		test.Errorf("CSR does not have expected dns name: %s", parsedcertreq.DNSNames[0])
		return
	}
	if parsedcertreq.DNSNames[1] != "*.service.domain.athenz.cloud" {
		test.Errorf("CSR does not have expected wildcard dns name: %s", parsedcertreq.DNSNames[1])
		return
	}
}


func TestGenerateCSRWithMultipleHostname(test *testing.T) {

	key, err := GenerateKeyPair(2048)
	if err != nil {
		test.Errorf("Cannot generate private key: %v", err)
		return
	}
	ztsDomains := []string{"athenz1.cloud"}
	ztsDomains = append(ztsDomains, "athenz2.cloud")
	csr, err := GenerateCSR(key, "US", "", "domain", "service", "domain.service", "", "Athenz", "spiffe://domain/sa/service", ztsDomains, true, false)
	if err != nil {
		test.Errorf("Cannot create CSR: %v", err)
		return
	}

	block, _ := pem.Decode([]byte(csr))
	parsedcertreq, err := x509.ParseCertificateRequest(block.Bytes)
	if err != nil {
		test.Errorf("Cannot parse CSR: %v", err)
		return
	}
	if len(parsedcertreq.DNSNames) != 4 {
		test.Errorf("CSR does not have 4 expected san dns names: %d", len(parsedcertreq.DNSNames))
		return
	}
	if parsedcertreq.DNSNames[0] != "service.domain.athenz1.cloud" {
		test.Errorf("CSR does not have expected dns name: %s", parsedcertreq.DNSNames[0])
		return
	}
	if parsedcertreq.DNSNames[1] != "*.service.domain.athenz1.cloud" {
		test.Errorf("CSR does not have expected wildcard dns name: %s", parsedcertreq.DNSNames[1])
		return
	}
	if parsedcertreq.DNSNames[2] != "service.domain.athenz2.cloud" {
		test.Errorf("CSR does not have expected dns name: %s", parsedcertreq.DNSNames[0])
		return
	}
	if parsedcertreq.DNSNames[3] != "*.service.domain.athenz2.cloud" {
		test.Errorf("CSR does not have expected wildcard dns name: %s", parsedcertreq.DNSNames[1])
		return
	}
}

func TestGetRoleCertFileName(test *testing.T) {
	name := GetRoleCertFileName("/var/run/sia/certs", "/test/file1", "athenz:role.hockey")
	if name != "/test/file1" {
		test.Errorf("Unable to verify role cert with given /test/file1 name: %s", name)
		return
	}
	name = GetRoleCertFileName("/var/run/sia/certs", "test/file1", "athenz:role.hockey")
	if name != "/var/run/sia/certs/test/file1" {
		test.Errorf("Unable to verify role cert with given test/file1 name: %s", name)
		return
	}
	name = GetRoleCertFileName("/var/run/sia/certs", "", "athenz:role.hockey")
	if name != "/var/run/sia/certs/athenz:role.hockey.cert.pem" {
		test.Errorf("Unable to verify role cert with given athenz:role.hockey name: %s", name)
		return
	}
}

func TestGetSvcCertFileName(test *testing.T) {
	name := GetSvcCertFileName("/var/run/sia/certs", "/test/file1", "athenz", "api")
	if name != "/test/file1" {
		test.Errorf("Unable to verify role cert with given /test/file1 name: %s", name)
		return
	}
	name = GetSvcCertFileName("/var/run/sia/certs", "test/file1", "athenz", "api")
	if name != "/var/run/sia/certs/test/file1" {
		test.Errorf("Unable to verify role cert with given test/file1 name: %s", name)
		return
	}
	name = GetSvcCertFileName("/var/run/sia/certs", "", "athenz", "api")
	if name != "/var/run/sia/certs/athenz.api.cert.pem" {
		test.Errorf("Unable to verify role cert with given athenz:role.hockey name: %s", name)
		return
	}
}

func TestExtractServiceName(test *testing.T) {
	domain, service, err := ExtractServiceName("test", ":instance-profile/")
	if err == nil {
		test.Errorf("Test was parsed as success")
	}
	domain, service, err = ExtractServiceName("arn:aws:iam::1234:instance-profile/athenz.ui", ":instance-profile/")
	if err == nil {
		test.Errorf("arn:aws:iam::1234:instance-profile/athenz.ui was parsed as success")
	}
	domain, service, err = ExtractServiceName("arn:aws:iam::1234:instance/athenz.ui-service", ":instance-profile/")
	if err == nil {
		test.Errorf("arn:aws:iam::1234:instance/athenz.ui-service was parsed as success")
	}
	domain, service, err = ExtractServiceName("arn:aws:iam::1234:instance-profile/athenz-ui-service", ":instance-profile/")
	if err == nil {
		test.Errorf("arn:aws:iam::1234:instance-profile/athenz-ui-service was parsed as success")
	}
	domain, service, err = ExtractServiceName("arn:aws:iam::1234:instance-profile/athenz.ui-service", ":instance-profile/")
	if err != nil {
		test.Errorf("arn:aws:iam::1234:instance-profile/athenz.ui-service was not parsed as success")
	}
	if domain != "athenz" {
		test.Errorf("did not get expected domain: athenz")
	}
	if service != "ui" {
		test.Errorf("did not get expected service: ui")
	}
	domain, service, err = ExtractServiceName("arn:aws:iam::1234:instance-profile/athenz.aws.ui-service", ":instance-profile/")
	if err != nil {
		test.Errorf("arn:aws:iam::1234:instance-profile/athenz.aws.ui-service was parsed as success")
	}
	if domain != "athenz.aws" {
		test.Errorf("did not get expected domain: athenz.aws")
	}
	if service != "ui" {
		test.Errorf("did not get expected service: ui")
	}
	domain, service, err = ExtractServiceName("arn:aws:iam::1234:role/athenz.syncer-service", ":role/")
	if err != nil {
		test.Errorf("arn:aws:iam::1234:role/athenz.syncer-service was parsed as success")
	}
	if domain != "athenz" {
		test.Errorf("did not get expected domain: athenz.aws")
	}
	if service != "syncer" {
		test.Errorf("did not get expected service: ui")
	}
}

func TestParseAssumedRoleArnInvalidPrefix(test *testing.T) {
	_, _, _, err := ParseAssumedRoleArn("arn:aws::123456789012:assumed-role/athenz.zts-service/i-0662a0226f2d9dc2b", "-service")
	if err == nil {
		test.Errorf("Unable to verify proper role arn prefix")
	}
	if !strings.Contains(err.Error(), "(prefix)") {
		test.Errorf("Error does not contain expected prefix error")
	}
}

func TestParseAssumedRoleArnInvalidNumberOfComponents(test *testing.T) {
	_, _, _, err := ParseAssumedRoleArn("arn:aws:sts::assumed-role/athenz.zts-service/i-0662a0226f2d9dc2b", "-service")
	if err == nil {
		test.Errorf("Unable to verify proper role arn number of components")
	}
	if !strings.Contains(err.Error(), "(number of components)") {
		test.Errorf("Error does not contain expected number of components error")
	}
}

func TestParseAssumedRoleArnInvalidRoleComponent(test *testing.T) {
	_, _, _, err := ParseAssumedRoleArn("arn:aws:sts::123456789012:assumed-role/i-0662a0226f2d9dc2b", "-service")
	if err == nil {
		test.Errorf("Unable to verify proper role arn number of role components")
	}
	if !strings.Contains(err.Error(), "(role components)") {
		test.Errorf("Error does not contain expected role components error")
	}
}

func TestParseAssumedRoleArnInvalidAssumedRoleComponent(test *testing.T) {
	_, _, _, err := ParseAssumedRoleArn("arn:aws:sts::123456789012:athenz.zts-service/athenz.zts-service/i-0662a0226f2d9dc2b", "-service")
	if err == nil {
		test.Errorf("Unable to verify proper role assumed-role prefix")
	}
	if !strings.Contains(err.Error(), "(assumed-role)") {
		test.Errorf("Error does not contain expected assumed-role prefix error")
	}
}

func TestParseAssumedRoleArnInvalidSuffix(test *testing.T) {
	_, _, _, err := ParseAssumedRoleArn("arn:aws:sts::123456789012:assumed-role/athenz.zts-sdbuild/i-0662a0226f2d9dc2b", "-service")
	if err == nil {
		test.Errorf("Unable to verify proper role suffix")
	}
	if !strings.Contains(err.Error(), "does not have '-service' suffix") {
		test.Errorf("Error does not contain expected suffix error")
	}
}

func TestParseAssumedRoleArnInvalidAthenzService(test *testing.T) {
	_, _, _, err := ParseAssumedRoleArn("arn:aws:sts::123456789012:assumed-role/athenz-service/i-0662a0226f2d9dc2b", "-service")
	if err == nil {
		test.Errorf("Unable to verify proper athenz service name")
	}
	if !strings.Contains(err.Error(), "cannot determine domain/service") {
		test.Errorf("Error does not contain expected domain/service error")
	}
}

func TestParseAssumedRoleArnValid(test *testing.T) {
	account, domain, service, err := ParseAssumedRoleArn("arn:aws:sts::123456789012:assumed-role/athenz.zts-service/i-0662a0226f2d9dc2b", "-service")
	if err != nil {
		test.Errorf("Unable to parse valid arn, error %v", err)
	}
	if account != "123456789012" {
		test.Errorf("Unable to parse valid arn, invalid account: %s", account)
	}
	if domain != "athenz" {
		test.Errorf("Unable to parse valid arn, invalid domain: %s", domain)
	}
	if service != "zts" {
		test.Errorf("Unable to parse valid arn, invalid service: %s", service)
	}
	account, domain, service, err = ParseAssumedRoleArn("arn:aws:sts::123456789012:assumed-role/athenz.zts-test/i-0662a0226f2d9dc2b", "-test")
	if err != nil {
		test.Errorf("Unable to parse valid arn, error %v", err)
	}
	if account != "123456789012" {
		test.Errorf("Unable to parse valid arn, invalid account: %s", account)
	}
	if domain != "athenz" {
		test.Errorf("Unable to parse valid arn, invalid domain: %s", domain)
	}
	if service != "zts" {
		test.Errorf("Unable to parse valid arn, invalid service: %s", service)
	}
}

func TestParseRoleArnInvalidPrefix(test *testing.T) {
	_, _, _, err := ParseRoleArn("arn:aws:sts:123456789012:role/athenz.zts-service")
	if err == nil {
		test.Errorf("Unable to verify proper role arn prefix")
	}
	if !strings.Contains(err.Error(), "(prefix)") {
		test.Errorf("Error does not contain expected prefix error")
	}
}

func TestParseRoleArnInvalidNumberOfComponents(test *testing.T) {
	_, _, _, err := ParseRoleArn("arn:aws:iam::role/athenz.zts-service")
	if err == nil {
		test.Errorf("Unable to verify proper role arn number of components")
	}
	if !strings.Contains(err.Error(), "(number of components)") {
		test.Errorf("Error does not contain expected number of components error")
	}
}

func TestParseRoleArnInvalidAssumedRoleComponent(test *testing.T) {
	_, _, _, err := ParseRoleArn("arn:aws:iam::123456789012:assumed-role/athenz.zts-service")
	if err == nil {
		test.Errorf("Unable to verify proper role assumed-role prefix")
	}
	if !strings.Contains(err.Error(), "'role/' prefix") {
		test.Errorf("Error does not contain expected assumed-role prefix error")
	}
}

func TestParseRoleArnInvalidAthenzService(test *testing.T) {
	_, _, _, err := ParseRoleArn("arn:aws:iam::123456789012:role/athenz-service")
	if err == nil {
		test.Errorf("Unable to verify proper athenz service name")
	}
	if !strings.Contains(err.Error(), "cannot determine domain/service") {
		test.Errorf("Error does not contain expected domain/service error")
	}
}

func TestParseRoleArnValid(test *testing.T) {
	account, domain, service, err := ParseRoleArn("arn:aws:iam::123456789012:role/athenz.zts-service")
	if err != nil {
		test.Errorf("Unable to parse valid arn, error %v", err)
	}
	if account != "123456789012" {
		test.Errorf("Unable to parse valid arn, invalid account: %s", account)
	}
	if domain != "athenz" {
		test.Errorf("Unable to parse valid arn, invalid domain: %s", domain)
	}
	if service != "zts-service" {
		test.Errorf("Unable to parse valid arn, invalid service: %s", service)
	}
}
