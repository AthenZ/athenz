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
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"log/syslog"
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

	host := ZtsHostName("athenz.storage", "zts-azure-domain")
	if host != "storage.athenz.zts-azure-domain" {
		test.Errorf("Host is not expected storage.athenz.zts-azure-domain value")
		return
	}

	host = ZtsHostName("athenz.ci.storage", "zts-azure-domain")
	if host != "storage.athenz-ci.zts-azure-domain" {
		test.Errorf("Host is not expected storage.athenz-ci.zts-azure-domain value")
		return
	}

	host = ZtsHostName("athenz", "zts-azure-domain")
	if host != "..zts-azure-domain" {
		test.Errorf("Host is not expected ..zts-azure-domain value")
		return
	}
}

func TestGidForGroupCommand(t *testing.T) {
	var sysLogger io.Writer
	sysLogger, err := syslog.New(syslog.LOG_INFO|syslog.LOG_DAEMON, "siad")
	if err != nil {
		log.Printf("Unable to create sys logger: %v\n", err)
		sysLogger = os.Stdout
	}

	// Get current group name.
	grp, err := exec.Command("id", "-gn").Output()
	if err != nil {
		t.Errorf("Cannot exec 'id -gn': %v", err)
		return
	}
	group := strings.Trim(string(grp), "\n\r ")

	// Get current group id.
	gidBytes, err := exec.Command("id", "-g").Output()
	if err != nil {
		t.Errorf("Cannot exec 'id -gn': %v", err)
		return
	}
	gid, err := strconv.Atoi(strings.Trim(string(gidBytes), "\n\r "))
	if err != nil {
		t.Errorf("Unexpected GID format in user record: %s", string(gidBytes))
	}

	// Test if function returns expected gid.
	actualGid := gidForGroup(group, sysLogger)
	if actualGid != gid {
		t.Errorf("Unexpected group id: group=%s, expected=%d, got=%d", group, gid, actualGid)
		return
	}
}

func TestGidForInvalidGroupCommand(t *testing.T) {
	var sysLogger io.Writer
	sysLogger, err := syslog.New(syslog.LOG_INFO|syslog.LOG_DAEMON, "siad")
	if err != nil {
		log.Printf("Unable to create sys logger: %v\n", err)
		sysLogger = os.Stdout
	}

	// Test if function returns -1
	gid := gidForGroup("invalid-group-name", sysLogger)
	if gid != -1 {
		t.Errorf("Did not get expected -1 for gid, got=%d", gid)
		return
	}
}

func TestUidGidForUserGroupCommand(t *testing.T) {
	var sysLogger io.Writer
	sysLogger, err := syslog.New(syslog.LOG_INFO|syslog.LOG_DAEMON, "siad")
	if err != nil {
		log.Printf("Unable to create sys logger: %v\n", err)
		sysLogger = os.Stdout
	}

	// Get current user id
	usr, err := exec.Command("id", "-un").Output()
	if err != nil {
		t.Errorf("Cannot exec 'id -un': %v", err)
		return
	}
	user := strings.Trim(string(usr), "\n\r ")

	// Get current user id.
	uidBytes, err := exec.Command("id", "-u").Output()
	if err != nil {
		t.Errorf("Cannot exec 'id -un': %v", err)
		return
	}
	uid, err := strconv.Atoi(strings.Trim(string(uidBytes), "\n\r "))
	if err != nil {
		t.Errorf("Unexpected UID format in user record: %s", string(uidBytes))
	}

	// Get current group id.
	gidBytes, err := exec.Command("id", "-g").Output()
	if err != nil {
		t.Errorf("Cannot exec 'id -gn': %v", err)
		return
	}
	gid, err := strconv.Atoi(strings.Trim(string(gidBytes), "\n\r "))
	if err != nil {
		t.Errorf("Unexpected GID format in user record: %s", string(gidBytes))
	}

	testUid, testGid := uidGidForUser(user, sysLogger)
	if testUid != uid {
		t.Errorf("Unexpected uid value returned: %d, expected: %d", testUid, uid)
	}
	if testGid != gid {
		t.Errorf("Unexpected gid value returned: %d, expected: %d", testGid, gid)
	}
	testUid, testGid = uidGidForUser("root", sysLogger)
	if testUid != 0 {
		t.Errorf("Unexpected uid value returned: %d, expected: 0", testUid)
	}
	if testGid != 0 {
		t.Errorf("Unexpected gid value returned: %d, expected: 0", testGid)
	}
}

func TestUpdateFileNew(test *testing.T) {

	var sysLogger io.Writer
	sysLogger, err := syslog.New(syslog.LOG_INFO|syslog.LOG_DAEMON, "siad")
	if err != nil {
		log.Printf("Unable to create sys logger: %v\n", err)
		sysLogger = os.Stdout
	}

	//make sure our temp file does not exist
	timeNano := time.Now().UnixNano()
	fileName := fmt.Sprintf("sia-test.tmp%d", timeNano)
	os.Remove(fileName)
	testContents := "sia-unit-test"
	err = UpdateFile(fileName, testContents, 0, 0, 0644, sysLogger)
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

	var sysLogger io.Writer
	sysLogger, err := syslog.New(syslog.LOG_INFO|syslog.LOG_DAEMON, "siad")
	if err != nil {
		log.Printf("Unable to create sys logger: %v\n", err)
		sysLogger = os.Stdout
	}

	//create our temporary file
	timeNano := time.Now().UnixNano()
	fileName := fmt.Sprintf("sia-test.tmp%d", timeNano)
	testContents := "sia-unit-test"
	err = ioutil.WriteFile(fileName, []byte(testContents), 0644)
	if err != nil {
		test.Errorf("Cannot create new file: %v", err)
		return
	}
	testNewContents := "sia-unit"
	err = UpdateFile(fileName, testNewContents, 0, 0, 0644, sysLogger)
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

	var sysLogger io.Writer
	sysLogger, err := syslog.New(syslog.LOG_INFO|syslog.LOG_DAEMON, "siad")
	if err != nil {
		log.Printf("Unable to create sys logger: %v\n", err)
		sysLogger = os.Stdout
	}

	key, err := GenerateKeyPair(2048)
	if err != nil {
		test.Errorf("Unable to generate private key pair %v", err)
		return
	}
	timeNano := time.Now().UnixNano()
	fileName := fmt.Sprintf("sia-test.tmp%d", timeNano)
	uid := localIdCommand("-u")
	gid := localIdCommand("-g")
	err = UpdateFile(fileName, PrivatePem(key), uid, gid, 0644, sysLogger)
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
	csr, err := GenerateCSR(key, "US", "domain", "service", "domain.service", "", "Athenz", "spiffe://domain/sa/service", "zts-azure-domain", true)
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

	if parsedcertreq.EmailAddresses[0] != "domain.service@zts-azure-domain" {
		test.Errorf("CSR does not have expected email address: %s", parsedcertreq.EmailAddresses[0])
		return
	}
	if parsedcertreq.DNSNames[0] != "service.domain.zts-azure-domain" {
		test.Errorf("CSR does not have expected dns name: %s", parsedcertreq.DNSNames[0])
		return
	}
	if parsedcertreq.URIs[0].String() != "spiffe://domain/sa/service" {
		test.Errorf("CSR does not have expected spiffe uri: %s", parsedcertreq.URIs[0].String())
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
}

func TestGetRoleCertFileName(test *testing.T) {
	name := GetRoleCertFileName("/var/run/sia/certs/", "/test/file1", "athenz:role.hockey")
	if name != "/test/file1" {
		test.Errorf("Unable to verify role cert with given /test/file1 name: %s", name)
		return
	}
	name = GetRoleCertFileName("/var/run/sia/certs/", "test/file1", "athenz:role.hockey")
	if name != "/var/run/sia/certs/test/file1" {
		test.Errorf("Unable to verify role cert with given test/file1 name: %s", name)
		return
	}
	name = GetRoleCertFileName("/var/run/sia/certs/", "", "athenz:role.hockey")
	if name != "/var/run/sia/certs/athenz:role.hockey.cert.pem" {
		test.Errorf("Unable to verify role cert with given athenz:role.hockey name: %s", name)
		return
	}
}

func TestExtractServiceName(test *testing.T) {
	domain, service, err := ExtractServiceName("athenz:instance-profile")
	if err == nil {
		test.Errorf("athenz:instance-profile was parsed as success")
	}
	domain, service, err = ExtractServiceName(":instance-profile.service")
	if err == nil {
		test.Errorf(":instance-profile.service was parsed as success")
	}
	domain, service, err = ExtractServiceName("tag1:athenz.api")
	if err == nil {
		test.Errorf("tag1:athenz.api was parsed as success")
	}
	domain, service, err = ExtractServiceName("athenz:athenz.ui")
	if err != nil {
		test.Errorf("athenz:ahtenz.ui was not parsed as success")
	}
	if domain != "athenz" {
		test.Errorf("did not get expected domain: athenz")
	}
	if service != "ui" {
		test.Errorf("did not get expected service: ui")
	}
	domain, service, err = ExtractServiceName("env:prod;athenz:athenz.api")
	if err != nil {
		test.Errorf("env:prod;athenz:athenz.api was not parsed as success")
	}
	if domain != "athenz" {
		test.Errorf("did not get expected domain: athenz")
	}
	if service != "api" {
		test.Errorf("did not get expected service: api")
	}
	domain, service, err = ExtractServiceName("env:prod;athenz:athenz.prod.syncer")
	if err != nil {
		test.Errorf("env:prod;athenz:athenz.prod.syncer was parsed as success")
	}
	if domain != "athenz.prod" {
		test.Errorf("did not get expected domain: athenz.prod")
	}
	if service != "syncer" {
		test.Errorf("did not get expected service: syncer")
	}
}
