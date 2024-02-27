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
	"os"
	"os/user"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/AthenZ/athenz/clients/go/zts"
	"github.com/ardielle/ardielle-go/rdl"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
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

func TestSanDNSHostname(test *testing.T) {

	host := SanDNSHostname("athenz", "storage", "athenz.io")
	if host != "storage.athenz.athenz.io" {
		test.Errorf("Host is not expected storage.athenz.athenz.io value: %s", host)
		return
	}

	host = SanDNSHostname("athenz.ci", "storage", "athenz.io")
	if host != "storage.athenz-ci.athenz.io" {
		test.Errorf("Host is not expected storage.athenz-ci.athenz.io value: %s", host)
		return
	}

	host = SanDNSHostname("athenz", "", "athenz.io")
	if host != ".athenz.athenz.io" {
		test.Errorf("Host is not expected .athenz.athenz.io value: %s", host)
		return
	}
}

func TestSanURIInstanceId(test *testing.T) {
	uri := SanURIInstanceId("athenz.provider", "id001")
	if uri != "athenz://instanceid/athenz.provider/id001" {
		test.Errorf("Host is not expected athenz://instanceid/athenz.provider/id001 value: %s", uri)
		return
	}
}

func TestUpdateFileNew(test *testing.T) {
	testInternalUpdateFileNew(test, true)
	testInternalUpdateFileNew(test, false)
}

func testInternalUpdateFileNew(test *testing.T, fileDirectUpdate bool) {
	//make sure our temp file does not exist
	timeNano := time.Now().UnixNano()
	fileName := fmt.Sprintf("sia-test.tmp%d", timeNano)
	os.Remove(fileName)
	testContents := "sia-unit-test"
	err := UpdateFile(fileName, []byte(testContents), ExecIdCommand("-u"), ExecIdCommand("-g"), 0644, fileDirectUpdate, true)
	if err != nil {
		test.Errorf("Cannot create new file: %v", err)
		return
	}
	data, err := os.ReadFile(fileName)
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
	testInternalUpdateFileExisting(test, true)
	testInternalUpdateFileExisting(test, false)
}

func testInternalUpdateFileExisting(test *testing.T, fileDirectUpdate bool) {
	//create our temporary file
	timeNano := time.Now().UnixNano()
	fileName := fmt.Sprintf("sia-test.tmp%d", timeNano)
	testContents := "sia-unit-test"
	err := os.WriteFile(fileName, []byte(testContents), 0644)
	if err != nil {
		test.Errorf("Cannot create new file: %v", err)
		return
	}
	testNewContents := "sia-unit"
	err = UpdateFile(fileName, []byte(testNewContents), ExecIdCommand("-u"), ExecIdCommand("-g"), 0644, fileDirectUpdate, true)
	if err != nil {
		test.Errorf("Cannot create new file: %v", err)
		return
	}
	data, err := os.ReadFile(fileName)
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
	key, err := GenerateKeyPair(2048)
	if err != nil {
		test.Errorf("Unable to generate private key pair %v", err)
		return
	}
	timeNano := time.Now().UnixNano()
	fileName := fmt.Sprintf("sia-test.tmp%d", timeNano)
	uid := ExecIdCommand("-u")
	gid := ExecIdCommand("-g")
	err = UpdateFile(fileName, []byte(PrivatePem(key)), uid, gid, 0644, false, true)
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

func TestGenerateSvcCertCSR(test *testing.T) {

	key, err := GenerateKeyPair(2048)
	if err != nil {
		test.Errorf("Cannot generate private key: %v", err)
		return
	}
	svcCertReqOptions := &SvcCertReqOptions{
		Country:          "US",
		Domain:           "domain",
		Service:          "service",
		CommonName:       "domain.service",
		InstanceId:       "instance001",
		Provider:         "Athenz",
		ZtsDomains:       []string{"athenz.cloud"},
		WildCardDnsName:  false,
		InstanceIdSanDNS: false,
	}
	csr, err := GenerateSvcCertCSR(key, svcCertReqOptions)
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

	if parsedcertreq.EmailAddresses != nil {
		test.Errorf("CSR has unexpected email address: %s", parsedcertreq.EmailAddresses[0])
		return
	}
	if len(parsedcertreq.DNSNames) != 1 {
		test.Errorf("CSR has more than 1 san dns name: %d", len(parsedcertreq.DNSNames))
		return
	}
	if parsedcertreq.DNSNames[0] != "service.domain.athenz.cloud" {
		test.Errorf("CSR does not have expected dns name: %s", parsedcertreq.DNSNames[0])
		return
	}
	if len(parsedcertreq.URIs) != 2 {
		test.Errorf("CSR does not have expected number of URI fields: %d", len(parsedcertreq.URIs))
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

func TestGenerateSvcCertCSRSpiffeTrustDomain(test *testing.T) {

	key, err := GenerateKeyPair(2048)
	if err != nil {
		test.Errorf("Cannot generate private key: %v", err)
		return
	}
	svcCertReqOptions := &SvcCertReqOptions{
		Country:           "US",
		Domain:            "domain",
		Service:           "service",
		CommonName:        "domain.service",
		Account:           "gcp-project1",
		InstanceName:      "api-instance",
		InstanceId:        "instance001",
		Provider:          "Athenz",
		ZtsDomains:        []string{"athenz.cloud"},
		WildCardDnsName:   false,
		InstanceIdSanDNS:  false,
		SpiffeTrustDomain: "athenz.io",
		SpiffeNamespace:   "default",
	}
	csr, err := GenerateSvcCertCSR(key, svcCertReqOptions)
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
	if len(parsedcertreq.URIs) != 3 {
		test.Errorf("CSR does not have expected number of URI fields: %d", len(parsedcertreq.URIs))
		return
	}
	if parsedcertreq.URIs[0].String() != "spiffe://athenz.io/ns/default/sa/domain.service" {
		test.Errorf("CSR does not have expected spiffe uri: %s", parsedcertreq.URIs[0].String())
		return
	}
	if parsedcertreq.URIs[1].String() != "athenz://instanceid/Athenz/instance001" {
		test.Errorf("CSR does not have expected instance id uri: %s", parsedcertreq.URIs[1].String())
		return
	}
	if parsedcertreq.URIs[2].String() != "athenz://instancename/gcp-project1/api-instance" {
		test.Errorf("CSR does not have expected instance name uri: %s", parsedcertreq.URIs[2].String())
		return
	}
}

func TestGenerateRoleCertCSR(test *testing.T) {

	key, err := GenerateKeyPair(2048)
	if err != nil {
		test.Errorf("Cannot generate private key: %v", err)
		return
	}
	roleCertReqOptions := &RoleCertReqOptions{
		Country:     "US",
		Domain:      "domain",
		Service:     "service",
		RoleName:    "athenz:role.readers",
		InstanceId:  "instance001",
		Provider:    "Athenz",
		EmailDomain: "athenz.cloud",
	}
	csr, err := GenerateRoleCertCSR(key, roleCertReqOptions)
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
	if parsedcertreq.DNSNames != nil {
		test.Errorf("CSR has unexpected san dns names: %d", len(parsedcertreq.DNSNames))
		return
	}
	if len(parsedcertreq.URIs) != 3 {
		test.Errorf("CSR does not have expected number of URI fields: %d", len(parsedcertreq.URIs))
		return
	}
	if parsedcertreq.URIs[0].String() != "spiffe://athenz/ra/readers" {
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
	if parsedcertreq.Subject.CommonName != "athenz:role.readers" {
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

func TestGenerateRoleCertCSRNoEmail(test *testing.T) {

	key, err := GenerateKeyPair(2048)
	if err != nil {
		test.Errorf("Cannot generate private key: %v", err)
		return
	}
	roleCertReqOptions := &RoleCertReqOptions{
		Country:    "US",
		Domain:     "domain",
		Service:    "service",
		RoleName:   "athenz:role.readers",
		InstanceId: "instance001",
		Provider:   "Athenz",
	}
	csr, err := GenerateRoleCertCSR(key, roleCertReqOptions)
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

	if parsedcertreq.EmailAddresses != nil {
		test.Errorf("CSR has an unexpected email addresses: %v", parsedcertreq.EmailAddresses)
		return
	}
}

func TestGenerateWithWildCardHostname(test *testing.T) {

	key, err := GenerateKeyPair(2048)
	if err != nil {
		test.Errorf("Cannot generate private key: %v", err)
		return
	}
	svcCertReqOptions := &SvcCertReqOptions{
		Country:           "US",
		Domain:            "domain",
		Service:           "service",
		CommonName:        "domain.service",
		Provider:          "Athenz",
		AddlSanDNSEntries: []string{},
		ZtsDomains:        []string{"athenz.cloud"},
		WildCardDnsName:   true,
		InstanceIdSanDNS:  false,
		SpiffeNamespace:   "default",
	}
	csr, err := GenerateSvcCertCSR(key, svcCertReqOptions)
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

func TestGenerateWithHostname(test *testing.T) {

	key, err := GenerateKeyPair(2048)
	if err != nil {
		test.Errorf("Cannot generate private key: %v", err)
		return
	}
	hostname, _ := os.Hostname()
	svcCertReqOptions := &SvcCertReqOptions{
		Country:           "US",
		Domain:            "domain",
		Service:           "service",
		CommonName:        "domain.service",
		Provider:          "Athenz",
		Hostname:          hostname,
		ZtsDomains:        []string{"athenz.cloud"},
		WildCardDnsName:   false,
		InstanceIdSanDNS:  false,
		SpiffeTrustDomain: "athenz.io",
	}
	csr, err := GenerateSvcCertCSR(key, svcCertReqOptions)
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
	if parsedcertreq.DNSNames[1] != hostname {
		test.Errorf("CSR does not have expected dns hostname: %s", parsedcertreq.DNSNames[1])
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
	svcCertReqOptions := &SvcCertReqOptions{
		Country:          "US",
		Domain:           "domain",
		Service:          "service",
		CommonName:       "domain.service",
		Provider:         "Athenz",
		ZtsDomains:       ztsDomains,
		WildCardDnsName:  true,
		InstanceIdSanDNS: false,
	}
	csr, err := GenerateSvcCertCSR(key, svcCertReqOptions)
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

func TestGenerateWithAddlSanDNSEntries(test *testing.T) {

	key, err := GenerateKeyPair(2048)
	if err != nil {
		test.Errorf("Cannot generate private key: %v", err)
		return
	}
	hostname, _ := os.Hostname()
	svcCertReqOptions := &SvcCertReqOptions{
		Country:           "US",
		Domain:            "domain",
		Service:           "service",
		CommonName:        "domain.service",
		Provider:          "Athenz",
		Hostname:          hostname,
		AddlSanDNSEntries: []string{"10-11-12-13.ns.pod.cluster.local", "svc1.ns.svc.cluster.local"},
		ZtsDomains:        []string{"athenz.cloud"},
		WildCardDnsName:   false,
		InstanceIdSanDNS:  false,
	}
	csr, err := GenerateSvcCertCSR(key, svcCertReqOptions)
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
	if parsedcertreq.DNSNames[0] != "service.domain.athenz.cloud" {
		test.Errorf("CSR does not have expected dns name: %s", parsedcertreq.DNSNames[0])
		return
	}
	if parsedcertreq.DNSNames[1] != hostname {
		test.Errorf("CSR does not have expected dns hostname: %s", parsedcertreq.DNSNames[1])
		return
	}
	if parsedcertreq.DNSNames[2] != "10-11-12-13.ns.pod.cluster.local" {
		test.Errorf("CSR does not have expected dns hostname: %s", parsedcertreq.DNSNames[1])
		return
	}
	if parsedcertreq.DNSNames[3] != "svc1.ns.svc.cluster.local" {
		test.Errorf("CSR does not have expected dns hostname: %s", parsedcertreq.DNSNames[1])
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
		test.Errorf("Unable to verify service cert with given /test/file1 name: %s", name)
		return
	}
	name = GetSvcCertFileName("/var/run/sia/certs", "test/file1", "athenz", "api")
	if name != "/var/run/sia/certs/test/file1" {
		test.Errorf("Unable to verify service cert with given test/file1 name: %s", name)
		return
	}
	name = GetSvcCertFileName("/var/run/sia/certs", "", "athenz", "api")
	if name != "/var/run/sia/certs/athenz.api.cert.pem" {
		test.Errorf("Unable to verify service cert with athenz.api.cert.pem name: %s", name)
		return
	}
}

func TestGetSvcKeyFileName(test *testing.T) {
	name := GetSvcKeyFileName("/var/run/sia/keys", "/test/file1", "athenz", "api")
	if name != "/test/file1" {
		test.Errorf("Unable to verify service key with given /test/file1 name: %s", name)
		return
	}
	name = GetSvcKeyFileName("/var/run/sia/keys", "test/file1", "athenz", "api")
	if name != "/var/run/sia/keys/test/file1" {
		test.Errorf("Unable to verify service key with given test/file1 name: %s", name)
		return
	}
	name = GetSvcKeyFileName("/var/run/sia/keys", "", "athenz", "api")
	if name != "/var/run/sia/keys/athenz.api.key.pem" {
		test.Errorf("Unable to verify service key with given athenz.api.key.pem name: %s", name)
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
	_, _, _, _, err := ParseAssumedRoleArn("arn:aws::123456789012:assumed-role/athenz.zts-service/i-0662a0226f2d9dc2b", "-service", "@")
	if err == nil {
		test.Errorf("Unable to verify proper role arn prefix")
	}
	if !strings.Contains(err.Error(), "(prefix)") {
		test.Errorf("Error does not contain expected prefix error")
	}
}

func TestParseAssumedRoleArnInvalidNumberOfComponents(test *testing.T) {
	_, _, _, _, err := ParseAssumedRoleArn("arn:aws:sts::assumed-role/athenz.zts-service/i-0662a0226f2d9dc2b", "-service", "@")
	if err == nil {
		test.Errorf("Unable to verify proper role arn number of components")
	}
	if !strings.Contains(err.Error(), "(number of components)") {
		test.Errorf("Error does not contain expected number of components error")
	}
}

func TestParseAssumedRoleArnInvalidRoleComponent(test *testing.T) {
	_, _, _, _, err := ParseAssumedRoleArn("arn:aws:sts::123456789012:assumed-role/i-0662a0226f2d9dc2b", "-service", "")
	if err == nil {
		test.Errorf("Unable to verify proper role arn number of role components")
	}
	if !strings.Contains(err.Error(), "(role components)") {
		test.Errorf("Error does not contain expected role components error")
	}
}

func TestParseAssumedRoleArnInvalidAssumedRoleComponent(test *testing.T) {
	_, _, _, _, err := ParseAssumedRoleArn("arn:aws:sts::123456789012:athenz.zts-service/athenz.zts-service/i-0662a0226f2d9dc2b", "-service", "@")
	if err == nil {
		test.Errorf("Unable to verify proper role assumed-role prefix")
	}
	if !strings.Contains(err.Error(), "(assumed-role)") {
		test.Errorf("Error does not contain expected assumed-role prefix error")
	}
}

func TestParseAssumedRoleArnInvalidSuffix(test *testing.T) {
	_, _, _, _, err := ParseAssumedRoleArn("arn:aws:sts::123456789012:assumed-role/athenz.zts-sdbuild/i-0662a0226f2d9dc2b", "-service", "@")
	if err == nil {
		test.Errorf("Unable to verify proper role suffix")
	}
	if !strings.Contains(err.Error(), "does not have '-service' suffix") {
		test.Errorf("Error does not contain expected suffix error")
	}
}

func TestParseAssumedRoleArnInvalidAthenzService(test *testing.T) {
	_, _, _, _, err := ParseAssumedRoleArn("arn:aws:sts::123456789012:assumed-role/athenz-service/i-0662a0226f2d9dc2b", "-service", "@")
	if err == nil {
		test.Errorf("Unable to verify proper athenz service name")
	}
	if !strings.Contains(err.Error(), "cannot determine domain/service") {
		test.Errorf("Error does not contain expected domain/service error")
	}
}

func TestParseAssumedRoleArnValid(test *testing.T) {
	account, domain, service, profile, err := ParseAssumedRoleArn("arn:aws:sts::123456789012:assumed-role/athenz.zts-service/i-0662a0226f2d9dc2b", "-service", "@")
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
	if profile != "" {
		test.Errorf("Unable to parse valid arn, invalid profile: %s", service)
	}
	account, domain, service, profile, err = ParseAssumedRoleArn("arn:aws:sts::123456789012:assumed-role/athenz.zts-test/i-0662a0226f2d9dc2b", "-test", "@")
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
	if profile != "" {
		test.Errorf("Unable to parse valid arn, invalid profile: %s", service)
	}
	account, domain, service, profile, err = ParseAssumedRoleArn("arn:aws:sts::123456789012:assumed-role/athenz.zts-service@sia-profile/i-0662a0226f2d9dc2b", "-service", "@")
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
	if profile != "sia-profile" {
		test.Errorf("Unable to parse valid arn, invalid profile: %s", service)
	}
	account, domain, service, profile, err = ParseAssumedRoleArn("arn:aws:sts::123456789012:assumed-role/athenz.zts-test@sia_profile/i-0662a0226f2d9dc2b", "-test", "@")
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
	if profile != "sia_profile" {
		test.Errorf("Unable to parse valid arn, invalid profile: %s", service)
	}
}

func TestParseRoleArnInvalidPrefix(test *testing.T) {
	_, _, _, _, err := ParseRoleArn("arn:aws:sts:123456789012:role/athenz.zts-service", "role/", "", "", false)
	if err == nil {
		test.Errorf("Unable to verify proper role arn prefix")
	}
	if !strings.Contains(err.Error(), "(prefix)") {
		test.Errorf("Error does not contain expected prefix error")
	}
}

func TestParseRoleArnInvalidNumberOfComponents(test *testing.T) {
	_, _, _, _, err := ParseRoleArn("arn:aws:iam::role/athenz.zts-service", "role/", "-service", "", false)
	if err == nil {
		test.Errorf("Unable to verify proper role arn number of components")
	}
	if !strings.Contains(err.Error(), "(number of components)") {
		test.Errorf("Error does not contain expected number of components error")
	}
}

func TestParseRoleArnInvalidAssumedRoleComponent(test *testing.T) {
	_, _, _, _, err := ParseRoleArn("arn:aws:iam::123456789012:assumed-role/athenz.zts-service", "role/", "-service", "", false)
	if err == nil {
		test.Errorf("Unable to verify proper role assumed-role prefix")
	}
	if !strings.Contains(err.Error(), "'role/' prefix") {
		test.Errorf("Error does not contain expected assumed-role prefix error")
	}
}

func TestParseRoleArnInvalidAthenzService(test *testing.T) {
	_, _, _, _, err := ParseRoleArn("arn:aws:iam::123456789012:role/athenz-service", "role/", "-service", "@", false)
	if err == nil {
		test.Errorf("Unable to verify proper athenz service name")
	}
	if !strings.Contains(err.Error(), "cannot determine domain/service") {
		test.Errorf("Error does not contain expected domain/service error")
	}
}

func TestParseRoleArnValid(test *testing.T) {

	tests := map[string]struct {
		roleArn             string
		rolePrefix          string
		roleSuffix          string
		profileSeparator    string
		roleServiceNameOnly bool
		account             string
		domain              string
		service             string
		profile             string
	}{
		"valid-role": {
			roleArn:             "arn:aws:iam::123456789012:role/athenz.zts-service",
			rolePrefix:          "role/",
			roleSuffix:          "-service",
			profileSeparator:    "@",
			roleServiceNameOnly: false,
			account:             "123456789012",
			domain:              "athenz",
			service:             "zts",
			profile:             "",
		},
		"valid-role-service-only-true": {
			roleArn:             "arn:aws:iam::123456789012:role/athenz.zts-service",
			rolePrefix:          "role/",
			roleSuffix:          "-service",
			profileSeparator:    "@",
			roleServiceNameOnly: true,
			account:             "123456789012",
			domain:              "athenz",
			service:             "zts",
			profile:             "",
		},
		"valid-instance-profile": {
			roleArn:             "arn:aws:iam::123456789012:instance-profile/sys.auth.zms",
			rolePrefix:          "instance-profile/",
			roleSuffix:          "",
			profileSeparator:    "@",
			roleServiceNameOnly: false,
			account:             "123456789012",
			domain:              "sys.auth",
			service:             "zms",
			profile:             "",
		},
		"valid-instance-profile-service-only-true": {
			roleArn:             "arn:aws:iam::123456789012:instance-profile/sys.auth.zms",
			rolePrefix:          "instance-profile/",
			roleSuffix:          "",
			profileSeparator:    "@",
			roleServiceNameOnly: true,
			account:             "123456789012",
			domain:              "sys.auth",
			service:             "zms",
			profile:             "",
		},
		"valid-instance-sia-profile": {
			roleArn:             "arn:aws:iam::123456789012:instance-profile/sys.auth.zms@sia_profile",
			rolePrefix:          "instance-profile/",
			roleSuffix:          "",
			profileSeparator:    "@",
			roleServiceNameOnly: false,
			account:             "123456789012",
			domain:              "sys.auth",
			service:             "zms",
			profile:             "sia_profile",
		},
		"valid-instance-sia-profile-service-only-true": {
			roleArn:             "arn:aws:iam::123456789012:instance-profile/sys.auth.zms@sia_profile",
			rolePrefix:          "instance-profile/",
			roleSuffix:          "",
			profileSeparator:    "@",
			roleServiceNameOnly: true,
			account:             "123456789012",
			domain:              "sys.auth",
			service:             "zms",
			profile:             "sia_profile",
		},
		"valid-role-sia-profile": {
			roleArn:             "arn:aws:iam::123456789012:role/athenz.zts-service@sia_profile",
			rolePrefix:          "role/",
			roleSuffix:          "-service",
			profileSeparator:    "@",
			roleServiceNameOnly: false,
			account:             "123456789012",
			domain:              "athenz",
			service:             "zts",
			profile:             "sia_profile",
		},
		"valid-role-sia-profile-service-only-true": {
			roleArn:             "arn:aws:iam::123456789012:role/athenz.zts-service@sia_profile",
			rolePrefix:          "role/",
			roleSuffix:          "-service",
			profileSeparator:    "@",
			roleServiceNameOnly: true,
			account:             "123456789012",
			domain:              "athenz",
			service:             "zts",
			profile:             "sia_profile",
		},
	}

	for name, tt := range tests {
		test.Run(name, func(t *testing.T) {
			account, domain, service, profile, _ := ParseRoleArn(tt.roleArn, tt.rolePrefix, tt.roleSuffix, tt.profileSeparator, tt.roleServiceNameOnly)
			assert.Equal(t, account, tt.account)
			assert.Equal(t, domain, tt.domain)
			assert.Equal(t, service, tt.service)
			assert.Equal(t, profile, tt.profile)
		})
	}
}

func TestParseRoleArnServiceNameOnly(test *testing.T) {

	tests := map[string]struct {
		roleArn          string
		rolePrefix       string
		roleSuffix       string
		profileSeparator string
		account          string
		service          string
		profile          string
	}{
		"valid-role": {
			roleArn:          "arn:aws:iam::123456789012:role/zts-service",
			rolePrefix:       "role/",
			roleSuffix:       "-service",
			profileSeparator: "@",
			account:          "123456789012",
			service:          "zts",
			profile:          "",
		},
		"valid-instance-profile": {
			roleArn:          "arn:aws:iam::123456789012:instance-profile/zms",
			rolePrefix:       "instance-profile/",
			roleSuffix:       "",
			profileSeparator: "@",
			account:          "123456789012",
			service:          "zms",
			profile:          "",
		},
		"valid-instance-sia-profile": {
			roleArn:          "arn:aws:iam::123456789012:instance-profile/zms@sia_profile",
			rolePrefix:       "instance-profile/",
			roleSuffix:       "",
			profileSeparator: "@",
			account:          "123456789012",
			service:          "zms",
			profile:          "sia_profile",
		},
		"valid-role-sia-profile": {
			roleArn:          "arn:aws:iam::123456789012:role/zts-service@sia_profile",
			rolePrefix:       "role/",
			roleSuffix:       "-service",
			profileSeparator: "@",
			account:          "123456789012",
			service:          "zts",
			profile:          "sia_profile",
		},
	}

	for name, tt := range tests {
		test.Run(name, func(t *testing.T) {
			account, domain, service, profile, _ := ParseRoleArn(tt.roleArn, tt.rolePrefix, tt.roleSuffix, tt.profileSeparator, true)
			assert.Equal(t, account, tt.account)
			assert.Equal(t, domain, "")
			assert.Equal(t, service, tt.service)
			assert.Equal(t, profile, tt.profile)
		})
	}
}

func TestParseEnvBooleanFlag(test *testing.T) {
	if ParseEnvBooleanFlag("unknown") {
		test.Errorf("Unknown env variable returned true")
	}
	os.Setenv("TEST-ENV1", "true")
	if !ParseEnvBooleanFlag("TEST-ENV1") {
		test.Errorf("True value env variable did not return true")
	}
	os.Setenv("TEST-ENV2", "1")
	if !ParseEnvBooleanFlag("TEST-ENV2") {
		test.Errorf("1 value env variable did not return true")
	}
	os.Setenv("TEST-ENV3", "false")
	if ParseEnvBooleanFlag("TEST-ENV3") {
		test.Errorf("false value env variable returned true")
	}
}

func TestParseEnvIntFlag(test *testing.T) {

	tests := []struct {
		name         string
		varName      string
		varValue     string
		defaultValue int
		returnValue  int
	}{
		{"valid", "TEST-INT-ENV1", "1", 2, 1},
		{"valid-negative", "TEST-INT-ENV2", "-1", 2, -1},
		{"not-set", "TEST-INT-ENV3", "", 2, 2},
		{"not-int1", "TEST-INT-ENV4", "abc", 3, 3},
		{"not-int2", "TEST-INT-ENV5", "4abc", 3, 3},
	}
	for _, tt := range tests {
		test.Run(tt.name, func(t *testing.T) {
			if tt.varValue != "" {
				os.Setenv(tt.varName, tt.varValue)
			}
			value := ParseEnvIntFlag(tt.varName, tt.defaultValue)
			if value != tt.returnValue {
				test.Errorf("%s: invalid value returned - expected: %d, received %d", tt.name, tt.returnValue, value)
			}
		})
	}
}

func TestParseEnvFloatFlag(test *testing.T) {

	tests := []struct {
		name         string
		varName      string
		varValue     string
		defaultValue float64
		returnValue  float64
	}{
		{"valid", "TEST-INT-ENV1", "1.5", 2, 1.5},
		{"valid-negative", "TEST-INT-ENV2", "-1", 2, -1},
		{"not-set", "TEST-INT-ENV3", "", 2, 2},
		{"not-int1", "TEST-INT-ENV4", "abc", 3.5, 3.5},
		{"not-int2", "TEST-INT-ENV5", "4abc", 3, 3},
	}
	for _, tt := range tests {
		test.Run(tt.name, func(t *testing.T) {
			if tt.varValue != "" {
				os.Setenv(tt.varName, tt.varValue)
			}
			value := ParseEnvFloatFlag(tt.varName, tt.defaultValue)
			if value != tt.returnValue {
				test.Errorf("%s: invalid value returned - expected: %f, received %f", tt.name, tt.returnValue, value)
			}
		})
	}
}

func TestParseServiceSpiffeUri(test *testing.T) {

	tests := []struct {
		name    string
		uri     string
		domain  string
		service string
		trust   string
		ns      string
	}{
		{"valid", "spiffe://athenz/sa/api", "athenz", "api", "", ""},
		{"valid-ns1", "spiffe://athenz.io/ns/default/sa/athenz.api", "athenz", "api", "athenz.io", "default"},
		{"valid-ns2", "spiffe://athenz.io/ns/prod-deployment/sa/sports.prod.backend", "sports.prod", "backend", "athenz.io", "prod-deployment"},
		{"not-valid1", "spiffe://athenz/ra/api", "", "", "", ""},
		{"not-valid2", "spiffe://athenz/sa/", "", "", "", ""},
		{"not-valid3", "spiffe:///sa/api", "", "", "", ""},
		{"nov-valid4", "spiffe://athenz.io/ns/default/athenz.api", "", "", "", ""},
		{"nov-valid5", "spiffe://athenz.io/ns/default/sa/athenz", "", "", "", ""},
	}
	for _, tt := range tests {
		test.Run(tt.name, func(t *testing.T) {
			trust, ns, domain, service := ParseServiceSpiffeUri(tt.uri)
			if domain != tt.domain {
				test.Errorf("%s: invalid domain returned - expected: %s, received %s", tt.name, tt.domain, domain)
			}
			if service != tt.service {
				test.Errorf("%s: invalid service returned - expected: %s, received %s", tt.name, tt.service, service)
			}
			if trust != tt.trust {
				test.Errorf("%s: invalid trust domain returned - expected: %s, received %s", tt.name, tt.trust, trust)
			}
			if ns != tt.ns {
				test.Errorf("%s: invalid namesparce returned - expected: %s, received %s", tt.name, tt.ns, ns)
			}
		})
	}
}

func TestParseRoleSpiffeUri(test *testing.T) {

	tests := []struct {
		name   string
		uri    string
		domain string
		role   string
	}{
		{"valid", "spiffe://athenz/ra/readers", "athenz", "readers"},
		{"not-valid1", "spiffe://athenz/sa/readers", "", ""},
		{"not-valid2", "spiffe://athenz/ra/", "", ""},
		{"not-valid3", "spiffe:///ra/readers", "", ""},
	}
	for _, tt := range tests {
		test.Run(tt.name, func(t *testing.T) {
			domain, role := ParseRoleSpiffeUri(tt.uri)
			if domain != tt.domain {
				test.Errorf("%s: invalid domain returned - expected: %s, received %s", tt.name, tt.domain, domain)
			}
			if role != tt.role {
				test.Errorf("%s: invalid role returned - expected: %s, received %s", tt.name, tt.role, role)
			}
		})
	}
}

func TestParseCASpiffeUri(test *testing.T) {
	tests := []struct {
		name    string
		uri     string
		trust   string
		ns      string
		cluster string
	}{
		{"valid1", "spiffe://athenz.io/ns/default/ca/us-west-2", "athenz.io", "default", "us-west-2"},
		{"valid2", "spiffe://athenz.io/ns/prod/ca/us-east-1", "athenz.io", "prod", "us-east-1"},
		{"not-valid1", "spiffe://athenz.io/ns/default", "", "", ""},
		{"not-valid2", "spiffe://athenz/sa/default", "", "", ""},
		{"not-valid3", "spiffe://athenz/sa/", "", "", ""},
		{"not-valid3", "spiffe://athenz.io/ns/default/sa/us-west-2", "", "", ""},
	}
	for _, tt := range tests {
		test.Run(tt.name, func(t *testing.T) {
			trust, ns, cluster := ParseCASpiffeUri(tt.uri)
			if trust != tt.trust {
				test.Errorf("invalid trust doamin returned - expected: %s, received %s", tt.trust, trust)
			}
			if ns != tt.ns {
				test.Errorf("invalid ns returned - expected: %s, received %s", tt.ns, ns)
			}
			if cluster != tt.cluster {
				test.Errorf("invalid cluster returned - expected: %s, received %s", tt.cluster, cluster)
			}
		})
	}
}

func TestNonce(test *testing.T) {
	nonce1, err := Nonce()
	if err != nil {
		test.Errorf("Unable to generate a nonce1 value, error %v", err)
	}
	nonce2, err := Nonce()
	if err != nil {
		test.Errorf("Unable to generate a nonce2 value, error %v", err)
	}
	if nonce1 == nonce2 {
		test.Errorf("generated identical nonce values")
	}
}

func mockAthenzJWK() *zts.AthenzJWKConfig {
	simpleKey := func() *zts.JWKList {

		keysArr := []*zts.JWK{
			{
				Kty: "kty",
				Kid: "kid",
				X:   "x",
			},
		}
		keys := func() []*zts.JWK {
			return keysArr
		}

		return &zts.JWKList{
			Keys: keys(),
		}
	}

	now := rdl.TimestampFromEpoch(100)
	jwkConf := zts.AthenzJWKConfig{
		Modified: &now,
		Zms:      simpleKey(),
		Zts:      simpleKey(),
	}

	return &jwkConf
}

func TestReadWriteAthenzJwkConf(t *testing.T) {
	a := assert.New(t)
	siaDir, err := os.MkdirTemp("", "sia.")
	require.Nil(t, err, "should be able to create temp folder for sia")
	defer os.RemoveAll(siaDir)

	// verify without athenz.conf - modify time is 0
	modTime := GetAthenzJwkConfModTime(siaDir)
	a.Equal(rdl.TimestampFromEpoch(0).Millis(), modTime.Millis())

	u, err := user.Current()
	if err != nil {
		panic(err)
	}
	uid, err := strconv.Atoi(u.Uid)
	gid, err := strconv.Atoi(u.Gid)
	jwkObj := mockAthenzJWK()
	err = WriteAthenzJWKFile(jwkObj, siaDir, uid, gid)

	require.Nil(t, err, "should be able to write athenz.conf")

	jwkConfFile := fmt.Sprintf("%s/"+JwkConfFile, siaDir)
	jwkObjFromFile := zts.AthenzJWKConfig{}
	err = ReadAthenzJwkConf(jwkConfFile, &jwkObjFromFile)
	require.Nil(t, err, "should be able to read athenz.conf")
	a.Equal("kty", jwkObjFromFile.Zms.Keys[0].Kty)
	a.Equal("kty", jwkObjFromFile.Zts.Keys[0].Kty)
	a.Equal("kid", jwkObjFromFile.Zms.Keys[0].Kid)
	a.Equal("kid", jwkObjFromFile.Zts.Keys[0].Kid)
	a.Equal("x", jwkObjFromFile.Zms.Keys[0].X)
	a.Equal("x", jwkObjFromFile.Zts.Keys[0].X)
	a.Equal(rdl.TimestampFromEpoch(100).Millis(), jwkObjFromFile.Modified.Millis())

	modTime = GetAthenzJwkConfModTime(siaDir)
	a.Equal(rdl.TimestampFromEpoch(100).Millis(), modTime.Millis())
}

func TestSetupSIADir(t *testing.T) {

	SetupSIADir("/tmp/sia-test-dir", -1, -1)
	assert.True(t, FileExists("/tmp/sia-test-dir"))
	os.RemoveAll("/tmp/sia-test-dir")

	SetupSIADir("/tmp/sia-test-dir", ExecIdCommand("-u"), ExecIdCommand("-g"))
	assert.True(t, FileExists("/tmp/sia-test-dir"))
	os.RemoveAll("/tmp/sia-test-dir")
}

func TestGenerateSSHHostRequest(t *testing.T) {

	// using invalid key file which should return nil

	req, err := GenerateSSHHostRequest("unknown-file", "athenz", "api", "hostname.athenz.io", "10.11.12.13", "i-0123", "host1.athenz.io,host2.athenz.io", []string{"athenz.cloud"})
	assert.NotNil(t, err)

	// now let's test with real ssh pub key file

	req, err = GenerateSSHHostRequest("data/ssh-pub-key", "athenz", "api", "hostname.athenz.io", "10.11.12.13", "i-0123", "host1.athenz.io,host2.athenz.io", []string{"athenz.cloud"})
	assert.Nil(t, err)

	assert.Equal(t, "host", req.CertRequestMeta.CertType)
	assert.Equal(t, "10.11.12.13", req.CertRequestMeta.Origin)
	assert.Equal(t, zts.PathElement("i-0123"), req.CertRequestMeta.InstanceId)
	assert.Equal(t, zts.EntityName("athenz.api"), req.CertRequestMeta.AthenzService)
	assert.Equal(t, "athenz.api", req.CertRequestMeta.Requestor)

	assert.Equal(t, int32(x509.ECDSA), *req.CertRequestData.CaPubKeyAlgo)
	assert.Equal(t, "ssh-pub-key", req.CertRequestData.PublicKey)
	assert.Equal(t, 5, len(req.CertRequestData.Principals))
	assert.Equal(t, "hostname.athenz.io", req.CertRequestData.Principals[0])
	assert.Equal(t, "host1.athenz.io", req.CertRequestData.Principals[1])
	assert.Equal(t, "host2.athenz.io", req.CertRequestData.Principals[2])
	assert.Equal(t, "10.11.12.13", req.CertRequestData.Principals[3])
	assert.Equal(t, "api.athenz.athenz.cloud", req.CertRequestData.Principals[4])

	// now let's test with without any optional arguments

	req, err = GenerateSSHHostRequest("data/ssh-pub-key", "athenz", "api", "", "", "i-0123", "", []string{"athenz.cloud"})
	assert.Nil(t, err)

	assert.Equal(t, "host", req.CertRequestMeta.CertType)
	assert.Empty(t, req.CertRequestMeta.Origin)
	assert.Equal(t, zts.PathElement("i-0123"), req.CertRequestMeta.InstanceId)
	assert.Equal(t, zts.EntityName("athenz.api"), req.CertRequestMeta.AthenzService)
	assert.Equal(t, "athenz.api", req.CertRequestMeta.Requestor)

	assert.Equal(t, int32(x509.ECDSA), *req.CertRequestData.CaPubKeyAlgo)
	assert.Equal(t, "ssh-pub-key", req.CertRequestData.PublicKey)
	assert.Equal(t, 1, len(req.CertRequestData.Principals))
	assert.Equal(t, "api.athenz.athenz.cloud", req.CertRequestData.Principals[0])
}

func TestAppendHostname(t *testing.T) {
	list := []string{}
	list = AppendHostname(list, "host1.athenz.io")
	assert.Equal(t, len(list), 1)
	assert.Equal(t, list[0], "host1.athenz.io")

	list = AppendHostname(list, "host1.athenz.io")
	assert.Equal(t, len(list), 1)
	assert.Equal(t, list[0], "host1.athenz.io")

	list = AppendHostname(list, "host2.athenz.io")
	assert.Equal(t, len(list), 2)
	assert.Equal(t, list[0], "host1.athenz.io")
	assert.Equal(t, list[1], "host2.athenz.io")

	list = AppendHostname(list, "host2.athenz.io")
	assert.Equal(t, len(list), 2)
	assert.Equal(t, list[0], "host1.athenz.io")
	assert.Equal(t, list[1], "host2.athenz.io")
}

func TestRequiredFilePerm(t *testing.T) {
	tests := []struct {
		name         string
		perm         int
		directUpdate bool
		resultPerm   int
	}{
		{"read-only-direct", 0400, true, 0600},
		{"read-only-non-direct", 0400, false, 0400},
		{"read-group-direct", 0440, true, 0640},
		{"read-group-non-direct", 0440, false, 0440},
		{"read-all-direct", 0444, true, 0644},
		{"read-all-non-direct", 0444, false, 0444},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, os.FileMode(tt.resultPerm), requiredFilePerm(os.FileMode(tt.perm), tt.directUpdate))
		})
	}
}

func TestCopy(t *testing.T) {

	timeNano := time.Now().UnixNano()
	fileName := fmt.Sprintf("copy-test.tmp%d", timeNano)
	testContents := "xx-yy-zz"
	err := os.WriteFile(fileName, []byte(testContents), 0644)
	defer os.Remove(fileName)

	siaDir, err := os.MkdirTemp("", "sia_bkup.")
	assert.Nil(t, err, "should be able to create backup folder for sia")
	defer os.RemoveAll(siaDir)
	assert.Nil(t, Copy(fileName, siaDir+"/"+fileName, os.FileMode(0644)))
	//non-existent file
	assert.Nil(t, Copy("./abcd", siaDir+"/abcd", os.FileMode(0644)))
}

func TestParseScriptArguments(t *testing.T) {

	tests := []struct {
		name       string
		scriptPath string
		result     []string
	}{
		{
			name:       "Empty Sia",
			scriptPath: "",
			result:     []string{},
		},
		{
			name:       "Unqualified path",
			scriptPath: "  bin/echo  ",
			result:     []string{},
		},
		{
			name:       "With white space",
			scriptPath: "  /bin/echo   Hello    World  ",
			result:     []string{"/bin/echo", "Hello", "World"},
		},
		{
			name:       "Double quoted argument",
			scriptPath: "  /bin/echo -n  \"Hello World\" And USA",
			result:     []string{"/bin/echo", "-n", "Hello World", "And", "USA"},
		},
		{
			name:       "Single quoted argument",
			scriptPath: "  /bin/echo   '\"Hello World\"'",
			result:     []string{"/bin/echo", `"Hello World"`},
		},
		{
			name:       "Broken quote argument",
			scriptPath: "  /bin/echo   \"Hello World",
			result:     []string{},
		},
		{
			name:       "Unsanitized path check",
			scriptPath: "/bin/////echo   '\"Hello World Sanitized\"'",
			result:     []string{"/bin/echo", `"Hello World Sanitized"`},
		},
		{
			name:       "Unsanitized path check2",
			scriptPath: "/../bin/echo   '\"Hello World Sanitized\"'",
			result:     []string{"/bin/echo", `"Hello World Sanitized"`},
		},
		{
			name:       "Unsanitized path check2",
			scriptPath: "/bin/../echo   '\"Hello World Sanitized\"'",
			result:     []string{"/echo", `"Hello World Sanitized"`},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			parts := ParseScriptArguments(tt.scriptPath)
			assert.Equal(t, len(parts), len(tt.result))
			if len(tt.result) != 0 {
				assert.Equalf(t, tt.result, parts, "test: %s, unexpected parts: %+v, expecting: %+v",
					tt.name, parts, tt.result)
			}
		})
	}
}

func TestGetCertKeyFileName(t *testing.T) {

	tests := []struct {
		name       string
		keyFile    string
		certFile   string
		keyDir     string
		certDir    string
		keyPrefix  string
		certPrefix string
		scriptPath string
		resultKey  string
		resultCert string
	}{
		{
			name:       "non-empty full-path key/cert files",
			keyFile:    "/var/athenz/key.pem",
			certFile:   "/var/athenz/cert.pem",
			keyDir:     "not-used",
			certDir:    "not-used",
			keyPrefix:  "not-used",
			certPrefix: "not-used",
			resultKey:  "/var/athenz/key.pem",
			resultCert: "/var/athenz/cert.pem",
		},
		{
			name:       "empty key file and full-path cert file",
			keyFile:    "",
			certFile:   "/var/athenz/cert.pem",
			keyDir:     "/var/test1",
			certDir:    "not-used",
			keyPrefix:  "key-prefix",
			certPrefix: "not-used",
			resultKey:  "/var/test1/key-prefix.key.pem",
			resultCert: "/var/athenz/cert.pem",
		},
		{
			name:       "non-empty full-path key file and cert file",
			keyFile:    "/var/athenz/key.pem",
			certFile:   "cert-file",
			keyDir:     "not-used",
			certDir:    "/var/test2",
			keyPrefix:  "not-used",
			certPrefix: "not-used",
			resultKey:  "/var/athenz/key.pem",
			resultCert: "/var/test2/cert-file",
		},
		{
			name:       "empty key file and full-path cert file",
			keyFile:    "",
			certFile:   "cert-file",
			keyDir:     "/var/test1",
			certDir:    "/var/test2",
			keyPrefix:  "key-prefix",
			certPrefix: "not-used",
			resultKey:  "/var/test1/key-prefix.key.pem",
			resultCert: "/var/test2/cert-file",
		},
		{
			name:       "empty key and cert files",
			keyFile:    "",
			certFile:   "",
			keyDir:     "/var/test3",
			certDir:    "/var/test4",
			keyPrefix:  "key-prefix",
			certPrefix: "cert-prefix",
			resultKey:  "/var/test3/key-prefix.key.pem",
			resultCert: "/var/test4/cert-prefix.cert.pem",
		},
		{
			name:       "non-empty full-path key file and empty cert files",
			keyFile:    "/var/athenz/key.pem",
			certFile:   "",
			keyDir:     "not-used",
			certDir:    "/var/test4",
			keyPrefix:  "not-used",
			certPrefix: "cert-prefix",
			resultKey:  "/var/athenz/key.pem",
			resultCert: "/var/test4/cert-prefix.cert.pem",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			keyFile, certFile := getCertKeyFileName(tt.keyFile, tt.certFile, tt.keyDir, tt.certDir, tt.keyPrefix, tt.certPrefix)
			assert.Equal(t, tt.resultKey, keyFile)
			assert.Equal(t, tt.resultCert, certFile)
		})
	}
}

func TestGetSvcSpiffeUri(t *testing.T) {

	tests := map[string]struct {
		domain      string
		service     string
		trustDomain string
		namespace   string
		uri         string
	}{
		"domain-service-only": {
			domain:      "sports",
			service:     "api",
			trustDomain: "",
			namespace:   "",
			uri:         "spiffe://sports/sa/api",
		},
		"only-trust-domain": {
			domain:      "sports",
			service:     "api",
			trustDomain: "athenz.cloud",
			namespace:   "",
			uri:         "spiffe://sports/sa/api",
		},
		"only-namespace": {
			domain:      "sports",
			service:     "api",
			trustDomain: "",
			namespace:   "default",
			uri:         "spiffe://sports/sa/api",
		},
		"namespace-format": {
			domain:      "sports",
			service:     "api",
			trustDomain: "athenz.io",
			namespace:   "default",
			uri:         "spiffe://athenz.io/ns/default/sa/sports.api",
		},
	}

	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			spiffeUri := GetSvcSpiffeUri(tt.trustDomain, tt.namespace, tt.domain, tt.service)
			assert.Equal(t, spiffeUri, tt.uri)
		})
	}
}

func TestParseSiaCmd(test *testing.T) {

	tests := []struct {
		name       string
		siaCmd     string
		cmd        string
		skipErrors bool
	}{
		{"empty-cmd", "", "", false},
		{"simple-valid-cmd", "init", "init", false},
		{"simple-unknown-cmd", "operation", "operation", false},
		{"simple-skip-errors", "init:skip-errors", "init", true},
		{"multiple-parts", "init:skip-errors:unknown", "init", true},
		{"multiple-parts-unknown", "init:test:unknown", "init", false},
	}
	for _, tt := range tests {
		test.Run(tt.name, func(t *testing.T) {
			cmd, skipErrors := ParseSiaCmd(tt.siaCmd)
			if tt.cmd != cmd {
				test.Errorf("%s: invalid cmd returned - expected: %v, received %v", tt.name, tt.cmd, cmd)
			}
			if tt.skipErrors != skipErrors {
				test.Errorf("%s: invalid skipErrors returned - expected: %v, received %v", tt.name, tt.skipErrors, skipErrors)
			}
		})
	}
}

func TestExecuteScript(test *testing.T) {

	// non-existent script
	err := ExecuteScript([]string{"unknown-script"})
	assert.NotNil(test, err)

	// remove our test file if it exists
	os.Remove("/tmp/test-after-script")
	// valid script
	err = ExecuteScript([]string{"data/test_after_script.sh"})
	assert.Nil(test, err)
	// verify our test file was created
	_, err = os.Stat("/tmp/test-after-script")
	assert.Nil(test, err)
}
