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
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"github.com/AthenZ/athenz/clients/go/zts"
	"github.com/dimfeld/httptreemux"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"regexp"
	"strings"
	"testing"
)

type testServer struct {
	listener net.Listener
	addr     string
}

func (t *testServer) start(h http.Handler) {
	listener, err := net.Listen("tcp", ":0")
	if err != nil {
		log.Panicln("Unable to serve on randomly assigned port")
	}
	s := &http.Server{Handler: h}
	t.listener = listener
	t.addr = listener.Addr().String()

	go func() {
		s.Serve(listener)
	}()
}

func (t *testServer) stop() {
	t.listener.Close()
}

func (t *testServer) httpUrl() string {
	return fmt.Sprintf("http://%s", t.addr)
}

func TestGenerateSecretJsonData(test *testing.T) {

	expectedOutput := "{\n  \"ca.cert.pem\": \"ca-pem\",\n  \"sports.api.cert.pem\": \"cert-pem\",\n  \"sports.api.key.pem\": \"key-pem\","
	siaCertData := SiaCertData{
		X509CertificatePem:       "cert-pem",
		PrivateKeyPem:            "key-pem",
		X509CertificateSignerPem: "ca-pem",
	}
	jsonData, err := GenerateSecretJsonData("sports", "api", &siaCertData)
	if err != nil {
		test.Errorf("unable to generate secret json data")
		return
	}
	// need to ignore the timestamp and just match the prefix
	if !strings.HasPrefix(string(jsonData), expectedOutput) {
		test.Errorf("json data mismatch: %s", jsonData)
		return
	}
}

func TestGenerateIdentity(test *testing.T) {
	// Mock the metadata endpoints
	router := httptreemux.New()
	router.POST("/instance", func(w http.ResponseWriter, r *http.Request, params map[string]string) {
		log.Println("Called /instance")
		certPem, _ := os.ReadFile("data/cert.pem")
		caCertPem, _ := os.ReadFile("data/ca.cert.pem")
		identity := &zts.InstanceIdentity{
			Provider:              "provider",
			Name:                  "sports.api",
			InstanceId:            "id-001",
			X509Certificate:       string(certPem),
			X509CertificateSigner: string(caCertPem),
		}
		data, _ := json.Marshal(identity)
		w.WriteHeader(201)
		io.WriteString(w, string(data))
	})

	metaServer := &testServer{}
	metaServer.start(router)
	defer metaServer.stop()

	privateKey, _ := PrivateKey("data/key.pem", false)
	csrSubjectFields := CsrSubjectFields{
		Country:      "US",
		Organization: "Athenz",
	}
	identity, err := RegisterIdentity("sports", "api", "provider", metaServer.httpUrl(), "id-001", "attestation-data", "", []string{"athenz.io"}, csrSubjectFields, false, privateKey)
	if err != nil {
		test.Errorf("unable to register identity :%v\n", err)
		return
	}
	if identity.TLSCertificate.Certificate == nil {
		test.Errorf("no TLS certificate available in the response\n")
	}
}

var testDataCustomSecretJson = []struct {
	testName        string
	jsonFieldMapper map[string]string
	expected        string
	expectedErr     error
}{
	{
		testName:        "pass nil as jsonFieldMapper",
		jsonFieldMapper: nil,
		expected:        "",
		expectedErr:     fmt.Errorf("json keys mapper is misssing, required atleast certificate and private key fields"),
	},
	{
		testName: "jsonFieldMapper with cert key as empty",
		jsonFieldMapper: map[string]string{
			SiaYieldMapperX509CertPemKey: "",
		},
		expected:    "",
		expectedErr: fmt.Errorf("x509 certificate pem and private pem keys are mandatory"),
	},
	{
		testName: "jsonFieldMapper with cert pem key as blank",
		jsonFieldMapper: map[string]string{
			SiaYieldMapperX509CertPemKey: " ",
		},
		expected:    "",
		expectedErr: fmt.Errorf("x509 certificate pem and private pem keys are mandatory"),
	},
	{
		testName: "jsonFieldMapper with private pem key as blank",
		jsonFieldMapper: map[string]string{
			SiaYieldMapperX509CertPemKey: "certPem",
		},
		expected:    "",
		expectedErr: fmt.Errorf("x509 certificate pem and private pem keys are mandatory"),
	},
	{
		testName: "jsonFieldMapper without CA pem and time keys",
		jsonFieldMapper: map[string]string{
			SiaYieldMapperX509CertPemKey: "certPem",
			SiaYieldMapperPvtPemKey:      "keyPem",
		},
		expected:    "{\n  \"certPem\": \"--- CERTIFICATE ---\",\n  \"keyPem\": \"--- PRIVATE KEY ---\"\n}",
		expectedErr: nil,
	},
	{
		testName: "jsonFieldMapper without CA pem and time keys, trim case",
		jsonFieldMapper: map[string]string{
			SiaYieldMapperX509CertPemKey: "certPem ",
			SiaYieldMapperPvtPemKey:      " keyPem ",
		},
		expected:    "{\n  \"certPem\": \"--- CERTIFICATE ---\",\n  \"keyPem\": \"--- PRIVATE KEY ---\"\n}",
		expectedErr: nil,
	},
	{
		testName: "jsonFieldMapper without time key",
		jsonFieldMapper: map[string]string{
			SiaYieldMapperX509CertPemKey:   "certPem ",
			SiaYieldMapperPvtPemKey:        " keyPem ",
			SiaYieldMapperCertSignerPemKey: " caCertPem ",
		},
		expected:    "{\n  \"caCertPem\": \"--- CA CERTIFICATE ---\",\n  \"certPem\": \"--- CERTIFICATE ---\",\n  \"keyPem\": \"--- PRIVATE KEY ---\"\n}",
		expectedErr: nil,
	},
	{
		testName: "jsonFieldMapper without CA pem key",
		jsonFieldMapper: map[string]string{
			SiaYieldMapperX509CertPemKey: "certPem ",
			SiaYieldMapperPvtPemKey:      " keyPem ",
			SiaYieldMapperIssueTimeKey:   " createdAt ",
		},
		expected:    "{\n  \"certPem\": \"--- CERTIFICATE ---\",\n  \"createdAt\": \"[0-9]+\",\n  \"keyPem\": \"--- PRIVATE KEY ---\"\n}",
		expectedErr: nil,
	},
	{
		testName: "jsonFieldMapper with all fields and additional fields",
		jsonFieldMapper: map[string]string{
			SiaYieldMapperX509CertPemKey:   "certPem ",
			SiaYieldMapperPvtPemKey:        " keyPem ",
			SiaYieldMapperIssueTimeKey:     " createdAt ",
			SiaYieldMapperCertSignerPemKey: "caCertPem",
			"test":                         "something",
		},
		expected:    "{\n  \"caCertPem\": \"--- CA CERTIFICATE ---\",\n  \"certPem\": \"--- CERTIFICATE ---\",\n  \"createdAt\": \"[0-9]+\",\n  \"keyPem\": \"--- PRIVATE KEY ---\"\n}",
		expectedErr: nil,
	},
}

func TestGenerateCustomSecret(test *testing.T) {
	siaCertData := SiaCertData{
		X509CertificatePem:       "--- CERTIFICATE ---",
		PrivateKeyPem:            "--- PRIVATE KEY ---",
		X509CertificateSignerPem: "--- CA CERTIFICATE ---",
		X509Certificate:          &x509.Certificate{},
		TLSCertificate:           tls.Certificate{},
		PrivateKey:               &rsa.PrivateKey{},
	}

	for _, testData := range testDataCustomSecretJson {

		test.Run(testData.testName, func(t *testing.T) {
			actual, actualErr := GenerateCustomSecretJsonData(&siaCertData, testData.jsonFieldMapper)

			if nil == testData.expectedErr {
				if nil != actualErr {
					test.Errorf("didn't expect an error, but got [%s]", actualErr.Error())
				}
				var regExp = regexp.MustCompile(testData.expected)
				if !regExp.Match(actual) {
					fmt.Println()
					fmt.Println(testData.expected)
					fmt.Println(string(actual))
					test.Errorf("expected result [%s], but got [%s]", testData.expected, string(actual))
				}
			} else {
				if nil == actualErr {
					test.Errorf("expected an error [%s], but got nil", testData.expectedErr)
				}
				if testData.expected != string(actual) {
					test.Errorf("expect result on error [%s], but got [%s]", testData.expected, string(actual))
				}
			}
		})
	}
}
