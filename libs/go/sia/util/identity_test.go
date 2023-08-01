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
	"encoding/json"
	"fmt"
	"github.com/AthenZ/athenz/clients/go/zts"
	"github.com/dimfeld/httptreemux"
	"io"
	"log"
	"net"
	"net/http"
	"os"
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
