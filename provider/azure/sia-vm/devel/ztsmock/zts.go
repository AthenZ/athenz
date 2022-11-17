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

package ztsmock

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"log"
	"math/big"
	"net"
	"net/http"
	"time"

	"github.com/AthenZ/athenz/clients/go/zts"
	"github.com/gorilla/mux"
)

var caKeyStr string
var caCertStr string

func SetupCA() (string, string) {

	key, err := generateKeyPair()
	if err != nil {
		log.Fatalf("Cannot generate private key: %v\n", err)
	}

	//create self-signed cert
	country := "US"
	province := "Oregon"
	locality := "Stafford"
	org := "Troy"
	unit := "Troy Certificate Authority"
	name := "Troy CA"
	certPem, err := createCACert(key, country, locality, province, org, unit, name, nil, nil)
	if err != nil {
		log.Fatalf("Cannot create CA Cert: %v\n", err)
	}

	return privatePem(key), certPem
}

func StartZtsServer(endPoint string) {
	router := mux.NewRouter()

	router.HandleFunc("/zts/v1/instance", func(w http.ResponseWriter, r *http.Request) {
		log.Println("/instance is called")

		body, err := io.ReadAll(r.Body)
		if err != nil {
			log.Fatalln("Could not read the body")
		}

		var data *zts.InstanceRegisterInformation
		err = json.Unmarshal(body, &data)
		if err != nil {
			log.Fatalln("Could not parse the body into zts.InstanceRegisterInformation")
		}

		caKey, err := privateKeyFromPem(caKeyStr)
		if err != nil {
			log.Fatalln("Could not generate caKey from string")
		}

		caCert, err := certFromPEM(caCertStr)
		if err != nil {
			log.Fatalln("Could not generate caCert from string")
		}

		service := fmt.Sprintf("%s.%s", data.Domain, data.Service)
		cert, err := generateCertInMemory(data.Csr, caKey, caCert, service)
		if err != nil {
			log.Fatalf("Could not generate cert in memory: %v\n", err)
		}

		identity := &zts.InstanceIdentity{
			Provider:              data.Provider,
			Name:                  zts.ServiceName(service),
			InstanceId:            "123456789012-vmid",
			X509CertificateSigner: caCertStr,
			X509Certificate:       cert,
		}
		identityBytes, err := json.Marshal(identity)
		if err == nil {
			w.WriteHeader(201)
			io.WriteString(w, string(identityBytes))
			log.Println("Successfully processed register instance request")
		}
	}).Methods("POST")

	router.HandleFunc("/zts/v1/instance/athenz.azure.west2/athenz/hockey/123456789012-vmid", func(w http.ResponseWriter, r *http.Request) {
		log.Println("instance refresh handler called")

		body, err := io.ReadAll(r.Body)
		if err != nil {
			log.Fatalln("Could not read the body")
		}
		var data *zts.InstanceRefreshInformation
		err = json.Unmarshal(body, &data)
		if err != nil {
			log.Fatalln("Could not parse the body into zts.InstanceRefreshInformation")
		}

		caKey, err := privateKeyFromPem(caKeyStr)
		if err != nil {
			log.Fatalln("Could not generate caKey from string")
		}

		caCert, err := certFromPEM(caCertStr)
		if err != nil {
			log.Fatalln("Could not generate caCert from string")
		}

		cert, err := generateCertInMemory(data.Csr, caKey, caCert, "athenz.hockey")
		if err != nil {
			log.Fatalf("Could not generate cert in memory: %v\n", err)
		}

		identity := &zts.InstanceIdentity{
			Provider:              "athenz.azure.west2",
			Name:                  zts.ServiceName("athenz.hockey"),
			InstanceId:            "123456789012-vmid",
			X509CertificateSigner: caCertStr,
			X509Certificate:       cert,
		}
		identityBytes, err := json.Marshal(identity)
		if err == nil {
			io.WriteString(w, string(identityBytes))
			log.Println("Successfully processed refresh instance request")
		}
	}).Methods("POST")

	router.HandleFunc("/zts/v1/rolecert", func(w http.ResponseWriter, r *http.Request) {
		log.Println("role certificate handler called")

		body, err := io.ReadAll(r.Body)
		if err != nil {
			log.Fatalln("Could not read the body")
		}
		var data *zts.RoleCertificateRequest
		err = json.Unmarshal(body, &data)
		if err != nil {
			log.Fatalln("Could not parse the body into zts.RoleCertificateRequest")
		}

		caKey, err := privateKeyFromPem(caKeyStr)
		if err != nil {
			log.Fatalln("Could not generate caKey from string")
		}

		caCert, err := certFromPEM(caCertStr)
		if err != nil {
			log.Fatalln("Could not generate caCert from string")
		}

		cert, err := generateCertInMemory(data.Csr, caKey, caCert, "athenz:role.writers")
		if err != nil {
			log.Fatalf("Could not generate cert in memory: %v\n", err)
		}

		identity := &zts.RoleCertificate{
			X509Certificate: cert,
		}
		identityBytes, err := json.Marshal(identity)
		if err == nil {
			io.WriteString(w, string(identityBytes))
			log.Println("Successfully processed role certificate request")
		}
	}).Methods("POST")

	err := http.ListenAndServe(endPoint, router)
	if err != nil {
		log.Fatalf("ListenAndServe: %v\n", err)
	}

}

func init() {
	caKeyStr, caCertStr = SetupCA()
}

func generateKeyPair() (*rsa.PrivateKey, error) {
	return rsa.GenerateKey(rand.Reader, 2048)
}

func createCACert(key *rsa.PrivateKey, country, locality, province, org, unit, cn string, hosts []string, ips []net.IP) (string, error) {
	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNumber, err := rand.Int(rand.Reader, serialNumberLimit)
	if err != nil {
		return "", err
	}
	algo := x509.SHA1WithRSA //for rsa
	notBefore := time.Now()
	validFor := 365 * 24 * time.Hour
	notAfter := notBefore.Add(validFor)
	subj := pkix.Name{
		CommonName:         cn,
		Country:            []string{country},
		Locality:           []string{locality},
		Province:           []string{province},
		Organization:       []string{org},
		OrganizationalUnit: []string{unit},
	}

	template := &x509.Certificate{
		Subject:               subj,
		SerialNumber:          serialNumber,
		PublicKeyAlgorithm:    x509.RSA,
		SignatureAlgorithm:    algo,
		NotBefore:             notBefore,
		NotAfter:              notAfter,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	if hosts != nil {
		template.DNSNames = hosts
	}
	if ips != nil {
		template.IPAddresses = ips
	}

	certBytes, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		return "", err
	}
	certOut := bytes.NewBuffer(make([]byte, 0))
	err = pem.Encode(certOut, &pem.Block{Type: "CERTIFICATE", Bytes: certBytes})
	if err != nil {
		return "", fmt.Errorf("Cannot encode Cert to PEM: %v", err)
	}
	return certOut.String(), nil
}

func privatePemBytes(privateKey *rsa.PrivateKey) []byte {
	privatePem := &pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(privateKey)}
	privateBytes := pem.EncodeToMemory(privatePem)
	return privateBytes
}

func privatePem(privateKey *rsa.PrivateKey) string {
	return string(privatePemBytes(privateKey))
}

func privateKeyFromPemBytes(pemBytes []byte) (*rsa.PrivateKey, error) {
	block, _ := pem.Decode(pemBytes)
	if block == nil {
		return nil, fmt.Errorf("no PEM block found")
	}
	return x509.ParsePKCS1PrivateKey(block.Bytes)
}

func privateKeyFromPem(pem string) (*rsa.PrivateKey, error) {
	return privateKeyFromPemBytes([]byte(pem))
}

func certFromPEM(pemString string) (*x509.Certificate, error) {
	return certFromPEMBytes([]byte(pemString))
}

func certFromPEMBytes(pemBytes []byte) (*x509.Certificate, error) {
	var derBytes []byte
	block, _ := pem.Decode(pemBytes)
	if block == nil {
		return nil, fmt.Errorf("Cannot parse cert (empty pem)")
	}
	derBytes = block.Bytes
	cert, err := x509.ParseCertificate(derBytes)
	if err != nil {
		return nil, err
	}
	return cert, nil
}

func generateCertInMemory(csrPem string, caKey *rsa.PrivateKey, caCert *x509.Certificate, cn string) (string, error) {
	csr, err := decodeCSR(csrPem)
	if err != nil {
		return "", err
	}
	if cn != "" && cn != csr.Subject.CommonName {
		return "", fmt.Errorf("CSR common name (%s) doesn't match expected common name (%s)", csr.Subject.CommonName, cn)
	}
	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNumber, err := rand.Int(rand.Reader, serialNumberLimit)
	algo := x509.SHA256WithRSA
	now := time.Now()
	tolerance := 15 * time.Minute // to account for time imprecision across machines
	notBefore := now.Add(-tolerance)
	validFor := 30 * 24 * time.Hour //30 day lifetime while debugging
	notAfter := notBefore.Add(validFor + tolerance)
	template := &x509.Certificate{
		Subject:               csr.Subject,
		SerialNumber:          serialNumber,
		PublicKeyAlgorithm:    csr.PublicKeyAlgorithm,
		SignatureAlgorithm:    algo,
		NotBefore:             notBefore,
		NotAfter:              notAfter,
		DNSNames:              csr.DNSNames,
		IPAddresses:           csr.IPAddresses,
		EmailAddresses:        csr.EmailAddresses,
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}

	cert, err := x509.CreateCertificate(rand.Reader, template, caCert, csr.PublicKey, caKey)
	if err != nil {
		return "", err
	}

	certOut := bytes.NewBuffer(make([]byte, 0))
	err = pem.Encode(certOut, &pem.Block{Type: "CERTIFICATE", Bytes: cert})
	if err != nil {
		return "", fmt.Errorf("Cannot encode Cert to PEM: %v", err)
	}
	return certOut.String(), nil
}

func decodeCSR(csr string) (*x509.CertificateRequest, error) {
	var derBytes []byte
	block, _ := pem.Decode([]byte(csr))
	if block == nil {
		return nil, fmt.Errorf("Cannot parse CSR (empty pem)")
	}
	derBytes = block.Bytes
	req, err := x509.ParseCertificateRequest(derBytes)
	if err != nil {
		return nil, err
	}
	err = req.CheckSignature()
	if err != nil {
		return nil, err
	}
	return req, nil
}
