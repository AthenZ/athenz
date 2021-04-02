package driver

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"github.com/AthenZ/athenz/clients/go/zts"
	"io/ioutil"
	"log"
	"math/big"
	"net"
	"net/http"
	"time"
)

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
		PublicKey:             key.PublicKey,
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

func SetupCA() (string, string) {

	key, err := generateKeyPair()
	if err != nil {
		log.Fatalf("Cannot generate private key: %v", err)
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
		log.Fatalf("Cannot create CA Cert: %v", err)
	}

	return privatePem(key), certPem
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
		PublicKey:             csr.PublicKey,
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

func GenerateRefreshIdentity(r *http.Request, domain, service, caKeyStr, caCertStr string) string {
	// Extract CSR from the body
	body, err := ioutil.ReadAll(r.Body)
	if err != nil {
		log.Fatalf("Could not read the body")
	}
	var data *zts.InstanceRefreshInformation
	err = json.Unmarshal(body, &data)
	if err != nil {
		log.Fatalf("Could not parse the body into zts.InstanceRefreshInformation")
	}

	name := fmt.Sprintf("%s.%s", domain, service)

	return generateIdentity(err, caKeyStr, caCertStr, data.Csr, name)
}

func GenerateRegisterIdentity(r *http.Request, caKeyStr, caCertStr string) string {
	// Extract CSR from the body
	body, err := ioutil.ReadAll(r.Body)
	if err != nil {
		log.Fatalf("Could not read the body")
	}
	var data *zts.InstanceRegisterInformation
	err = json.Unmarshal(body, &data)
	if err != nil {
		log.Fatalf("Could not parse the body into zts.InstanceRefreshInformation")
	}

	name := fmt.Sprintf("%s.%s", data.Domain, data.Service)

	return generateIdentity(err, caKeyStr, caCertStr, data.Csr, name)
}

func generateIdentity(err error, caKeyStr string, caCertStr string, csr, name string) string {
	caKey, err := privateKeyFromPem(caKeyStr)
	if err != nil {
		log.Fatalf("Could not generate caKey from string")
	}

	caCert, err := certFromPEM(caCertStr)
	if err != nil {
		log.Fatalf("Could not generate caCert from string")
	}

	cert, err := generateCertInMemory(csr, caKey, caCert, name)
	if err != nil {
		log.Fatalf("Could not generate cert in memory: %v", err)
	}

	identity := &zts.InstanceIdentity{
		Provider:              "athenz.aws.us-west-2",
		Name:                  zts.ServiceName(name),
		InstanceId:            "i-03d1ae7035f931a90",
		X509CertificateSigner: caCertStr,
		X509Certificate:       cert,
	}
	identityBytes, err := json.Marshal(identity)

	return string(identityBytes)
}

func GenerateRoleCertificate(r *http.Request, caKeyStr, caCertStr string) string {
	// Extract CSR from the body
	body, err := ioutil.ReadAll(r.Body)
	if err != nil {
		log.Fatalf("Could not read the body")
	}
	var data *zts.RoleCertificateRequest
	err = json.Unmarshal(body, &data)
	if err != nil {
		log.Fatalf("Could not parse the body into zts.RoleCertificateRequest")
	}

	caKey, err := privateKeyFromPem(caKeyStr)
	if err != nil {
		log.Fatalf("Could not generate caKey from string")
	}

	caCert, err := certFromPEM(caCertStr)
	if err != nil {
		log.Fatalf("Could not generate caCert from string")
	}

	cert, err := generateCertInMemory(data.Csr, caKey, caCert, "athenz:role.writers")
	if err != nil {
		log.Fatalf("Could not generate cert in memory: %v", err)
	}

	identity := &zts.RoleToken{
		ExpiryTime: 10000,
		Token:      cert,
	}
	identityBytes, err := json.Marshal(identity)

	return string(identityBytes)
}
