package main

import (
	"bytes"
	"crypto"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"strings"
	"time"

	"github.com/yahoo/athenz/clients/go/zts"
	"github.com/yahoo/athenz/libs/go/zmssvctoken"
)

const authHeader = "Athenz-Principal-Auth"

type signer struct {
	key crypto.Signer
}

func main() {

	var ztsUrl, privateKeyFile, domain, service, keyVersion, certFile, dnsDomain string
	flag.StringVar(&certFile, "cert-file", "", "output certificate file")
	flag.StringVar(&privateKeyFile, "private-key", "", "private key file")
	flag.StringVar(&domain, "domain", "", "domain of service")
	flag.StringVar(&service, "service", "", "name of service")
	flag.StringVar(&keyVersion, "key-version", "", "key version")
	flag.StringVar(&ztsUrl, "zts", "", "url of the ZTS Service")
	flag.StringVar(&dnsDomain, "dns-domain", "", "dns domain suffix to be included in the csr")
	flag.Parse()

	if privateKeyFile == "" || domain == "" || service == "" ||
		keyVersion == "" || ztsUrl == "" || dnsDomain == "" {
		log.Fatalln("usage: zts-svccert -domain <domain> -service <service> -private-key <key-file> -key-version <version> -zts <zts-server-url> -dns-domain <dns-domain> [-cert-file <output-cert-file>]")
	}

	// load private key
	bytes, err := ioutil.ReadFile(privateKeyFile)
	if err != nil {
		log.Fatalln(err)
	}

	// get token builder instance
	builder, err := zmssvctoken.NewTokenBuilder(domain, service, bytes, keyVersion)
	if err != nil {
		log.Fatalln(err)
	}

	// set optional attributes
	builder.SetExpiration(10 * time.Minute)

	// get a token instance that always gives you unexpired tokens values
	// safe for concurrent use
	tok := builder.Token()

	// get a token for use
	ntoken, err := tok.Value()
	if err != nil {
		log.Fatalln(err)
	}

	// use the ntoken to talk to Athenz
	client := zts.NewClient(ztsUrl, nil)
	client.AddCredentials(authHeader, ntoken)

	// get our private key signer for csr
	pkSigner, err := newSigner(bytes)
	if err != nil {
		log.Fatalln(err)
	}

	// generate a csr for this service

	hyphenDomain := strings.Replace(domain, ".", "-", -1)
	host := fmt.Sprintf("%s.%s.%s", service, hyphenDomain, dnsDomain)
	commonName := fmt.Sprintf("%s.%s", domain, service)
	csr, err := generateCSR(pkSigner, commonName, host)
	if err != nil {
		log.Fatalln(err)
	}
	req := &zts.InstanceRefreshRequest{Csr: csr}

	// request a tls certificate for this service
	identity, err := client.PostInstanceRefreshRequest(zts.CompoundName(domain), zts.SimpleName(service), req)
	if err != nil {
		log.Fatalln(err)
	}

	if certFile != "" {
		err = ioutil.WriteFile(certFile, []byte(identity.Certificate), 0444)
		if err != nil {
			log.Fatalln(err)
		}
	} else {
		fmt.Println(identity.Certificate)
	}
}

func newSigner(privateKeyPEM []byte) (*signer, error) {
	block, _ := pem.Decode(privateKeyPEM)
	if block == nil {
		return nil, fmt.Errorf("Unable to load private key")
	}

	switch block.Type {
	case "EC PRIVATE KEY":
		key, err := x509.ParseECPrivateKey(block.Bytes)
		if err != nil {
			return nil, err
		}
		return &signer{key: key}, nil
	case "RSA PRIVATE KEY":
		key, err := x509.ParsePKCS1PrivateKey(block.Bytes)
		if err != nil {
			return nil, err
		}
		return &signer{key: key}, nil
	default:
		return nil, fmt.Errorf("Unsupported private key type: %s", block.Type)
	}
}

func generateCSR(keySigner *signer, commonName, host string) (string, error) {
	//note: RFC 6125 states that if the SAN (Subject Alternative Name) exists,
	//it is used, not the CA. So, we will always put the Athenz name in the CN
	//(it is *not* a DNS domain name), and put the host name into the SAN.
	subj := pkix.Name{CommonName: commonName}
	subj.OrganizationalUnit = []string{"Athenz"}

	template := x509.CertificateRequest{
		Subject:            subj,
		SignatureAlgorithm: x509.SHA256WithRSA,
	}
	if host != "" {
		template.DNSNames = []string{host}
	}
	csr, err := x509.CreateCertificateRequest(rand.Reader, &template, keySigner.key)
	if err != nil {
		return "", fmt.Errorf("Cannot create CSR: %v", err)
	}
	block := &pem.Block{
		Type:  "CERTIFICATE REQUEST",
		Bytes: csr,
	}
	var buf bytes.Buffer
	err = pem.Encode(&buf, block)
	if err != nil {
		return "", fmt.Errorf("Cannot encode CSR to PEM: %v", err)
	}
	return buf.String(), nil
}
