package main

import (
	"bytes"
	"crypto"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"strings"
	"time"

	"github.com/yahoo/athenz/clients/go/zts"
	"github.com/yahoo/athenz/libs/go/zmssvctoken"
)

type signer struct {
	key       crypto.Signer
	algorithm x509.SignatureAlgorithm
}

func main() {
	var ztsURL, serviceKey, serviceCert, domain, service, keyID string
	var caCertFile, certFile, signerCertFile, dnsDomain, hdr string
	var csr bool
	var expiryTime int
	flag.BoolVar(&csr, "csr", false, "request csr only")
	flag.IntVar(&expiryTime, "expiry-time", 0, "expiry time in seconds")
	flag.StringVar(&certFile, "cert-file", "", "output certificate file")
	flag.StringVar(&signerCertFile, "signer-cert-file", "", "output signer certificate file")
	flag.StringVar(&caCertFile, "cacert", "", "CA certificate file")
	flag.StringVar(&serviceKey, "private-key", "", "private key file")
	flag.StringVar(&serviceCert, "service-cert", "", "service certificate file")
	flag.StringVar(&domain, "domain", "", "domain of service")
	flag.StringVar(&service, "service", "", "name of service")
	flag.StringVar(&keyID, "key-version", "", "key version")
	flag.StringVar(&ztsURL, "zts", "", "url of the ZTS Service")
	flag.StringVar(&dnsDomain, "dns-domain", "", "dns domain suffix to be included in the csr")
	flag.StringVar(&hdr, "hdr", "Athenz-Principal-Auth", "Header name")
	flag.Parse()

	if serviceKey == "" || domain == "" || service == "" ||
		keyID == "" || dnsDomain == "" {
		fmt.Println("Error: missing required attributes")
		usage()
	}

	// load private key
	keyBytes, err := ioutil.ReadFile(serviceKey)
	if err != nil {
		log.Fatalln(err)
	}

	// get our private key signer for csr
	pkSigner, err := newSigner(keyBytes)
	if err != nil {
		log.Fatalln(err)
	}

	// generate a csr for this service
	hyphenDomain := strings.Replace(domain, ".", "-", -1)
	host := fmt.Sprintf("%s.%s.%s", service, hyphenDomain, dnsDomain)
	commonName := fmt.Sprintf("%s.%s", domain, service)
	csrData, err := generateCSR(pkSigner, commonName, host)
	if err != nil {
		log.Fatalln(err)
	}

	// if we're provided the csr flag then we're going to display
	// it and return right away
	if csr {
		fmt.Println(csrData)
		return
	}

	// for all other operations we need to have ZTS Server url
	if ztsURL == "" {
		fmt.Println("Error: missing ZTS Server url")
		usage()
	}

	// if we're given a certficate then we'll use that otherwise
	// we're going to generate a ntoken for our request
	var client *zts.ZTSClient
	if serviceCert == "" {
		client, err = ntokenClient(ztsURL, domain, service, keyID, caCertFile, hdr, keyBytes)
	} else {
		client, err = certClient(ztsURL, keyBytes, serviceCert, caCertFile)
	}
	if err != nil {
		log.Fatalln(err)
	}

	expiryTime32 := int32(expiryTime)
	req := &zts.InstanceRefreshRequest{Csr: csrData, KeyId: keyID, ExpiryTime: &expiryTime32}

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

	if signerCertFile != "" {
		err = ioutil.WriteFile(signerCertFile, []byte(identity.CaCertBundle), 0444)
		if err != nil {
			log.Fatalln(err)
		}
	}
}

func usage() {
	log.Fatalln("usage: zts-svccert [-csr] -domain <domain> -service <service> -private-key <key-file> -key-version <version> -zts <zts-server-url> -dns-domain <dns-domain> [-cert-file <output-cert-file>] [-signer-cert-file <output-signer-file>] [-cacert <ca-certificate-file>] [-hdr <auth-header-name>]")
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
		return &signer{key: key, algorithm: x509.ECDSAWithSHA256}, nil
	case "RSA PRIVATE KEY":
		key, err := x509.ParsePKCS1PrivateKey(block.Bytes)
		if err != nil {
			return nil, err
		}
		return &signer{key: key, algorithm: x509.SHA256WithRSA}, nil
	default:
		return nil, fmt.Errorf("Unsupported private key type: %s", block.Type)
	}
}

func generateCSR(keySigner *signer, commonName, host string) (string, error) {
	// note: RFC 6125 states that if the SAN (Subject Alternative Name) exists,
	// it is used, not the CA. So, we will always put the Athenz name in the CN
	// (it is *not* a DNS domain name), and put the host name into the SAN.
	subj := pkix.Name{CommonName: commonName}
	subj.OrganizationalUnit = []string{"Athenz"}
	subj.Country = []string{"US"}
	subj.Organization = []string{"Oath Inc."}

	template := x509.CertificateRequest{
		Subject:            subj,
		SignatureAlgorithm: keySigner.algorithm,
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

func ntokenClient(ztsURL, domain, service, keyID, caCertFile, hdr string, keyBytes []byte) (*zts.ZTSClient, error) {
	// get token builder instance
	builder, err := zmssvctoken.NewTokenBuilder(domain, service, keyBytes, keyID)
	if err != nil {
		return nil, err
	}

	// set optional attributes
	builder.SetExpiration(10 * time.Minute)

	// get a token instance that always gives you unexpired tokens values
	// safe for concurrent use
	tok := builder.Token()

	// get a token for use
	ntoken, err := tok.Value()
	if err != nil {
		return nil, err
	}

	transport := &http.Transport{
		ResponseHeaderTimeout: 30 * time.Second,
	}
	if caCertFile != "" {
		config := &tls.Config{}
		certPool := x509.NewCertPool()
		caCert, err := ioutil.ReadFile(caCertFile)
		if err != nil {
			return nil, err
		}
		certPool.AppendCertsFromPEM(caCert)
		config.RootCAs = certPool
		transport.TLSClientConfig = config
	}
	// use the ntoken to talk to Athenz
	client := zts.NewClient(ztsURL, transport)
	client.AddCredentials(hdr, ntoken)
	return &client, nil
}

func certClient(ztsURL string, keyBytes []byte, certfile, caCertFile string) (*zts.ZTSClient, error) {
	certpem, err := ioutil.ReadFile(certfile)
	if err != nil {
		return nil, err
	}
	var cacertpem []byte
	if caCertFile != "" {
		cacertpem, err = ioutil.ReadFile(caCertFile)
		if err != nil {
			return nil, err
		}
	}
	config, err := tlsConfiguration(keyBytes, certpem, cacertpem)
	if err != nil {
		return nil, err
	}
	transport := &http.Transport{
		TLSClientConfig: config,
	}
	client := zts.NewClient(ztsURL, transport)
	return &client, nil
}

func tlsConfiguration(keypem, certpem, cacertpem []byte) (*tls.Config, error) {
	config := &tls.Config{}
	if certpem != nil && keypem != nil {
		mycert, err := tls.X509KeyPair(certpem, keypem)
		if err != nil {
			return nil, err
		}
		config.Certificates = make([]tls.Certificate, 1)
		config.Certificates[0] = mycert
	}
	if cacertpem != nil {
		certPool := x509.NewCertPool()
		certPool.AppendCertsFromPEM(cacertpem)
		config.RootCAs = certPool
	}
	return config, nil
}
