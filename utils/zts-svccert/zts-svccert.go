package main

import (
	"bytes"
	"crypto"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"net"
	"net/http"
	"net/url"
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
	var caCertFile, certFile, signerCertFile, dnsDomain, hdr, ip string
	var subjC, subjO, subjOU, uri, provider, instance, instanceId string
	var attestationDataFile string
	var csr, spiffe bool
	var expiryTime int
	flag.BoolVar(&csr, "csr", false, "request csr only")
	flag.BoolVar(&spiffe, "spiffe", true, "include spiffe uri in csr")
	flag.IntVar(&expiryTime, "expiry-time", 0, "expiry time in minutes")
	flag.StringVar(&certFile, "cert-file", "", "output certificate file")
	flag.StringVar(&signerCertFile, "signer-cert-file", "", "output signer certificate file")
	flag.StringVar(&caCertFile, "cacert", "", "CA certificate file")
	flag.StringVar(&serviceKey, "private-key", "", "private key file (required)")
	flag.StringVar(&serviceCert, "service-cert", "", "service certificate file")
	flag.StringVar(&domain, "domain", "", "domain of service (required)")
	flag.StringVar(&service, "service", "", "name of service (required)")
	flag.StringVar(&keyID, "key-version", "", "key version")
	flag.StringVar(&ztsURL, "zts", "", "url of the ZTS Service")
	flag.StringVar(&dnsDomain, "dns-domain", "", "dns domain suffix to be included in the csr (required)")
	flag.StringVar(&hdr, "hdr", "Athenz-Principal-Auth", "Header name")
	flag.StringVar(&subjC, "subj-c", "US", "Subject C/Country field")
	flag.StringVar(&subjO, "subj-o", "Oath Inc.", "Subject O/Organization field")
	flag.StringVar(&subjOU, "subj-ou", "Athenz", "Subject OU/OrganizationalUnit field")
	flag.StringVar(&ip, "ip", "", "IP address")
	flag.StringVar(&provider, "provider", "", "Athenz Provider")
	flag.StringVar(&instance, "instance", "", "Instance Id")
	flag.StringVar(&attestationDataFile, "attestation-data", "", "Attestation Data File")
	flag.Parse()

	if serviceKey == "" || domain == "" || service == "" || dnsDomain == "" {
		log.Fatalln("Error: missing required attributes. Run with -help for command line arguments")
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
	// note: RFC 6125 states that if the SAN (Subject Alternative Name) exists,
	// it is used, not the CA. So, we will always put the Athenz name in the CN
	// (it is *not* a DNS domain name), and put the host name into the SAN.

	hyphenDomain := strings.Replace(domain, ".", "-", -1)
	host := fmt.Sprintf("%s.%s.%s", service, hyphenDomain, dnsDomain)
	commonName := fmt.Sprintf("%s.%s", domain, service)
	if instance != "" {
		uriProvider := "zts"
		if provider != "" {
			uriProvider = provider
		}
		instanceId = fmt.Sprintf("athenz://instanceid/%s/%s", uriProvider, instance)
	}
	if spiffe {
		uri = fmt.Sprintf("spiffe://%s/sa/%s", domain, service)
	}

	subj := pkix.Name{
		CommonName:         commonName,
		OrganizationalUnit: []string{subjOU},
		Organization:       []string{subjO},
		Country:            []string{subjC},
	}

	csrData, err := generateCSR(pkSigner, subj, host, instanceId, ip, uri)
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
		log.Fatalln("Error: missing ZTS Server url. Run with -help for command line arguments")
	}

	// if we're given a certificate then we'll use that otherwise
	// we're going to generate a ntoken for our request unless
	// we're using copper argos which only uses tls and the attestation
	// data contains the authentication details

	var client *zts.ZTSClient
	if provider != "" {
		client, err = certClient(ztsURL, nil, "", caCertFile)
	} else if serviceCert == "" {
		client, err = ntokenClient(ztsURL, domain, service, keyID, caCertFile, hdr, keyBytes)
	} else {
		client, err = certClient(ztsURL, keyBytes, serviceCert, caCertFile)
	}
	if err != nil {
		log.Fatalln(err)
	}

	var certificate, caCertificates string

	// if we're given provider then we're going to use our
	// copper argos model to request the certificate
	if provider != "" {

		if instanceId == "" {
			log.Fatalln("Error: Please specify instance value. Run with -help for command line arguments")
		}
		attestationData := ""
		if attestationDataFile != "" {
			attestationDataBytes, err := ioutil.ReadFile(attestationDataFile)
			if err != nil {
				log.Fatalln(err)
			}
			attestationData = string(attestationDataBytes)
		} else {
			attestationData, err = getNToken(domain, service, keyID, keyBytes)
			if err != nil {
				log.Fatalln(err)
			}
		}
		req := &zts.InstanceRegisterInformation{
			Provider:        zts.ServiceName(provider),
			Domain:          zts.DomainName(domain),
			Service:         zts.SimpleName(service),
			AttestationData: attestationData,
			Csr:             csrData,
		}

		// request a tls certificate for this service
		identity, _, err := client.PostInstanceRegisterInformation(req)
		if err != nil {
			log.Fatalln(err)
		}

		certificate = identity.X509Certificate
		caCertificates = identity.X509CertificateSigner

	} else {

		expiryTime32 := int32(expiryTime)
		req := &zts.InstanceRefreshRequest{
			Csr:        csrData,
			KeyId:      keyID,
			ExpiryTime: &expiryTime32,
		}

		// request a tls certificate for this service
		identity, err := client.PostInstanceRefreshRequest(zts.CompoundName(domain), zts.SimpleName(service), req)
		if err != nil {
			log.Fatalln(err)
		}

		certificate = identity.Certificate
		caCertificates = identity.CaCertBundle
	}

	if certFile != "" {
		err = ioutil.WriteFile(certFile, []byte(certificate), 0444)
		if err != nil {
			log.Fatalln(err)
		}
	} else {
		fmt.Println(certificate)
	}

	if signerCertFile != "" {
		err = ioutil.WriteFile(signerCertFile, []byte(caCertificates), 0444)
		if err != nil {
			log.Fatalln(err)
		}
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

func generateCSR(keySigner *signer, subj pkix.Name, host, instanceId, ip, uri string) (string, error) {

	template := x509.CertificateRequest{
		Subject:            subj,
		SignatureAlgorithm: keySigner.algorithm,
	}
	if host != "" {
		template.DNSNames = []string{host}
	}
	if uri != "" {
		uriptr, err := url.Parse(uri)
		if err == nil {
			template.URIs = []*url.URL{uriptr}
		}
	}
	if instanceId != "" {
		uriptr, err := url.Parse(instanceId)
		if err == nil {
			if len(template.URIs) > 0 {
				template.URIs = append(template.URIs, uriptr)
			} else {
				template.URIs = []*url.URL{uriptr}
			}
		}
	}
	if ip != "" {
		template.IPAddresses = []net.IP{net.ParseIP(ip)}
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

func getNToken(domain, service, keyID string, keyBytes []byte) (string, error) {

	if keyID == "" {
		return "", errors.New("Missing key-version for the specified private key")
	}

	// get token builder instance
	builder, err := zmssvctoken.NewTokenBuilder(domain, service, keyBytes, keyID)
	if err != nil {
		return "", err
	}

	// set optional attributes
	builder.SetExpiration(10 * time.Minute)

	// get a token instance that always gives you unexpired tokens values
	// safe for concurrent use
	tok := builder.Token()

	// get a token for use
	return tok.Value()
}

func ntokenClient(ztsURL, domain, service, keyID, caCertFile, hdr string, keyBytes []byte) (*zts.ZTSClient, error) {

	ntoken, err := getNToken(domain, service, keyID, keyBytes)
	if err != nil {
		return nil, err
	}
	transport := &http.Transport{
		Proxy:                 http.ProxyFromEnvironment,
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
	var certpem []byte
	var err error
	if certfile != "" {
		certpem, err = ioutil.ReadFile(certfile)
		if err != nil {
			return nil, err
		}
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
		Proxy:           http.ProxyFromEnvironment,
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
