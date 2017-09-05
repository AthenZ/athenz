// Copyright 2017 Yahoo Holdings, Inc.
// Licensed under the terms of the Apache version 2.0 license. See LICENSE file for terms.

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

	"github.com/yahoo/athenz/clients/go/zts"
)

type signer struct {
	key       crypto.Signer
	algorithm x509.SignatureAlgorithm
}

func main() {

	var ztsUrl, svcKeyFile, svcCertFile, domain, service string
	var caCertFile, roleCertFile, roleDomain, roleName, dnsDomain string
	flag.StringVar(&roleCertFile, "role-cert-file", "", "output role certificate file")
	flag.StringVar(&caCertFile, "cacert", "", "CA certificate file")
	flag.StringVar(&svcKeyFile, "svc-key-file", "", "service identity private key file")
	flag.StringVar(&svcCertFile, "svc-cert-file", "", "service identity certificate file")
	flag.StringVar(&domain, "domain", "", "domain of service")
	flag.StringVar(&service, "service", "", "name of service")
	flag.StringVar(&ztsUrl, "zts", "", "url of the ZTS Service")
	flag.StringVar(&roleDomain, "role-domain", "", "requested role domain name")
	flag.StringVar(&roleName, "role-name", "", "requested role name in the role-domain")
	flag.StringVar(&dnsDomain, "dns-domain", "", "dns domain suffix to be included in the csr")
	flag.Parse()

	if svcKeyFile == "" || svcCertFile == "" || domain == "" || service == "" ||
		ztsUrl == "" || dnsDomain == "" || roleDomain == "" || roleName == "" {
		log.Fatalf("usage: zts-rolecert -domain <domain> -service <service> -svc-key-file <key-file> -svc-cert-file <cert-file> -zts <zts-server-url> -role-domain <domain> -role-name <name> -dns-domain <dns-domain> [-role-cert-file <output-cert-file>] [-cacert <ca-certificate-file>]\n")
	}

	hyphenDomain := strings.Replace(domain, ".", "-", -1)
	host := fmt.Sprintf("%s.%s.%s", service, hyphenDomain, dnsDomain)
	rfc822 := fmt.Sprintf("%s.%s@%s", domain, service, dnsDomain)

	client, err := ztsClient(ztsUrl, host, svcKeyFile, svcCertFile, caCertFile)
	if err != nil {
		log.Fatalf("Unable to initialize ZTS Client for %s, err: %v\n", ztsUrl, err)
	}

	// load private key
	bytes, err := ioutil.ReadFile(svcKeyFile)
	if err != nil {
		log.Fatalf("Unable to read private key file %s, err: %v\n", svcKeyFile, err)
	}

	// get our private key signer for csr
	pkSigner, err := newSigner(bytes)
	if err != nil {
		log.Fatalf("Unable to retrieve private key %s, err: %v\n", svcKeyFile, err)
	}

	getRoleCertificate(client, pkSigner, host, rfc822, roleDomain, roleName, roleCertFile)
}

func generateCSR(keySigner *signer, roleDomain, roleName, host, rfc822 string) (string, error) {
	//note: RFC 6125 states that if the SAN (Subject Alternative Name) exists,
	//it is used, not the CA. So, we will always put the Athens name in the CN
	//(it is *not* a DNS domain name), and put the host name into the SAN.
	commonName := fmt.Sprintf("%s:role.%s", roleDomain, roleName)
	subj := pkix.Name{CommonName: commonName}
	subj.Country = []string{"US"}
	subj.Province = []string{"CA"}
	subj.Organization = []string{"Oath"}
	subj.OrganizationalUnit = []string{"Athenz"}

	template := x509.CertificateRequest{
		Subject:            subj,
		SignatureAlgorithm: x509.SHA256WithRSA,
	}
	if host != "" {
		template.DNSNames = []string{host}
	}
	if rfc822 != "" {
		template.EmailAddresses = []string{rfc822}
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

func getRoleCertificate(client *zts.ZTSClient, keySigner *signer, host, rfc822, roleDomain, roleName, roleCertFile string) bool {

	var roleRequest = new(zts.RoleCertificateRequest)
	csr, err := generateCSR(keySigner, roleDomain, roleName, host, rfc822)
	if err != nil {
		log.Printf("Unable to generate CSR for %s, err: %v\n", roleName, err)
		return false
	}

	roleRequest.Csr = csr
	roleToken, err := client.PostRoleCertificateRequest(zts.DomainName(roleDomain), zts.EntityName(roleName), roleRequest)
	if err != nil {
		log.Printf("PostRoleCertificateRequest failed for %s, err: %v\n", roleName, err)
		return false
	}

	if roleCertFile != "" {
		err = ioutil.WriteFile(roleCertFile, []byte(roleToken.Token), 0444)
		if err != nil {
			log.Printf("Unable to save role token certificate in %s, err: %v\n", roleCertFile, err)
			return false
		}
	} else {
		fmt.Println(roleToken.Token)
	}

	return true
}

func ztsClient(ztsUrl, ztsHostName, keyFile, certFile, caFile string) (*zts.ZTSClient, error) {
	config, err := tlsConfiguration(keyFile, certFile, caFile)
	if err != nil {
		return nil, err
	}
	tr := &http.Transport{
		TLSClientConfig: config,
	}
	client := zts.NewClient(ztsUrl, tr)
	return &client, nil
}

func tlsConfiguration(keyFile, certFile, caFile string) (*tls.Config, error) {
	var capem []byte
	var err error
	if caFile != "" {
		capem, err = ioutil.ReadFile(caFile)
		if err != nil {
			return nil, err
		}
	}
	var keypem []byte
	var certpem []byte
	if keyFile != "" && certFile != "" {
		keypem, err = ioutil.ReadFile(keyFile)
		if err != nil {
			return nil, err
		}
		certpem, err = ioutil.ReadFile(certFile)
		if err != nil {
			return nil, err
		}
	}
	return tlsConfigurationFromPEM(keypem, certpem, capem)
}

func tlsConfigurationFromPEM(keypem, certpem, capem []byte) (*tls.Config, error) {
	config := &tls.Config{}

	certPool := x509.NewCertPool()
	if capem != nil {
		if !certPool.AppendCertsFromPEM(capem) {
			return nil, fmt.Errorf("Failed to append certs to pool")
		}
		config.RootCAs = certPool
	}

	if certpem != nil && keypem != nil {
		mycert, err := tls.X509KeyPair(certpem, keypem)
		if err != nil {
			return nil, err
		}
		config.Certificates = make([]tls.Certificate, 1)
		config.Certificates[0] = mycert

		config.ClientCAs = certPool
		config.ClientAuth = tls.VerifyClientCertIfGiven
	}

	//Use only modern ciphers
	config.CipherSuites = []uint16{tls.TLS_RSA_WITH_AES_128_CBC_SHA,
		tls.TLS_RSA_WITH_AES_256_CBC_SHA,
		tls.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA,
		tls.TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA,
		tls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
		tls.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,
		tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
		tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256}

	//Use only TLS v1.2
	config.MinVersion = tls.VersionTLS12

	//Don't allow session resumption
	config.SessionTicketsDisabled = true
	return config, nil
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
