// Copyright 2017 Yahoo Holdings, Inc.
// Licensed under the terms of the Apache version 2.0 license. See LICENSE file for terms.

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
	"net"
	"net/url"
	"strings"

	"github.com/yahoo/athenz/clients/go/zts"
	"github.com/yahoo/athenz/libs/go/athenzutils"
)

type signer struct {
	key       crypto.Signer
	algorithm x509.SignatureAlgorithm
}

func main() {

	var ztsURL, svcKeyFile, svcCertFile, roleKeyFile, dom, svc string
	var caCertFile, roleCertFile, roleDomain, roleName, dnsDomain string
	var subjC, subjO, subjOU, ip, uri string
	var spiffe, csr, proxy bool
	var expiryTime int

	flag.StringVar(&roleKeyFile, "role-key-file", "", "role cert private key file (default: service identity private key)")
	flag.StringVar(&roleCertFile, "role-cert-file", "", "output role certificate file")
	flag.StringVar(&caCertFile, "cacert", "", "CA certificate file")
	flag.StringVar(&svcKeyFile, "svc-key-file", "", "service identity private key file (required)")
	flag.StringVar(&svcCertFile, "svc-cert-file", "", "service identity certificate file (required)")
	flag.StringVar(&dom, "domain", "", "domain of service")
	flag.StringVar(&svc, "service", "", "name of service")
	flag.StringVar(&ztsURL, "zts", "", "url of the ZTS Service (required)")
	flag.StringVar(&roleDomain, "role-domain", "", "requested role domain name (required)")
	flag.StringVar(&roleName, "role-name", "", "requested role name in the role-domain (required)")
	flag.StringVar(&dnsDomain, "dns-domain", "", "dns domain suffix to be included in the csr (required)")
	flag.StringVar(&subjC, "subj-c", "US", "Subject C/Country field")
	flag.StringVar(&subjO, "subj-o", "Oath Inc.", "Subject O/Organization field")
	flag.StringVar(&subjOU, "subj-ou", "Athenz", "Subject OU/OrganizationalUnit field")
	flag.StringVar(&ip, "ip", "", "IP address")
	flag.BoolVar(&spiffe, "spiffe", true, "include spiffe uri in csr")
	flag.BoolVar(&csr, "csr", false, "request csr only")
	flag.IntVar(&expiryTime, "expiry-time", 0, "expiry time in minutes")
	flag.BoolVar(&proxy, "proxy", true, "enable proxy mode for request")

	flag.Parse()

	if svcKeyFile == "" || svcCertFile == "" || roleDomain == "" || roleName == "" ||
		ztsURL == "" || dnsDomain == "" {
		log.Fatalln("Error: missing required attributes. Run with -help for command line arguments")
	}

	// If a separate private key is not provided for role cert csr, use service identity private key
	if roleKeyFile == "" {
		roleKeyFile = svcKeyFile
	}

	// let's extract our domain/service values from our certificate

	domain, service, err := extractServiceDetailsFromCert(svcCertFile)
	if err != nil {
		log.Fatalf("Unable to extract service details from certificate: %v\n", err)
	}
	hyphenDomain := strings.Replace(domain, ".", "-", -1)
	host := fmt.Sprintf("%s.%s.%s", service, hyphenDomain, dnsDomain)
	rfc822 := fmt.Sprintf("%s.%s@%s", domain, service, dnsDomain)
	if spiffe {
		uri = fmt.Sprintf("spiffe://%s/ra/%s", roleDomain, roleName)
	}

	//note: RFC 6125 states that if the SAN (Subject Alternative Name) exists,
	//it is used, not the CA. So, we will always put the Athens name in the CN
	//(it is *not* a DNS domain name), and put the host name into the SAN.

	commonName := fmt.Sprintf("%s:role.%s", roleDomain, roleName)
	subj := pkix.Name{
		CommonName:         commonName,
		OrganizationalUnit: []string{subjOU},
		Organization:       []string{subjO},
		Country:            []string{subjC},
	}

	// load private key
	bytes, err := ioutil.ReadFile(roleKeyFile)
	if err != nil {
		log.Fatalf("Unable to read private key file %s, err: %v\n", roleKeyFile, err)
	}

	// get our private key signer for csr
	pkSigner, err := newSigner(bytes)
	if err != nil {
		log.Fatalf("Unable to retrieve private key %s, err: %v\n", svcKeyFile, err)
	}

	csrData, err := generateCSR(pkSigner, subj, host, rfc822, ip, uri)
	if err != nil {
		log.Fatalf("Unable to generate CSR for %s, err: %v\n", roleName, err)
	}

	// if we're provided the csr flag then we're going to display
	// it and return right away
	if csr {
		fmt.Println(csrData)
		return
	}

	client, err := athenzutils.ZtsClient(ztsURL, svcKeyFile, svcCertFile, caCertFile, proxy)
	if err != nil {
		log.Fatalf("Unable to initialize ZTS Client for %s, err: %v\n", ztsURL, err)
	}

	getRoleCertificate(client, csrData, roleDomain, roleName, roleCertFile, int64(expiryTime))
}

func extractServiceDetailsFromCert(certFile string) (string, string, error) {
	data, err := ioutil.ReadFile(certFile)
	if err != nil {
		return "", "", err
	}
	block, _ := pem.Decode(data)
	if block == nil {
		return "", "", fmt.Errorf("cannot decode pem from certificate file: %s", certFile)
	}

	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return "", "", err
	}
	cn := cert.Subject.CommonName
	idx := strings.LastIndex(cn, ".")
	if idx < 0 {
		return "", "", fmt.Errorf("cannot determine domain/service from certificate: %s", cn)
	}
	return cn[:idx], cn[idx+1:], nil
}

func generateCSR(keySigner *signer, subj pkix.Name, host, rfc822, ip, uri string) (string, error) {

	template := x509.CertificateRequest{
		Subject:            subj,
		SignatureAlgorithm: keySigner.algorithm,
	}
	if host != "" {
		template.DNSNames = []string{host}
	}
	if rfc822 != "" {
		template.EmailAddresses = []string{rfc822}
	}
	if ip != "" {
		template.IPAddresses = []net.IP{net.ParseIP(ip)}
	}
	if uri != "" {
		uriptr, err := url.Parse(uri)
		if err == nil {
			template.URIs = []*url.URL{uriptr}
		}
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

func getRoleCertificate(client *zts.ZTSClient, csr, roleDomain, roleName, roleCertFile string, expiryTime int64) {

	roleRequest := &zts.RoleCertificateRequest{
		Csr:        csr,
		ExpiryTime: expiryTime,
	}
	roleToken, err := client.PostRoleCertificateRequest(zts.DomainName(roleDomain), zts.EntityName(roleName), roleRequest)
	if err != nil {
		log.Fatalf("PostRoleCertificateRequest failed for %s, err: %v\n", roleName, err)
	}

	if roleCertFile != "" {
		err = ioutil.WriteFile(roleCertFile, []byte(roleToken.Token), 0644)
		if err != nil {
			log.Fatalf("Unable to save role token certificate in %s, err: %v\n", roleCertFile, err)
		}
	} else {
		fmt.Println(roleToken.Token)
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
