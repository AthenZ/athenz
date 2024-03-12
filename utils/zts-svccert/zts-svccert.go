package main

import (
	"bytes"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/AthenZ/athenz/clients/go/zts"
	"github.com/AthenZ/athenz/libs/go/athenzutils"
	"github.com/AthenZ/athenz/libs/go/tls/config"
	"github.com/AthenZ/athenz/libs/go/zmssvctoken"
)

type signer struct {
	key       crypto.Signer
	algorithm x509.SignatureAlgorithm
}

var (
	// VERSION gets set by the build script via the LDFLAGS.
	VERSION string

	// BUILD_DATE gets set by the build script via the LDFLAGS.
	BUILD_DATE string
)

func printVersion() {
	if VERSION == "" {
		fmt.Println("zts-svccert (development version)")
	} else {
		fmt.Println("zts-svccert " + VERSION + " " + BUILD_DATE)
	}
}

func usage() {
	fmt.Println("")
	fmt.Println("Request Instance Register Token Only:")
	fmt.Println("")
	fmt.Println("    zts-svccert -get-instance-register-token -zts <zts-server-url> <principal-credentials> -provider <provider-name> <service-details> -instance <instance-id> [attestation-data <token-output-file>]")
	fmt.Println("")
	fmt.Println("Request Service Identity Certificate using Instance Register Token:")
	fmt.Println("")
	fmt.Println("    zts-svccert -use-instance-register-token -zts <zts-server-url> <principal-credentials> -private-key <private-key-path> -provider <provider-name> <service-details> -instance <instance-id> <certificate-details>")
	fmt.Println("")
	fmt.Println("Request Service Identity Certificate using Registered Public/Private Key Pair:")
	fmt.Println("")
	fmt.Println("    zts-svccert -zts <zts-server-url> -private-key <private-key-path> -key-version <private-key-version> -hdr <credential-header-name> [-provider <provider-name>[ <service-details> [-instance <instance-id>] <certificate-details>")
	fmt.Println("")
	fmt.Println("Request Service Identity Certificate Signing Request (CSR) Only:")
	fmt.Println("")
	fmt.Println("    zts-svccert -csr -private-key <private-key-path> [-provider <provider-name>] <service-details> [-instance <instance-id>] <certificate-details>")
	fmt.Println("")
	fmt.Println("Request Service Identity Certificate using Provided Attestation Data:")
	fmt.Println("")
	fmt.Println("    zts-svccert -private-key <private-key-path> -attestation-data <attestation-data-file> [-hdr <credential-header-name>] [-provider <provider-name>] <service-details> [-instance <instance-id>] <certificate-details>")
	fmt.Println("")
	fmt.Println("Common parameters:")
	fmt.Println("")
	fmt.Println("      <service-details> := -domain <domain-name> -service <service-name>")
	fmt.Println("")
	fmt.Println("      <certificate-details> := -dns-domain <san-dns-domain-component> [-signer-cert-file <cert-output-file>] [-spiffe] [-expiry-time <mins>] [-sub-c <subject country>] [-sub-o <subject org] [-sub-ou <subject orgunit] [-ip <san-ip-address>] [-signer-cert-file <root-ca-output-file>]")
	fmt.Println("")
	fmt.Println("      <principal-credentials> := -svc-key-file <private-key-file> -svc-cert-file <service-cert-file> [-cacert <ca-cert-file>] |")
	fmt.Println("                                 -ntoken-file <ntoken-file> [-hdr <auth-header-name>] [-cacert <ca-cert-file>]")
	fmt.Println("")
	os.Exit(1)
}

func main() {
	var ztsURL, serviceKey, serviceCert, domain, service, keyID string
	var caCertFile, certFile, signerCertFile, dnsDomain, hdr, ip string
	var subjC, subjO, subjOU, uri, provider, instance, instanceId string
	var svcKeyFile, svcCertFile, ntokenFile, attestationDataFile, spiffeTrustDomain string
	var csr, spiffe, showVersion, getInstanceRegisterToken, useInstanceRegisterToken bool
	var expiryTime int
	flag.BoolVar(&csr, "csr", false, "request csr only")
	flag.BoolVar(&getInstanceRegisterToken, "get-instance-register-token", false, "request instance register token only")
	flag.BoolVar(&useInstanceRegisterToken, "use-instance-register-token", false, "request certificate using instance register token")
	flag.BoolVar(&spiffe, "spiffe", true, "include spiffe uri in csr")
	flag.IntVar(&expiryTime, "expiry-time", 0, "expiry time in minutes")
	flag.StringVar(&certFile, "cert-file", "", "output certificate file")
	flag.StringVar(&ntokenFile, "ntoken-file", "", "service identity token file")
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
	flag.StringVar(&svcKeyFile, "svc-key-file", "", "service identity private key file")
	flag.StringVar(&svcCertFile, "svc-cert-file", "", "service identity certificate file")
	flag.BoolVar(&showVersion, "version", false, "Show version")
	flag.StringVar(&spiffeTrustDomain, "spiffe-trust-domain", "", "spiffe-trust-domain")
	flag.Parse()

	if showVersion {
		printVersion()
		return
	}

	// if we're asked to obtain instance register token then we can handle
	// that separately and return right away

	attestationData := ""
	var err error

	if getInstanceRegisterToken || useInstanceRegisterToken {

		defaultConfig, _ := athenzutils.ReadDefaultConfig()
		// check to see if we need to use zts url from our default config file
		if ztsURL == "" && defaultConfig != nil {
			ztsURL = defaultConfig.Zts
		}

		if ztsURL == "" || domain == "" || service == "" || provider == "" || instance == "" || svcKeyFile == "" || svcCertFile == "" {
			log.Println("Error: missing required attributes. Run with -help for command line arguments")
			usage()
		}
		attestationData, err = fetchInstanceRegisterToken(ztsURL, svcKeyFile, svcCertFile, caCertFile, ntokenFile, hdr, provider, domain, service, instance)
		if err != nil {
			log.Fatalln(err)
		}
		if getInstanceRegisterToken {
			if attestationDataFile != "" {
				err := os.WriteFile(attestationDataFile, []byte(attestationData), 0444)
				if err != nil {
					log.Fatalln(err)
				}
			} else {
				fmt.Println(attestationData)
			}
			return
		}
	}

	if serviceKey == "" || domain == "" || service == "" || dnsDomain == "" {
		log.Println("Error: missing required attributes. Run with -help for command line arguments")
		usage()
	}

	// load private key
	keyBytes, err := os.ReadFile(serviceKey)
	if err != nil {
		if useInstanceRegisterToken {
			keyBytes, err = generatePrivateKey(serviceKey)
		}
		if err != nil {
			log.Fatalln(err)
		}
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
	if spiffe || spiffeTrustDomain != "" {
		if spiffeTrustDomain != "" {
			uri = fmt.Sprintf("spiffe://%s/ns/default/sa/%s", spiffeTrustDomain, commonName)
		} else {
			uri = fmt.Sprintf("spiffe://%s/sa/%s", domain, service)
		}
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
		log.Println("Error: missing ZTS Server url. Run with -help for command line arguments")
		usage()
	}

	// if we're given a certificate then we'll use that otherwise
	// we're going to generate a ntoken for our request unless
	// we're using copper argos which only uses tls and the attestation
	// data contains the authentication details

	var client *zts.ZTSClient
	var ntoken string
	if provider != "" {
		client, err = certClient(ztsURL, nil, "", caCertFile)
	} else if serviceCert == "" {
		ntoken, err = getNToken(domain, service, keyID, keyBytes)
		if err != nil {
			log.Fatalln(err)
		}
		client, err = ntokenClient(ztsURL, ntoken, caCertFile, hdr)
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
			log.Println("Error: Please specify instance value. Run with -help for command line arguments")
			usage()
		}
		if attestationData == "" {
			if attestationDataFile != "" {
				attestationDataBytes, err := os.ReadFile(attestationDataFile)
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
		err = os.WriteFile(certFile, []byte(certificate), 0444)
		if err != nil {
			log.Fatalln(err)
		}
	} else {
		fmt.Println(certificate)
	}

	if signerCertFile != "" {
		err = os.WriteFile(signerCertFile, []byte(caCertificates), 0444)
		if err != nil {
			log.Fatalln(err)
		}
	}
}

func generatePrivateKey(serviceKey string) ([]byte, error) {
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, err
	}
	keyBytes := getPEMBlock(rsaKey)
	err = os.WriteFile(serviceKey, keyBytes, 0400)
	if err != nil {
		return nil, err
	}
	return keyBytes, nil
}

func getPEMBlock(privateKey *rsa.PrivateKey) []byte {
	block := &pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(privateKey),
	}
	return pem.EncodeToMemory(block)
}

func fetchInstanceRegisterToken(ztsURL, svcKeyFile, svcCertFile, caCertFile, ntokenFile, hdr, provider, domain, service, instance string) (string, error) {

	var client *zts.ZTSClient
	var err error
	var ntokenBytes []byte
	if svcKeyFile != "" {
		client, err = athenzutils.ZtsClient(ztsURL, svcKeyFile, svcCertFile, caCertFile, true)
	} else {
		// we need to load our ntoken from the given file
		ntokenBytes, err = os.ReadFile(ntokenFile)
		if err != nil {
			return "", err
		}
		ntoken := strings.TrimSpace(string(ntokenBytes))
		client, err = ntokenClient(ztsURL, ntoken, hdr, caCertFile)
	}
	if err != nil {
		return "", err
	}
	instanceRegisterToken, err := client.GetInstanceRegisterToken(zts.ServiceName(provider), zts.DomainName(domain), zts.SimpleName(service), zts.PathElement(instance))
	if err != nil {
		return "", err
	}
	return instanceRegisterToken.AttestationData, nil
}

func newSigner(privateKeyPEM []byte) (*signer, error) {
	key, algorithm, err := athenzutils.ExtractSignerInfo(privateKeyPEM)
	if err != nil {
		return nil, err
	}
	return &signer{key: key, algorithm: algorithm}, nil
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
		return "", fmt.Errorf("cannot create CSR: %v", err)
	}
	block := &pem.Block{
		Type:  "CERTIFICATE REQUEST",
		Bytes: csr,
	}
	var buf bytes.Buffer
	err = pem.Encode(&buf, block)
	if err != nil {
		return "", fmt.Errorf("cannot encode CSR to PEM: %v", err)
	}
	return buf.String(), nil
}

func getNToken(domain, service, keyID string, keyBytes []byte) (string, error) {

	if keyID == "" {
		return "", errors.New("missing key-version for the specified private key")
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

func ntokenClient(ztsURL, ntoken, caCertFile, hdr string) (*zts.ZTSClient, error) {

	transport := &http.Transport{
		Proxy:                 http.ProxyFromEnvironment,
		ResponseHeaderTimeout: 30 * time.Second,
	}
	if caCertFile != "" {
		config := &tls.Config{}
		certPool := x509.NewCertPool()
		caCert, err := os.ReadFile(caCertFile)
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
		certpem, err = os.ReadFile(certfile)
		if err != nil {
			return nil, err
		}
	}
	var cacertpem []byte
	if caCertFile != "" {
		cacertpem, err = os.ReadFile(caCertFile)
		if err != nil {
			return nil, err
		}
	}
	config, err := config.ClientTLSConfigFromPEM(keyBytes, certpem, cacertpem)
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
