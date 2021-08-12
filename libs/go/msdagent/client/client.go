package client

import (
	"crypto/tls"
	"fmt"
	"io/ioutil"
	"net/http"
	"regexp"

	"github.com/AthenZ/athenz/libs/go/msdagent/log"
	"github.com/AthenZ/athenz/libs/go/msdagent/svc"

	"github.com/AthenZ/athenz/clients/go/msd"
)

const USER_AGENT = "User-Agent"

type MsdClient interface {
	PutWorkload(domain string, service string, options *msd.WorkloadOptions) error
}

type Client struct {
	Url       string
	Transport *http.Transport
}

var version = ""

func (c Client) PutWorkload(domain string, service string, options *msd.WorkloadOptions) error {
	msdClient := clientWithUserAgent(c)
	return msdClient.PutWorkload(msd.DomainName(domain), msd.EntityName(service), options)
}

func clientWithUserAgent(c Client) msd.MSDClient {
	msdClient := msd.NewClient(c.Url, c.Transport)
	osVersion := func() string {
		b, err := ioutil.ReadFile("/etc/redhat-release")
		if err != nil {
			log.Debugf("Failed to read os version")
			return ""
		}
		versionReg, _ := regexp.Compile(`\d+\.\d+`)
		v := versionReg.FindString(string(b))
		return fmt.Sprintf("rhel-%s", v)
	}
	msdClient.AddCredentials(USER_AGENT, fmt.Sprintf("c:%s %s", version, osVersion()))
	return msdClient
}

func NewClient(msdAgentVersion string, url string, domain string, service string) (*Client, error) {
	version = msdAgentVersion
	certFile := certFile(service, domain)
	keyFile := keyFile(service, domain)
	log.Printf("Creating MsdClient using cert: %s, and key: %s", certFile, keyFile)

	tlsConfig, err := GetTLSConfigFromFiles(certFile, keyFile)
	if err != nil {
		return nil, err
	}
	transport := http.Transport{
		TLSClientConfig: tlsConfig,
	}
	client := &Client{
		Url:       url,
		Transport: &transport,
	}
	return client, err
}

func certFile(service string, domain string) string {
	return svc.SIA_DIR + "/certs/" + domain + "." + service + ".cert.pem"
}

func keyFile(service string, domain string) string {
	return svc.SIA_DIR + "/keys/" + domain + "." + service + ".key.pem"
}

func GetTLSConfigFromFiles(certFile, keyFile string) (*tls.Config, error) {
	cert, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		return nil, log.Errorf("Unable to formulate clientCert from key and cert bytes, error: %v", err)
	}
	config := &tls.Config{}
	config.Certificates = make([]tls.Certificate, 1)
	config.Certificates[0] = cert

	// Set Renegotiation explicitly
	config.Renegotiation = tls.RenegotiateOnceAsClient

	return config, err
}
