package client

import (
	"crypto/tls"
	"net/http"

	"github.com/AthenZ/athenz/libs/go/msdagent/log"
	"github.com/AthenZ/athenz/libs/go/msdagent/svc"

	"github.com/AthenZ/athenz/clients/go/msd"
)

type MsdClient interface {
	PutWorkload(domain string, service string, options *msd.WorkloadOptions) error
}

type Client struct {
	Url       string
	Transport *http.Transport
}

func (c Client) PutWorkload(domain string, service string, options *msd.WorkloadOptions) error {
	msdClient := msd.NewClient(c.Url, c.Transport)
	return msdClient.PutWorkload(msd.DomainName(domain), msd.EntityName(service), options)
}

func NewClient(url string, domain string, service string) (*Client, error) {
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
