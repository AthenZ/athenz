package main

import (
	"crypto/tls"
	"fmt"
	"github.com/yahoo/athenz/clients/go/zms"
	"go.vzbuilders.com/go/ytls"
	"net/http"
)

func GetZmsClient(certFile, keyFile, zmsUrl string) (*zms.ZMSClient, error) {
	tlsConfig, err := GetTLSConfigFromFiles(certFile, keyFile)
	if err != nil {
		return nil, fmt.Errorf("Unable to formulate tlsConfig from cert: %q, key: %q, error: %v", certFile, keyFile, err)
	}
	zmsClient, err := GetZMSClient(zmsUrl, tlsConfig)
	if err != nil {
		return nil, fmt.Errorf("Unable to generate ZMS client from cert: %q, key: %q, error: %v", certFile, keyFile, err)
	}

	return zmsClient, nil
}

// GetZMSClient returns a client seeded with the tlsConfig provided
func GetZMSClient(zmsUrl string, tlsConfig *tls.Config) (*zms.ZMSClient, error) {
	zmsClient := zms.NewClient(zmsUrl, &http.Transport{
		TLSClientConfig: tlsConfig,
	})
	return &zmsClient, nil
}

func GetTLSConfigFromFiles(certFile, keyFile string) (*tls.Config, error) {
	cert, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		return nil, err
	}
	config :=  ytls.ClientTLSConfig()
	config.Certificates = []tls.Certificate{cert}

	return config, nil
}