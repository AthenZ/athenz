package main

import (
	"crypto/tls"
	"encoding/json"
	"fmt"
	"go.vzbuilders.com/go/ytls"
	"log"
	"net/http"
)

func GetProductsFromOpm(certFile, keyFile string) (Products, error) {
	httpClient, err := GetHttpClient(certFile, keyFile)
	if err != nil {
		log.Fatal("Failed to get http client, error: " + err.Error())
	}

	url := "https://opmapis.corp.yahoo.com:4443/opm_services/rest/productservice/products"

	resp, err := httpGet(url, httpClient)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	var data Products
	err = json.NewDecoder(resp.Body).Decode(&data)
	if err != nil {
		return data, err
	}
	return data, nil
}

func httpGet(url string, hclient *http.Client) (*http.Response, error) {
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, err
	}
	return hclient.Do(req)
}

func GetHttpClient(certFile, keyFile string) (*http.Client, error) {
	tlsConfig, err := getTLSConfigFromFiles(certFile, keyFile)
	if err != nil {
		return nil, fmt.Errorf("Unable to formulate tlsConfig from cert: %q, key: %q, error: %v", certFile, keyFile, err)
	}
	httpCLient, err := getHttpClient(tlsConfig)
	if err != nil {
		return nil, fmt.Errorf("Unable to generate ZMS client from cert: %q, key: %q, error: %v", certFile, keyFile, err)
	}

	return httpCLient, nil
}

func getClient(transport http.RoundTripper) *http.Client {
	var c *http.Client
	if transport != nil {
		c = &http.Client{Transport: transport}
	} else {
		c = &http.Client{}
	}
	return c
}

// getHttpClient returns a client seeded with the tlsConfig provided
func getHttpClient(tlsConfig *tls.Config) (*http.Client, error) {
	httpClient := getClient(&http.Transport{
		TLSClientConfig: tlsConfig,
	})
	return httpClient, nil
}

func getTLSConfigFromFiles(certFile, keyFile string) (*tls.Config, error) {
	cert, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		return nil, err
	}
	config :=  ytls.ClientTLSConfig()
	config.Certificates = []tls.Certificate{cert}

	return config, nil
}