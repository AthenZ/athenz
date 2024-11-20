// Copyright The Athenz Authors
// Licensed under the terms of the Apache version 2.0 license. See LICENSE file for terms.

package main

import (
	"flag"
	"fmt"
	"log"
	"os"
	"strings"

	"github.com/AthenZ/athenz/clients/go/zms"
	"github.com/AthenZ/athenz/libs/go/athenzutils"
)

var (
	// VERSION gets set by the build script via the LDFLAGS.
	VERSION string

	// BUILD_DATE gets set by the build script via the LDFLAGS.
	BUILD_DATE string
)

func usage() {
	fmt.Println("usage: zms-domainattrs -svc-key-file <private-key-file> -svc-cert-file <service-cert-file> -zms <zms-server-url> -domain-file <domain-file> [-attrs <list-of-attrs>]")
	os.Exit(1)
}

func printVersion() {
	if VERSION == "" {
		fmt.Println("zms-domainattrs (development version)")
	} else {
		fmt.Println("zms-domainattrs " + VERSION + " " + BUILD_DATE)
	}
}

func main() {
	var domainFile, attrs, svcKeyFile, svcCertFile, svcCACertFile, zmsURL string
	var showVersion bool
	flag.StringVar(&domainFile, "domain-file", "", "domain file with list of domains")
	flag.StringVar(&svcCACertFile, "svc-cacert-file", "", "CA Certificates file")
	flag.StringVar(&svcKeyFile, "svc-key-file", "", "service identity private key file")
	flag.StringVar(&svcCertFile, "svc-cert-file", "", "service identity certificate file")
	flag.StringVar(&zmsURL, "zms", "", "url of the ZMS Service")
	flag.StringVar(&attrs, "attrs", "businessService,productId,account,gcpProject,gcpProjectNumber,azureSubscription,azureTenant,azureClient,org,slackChannel,environment", "comma separated list of domain attribute names")
	flag.BoolVar(&showVersion, "version", false, "Show version")
	flag.Parse()

	if showVersion {
		printVersion()
		return
	}

	if domainFile == "" || svcKeyFile == "" || svcCertFile == "" || zmsURL == "" {
		usage()
	}

	// first get the list of domains from the file

	domains, err := getDomainList(domainFile)
	if err != nil {
		log.Fatalf("unable to get domain list from file: %s error: %v\n", domainFile, err)
	}

	fetchDomainAttrs(zmsURL, svcKeyFile, svcCertFile, svcCACertFile, domains, attrs)
}

func getDomainList(domainFile string) ([]string, error) {

	bytes, err := os.ReadFile(domainFile)
	if err != nil {
		return nil, err
	}

	return strings.Split(string(bytes), "\n"), nil
}

func fetchDomainAttrs(zmsURL, svcKeyFile, svcCertFile, svcCACertFile string, domains []string, attrs string) {

	client, err := athenzutils.ZmsClient(zmsURL, svcKeyFile, svcCertFile, svcCACertFile, false)
	if err != nil {
		log.Fatalf("unable to create zms client: %v\n", err)
	}

	signedDomains, _, err := client.GetSignedDomains("", "true", "all", nil, nil, "")
	if err != nil {
		log.Fatalf("unable to fetch domains with list of attributes from ZMS: %v\n", err)
	}

	// put the results in a map

	domainMap := make(map[string]*zms.SignedDomain, len(signedDomains.Domains))
	for _, signedDomain := range signedDomains.Domains {
		domainMap[string(signedDomain.Domain.Name)] = signedDomain
	}

	// convert the attributes to list

	attrList := strings.Split(attrs, ",")

	// write the header line

	fmt.Print("Domain")
	for _, attr := range attrList {
		fmt.Print("," + attr)
	}
	fmt.Println()

	// go through the list of domains and print the requested attributes

	for _, domain := range domains {

		if domain == "" {
			continue
		}

		fmt.Print(domain)
		signedDomain, ok := domainMap[domain]
		if !ok {
			fmt.Println(",<not found>")
			continue
		}

		// now go through the list of attributes and print the values

		for _, attr := range attrList {
			attrName := strings.ToLower(attr)
			attrVal := getDomainAttributeValue(signedDomain.Domain, attrName)
			if attrVal == "" && isRecursiveAttribute(attrName) {
				attrVal = getDomainAttributeValueRecursive(domain, domainMap, attrName)
			}
			fmt.Print("," + attrVal)
		}
		fmt.Println()
	}
	fmt.Println()
}

func getParentDomainName(domainName string) string {
	idx := strings.LastIndex(domainName, ".")
	if idx == -1 {
		return ""
	}
	return domainName[:idx]
}

func getDomainAttributeValueRecursive(domainName string, domainMap map[string]*zms.SignedDomain, attrName string) string {
	// first get the parent domain name
	parentDomainName := getParentDomainName(domainName)
	if parentDomainName == "" {
		return ""
	}
	signedDomain, ok := domainMap[parentDomainName]
	if !ok {
		return ""
	}
	attrValue := getDomainAttributeValue(signedDomain.Domain, attrName)
	if attrValue == "" {
		attrValue = getDomainAttributeValueRecursive(parentDomainName, domainMap, attrName)
	}
	return attrValue
}

func isRecursiveAttribute(attrName string) bool {
	return attrName == "businessservice" || attrName == "productid"
}

func getDomainAttributeValue(domainData *zms.DomainData, attrName string) string {
	switch attrName {
	case "businessservice":
		return domainData.BusinessService
	case "productid":
		return domainData.ProductId
	case "account":
		return domainData.Account
	case "gcpproject":
		return domainData.GcpProject
	case "gcpprojectnumber":
		return domainData.GcpProjectNumber
	case "azuresubscription":
		return domainData.AzureSubscription
	case "azuretenant":
		return domainData.AzureTenant
	case "azureclient":
		return domainData.AzureClient
	case "org":
		return string(domainData.Org)
	case "slackchannel":
		return domainData.SlackChannel
	}

	return ""
}
