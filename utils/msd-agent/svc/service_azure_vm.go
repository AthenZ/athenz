// Copyright The Athenz Authors
// Licensed under the terms of the Apache version 2.0 license. See LICENSE file for terms.

package svc

import (
	"github.com/AthenZ/athenz/libs/go/athenz-common/log"
	"github.com/AthenZ/athenz/provider/azure/sia-vm/data/attestation"
	"github.com/AthenZ/athenz/provider/azure/sia-vm/options"
)

var AzureVmMetaEndPoint = "http://169.254.169.254"
var ApiVersion = "2020-06-01"

type AzureVmFetcher struct {
}

func (fetcher *AzureVmFetcher) Fetch(host MsdHost, accountId string) (ServicesData, error) {

	identityDocument, err := attestation.GetIdentityDocument(AzureVmMetaEndPoint, ApiVersion)
	if err != nil {
		log.Fatalf("Unable to get the instance identity document, error: %v", err)
	}

	opts, err := options.NewOptions(host.SiaConfig, identityDocument, "", SIA_DIR, "", "", nil, "", "")
	if err != nil {
		log.Fatalf("Unable to formulate options, error: %v\n", err)
	}

	return ServicesData{
		SrvArr: azureToMsdService(opts.Services),
		Domain: opts.Domain,
	}, nil
}

func azureToMsdService(services []options.Service) []Service {
	srv := make([]Service, 0)
	for _, service := range services {
		s := Service{
			Name:         service.Name,
			User:         service.User,
			Uid:          service.Uid,
			Gid:          service.Gid,
			KeyFilename:  service.KeyFilename,
			CertFilename: service.CertFilename,
		}
		srv = append(srv, s)
	}
	return srv
}

func (fetcher *AzureVmFetcher) GetAccountId() (string, error) {
	return "", nil
}

// ensure interface is not broken in compile time
var _ Fetcher = &AzureVmFetcher{}
