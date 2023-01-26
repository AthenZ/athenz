// Copyright The Athenz Authors
// Licensed under the terms of the Apache version 2.0 license. See LICENSE file for terms.

package svc

import (
	"github.com/AthenZ/athenz/libs/go/athenz-common/log"
	"github.com/AthenZ/athenz/libs/go/sia/aws/options"
	"github.com/AthenZ/athenz/libs/go/sia/aws/stssession"
	"github.com/AthenZ/athenz/provider/aws/sia-eks"
)

var EksMetaEndPoint = "http://169.254.169.254:80"

type EKSFetcher struct {
}

func (fetcher *EKSFetcher) Fetch(host MsdHost, accountId string) (ServicesData, error) {

	config, configAccount, accessProfileConfig, err := sia.GetEKSConfig(SIA_CONFIG, PROFILE_CONFIG, EksMetaEndPoint, false, "")
	if err != nil {
		log.Fatalf("Unable to formulate config, error: %v\n", err)
	}

	opts, err := options.NewOptions(config, configAccount, accessProfileConfig, SIA_DIR, "", false, "")
	if err != nil {
		log.Fatalf("Unable to formulate options, error: %v\n", err)
	}

	return ServicesData{
		SrvArr: ec2ToMsdService(opts.Services),
		Domain: opts.Domain,
	}, nil
}

func (fetcher *EKSFetcher) GetAccountId() (string, error) {
	accountId, _, _, _, err := stssession.GetMetaDetailsFromCreds("-service", "", false, "")
	if err != nil {
		log.Fatalf("Unable to get account id from available credentials, error: %v", err)
	}
	return accountId, nil
}

// ensure interface is not broken in compile time
var _ Fetcher = &EKSFetcher{}
