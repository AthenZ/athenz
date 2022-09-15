// Copyright The Athenz Authors
// Licensed under the terms of the Apache version 2.0 license. See LICENSE file for terms.

package svc

import (
	"github.com/AthenZ/athenz/libs/go/athenz-common/log"
	"github.com/AthenZ/athenz/libs/go/sia/aws/options"
	"github.com/AthenZ/athenz/provider/aws/sia-fargate"
)

var FargateMetaEndPoint = "http://169.254.170.2"

type FargateFetcher struct {
}

func (fetcher *FargateFetcher) Fetch(host MsdHost, accountId string) (ServicesData, error) {

	config, configAccount, err := sia.GetFargateConfig(SIA_CONFIG, FargateMetaEndPoint, false, accountId, "")
	if err != nil {
		log.Fatalf("Unable to formulate config, error: %v\n", err)
	}

	opts, err := options.NewOptions(config, configAccount, nil, SIA_DIR, "", false, "")
	if err != nil {
		log.Fatalf("Unable to formulate options, error: %v\n", err)
	}

	return ServicesData{
		SrvArr: ec2ToMsdService(opts.Services),
		Domain: opts.Domain,
	}, nil
}

func (fetcher *FargateFetcher) GetAccountId() (string, error) {
	account, _, _, err := sia.GetFargateData(FargateMetaEndPoint)
	if err != nil {
		return "", err
	}
	return account, nil
}

// ensure interface is not broken in compile time
var _ Fetcher = &FargateFetcher{}
