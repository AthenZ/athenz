package svc

import (
	"github.com/AthenZ/athenz/libs/go/msdagent/log"
	"github.com/AthenZ/athenz/provider/aws/sia-ec2/options"
	"github.com/AthenZ/athenz/provider/aws/sia-eks/util"
)

type EKSFetcher struct {
}

func (fetcher *EKSFetcher) Fetch(host MsdHost, accountId string) (ServicesData, error) {

	opts, err := options.NewOptions(host.SiaConfig, accountId, "", SIA_DIR, "", "", "", "", "", nil)
	if err != nil {
		log.Fatalf("Unable to formulate options, error: %v\n", err)
	}

	return ServicesData{
		SrvArr: opts.Services,
		Domain: opts.Domain,
	}, nil
}

func (fetcher *EKSFetcher) GetAccountId() (string, error) {
	accountId, _, _, _, err := util.GetMetaDetailsFromCreds()
	if err != nil {
		log.Fatalf("Unable to get account id from available credentials, error: %v", err)
	}
	return accountId, nil
}

// ensure interface is not broken in compile time
var _ Fetcher = &EKSFetcher{}
