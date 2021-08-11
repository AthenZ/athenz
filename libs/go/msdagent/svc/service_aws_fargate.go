package svc

import (
	"os"

	"github.com/AthenZ/athenz/libs/go/msdagent/log"
	"github.com/AthenZ/athenz/provider/aws/sia-ec2/options"
	"github.com/AthenZ/athenz/provider/aws/sia-fargate"
)

var FargateMetaEndPoint = os.Getenv("ECS_CONTAINER_METADATA_URI_V4")

type FargateFetcher struct {
}

func (fetcher *FargateFetcher) Fetch(host MsdHost, accountId string) (ServicesData, error) {

	opts, err := options.NewOptions(host.SiaConfig, accountId, "", SIA_DIR, "", "", "", "", "", nil)
	if err != nil {
		log.Fatalf("Unable to formulate options, error: %v\n", err)
	}

	return ServicesData{
		SrvArr: opts.Services,
		Domain: opts.Domain,
	}, nil
}

func (fetcher *FargateFetcher) GetAccountId() (string, error) {
	account, _, _, err := sia.GetECSFargateData(FargateMetaEndPoint)
	if err != nil {
		return "", err
	}
	return account, nil
}

// ensure interface is not broken in compile time
var _ Fetcher = &FargateFetcher{}
