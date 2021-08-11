package svc

import (
	"github.com/AthenZ/athenz/libs/go/msdagent/log"
	awsopts "github.com/AthenZ/athenz/provider/aws/sia-ec2/options"
	"github.com/AthenZ/athenz/provider/azure/sia-vm/data/attestation"
	"github.com/AthenZ/athenz/provider/azure/sia-vm/options"
)

var AzureVmMetaEndPoint = "http://169.254.169.254"
var ApiVersion = "2020-06-01"

type AzureVmFetcher struct {
}

func (fetcher *AzureVmFetcher) Fetch(host MsdHost, accountId string) (ServicesData, error) {

	identityDocument, err := attestation.GetIdentityDocument(AzureVmMetaEndPoint, ApiVersion, log.GetWriter())
	if err != nil {
		log.Fatalf("Unable to get the instance identity document, error: %v", err)
	}

	opts, err := options.NewOptions(host.SiaConfig, identityDocument, "", SIA_DIR, "", "", "", "", "", nil)
	if err != nil {
		log.Fatalf("Unable to formulate options, error: %v\n", err)
	}

	srvArr := fromAzureVmSrv(opts.Services)

	return ServicesData{
		SrvArr: srvArr,
		Domain: opts.Domain,
	}, nil
}

func fromAzureVmSrv(services []options.Service) []awsopts.Service {
	srv := make([]awsopts.Service, 0)
	for _, service := range services {
		s := awsopts.Service{
			Name:     service.Name,
			User:     service.User,
			Uid:      service.Uid,
			Gid:      service.Gid,
			Filename: service.Filename,
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
