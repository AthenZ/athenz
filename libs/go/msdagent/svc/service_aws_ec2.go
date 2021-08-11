package svc

import (
	"github.com/AthenZ/athenz/libs/go/msdagent/log"
	"github.com/AthenZ/athenz/libs/go/sia/aws/doc"
	"github.com/AthenZ/athenz/libs/go/sia/aws/meta"
	"github.com/AthenZ/athenz/provider/aws/sia-ec2/options"
)

var Ec2MetaEndPoint = "http://169.254.169.254:80"

type Fetcher interface {
	Fetch(host MsdHost, accountId string) (ServicesData, error)
	GetAccountId() (string, error)
}

type EC2Fetcher struct {
}

func (fetcher *EC2Fetcher) Fetch(host MsdHost, accountId string) (ServicesData, error) {

	opts, err := options.NewOptions(host.SiaConfig, accountId, "", SIA_DIR, "", "", "", "", "", nil)
	if err != nil {
		log.Fatalf("Unable to formulate options, error: %v\n", err)
	}

	return ServicesData{
		SrvArr: opts.Services,
		Domain: opts.Domain,
	}, nil
}

func (fetcher *EC2Fetcher) GetAccountId() (string, error) {

	document, err := meta.GetData(Ec2MetaEndPoint, "/latest/dynamic/instance-identity/document")
	if err != nil {
		log.Fatalf("Unable to get the instance identity document, error: %v", err)
	}

	account, err := doc.GetAccountId(document)
	if err != nil {
		log.Printf("error is : %s", err.Error())
		return "", err
	}
	log.Printf("account is : %s", account)
	return account, nil
}

// ensure interface is not broken in compile time
var _ Fetcher = &EC2Fetcher{}
