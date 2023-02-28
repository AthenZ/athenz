// Copyright The Athenz Authors
// Licensed under the terms of the Apache version 2.0 license. See LICENSE file for terms.

package svc

import (
	"github.com/AthenZ/athenz/libs/go/athenz-common/log"
	"github.com/AthenZ/athenz/libs/go/sia/aws/doc"
	"github.com/AthenZ/athenz/libs/go/sia/aws/meta"
	"github.com/AthenZ/athenz/libs/go/sia/aws/options"
	"github.com/AthenZ/athenz/provider/aws/sia-ec2"
)

var Ec2MetaEndPoint = "http://169.254.169.254:80"

type Fetcher interface {
	Fetch(host MsdHost, accountId string) (ServicesData, error)
	GetAccountId() (string, error)
}

type EC2Fetcher struct {
}

func (fetcher *EC2Fetcher) Fetch(host MsdHost, accountId string) (ServicesData, error) {

	config, configAccount, _, err := sia.GetEC2Config(SIA_CONFIG, PROFILE_CONFIG, PROFILE_TAG_KEY, Ec2MetaEndPoint, false, "", accountId)
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

func ec2ToMsdService(services []options.Service) []Service {
	srv := make([]Service, 0)
	for _, service := range services {
		s := Service{
			Name:         service.Name,
			KeyFilename:  service.KeyFilename,
			CertFilename: service.CertFilename,
			User:         service.User,
			Group:        service.Group,
			Uid:          service.Uid,
			Gid:          service.Gid,
			FileMode:     service.FileMode,
		}
		srv = append(srv, s)
	}
	return srv
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
