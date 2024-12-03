//
// Copyright The Athenz Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//

package stssession

import (
	"context"
	"fmt"
	"github.com/AthenZ/athenz/libs/go/sia/util"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/sts"
)

func New(useRegionalSTS bool, region string) (*sts.Client, error) {
	cfg, err := config.LoadDefaultConfig(context.TODO(),
		config.WithRegion(region),
	)
	if err != nil {
		return nil, fmt.Errorf("unable to create new session: %v", err)
	}
	if useRegionalSTS {
		stsUrl := "https://sts." + region + ".amazonaws.com"
		return sts.NewFromConfig(cfg, func(o *sts.Options) {
			o.BaseEndpoint = aws.String(stsUrl)
		}), nil
	} else {
		return sts.NewFromConfig(cfg), nil
	}
}

func GetCallerIdentity(useRegionalSTS bool, region string) (*sts.GetCallerIdentityOutput, error) {
	stsClient, err := New(useRegionalSTS, region)
	if err != nil {
		return nil, err
	}
	input := &sts.GetCallerIdentityInput{}
	return stsClient.GetCallerIdentity(context.TODO(), input)
}

func GetMetaDetailsFromCreds(serviceSuffix, accessProfileSeparator string, useRegionalSTS bool, region string) (string, string, string, string, error) {
	result, err := GetCallerIdentity(useRegionalSTS, region)
	if err != nil {
		return "", "", "", "", err
	}
	return util.ParseAssumedRoleArn(*result.Arn, serviceSuffix, accessProfileSeparator)
}
