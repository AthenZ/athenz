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
	"fmt"
	"github.com/AthenZ/athenz/libs/go/sia/logutil"
	"github.com/AthenZ/athenz/libs/go/sia/util"
	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/sts"
	"io"
)

func New(useRegionalSTS bool, region string, sysLogger io.Writer) (*session.Session, error) {
	if useRegionalSTS {
		stsUrl := "sts." + region + ".amazonaws.com"
		logutil.LogInfo(sysLogger, "Creating session to regional STS endpoint: %s\n", stsUrl)
		return session.NewSessionWithOptions(session.Options{
			Config: aws.Config{
				Endpoint: aws.String(stsUrl),
				Region:   aws.String(region),
			},
		})
	} else {
		logutil.LogInfo(sysLogger, "Creating session to global STS endpoint\n")
		return session.NewSession()
	}
}

func GetMetaDetailsFromCreds(serviceSuffix string, useRegionalSTS bool, region string, sysLogger io.Writer) (string, string, string, error) {
	stsSession, err := New(useRegionalSTS, region, sysLogger)
	if err != nil {
		return "", "", "", fmt.Errorf("unable to create new session: %v", err)
	}
	stsService := sts.New(stsSession)
	input := &sts.GetCallerIdentityInput{}

	result, err := stsService.GetCallerIdentity(input)
	if err != nil {
		return "", "", "", err
	}
	return util.ParseAssumedRoleArn(*result.Arn, serviceSuffix)
}
