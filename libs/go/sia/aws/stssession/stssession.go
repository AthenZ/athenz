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
	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/sts"
	"io"
	"strings"
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
	return parseRoleArn(*result.Arn, serviceSuffix)
}

func parseRoleArn(roleArn, serviceSuffix string) (string, string, string, error) {
	//arn:aws:sts::123456789012:assumed-role/athenz.zts-service/i-0662a0226f2d9dc2b
	if !strings.HasPrefix(roleArn, "arn:aws:sts:") {
		return "", "", "", fmt.Errorf("unable to parse role arn (prefix): %s", roleArn)
	}
	arn := strings.Split(roleArn, ":")
	// make sure we have correct number of components
	if len(arn) < 6 {
		return "", "", "", fmt.Errorf("unable to parse role arn (number of components): %s", roleArn)
	}
	// our role part as 3 components separated by /
	roleComps := strings.Split(arn[5], "/")
	if len(roleComps) != 3 {
		return "", "", "", fmt.Errorf("unable to parse role arn (role components): %s", roleArn)
	}
	// the first component must be assumed-role
	if roleComps[0] != "assumed-role" {
		return "", "", "", fmt.Errorf("unable to parse role arn (assumed-role): %s", roleArn)
	}
	// second component is our athenz service name with the requested service suffix
	if !strings.HasSuffix(roleComps[1], serviceSuffix) {
		return "", "", "", fmt.Errorf("service name does not have '%s' suffix: %s", serviceSuffix, roleArn)
	}
	roleName := roleComps[1][0 : len(roleComps[1])-8]
	idx := strings.LastIndex(roleName, ".")
	if idx < 0 {
		return "", "", "", fmt.Errorf("cannot determine domain/service from arn: %s", roleArn)
	}
	domain := roleName[:idx]
	service := roleName[idx+1:]
	account := arn[4]
	return account, domain, service, nil
}
