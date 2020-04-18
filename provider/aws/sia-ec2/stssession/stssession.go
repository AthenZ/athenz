//
// Copyright 2020 Verizon Media
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
	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/yahoo/athenz/provider/aws/sia-ec2/logutil"
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
