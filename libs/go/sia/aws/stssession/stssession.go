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
	"github.com/aws/aws-sdk-go-v2/service/sts/types"
)

// WebIdentityTokenFetcher is a function type for fetching an AWS web identity token.
// It is a package-level variable so tests can replace it with a stub.
var WebIdentityTokenFetcher = fetchWebIdentityToken

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

// GetWebIdentityToken requests an AWS-issued OIDC web identity token via STS and returns
// the raw JWT string. audience is set as the token's aud claim (typically the ZTS URL).
// signingAlgorithm must be "RS256" or "ES384". durationSeconds controls token lifetime
// and must be between 60 and 3600 (inclusive) to account for clock skew tolerance.
// tags is an optional list of key/value pairs to embed as custom claims in the JWT;
// pass nil when not needed.
func GetWebIdentityToken(useRegionalSTS bool, region, audience, signingAlgorithm string, durationSeconds int32, tags []types.Tag) (string, error) {
	if signingAlgorithm != "RS256" && signingAlgorithm != "ES384" {
		return "", fmt.Errorf("invalid signing algorithm %q: must be RS256 or ES384", signingAlgorithm)
	}
	if durationSeconds < 60 || durationSeconds > 3600 {
		return "", fmt.Errorf("invalid durationSeconds %d: must be between 60 and 3600", durationSeconds)
	}
	return WebIdentityTokenFetcher(useRegionalSTS, region, audience, signingAlgorithm, durationSeconds, tags)
}

func fetchWebIdentityToken(useRegionalSTS bool, region, audience, signingAlgorithm string, durationSeconds int32, tags []types.Tag) (string, error) {
	stsClient, err := New(useRegionalSTS, region)
	if err != nil {
		return "", fmt.Errorf("unable to create STS session for web identity token: %w", err)
	}
	input := &sts.GetWebIdentityTokenInput{
		Audience:         []string{audience},
		SigningAlgorithm: aws.String(signingAlgorithm),
		DurationSeconds:  aws.Int32(durationSeconds),
	}
	if len(tags) > 0 {
		input.Tags = tags
	}
	out, err := stsClient.GetWebIdentityToken(context.TODO(), input)
	if err != nil {
		return "", fmt.Errorf("unable to get web identity token: %w", err)
	}
	if out.WebIdentityToken == nil {
		return "", fmt.Errorf("web identity token response contained nil token")
	}
	return *out.WebIdentityToken, nil
}
