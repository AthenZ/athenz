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
	"strings"
	"testing"
)

func TestParseRoleArnInvalidPrefix(test *testing.T) {
	_, _, _, _, err := parseRoleArn("arn:aws::123456789012:assumed-role/athenz.zts-service/i-0662a0226f2d9dc2b", "-service", "us-west-2")
	if err == nil {
		test.Errorf("Unable to verify proper role arn prefix")
	}
	if !strings.Contains(err.Error(), "(prefix)") {
		test.Errorf("Error does not contain expected prefix error")
	}
}

func TestParseRoleArnInvalidNumberOfComponents(test *testing.T) {
	_, _, _, _, err := parseRoleArn("arn:aws:sts::assumed-role/athenz.zts-service/i-0662a0226f2d9dc2b", "-service", "us-west-2")
	if err == nil {
		test.Errorf("Unable to verify proper role arn number of components")
	}
	if !strings.Contains(err.Error(), "(number of components)") {
		test.Errorf("Error does not contain expected number of components error")
	}
}

func TestParseRoleArnInvalidRoleComponent(test *testing.T) {
	_, _, _, _, err := parseRoleArn("arn:aws:sts::123456789012:assumed-role/i-0662a0226f2d9dc2b", "-service", "us-west-2")
	if err == nil {
		test.Errorf("Unable to verify proper role arn number of role components")
	}
	if !strings.Contains(err.Error(), "(role components)") {
		test.Errorf("Error does not contain expected role components error")
	}
}

func TestParseRoleArnInvalidAssumedRoleComponent(test *testing.T) {
	_, _, _, _, err := parseRoleArn("arn:aws:sts::123456789012:athenz.zts-service/athenz.zts-service/i-0662a0226f2d9dc2b", "-service", "us-west-2")
	if err == nil {
		test.Errorf("Unable to verify proper role assumed-role prefix")
	}
	if !strings.Contains(err.Error(), "(assumed-role)") {
		test.Errorf("Error does not contain expected assumed-role prefix error")
	}
}

func TestParseRoleArnInvalidSuffix(test *testing.T) {
	_, _, _, _, err := parseRoleArn("arn:aws:sts::123456789012:assumed-role/athenz.zts-sdbuild/i-0662a0226f2d9dc2b", "-service", "us-west-2")
	if err == nil {
		test.Errorf("Unable to verify proper role suffix")
	}
	if !strings.Contains(err.Error(), "does not have '-service' suffix") {
		test.Errorf("Error does not contain expected suffix error")
	}
}

func TestParseRoleArnInvalidAthenzService(test *testing.T) {
	_, _, _, _, err := parseRoleArn("arn:aws:sts::123456789012:assumed-role/athenz-service/i-0662a0226f2d9dc2b", "-service", "us-west-2")
	if err == nil {
		test.Errorf("Unable to verify proper athenz service name")
	}
	if !strings.Contains(err.Error(), "cannot determine domain/service") {
		test.Errorf("Error does not contain expected domain/service error")
	}
}

func TestParseRoleArnValid(test *testing.T) {
	account, domain, service, region, err := parseRoleArn("arn:aws:sts::123456789012:assumed-role/athenz.zts-service/i-0662a0226f2d9dc2b", "-service", "us-west-2")
	if err != nil {
		test.Errorf("Unable to parse valid arn, error %v", err)
	}
	if account != "123456789012" {
		test.Errorf("Unable to parse valid arn, invalid account: %s", account)
	}
	if domain != "athenz" {
		test.Errorf("Unable to parse valid arn, invalid domain: %s", domain)
	}
	if service != "zts" {
		test.Errorf("Unable to parse valid arn, invalid service: %s", service)
	}
	if region != "us-west-2" {
		test.Errorf("Unable to parse valid arn, invalid region: %s", region)
	}
}
