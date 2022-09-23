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

package util

import "testing"

func TestExtractServiceName(test *testing.T) {
	domain, service, err := ExtractServiceName("athenz:instance-profile")
	if err == nil {
		test.Errorf("athenz:instance-profile was parsed as success")
	}
	domain, service, err = ExtractServiceName(":instance-profile.service")
	if err == nil {
		test.Errorf(":instance-profile.service was parsed as success")
	}
	domain, service, err = ExtractServiceName("tag1:athenz.api")
	if err == nil {
		test.Errorf("tag1:athenz.api was parsed as success")
	}
	domain, service, err = ExtractServiceName("athenz:athenz.ui")
	if err != nil {
		test.Errorf("athenz:ahtenz.ui was not parsed as success")
	}
	if domain != "athenz" {
		test.Errorf("did not get expected domain: athenz")
	}
	if service != "ui" {
		test.Errorf("did not get expected service: ui")
	}
	domain, service, err = ExtractServiceName("env:prod;athenz:athenz.api")
	if err != nil {
		test.Errorf("env:prod;athenz:athenz.api was not parsed as success")
	}
	if domain != "athenz" {
		test.Errorf("did not get expected domain: athenz")
	}
	if service != "api" {
		test.Errorf("did not get expected service: api")
	}
	domain, service, err = ExtractServiceName("env:prod;athenz:athenz.prod.syncer")
	if err != nil {
		test.Errorf("env:prod;athenz:athenz.prod.syncer was parsed as success")
	}
	if domain != "athenz.prod" {
		test.Errorf("did not get expected domain: athenz.prod")
	}
	if service != "syncer" {
		test.Errorf("did not get expected service: syncer")
	}
}
