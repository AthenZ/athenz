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

package sia

import (
	"os"
	"testing"
	"time"

	"github.com/AthenZ/athenz/provider/aws/sia-fargate/devel/metamock"
)

func setup() {
	os.Setenv("ECS_CONTAINER_METADATA_URI_V4", "http://127.0.0.1:5081")

	go metamock.StartMetaServer("127.0.0.1:5081")
	time.Sleep(3 * time.Second)
}

func teardown() {}

func TestMain(m *testing.M) {
	setup()
	code := m.Run()
	teardown()
	os.Exit(code)
}

func TestGetFargateData(test *testing.T) {
	// "TaskARN": "arn:aws:ecs:us-west-2:012345678910:task/9781c248-0edd-4cdb-9a93-f63cb662a5d3",
	account, taskId, region, err := GetFargateData("http://127.0.0.1:5081")
	if err != nil {
		test.Errorf("Unable to get account, task id from fargate: %v", err)
	}
	if account != "012345678910" {
		test.Errorf("Account number mismatch %s vs 012345678910", account)
	}
	if taskId != "9781c248-0edd-4cdb-9a93-f63cb662a5d3" {
		test.Errorf("Task Id mismatch %s vs 9781c248-0edd-4cdb-9a93-f63cb662a5d3", taskId)
	}
	if region != "us-west-2" {
		test.Errorf("Region mismatch %s vs us-west-2", region)
	}
}
