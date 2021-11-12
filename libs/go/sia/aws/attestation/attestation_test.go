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

package attestation

import (
	"os"
	"testing"
)

func TestGetECSTaskId(test *testing.T) {
	os.Setenv("ECS_CONTAINER_METADATA_FILE", "data/task.json")
	taskId := GetECSTaskId()
	if taskId != "776b2c2e-6bfb-4328-bd04-204536cfb7f2" {
		test.Errorf("Unable to extract task id")
		return
	}
	os.Setenv("ECS_CONTAINER_METADATA_FILE", "data/task-new-arn.json")
	taskId = GetECSTaskId()
	if taskId != "776b2c2e-6bfb-4328-bd04-204536cfb7f2" {
		test.Errorf("Unable to extract task id")
		return
	}
	//invalid file
	os.Setenv("ECS_CONTAINER_METADATA_FILE", "data/nonexistent-task.json")
	taskId = GetECSTaskId()
	if taskId != "" {
		test.Errorf("Invalid file returned valid task id: %s", taskId)
		return
	}
}
