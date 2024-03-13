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

	"github.com/AthenZ/athenz/provider/aws/sia-ec2/devel/metamock"
	"github.com/stretchr/testify/assert"
)

func setup() {
	go metamock.StartMetaServer("127.0.0.1:5080")
	time.Sleep(3 * time.Second)
}

func teardown() {}

func TestMain(m *testing.M) {
	setup()
	code := m.Run()
	teardown()
	os.Exit(code)
}

func TestGetECSonEC2TaskId(t *testing.T) {
	os.Setenv("ECS_CONTAINER_METADATA_FILE", "devel/data/ecs.json")
	assert.True(t, GetECSOnEC2TaskId() == "1234")
	os.Setenv("ECS_CONTAINER_METADATA_FILE", "devel/data/ecs-old.json")
	assert.True(t, GetECSOnEC2TaskId() == "3456")
	os.Setenv("ECS_CONTAINER_METADATA_FILE", "devel/data/ecs-notask.json")
	assert.True(t, GetECSOnEC2TaskId() == "")
	os.Setenv("ECS_CONTAINER_METADATA_FILE", "devel/data/ecs-invalid.json")
	assert.True(t, GetECSOnEC2TaskId() == "")
}

func TestGetEC2DocumentDetails(t *testing.T) {
	document, signature, account, instanceId, region, privateIp, time, err := GetEC2DocumentDetails("http://127.0.0.1:5080")
	assert.Nil(t, err)
	assert.NotNil(t, document)
	assert.NotNil(t, signature)
	assert.True(t, string(signature) == "aws-signature")
	assert.True(t, account == "000000000001")
	assert.True(t, instanceId == "i-03d1ae7035f931a90")
	assert.True(t, region == "us-west-2")
	assert.True(t, time.String() == "2016-05-02 22:23:14 +0000 UTC")
	assert.Equal(t, "172.31.30.74", privateIp)
}

func TestGetPublicIP(t *testing.T) {
	publicIP, err := GetEC2PublicIP("http://127.0.0.1:5080")
	assert.Nil(t, err)
	assert.Equal(t, "172.31.30.75", publicIP)
}
