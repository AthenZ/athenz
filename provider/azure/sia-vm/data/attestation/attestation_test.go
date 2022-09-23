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
	"github.com/AthenZ/athenz/provider/azure/sia-vm/devel/metamock"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"os"
	"testing"
	"time"
)

var (
	MetaEndPoint = "http://127.0.0.1:5083"
	ApiVersion   = "2020-06-01"
)

func setup() {
	go metamock.StartMetaServer("127.0.0.1:5083")
	time.Sleep(3 * time.Second)
}

func teardown() {}

func TestMain(m *testing.M) {
	setup()
	code := m.Run()
	teardown()
	os.Exit(code)
}

func TestGetIdentityDocument(test *testing.T) {
	identityDocument, err := GetIdentityDocument(MetaEndPoint, ApiVersion)
	require.Nilf(test, err, "error for get identity document should be empty, error: %v", err)

	assert.True(test, identityDocument.Name == "athenz-client")
	assert.True(test, identityDocument.Location == "westus2")
	assert.True(test, identityDocument.ResourceGroupName == "Athenz")
	assert.True(test, identityDocument.SubscriptionId == "1111111-1111-1111-1111-111111111111")
	assert.True(test, identityDocument.VmId == "22222222-2222-2222-2222-222222222222")
	assert.True(test, identityDocument.OsType == "Linux")
	assert.True(test, identityDocument.Tags == "athenz:athenz.backend")
	assert.True(test, identityDocument.PublicIp == "")
	assert.True(test, identityDocument.PrivateIp == "10.0.0.4")
}

func TestGetAccessToken(test *testing.T) {

	identityDocument := IdentityDocument{
		Location:          "westus2",
		Name:              "athenz-client",
		ResourceGroupName: "Athenz",
		SubscriptionId:    "1111111-1111-1111-1111-111111111111",
		VmId:              "22222222-2222-2222-2222-222222222222",
		OsType:            "Linux",
		Tags:              "athenz:athenz.backend",
		PrivateIp:         "10.0.0.4",
		PublicIp:          "",
		Document:          nil,
	}

	attestData, err := New("athenz", "backend", MetaEndPoint, ApiVersion, "https://test.athenz.io/", &identityDocument)
	require.Nilf(test, err, "error for get attestation data should be empty, error: %v", err)

	assert.True(test, attestData.Name == "athenz-client")
	assert.True(test, attestData.Location == "westus2")
	assert.True(test, attestData.ResourceGroupName == "Athenz")
	assert.True(test, attestData.SubscriptionId == "1111111-1111-1111-1111-111111111111")
	assert.True(test, attestData.VmId == "22222222-2222-2222-2222-222222222222")
	assert.True(test, attestData.Token == "test-access-token")
}
