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
	"fmt"
	"os"
	"testing"
	"time"

	"github.com/AthenZ/athenz/provider/gcp/sia-gce/devel/metamock"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func setup() {
	go metamock.StartMetaServer("127.0.0.1:5082")
	time.Sleep(3 * time.Second)
}

func teardown() {}

func TestMain(m *testing.M) {
	setup()
	code := m.Run()
	teardown()
	os.Exit(code)
}

// TestGetConfigNoConfig tests the scenario when there is no /etc/sia/sia_config, the system uses profile from meta
func TestGetConfigNoConfig(t *testing.T) {
	provider := GCEProvider{
		Name: fmt.Sprintf("test.gcp"),
	}
	config, accessProfileConfig, err := GetGCEConfig("devel/data/sia_empty_config", "devel/data/access_profile_empty_config", "http://127.0.0.1:5082", "us-west-2", provider)
	require.Nil(t, err)
	require.NotNil(t, config)
	require.NotNil(t, accessProfileConfig)
	assert.True(t, config.Domain == "athenz.test")
	assert.True(t, config.Service == "my-sa")
	assert.True(t, accessProfileConfig.Profile == "access-profile")
}

// TestGetConfigWithConfig test the scenario when /etc/sia/sia_config is present
func TestGetConfigWithConfig(t *testing.T) {
	provider := GCEProvider{
		Name: fmt.Sprintf("test.gcp"),
	}
	config, accessProfileConfig, err := GetGCEConfig("devel/data/sia_config", "devel/data/access_profile_config", "http://127.0.0.1:5082", "us-west-2", provider)
	require.Nilf(t, err, "error should be empty, error: %v", err)
	require.NotNil(t, config, "should be able to get config")
	require.NotNil(t, accessProfileConfig, "should be able to get user access management config")

	// Make sure services are set
	assert.True(t, config.Domain == "athenz")
	assert.True(t, config.Service == "api")
	assert.True(t, accessProfileConfig.Profile == "dev")
}
