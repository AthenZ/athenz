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

	"github.com/AthenZ/athenz/provider/aws/sia-eks/devel/metamock"
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

// TestGetConfigNoConfig tests the scenario when there is no /etc/sia/sia_config, the system uses profile arn
func TestGetConfigNoConfig(t *testing.T) {
	config, configAccount, accessProfileConfig, err := GetEKSConfig("devel/data/sia_empty_config", "devel/data/access_profile_empty_config", "http://127.0.0.1:5082", false, "us-west-2")
	require.Nil(t, err)
	require.NotNil(t, config)
	require.NotNil(t, configAccount)
	require.Nil(t, accessProfileConfig)
	assert.True(t, configAccount.Domain == "athenz")
	assert.True(t, configAccount.Service == "hockey")
}

// TestGetConfigWithConfig test the scenario when /etc/sia/sia_config is present
func TestGetConfigWithConfig(t *testing.T) {
	config, configAccount, accessProfileConfig, err := GetEKSConfig("devel/data/sia_config", "devel/data/access_profile_config", "http://127.0.0.1:5082", false, "us-west-2")
	require.Nilf(t, err, "error should be empty, error: %v", err)
	require.NotNil(t, config, "should be able to get config")
	require.NotNil(t, configAccount, "should be able to get config")
	require.NotNil(t, accessProfileConfig, "should be able to get user access management config")

	// Make sure services are set
	assert.True(t, config.Service == "api")
	assert.True(t, configAccount.Domain == "athenz")
	assert.True(t, configAccount.Service == "api")
	assert.True(t, accessProfileConfig.Profile == "dev")
}

// TestGetConfigNoService test the scenario when /etc/sia/sia_config is present, but service is not repeated in services
func TestGetConfigNoService(t *testing.T) {
	config, _, _, err := GetEKSConfig("devel/data/sia_no_service", "devel/data/access_profile_config", "http://127.0.0.1:5082", false, "us-west-2")
	require.Nilf(t, err, "error should not be thrown, error: %v", err)
	assert.True(t, len(config.Services) == 2)

	config, _, _, err = GetEKSConfig("devel/data/sia_no_service2", "devel/data/access_profile_config", "http://127.0.0.1:5082", false, "us-west-2")
	require.Nilf(t, err, "error should not be thrown, error: %v", err)
	assert.True(t, config.Service == "api")
	assert.True(t, len(config.Services) == 1)
	assert.NotNil(t, config.Services["ui"])
}

// TestGetConfigNoServices test the scenario when only "service" is mentioned and there are no multiple "services"
func TestGetConfigNoServices(t *testing.T) {
	config, configAccount, _, err := GetEKSConfig("devel/data/sia_no_services", "devel/data/access_profile_config", "http://127.0.0.1:5082", false, "us-west-2")
	require.Nilf(t, err, "error should not be thrown, error: %v", err)

	// Make sure one service is set
	assert.True(t, len(config.Services) == 0)
	assert.True(t, config.Service == "api")
	assert.True(t, configAccount.Domain == "athenz")
	assert.True(t, configAccount.Name == "athenz.api")
}

func TestGetConfigWithGenerateRoleKeyConfig(t *testing.T) {
	config, _, _, err := GetEKSConfig("devel/data/sia_generate_role_key", "devel/data/access_profile_config", "http://127.0.0.1:5082", false, "us-west-2")
	require.Nilf(t, err, "error should not be thrown, error: %v", err)
	assert.True(t, config.GenerateRoleKey == true)
}

func TestGetConfigWithRotateKeyConfig(t *testing.T) {
	config, _, _, err := GetEKSConfig("devel/data/sia_rotate_key", "devel/data/access_profile_config", "http://127.0.0.1:5082", false, "us-west-2")
	require.Nilf(t, err, "error should not be thrown, error: %v", err)
	assert.True(t, config.RotateKey == true)
}

func TestGetEKSPodId(t *testing.T) {
	hostname := os.Getenv("HOSTNAME")
	os.Setenv("HOSTNAME", "localhost")
	assert.True(t, GetEKSPodId() == "localhost")
	os.Setenv("HOSTNAME", "")
	assert.True(t, GetEKSPodId() == "eksPod")
	os.Setenv("HOSTNAME", hostname)
}
