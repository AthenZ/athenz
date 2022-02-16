//
// Copyright Athenz Authors
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

package options

import (
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"net"
	"net/http"
	"os/exec"
	"os/user"
	"strconv"
	"strings"
	"testing"

	"github.com/dimfeld/httptreemux"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const iamJson = `{
  "Code" : "Success",
  "LastUpdated" : "2019-05-06T15:35:48Z",
  "InstanceProfileArn" : "arn:aws:iam::123456789012:instance-profile/athenz.hockey-service",
  "InstanceProfileId" : "XXXXPROFILEIDYYYY"
}`

type testServer struct {
	listener net.Listener
	addr     string
}

func (t *testServer) start(h http.Handler) {
	listener, err := net.Listen("tcp", ":0")
	if err != nil {
		log.Panicln("Unable to serve on randomly assigned port")
	}
	s := &http.Server{Handler: h}
	t.listener = listener
	t.addr = listener.Addr().String()

	go func() {
		s.Serve(listener)
	}()
}

func (t *testServer) stop() {
	t.listener.Close()
}

func (t *testServer) httpUrl() string {
	return fmt.Sprintf("http://%s", t.addr)
}

func getConfig(fileName, roleSuffix, metaEndPoint string, useRegionalSTS bool, region string) (*Config, *ConfigAccount, error) {
	// Parse config bytes first, and if that fails, load values from Instance Profile and IAM info
	config, configAccount, err := InitFileConfig(fileName, metaEndPoint, useRegionalSTS, region, "")
	if err != nil {
		log.Printf("unable to parse configuration file, error: %v\n", err)
		// if we do not have a configuration file, we're going
		// to use fallback to <domain>.<service>-service
		// naming structure
		log.Println("trying to determine service name from profile arn...")
		configAccount, err = InitProfileConfig(metaEndPoint, roleSuffix)
		if err != nil {
			return nil, nil, fmt.Errorf("config non-parsable and unable to determine service name from profile arn, error: %v", err)
		}
	}
	return config, configAccount, nil
}

func assertService(expected Service, actual Service) bool {
	log.Printf("expected: %+v\n", expected)
	log.Printf("actual: %+v\n", actual)
	return expected.Name == actual.Name &&
		expected.User == actual.User &&
		expected.Uid == actual.Uid &&
		expected.Group == actual.Group &&
		expected.Gid == actual.Gid &&
		expected.Filename == actual.Filename
}

func assertInServices(svcs []Service, actual Service) bool {
	log.Printf("svcs passed: %+v\n", svcs)
	log.Printf("actual: %+v\n", actual)
	for _, s := range svcs {
		if s.Name == actual.Name && s.User == actual.User && s.Uid == actual.Uid && s.Group == actual.Group && s.Gid == actual.Gid && s.Filename == actual.Filename {
			return true
		}

	}
	return false
}

func getUid(name string) int {
	u, _ := user.Lookup(name)
	i, _ := strconv.Atoi(u.Uid)
	return i
}

func getUserGid(name string) int {
	u, _ := user.Lookup(name)
	i, _ := strconv.Atoi(u.Gid)
	return i
}

func getGid(t *testing.T, group string) int {
	out, err := ioutil.ReadFile("/etc/group")
	require.Nil(t, err)

	for _, line := range strings.Split(string(out), "\n") {
		parts := strings.Split(strings.Trim(line, "\r"), ":")
		if parts[0] == group {
			gid, err := strconv.Atoi(parts[2])
			require.Nil(t, err)
			return gid
		}
	}

	require.FailNow(t, fmt.Sprintf("Unable to find group: %q", group))
	return 0
}

// TestOptionsNoConfig tests the scenario when there is no /etc/sia/sia_config, the system uses profile arn
func TestOptionsNoConfig(t *testing.T) {
	// Mock the metadata endpoints
	router := httptreemux.New()
	router.GET("/latest/meta-data/iam/info", func(w http.ResponseWriter, r *http.Request, params map[string]string) {
		log.Println("Called /latest/dynamic/instance-identity/document")
		io.WriteString(w, iamJson)
	})

	metaServer := &testServer{}
	metaServer.start(router)
	defer metaServer.stop()

	config, configAccount, _ := getConfig("data/sia_empty_config", "-service", metaServer.httpUrl(), false, "us-west-2")
	opts, e := setOptions(config, configAccount, "/tmp", "1.0.0")
	require.Nilf(t, e, "error should be empty, error: %v", e)
	require.NotNil(t, opts, "should be able to get Options")

	// Make sure one service is set
	assert.True(t, len(opts.Services) == 1)
	assert.True(t, opts.Domain == "athenz")
	assert.True(t, opts.Name == "athenz.hockey")
	assert.True(t, assertService(opts.Services[0], Service{Name: "hockey", Uid: idCommandId("-u"), Gid: idCommandId("-g"), FileMode: 288}))
}

// TestOptionsWithConfig test the scenario when /etc/sia/sia_config is present
func TestOptionsWithConfig(t *testing.T) {
	config, configAccount, _ := getConfig("data/sia_config", "-service", "http://localhost:80", false, "us-west-2")
	opts, e := setOptions(config, configAccount, "/tmp", "1.0.0")
	require.Nilf(t, e, "error should be empty, error: %v", e)
	require.NotNil(t, opts, "should be able to get Options")
	assert.True(t, opts.RefreshInterval == 1440)
	assert.True(t, opts.ZTSRegion == "")

	// Make sure services are set
	assert.True(t, len(opts.Services) == 3)
	assert.True(t, opts.Domain == "athenz")
	assert.True(t, opts.Name == "athenz.api")

	// Zeroth service should be the one from "service" key, the remaining are from "services" in no particular order
	assert.True(t, assertService(opts.Services[0], Service{Name: "api", User: "nobody", Uid: getUid("nobody"), Gid: getUserGid("nobody"), FileMode: 288}))
	assert.True(t, assertInServices(opts.Services[1:], Service{Name: "ui", User: "root", Uid: 0, Gid: 0, FileMode: 288}))
	assert.True(t, assertInServices(opts.Services[1:], Service{Name: "yamas", User: "nobody", Uid: getUid("nobody"), Group: "sys", Gid: getGid(t, "sys")}))
}

// TestOptionsNoService test the scenario when /etc/sia/sia_config is present, but service is not repeated in services
func TestOptionsNoService(t *testing.T) {
	config, configAccount, e := getConfig("data/sia_no_service", "-service", "http://localhost:80", false, "us-west-2")
	require.NotNilf(t, e, "error should be thrown, error: %v", e)

	config, configAccount, _ = getConfig("data/sia_no_service2", "-service", "http://localhost:80", false, "us-west-2")
	_, e = setOptions(config, configAccount, "/tmp", "1.0.0")
	require.NotNilf(t, e, "error should be thrown, error: %v", e)
}

// TestOptionsNoServices test the scenario when only "service" is mentioned and there are no multiple "services"
func TestOptionsNoServices(t *testing.T) {
	config, configAccount, _ := getConfig("data/sia_no_services", "-service", "http://localhost:80", false, "us-west-2")
	opts, e := setOptions(config, configAccount, "/tmp", "1.0.0")
	require.Nilf(t, e, "error should not be thrown, error: %v", e)
	assert.True(t, opts.RefreshInterval == 120)
	assert.True(t, opts.ZTSRegion == "us-west-2")

	// Make sure one service is set
	assert.True(t, len(opts.Services) == 1)
	assert.True(t, opts.Domain == "athenz")
	assert.True(t, opts.Name == "athenz.api")
	assert.True(t, assertService(opts.Services[0], Service{Name: "api", User: "nobody", Uid: getUid("nobody"), Gid: getUserGid("nobody"), FileMode: 288}))
}

func TestOptionsWithGenerateRoleKeyConfig(t *testing.T) {
	config, configAccount, _ := getConfig("data/sia_generate_role_key", "-service", "http://localhost:80", false, "us-west-2")
	opts, e := setOptions(config, configAccount, "/tmp", "1.0.0")
	require.Nilf(t, e, "error should not be thrown, error: %v", e)
	assert.True(t, opts.GenerateRoleKey == true)
}

func TestOptionsWithRotateKeyConfig(t *testing.T) {
	config, configAccount, _ := getConfig("data/sia_rotate_key", "-service", "http://localhost:80", false, "us-west-2")
	opts, e := setOptions(config, configAccount, "/tmp", "1.0.0")
	require.Nilf(t, e, "error should not be thrown, error: %v", e)
	assert.True(t, opts.RotateKey == true)
}

func idCommandId(arg string) int {
	out, err := exec.Command("id", arg).Output()
	if err != nil {
		log.Fatalf("Cannot exec 'id %s': %v\n", arg, err)
	}
	s := strings.Trim(string(out), "\n\r ")
	id, err := strconv.Atoi(s)
	if err != nil {
		log.Fatalf("Unexpected UID/GID format in user record: %s\n", string(out))
	}
	return id
}
