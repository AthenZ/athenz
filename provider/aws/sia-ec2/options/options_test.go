//
// Copyright 2020 Verizon Media
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
	"github.com/dimfeld/httptreemux"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"io"
	"io/ioutil"
	"log"
	"net"
	"net/http"
	"os"
	"os/user"
	"strconv"
	"strings"
	"testing"
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

// TestOptionsNoConfig tests the scenario when there is no /etc/sia/sia_config, the system uses profile arn
func TestOptionsNoConfig(t *testing.T) {
	// Mock the metadata endpoints
	router := httptreemux.New()
	router.GET("/latest/meta-data/iam/info", func(w http.ResponseWriter, r *http.Request, params map[string]string) {
		log.Printf("Called /latest/dynamic/instance-identity/document")
		io.WriteString(w, string(iamJson))
	})

	metaServer := &testServer{}
	metaServer.start(router)
	defer metaServer.stop()

	opts, e := NewOptions([]byte{}, "123456789012", metaServer.httpUrl(), "/tmp", "1.0.0", "", "", "zts-aws-domain", "", os.Stdout)
	require.Nilf(t, e, "error should be empty, error: %v", e)
	require.NotNil(t, opts, "should be able to get Options")

	// Make sure one service is set
	assert.True(t, len(opts.Services) == 1)
	assert.True(t, opts.Domain == "athenz")
	assert.True(t, opts.Name == "athenz.hockey")
	assert.True(t, assertService(opts.Services[0], Service{Name: "hockey", Uid: 0, Gid: 0}))
}

// TestOptionsWithConfig test the scenario when /etc/sia/sia_config is present
func TestOptionsWithConfig(t *testing.T) {
	config := `{
		"version": "1.0.0",
  		"service": "api",
  		"services": {
    		"api": {},
    		"ui": {},
			"yamas": {
				"user": "nobody",
				"group": "sys"
			}
  		},
  		"accounts": [
  			{
  			    "domain": "athenz",
    			"user": "nobody",
    	  		"account": "123456789012"
    		}
  		]
	}`

	opts, e := NewOptions([]byte(config), "123456789012", "http://localhost:80", "/tmp", "1.0.0", "", "", "zts-aws-domain", "", os.Stdout)
	require.Nilf(t, e, "error should be empty, error: %v", e)
	require.NotNil(t, opts, "should be able to get Options")

	// Make sure services are set
	assert.True(t, len(opts.Services) == 3)
	assert.True(t, opts.Domain == "athenz")
	assert.True(t, opts.Name == "athenz.api")

	// Zeroth service should be the one from "service" key, the remaining are from "services" in no particular order
	assert.True(t, assertService(opts.Services[0], Service{Name: "api", User: "nobody", Uid: getUid("nobody"), Gid: getUserGid("nobody")}))
	assert.True(t, assertInServices(opts.Services[1:], Service{Name: "ui"}))
	assert.True(t, assertInServices(opts.Services[1:], Service{Name: "yamas", User: "nobody", Uid: getUid("nobody"), Group: "sys", Gid: getGid(t, "sys")}))
}

// TestOptionsNoService test the scenario when /etc/sia/sia_config is present, but service is not repeated in services
func TestOptionsNoService(t *testing.T) {
	config := `{
		"version": "1.0.0",
  		"services": {
    		"api": {},
    		"ui": {}
  		},
  		"accounts": [
  			{
  			    "domain": "athenz",
    			"user": "nobody",
    	  		"account": "123456789012"
    		}
  		]
	}`

	_, e := NewOptions([]byte(config), "123456789012", "http://localhost:80", "/tmp", "1.0.0", "", "", "zts-aws-domain", "", os.Stdout)
	require.NotNilf(t, e, "error should be thrown, error: %v", e)

	config = `{
		"version": "1.0.0",
		"service": "api",
  		"services": {
    		"ui": {}
  		},
  		"accounts": [
  			{
  			    "domain": "athenz",
    			"user": "nobody",
    	  		"account": "123456789012"
    		}
  		]
	}`

	_, e = NewOptions([]byte(config), "123456789012", "http://localhost:80", "/tmp", "1.0.0", "", "", "zts-aws-domain", "", os.Stdout)
	require.NotNilf(t, e, "error should be thrown, error: %v", e)
}

// TestOptionsNoServices test the scenario when only "service" is mentioned and there are no multiple "services"
func TestOptionsNoServices(t *testing.T) {
	config := `{
		"version": "1.0.0",
		"service": "api",
  		"accounts": [
  			{
  			    "domain": "athenz",
    			"user": "nobody",
    	  		"account": "123456789012"
    		}
  		]
	}`

	opts, e := NewOptions([]byte(config), "123456789012", "http://localhost:80", "/tmp", "1.0.0", "", "", "zts-aws-domain", "", os.Stdout)
	require.Nilf(t, e, "error should not be thrown, error: %v", e)

	// Make sure one service is set
	assert.True(t, len(opts.Services) == 1)
	assert.True(t, opts.Domain == "athenz")
	assert.True(t, opts.Name == "athenz.api")
	assert.True(t, assertService(opts.Services[0], Service{Name: "api", User: "nobody", Uid: getUid("nobody"), Gid: getUserGid("nobody")}))
}

func assertService(expected Service, actual Service) bool {
	log.Printf("expected: %+v", expected)
	log.Printf("actual: %+v", actual)
	return expected.Name == actual.Name &&
		expected.User == actual.User &&
		expected.Uid == actual.Uid &&
		expected.Group == actual.Group &&
		expected.Gid == actual.Gid &&
		expected.Filename == actual.Filename
}

func assertInServices(svcs []Service, actual Service) bool {
	log.Printf("svcs passed: %+v", svcs)
	log.Printf("actual: %+v", actual)
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
		parts := strings.Split(strings.Trim(string(line), "\r"), ":")
		if parts[0] == group {
			gid, err := strconv.Atoi(parts[2])
			require.Nil(t, err)
			return gid
		}
	}

	require.FailNow(t, fmt.Sprintf("Unable to find group: %q", group))
	return 0
}

func TestOptionsWithGenerateRoleKeyConfig(t *testing.T) {
	config := `{
		"version": "1.0.0",
		"service": "api",
		"generate_role_key": true,
  		"accounts": [
  			{
  			    "domain": "athenz",
    			"user": "nobody",
    	  		"account": "123456789012"
    		}
  		]
	}`

	opts, e := NewOptions([]byte(config), "123456789012", "http://localhost:80", "/tmp", "1.0.0", "", "", "zts-aws-domain", "", os.Stdout)
	require.Nilf(t, e, "error should not be thrown, error: %v", e)
	assert.True(t, opts.GenerateRoleKey == true)
}

func TestOptionsWithRotateKeyConfig(t *testing.T) {
	config := `{
		"version": "1.0.0",
		"service": "api",
		"rotate_key": true,
  		"accounts": [
  			{
  			    "domain": "athenz",
    			"user": "nobody",
    	  		"account": "123456789012"
    		}
  		]
	}`

	opts, e := NewOptions([]byte(config), "123456789012", "http://localhost:80", "/tmp", "1.0.0", "", "", "zts-aws-domain", "", os.Stdout)
	require.Nilf(t, e, "error should not be thrown, error: %v", e)
	assert.True(t, opts.RotateKey == true)
}
