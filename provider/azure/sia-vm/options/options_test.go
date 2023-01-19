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

package options

import (
	"fmt"
	"github.com/AthenZ/athenz/provider/azure/sia-vm/data/attestation"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"log"
	"os"
	"os/exec"
	"os/user"
	"strconv"
	"strings"
	"testing"
)

func TestGetSvcNames(t *testing.T) {
	var svcs []Service
	ts1 := Service{
		Name: "service1",
	}
	ts2 := Service{
		Name: "service2",
	}
	svcs = append(svcs, ts1)
	svcs = append(svcs, ts2)
	assert.True(t, GetSvcNames(svcs) == "service1,service2")
}

// TestOptionsNoConfig tests the scenario when there is no /etc/sia/sia_config, the system uses profile arn
func TestOptionsNoConfig(t *testing.T) {

	identityDocument := attestation.IdentityDocument{
		Location:          "west2",
		Name:              "athenz",
		ResourceGroupName: "athenz-rg",
		SubscriptionId:    "123456789012",
		VmId:              "123456789012-vmid",
		OsType:            "Linux",
		Tags:              "athenz:athenz.hockey",
		PrivateIp:         "10.0.0.1",
		PublicIp:          "",
		Document:          nil,
	}

	ztsAzureDomains := []string{"zts-azure-domain"}
	opts, e := NewOptions([]byte{}, &identityDocument, "/tmp", "1.0.0", "", "", ztsAzureDomains, "US", "azure.provider")
	require.Nilf(t, e, "error should be empty, error: %v", e)
	require.NotNil(t, opts, "should be able to get Options")

	// Make sure one service is set
	assert.True(t, len(opts.Services) == 1)
	assert.True(t, opts.Domain == "athenz")
	assert.True(t, opts.Name == "athenz.hockey")
	assert.True(t, assertService(opts.Services[0], Service{Name: "hockey", Uid: idCommandId("-u"), Gid: idCommandId("-g")}))
}

// TestOptionsWithConfig test the scenario when /etc/sia/sia_config is present
func TestOptionsWithConfig(t *testing.T) {
	config := `{
		"version": "1.0.0",
  		"service": "api",
  		"services": {
    		"api": {},
			"ui": {
				"user": "root"
			},
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

	identityDocument := attestation.IdentityDocument{
		Location:          "west2",
		Name:              "athenz",
		ResourceGroupName: "athenz-rg",
		SubscriptionId:    "123456789012",
		VmId:              "123456789012-vmid",
		OsType:            "Linux",
		Tags:              "athenz:athenz.api",
		PrivateIp:         "10.0.0.1",
		PublicIp:          "",
		Document:          nil,
	}

	ztsAzureDomains := []string{"zts-azure-domain"}
	opts, e := NewOptions([]byte(config), &identityDocument, "/tmp", "1.0.0", "", "", ztsAzureDomains, "US", "azure.provider")
	require.Nilf(t, e, "error should be empty, error: %v", e)
	require.NotNil(t, opts, "should be able to get Options")

	// Make sure services are set
	assert.True(t, len(opts.Services) == 3)
	assert.True(t, opts.Domain == "athenz")
	assert.True(t, opts.Name == "athenz.api")

	// Zeroth service should be the one from "service" key, the remaining are from "services" in no particular order
	assert.True(t, assertService(opts.Services[0], Service{Name: "api", User: "nobody", Uid: getUid("nobody"), Gid: getUserGid("nobody")}))
	assert.True(t, assertInServices(opts.Services[1:], Service{Name: "ui", User: "root", Uid: 0, Gid: 0}))
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

	identityDocument := attestation.IdentityDocument{
		Location:          "west2",
		Name:              "athenz",
		ResourceGroupName: "athenz-rg",
		SubscriptionId:    "123456789012",
		VmId:              "123456789012-vmid",
		OsType:            "Linux",
		Tags:              "",
		PrivateIp:         "10.0.0.1",
		PublicIp:          "",
		Document:          nil,
	}

	ztsAzureDomains := []string{"zts-azure-domain"}
	_, e := NewOptions([]byte(config), &identityDocument, "/tmp", "1.0.0", "", "", ztsAzureDomains, "US", "azure.provider")
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

	_, e = NewOptions([]byte(config), &identityDocument, "/tmp", "1.0.0", "", "", ztsAzureDomains, "US", "azure.provider")
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

	identityDocument := attestation.IdentityDocument{
		Location:          "west2",
		Name:              "athenz",
		ResourceGroupName: "athenz-rg",
		SubscriptionId:    "123456789012",
		VmId:              "123456789012-vmid",
		OsType:            "Linux",
		Tags:              "athenz:athenz.api",
		PrivateIp:         "10.0.0.1",
		PublicIp:          "",
		Document:          nil,
	}

	ztsAzureDomains := []string{"zts-azure-domain"}
	opts, e := NewOptions([]byte(config), &identityDocument, "/tmp", "1.0.0", "", "", ztsAzureDomains, "US", "azure.provider")
	require.Nilf(t, e, "error should not be thrown, error: %v", e)

	// Make sure one service is set
	assert.True(t, len(opts.Services) == 1)
	assert.True(t, opts.Domain == "athenz")
	assert.True(t, opts.Name == "athenz.api")
	assert.True(t, assertService(opts.Services[0], Service{Name: "api", User: "nobody", Uid: getUid("nobody"), Gid: getUserGid("nobody")}))
}

func assertService(expected Service, actual Service) bool {
	log.Printf("expected: %+v\n", expected)
	log.Printf("actual: %+v\n", actual)
	return expected.Name == actual.Name &&
		expected.User == actual.User &&
		expected.Uid == actual.Uid &&
		expected.Group == actual.Group &&
		expected.Gid == actual.Gid &&
		expected.KeyFilename == actual.KeyFilename &&
		expected.CertFilename == actual.CertFilename
}

func assertInServices(svcs []Service, actual Service) bool {
	log.Printf("svcs passed: %+v\n", svcs)
	log.Printf("actual: %+v\n", actual)
	for _, s := range svcs {
		if s.Name == actual.Name && s.User == actual.User && s.Uid == actual.Uid && s.Group == actual.Group && s.Gid == actual.Gid && s.KeyFilename == actual.KeyFilename && s.CertFilename == actual.CertFilename {
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
	out, err := os.ReadFile("/etc/group")
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
