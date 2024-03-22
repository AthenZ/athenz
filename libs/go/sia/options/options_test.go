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
	"github.com/dimfeld/httptreemux"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"testing"

	"github.com/AthenZ/athenz/libs/go/sia/access/config"
	"github.com/AthenZ/athenz/libs/go/sia/ssh/hostkey"
	"github.com/AthenZ/athenz/libs/go/sia/util"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const iamJson = `{
  "Code" : "Success",
  "LastUpdated" : "2019-05-06T15:35:48Z",
  "InstanceProfileArn" : "arn:aws:iam::123456789012:instance-profile/athenz.hockey-service",
  "InstanceProfileId" : "XXXXPROFILEIDYYYY"
}`

const iamAccessProfileJson = `{
  "Code" : "Success",
  "LastUpdated" : "2019-05-06T15:35:48Z",
  "InstanceProfileArn" : "arn:aws:iam::123456789012:instance-profile/athenz.hockey-service@test-profile",
  "InstanceProfileId" : "XXXXPROFILEIDYYYY"
}`

const iamAccessProfileJsonServiceNameOnly = `{
  "Code" : "Success",
  "LastUpdated" : "2019-05-06T15:35:48Z",
  "InstanceProfileArn" : "arn:aws:iam::123456789012:instance-profile/hockey-service@test-profile",
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

	provider := MockAWSProvider{
		Name:     fmt.Sprintf("athenz.aws.us-west-2"),
		Hostname: "",
	}
	// Parse config bytes first, and if that fails, load values from Instance Profile and IAM info
	cfg, cfgAccount, err := InitFileConfig(fileName, metaEndPoint, useRegionalSTS, region, "", provider)
	if err != nil {
		log.Printf("unable to parse configuration file, error: %v\n", err)
		// if we do not have a configuration file, we're going
		// to use fallback to <domain>.<service>-service
		// naming structure
		log.Println("trying to determine service name from profile arn...")
		cfgAccount, _, err = InitProfileConfig(metaEndPoint, roleSuffix, "@")
		if err != nil {
			return nil, nil, fmt.Errorf("config non-parsable and unable to determine service name from profile arn, error: %v", err)
		}
	}
	return cfg, cfgAccount, nil
}

func getAccessProfileConfig(fileName, metaEndPoint string) (*ConfigAccount, *AccessProfileConfig, error) {
	// Parse config bytes first, and if that fails, load values from Instance Profile and IAM info
	profileConfig, err := InitAccessProfileFileConfig(fileName)
	var configAccount *ConfigAccount = nil
	if err != nil {
		log.Printf("unable to parse configuration file, error: %v\n", err)
		log.Println("trying to determine profile name from instance profile arn...")
		configAccount, profileConfig, err = InitProfileConfig(metaEndPoint, "-service", "@")
		if err != nil {
			return nil, nil, fmt.Errorf("config non-parsable and unable to determine profile name from profile arn, error: %v", err)
		}
	}

	return configAccount, profileConfig, nil
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
		expected.CertFilename == actual.CertFilename &&
		expected.Threshold == actual.Threshold
}

func assertInServices(svcs []Service, actual Service) bool {
	log.Printf("svcs passed: %+v\n", svcs)
	log.Printf("actual: %+v\n", actual)
	for _, s := range svcs {
		if s.Name == actual.Name && s.User == actual.User && s.Uid == actual.Uid && s.Group == actual.Group && s.Gid == actual.Gid && s.KeyFilename == actual.KeyFilename && s.CertFilename == actual.CertFilename && s.Threshold == actual.Threshold {
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

	cfg, cfgAccount, _ := getConfig("data/sia_empty_config", "-service", metaServer.httpUrl(), false, "us-west-2")
	opts, e := setOptions(cfg, cfgAccount, nil, "/var/lib/sia", "1.0.0")
	require.Nilf(t, e, "error should be empty, error: %v", e)
	require.NotNil(t, opts, "should be able to get Options")

	// Make sure one service is set
	assert.Equal(t, 1, len(opts.Services))
	assert.Equal(t, "athenz", opts.Domain)
	assert.Equal(t, "athenz.hockey", opts.Name)
	assert.True(t, assertService(opts.Services[0], Service{Name: "hockey", Uid: idCommandId("-u"), Gid: idCommandId("-g"), FileMode: 288, Threshold: DefaultThreshold}))
	assert.Equal(t, DefaultThreshold, opts.Threshold)
	assert.Equal(t, DefaultThreshold, opts.SshThreshold)
	assert.False(t, opts.FileDirectUpdate)
	assert.Equal(t, "/var/lib/sia/keys", opts.KeyDir)
	assert.Equal(t, "/var/lib/sia/certs", opts.CertDir)
	assert.Equal(t, "/var/lib/sia/tokens", opts.TokenDir)
	assert.Equal(t, "/var/lib/sia/backup", opts.BackupDir)
	assert.Equal(t, 2, opts.FailCountForExit)
}

// TestOptionsNoProfileConfig tests the scenario when there is no /etc/sia/profile_config, the system uses instance profile arn
func TestOptionsNoProfileConfig(t *testing.T) {
	// Mock the metadata endpoints
	router := httptreemux.New()
	router.GET("/latest/meta-data/iam/info", func(w http.ResponseWriter, r *http.Request, params map[string]string) {
		log.Println("Called /latest/dynamic/instance-identity/document")
		io.WriteString(w, iamAccessProfileJson)
	})

	metaServer := &testServer{}
	metaServer.start(router)
	defer metaServer.stop()

	configAccount, profileConfig, err := getAccessProfileConfig("data/profile_config.empty", metaServer.httpUrl())
	require.Nilf(t, err, "error should be empty, error: %v", err)

	opts, e := setOptions(nil, configAccount, profileConfig, "/tmp", "1.0.0")
	require.Nilf(t, e, "error should be empty, error: %v", e)
	require.NotNil(t, opts, "should be able to get Options")

	// Make sure one service is set
	assert.True(t, len(opts.Services) == 1)
	assert.True(t, opts.Domain == "athenz")
	assert.True(t, opts.Name == "athenz.hockey")
	assert.Equal(t, opts.Profile, "test-profile")

	assert.Equal(t, opts.Threshold, DefaultThreshold)
	assert.Equal(t, opts.SshThreshold, DefaultThreshold)
}

// TestOptionsWithProfileConfig test the scenario when profile config file is present
func TestOptionsWithProfileConfig(t *testing.T) {
	_, profileConfig, _ := getAccessProfileConfig("data/profile_config", "http://localhost:80")
	cfg, cfgAccount, _ := getConfig("data/sia_config", "-service", "http://localhost:80", false, "us-west-2")
	opts, e := setOptions(cfg, cfgAccount, profileConfig, "/tmp", "1.0.0")
	require.Nilf(t, e, "error should be empty, error: %v", e)
	require.NotNil(t, opts, "should be able to get Options")
	assert.Equal(t, 1440, opts.RefreshInterval)
	assert.Empty(t, opts.ZTSRegion)

	// Make sure profile is correct
	assert.Equal(t, "zts-profile", opts.Profile)
	assert.Empty(t, opts.ProfileRestrictTo)

	// Make sure services are set
	assert.Equal(t, 3, len(opts.Services))
	assert.Equal(t, "athenz", opts.Domain)
	assert.Equal(t, "athenz.api", opts.Name)

	// Zeroth service should be the one from "service" key, the remaining are from "services" in no particular order
	assert.True(t, assertService(opts.Services[0], Service{Name: "api", User: "nobody", Uid: getUid("nobody"), Gid: getUserGid("nobody"), FileMode: 288, Threshold: DefaultThreshold}))
	assert.True(t, assertInServices(opts.Services[1:], Service{Name: "ui", User: "root", Uid: 0, Gid: 0, FileMode: 288, Threshold: DefaultThreshold}))
	assert.True(t, assertInServices(opts.Services[1:], Service{Name: "yamas", User: "nobody", Uid: getUid("nobody"), Group: "sys", Gid: getGid(t, "sys"), Threshold: DefaultThreshold}))

	assert.Equal(t, DefaultThreshold, opts.SshThreshold)
	assert.Equal(t, DefaultThreshold, opts.Threshold)
	assert.Equal(t, "host1.athenz.io,host2.athenz.io", opts.SshPrincipals)
}

// TestOptionsWithProfileConfigAndProfileTag test the scenario when profile config file is present anbd has profile tag key
func TestOptionsWithProfileConfigAndProfileRestrictTo(t *testing.T) {
	_, profileConfig, _ := getAccessProfileConfig("data/profile_config_tag_key", "http://localhost:80")
	cfg, cfgAccount, _ := getConfig("data/sia_config", "-service", "http://localhost:80", false, "us-west-2")
	opts, e := setOptions(cfg, cfgAccount, profileConfig, "/tmp", "1.0.0")
	require.Nilf(t, e, "error should be empty, error: %v", e)
	require.NotNil(t, opts, "should be able to get Options")
	assert.True(t, opts.RefreshInterval == 1440)
	assert.True(t, opts.ZTSRegion == "")

	// Make sure profile is correct
	assert.True(t, opts.Profile == "zts-profile")
	assert.True(t, opts.ProfileRestrictTo == "zts:RestrictTo")

	// Make sure services are set
	assert.True(t, len(opts.Services) == 3)
	assert.True(t, opts.Domain == "athenz")
	assert.True(t, opts.Name == "athenz.api")

	// Zeroth service should be the one from "service" key, the remaining are from "services" in no particular order
	assert.True(t, assertService(opts.Services[0], Service{Name: "api", User: "nobody", Uid: getUid("nobody"), Gid: getUserGid("nobody"), FileMode: 288, Threshold: DefaultThreshold}))
	assert.True(t, assertInServices(opts.Services[1:], Service{Name: "ui", User: "root", Uid: 0, Gid: 0, FileMode: 288, Threshold: DefaultThreshold}))
	assert.True(t, assertInServices(opts.Services[1:], Service{Name: "yamas", User: "nobody", Uid: getUid("nobody"), Group: "sys", Gid: getGid(t, "sys"), Threshold: DefaultThreshold}))

	assert.Equal(t, DefaultThreshold, opts.SshThreshold)
	assert.Equal(t, DefaultThreshold, opts.Threshold)
}

func TestOptionsWithRoleThreshold(t *testing.T) {
	_, profileConfig, _ := getAccessProfileConfig("data/profile_config", "http://localhost:80")
	cfg, cfgAccount, _ := getConfig("data/sia_config_threshold_role", "-service", "http://localhost:80", false, "us-west-2")
	opts, e := setOptions(cfg, cfgAccount, profileConfig, "/tmp", "1.0.0")
	require.Nilf(t, e, "error should be empty, error: %v", e)
	require.NotNil(t, opts, "should be able to get Options")
	assert.Equal(t, 1440, opts.RefreshInterval)
	assert.Empty(t, opts.ZTSRegion)
	assert.Equal(t, 5, opts.FailCountForExit)
	assert.Equal(t, 2, *opts.StoreTokenOption)

	// Make sure profile is correct
	assert.Equal(t, "zts-profile", opts.Profile)

	// Make sure services are set
	assert.Equal(t, 3, len(opts.Services))
	assert.Equal(t, "athenz", opts.Domain)
	assert.Equal(t, "athenz.api", opts.Name)

	// Zeroth service should be the one from "service" key, the remaining are from "services" in no particular order
	assert.True(t, assertService(opts.Services[0], Service{Name: "api", User: "nobody", Uid: getUid("nobody"), Gid: getUserGid("nobody"), FileMode: 288, Threshold: 20}))
	assert.True(t, assertInServices(opts.Services[1:], Service{Name: "ui", User: "root", Uid: 0, Gid: 0, FileMode: 288, Threshold: 20}))
	assert.True(t, assertInServices(opts.Services[1:], Service{Name: "yamas", User: "nobody", Uid: getUid("nobody"), Group: "sys", Gid: getGid(t, "sys"), Threshold: 20}))
	assert.Equal(t, float64(25), opts.Roles[0].Threshold)

	assert.Equal(t, DefaultThreshold, opts.SshThreshold)
	assert.Equal(t, float64(20), opts.Threshold)
}

func TestOptionsWithServiceAccountThreshold(t *testing.T) {
	_, profileConfig, _ := getAccessProfileConfig("data/profile_config", "http://localhost:80")
	cfg, cfgAccount, _ := getConfig("data/sia_config_threshold_service", "-service", "http://localhost:80", false, "us-west-2")
	opts, e := setOptions(cfg, cfgAccount, profileConfig, "/tmp", "1.0.0")
	require.Nilf(t, e, "error should be empty, error: %v", e)
	require.NotNil(t, opts, "should be able to get Options")
	assert.True(t, opts.RefreshInterval == 1440)
	assert.True(t, opts.ZTSRegion == "")

	// Make sure profile is correct
	assert.True(t, opts.Profile == "zts-profile")

	// Make sure services are set
	assert.True(t, len(opts.Services) == 3)
	assert.True(t, opts.Domain == "athenz")
	assert.True(t, opts.Name == "athenz.api")

	// Zeroth service should be the one from "service" key, the remaining are from "services" in no particular order
	assert.True(t, assertService(opts.Services[0], Service{Name: "api", User: "nobody", Uid: getUid("nobody"), Gid: getUserGid("nobody"), FileMode: 288, Threshold: 35}))
	assert.True(t, assertInServices(opts.Services[1:], Service{Name: "ui", User: "root", Uid: 0, Gid: 0, FileMode: 288, Threshold: 35}))
	assert.True(t, assertInServices(opts.Services[1:], Service{Name: "yamas", User: "nobody", Uid: getUid("nobody"), Group: "sys", Gid: getGid(t, "sys"), Threshold: 25}))

	assert.Equal(t, float64(60), opts.SshThreshold)
	assert.Equal(t, float64(35), opts.Threshold)
}

// TestOptionsWithConfig test the scenario when /etc/sia/sia_config is present
func TestOptionsWithConfig(t *testing.T) {
	cfg, cfgAccount, _ := getConfig("data/sia_config", "-service", "http://localhost:80", false, "us-west-2")
	assert.Equal(t, "", cfg.SiaKeyDir)
	assert.Equal(t, "", cfg.SiaCertDir)
	assert.Equal(t, "", cfg.SiaTokenDir)
	assert.Equal(t, "", cfg.SiaBackupDir)

	opts, e := setOptions(cfg, cfgAccount, nil, "/var/lib/sia", "1.0.0")
	require.Nilf(t, e, "error should be empty, error: %v", e)
	require.NotNil(t, opts, "should be able to get Options")
	assert.Equal(t, 1440, opts.RefreshInterval)
	assert.Equal(t, "", opts.ZTSRegion)
	assert.Equal(t, "/var/lib/sia/keys", opts.KeyDir)
	assert.Equal(t, "/var/lib/sia/certs", opts.CertDir)
	assert.Equal(t, "/var/lib/sia/tokens", opts.TokenDir)
	assert.Equal(t, "/var/lib/sia/backup", opts.BackupDir)
	assert.Equal(t, "host1.athenz.io,host2.athenz.io", opts.SshPrincipals)

	assert.Equal(t, 2, len(opts.AddlSanDNSEntries))
	assert.Equal(t, "svc1.athenz.io", opts.AddlSanDNSEntries[0])
	assert.Equal(t, "svc2.athenz.io", opts.AddlSanDNSEntries[1])

	// Make sure services are set
	assert.Equal(t, 3, len(opts.Services))
	assert.Equal(t, "athenz", opts.Domain)
	assert.Equal(t, "athenz.api", opts.Name)

	// Zeroth service should be the one from "service" key, the remaining are from "services" in no particular order
	assert.True(t, assertService(opts.Services[0], Service{Name: "api", User: "nobody", Uid: getUid("nobody"), Gid: getUserGid("nobody"), FileMode: 288, Threshold: DefaultThreshold}))
	assert.True(t, assertInServices(opts.Services[1:], Service{Name: "ui", User: "root", Uid: 0, Gid: 0, FileMode: 288, Threshold: DefaultThreshold}))
	assert.True(t, assertInServices(opts.Services[1:], Service{Name: "yamas", User: "nobody", Uid: getUid("nobody"), Group: "sys", Gid: getGid(t, "sys"), Threshold: DefaultThreshold}))

	assert.Equal(t, DefaultThreshold, opts.Threshold)
	assert.Equal(t, DefaultThreshold, opts.SshThreshold)
}

// TestOptionsNoService test the scenario when /etc/sia/sia_config is present, but service is not repeated in services
func TestOptionsNoService(t *testing.T) {
	cfg, cfgAccount, e := getConfig("data/sia_no_service", "-service", "http://localhost:80", false, "us-west-2")
	require.NotNilf(t, e, "error should be thrown, error: %v", e)

	cfg, cfgAccount, _ = getConfig("data/sia_no_service2", "-service", "http://localhost:80", false, "us-west-2")
	_, e = setOptions(cfg, cfgAccount, nil, "/tmp", "1.0.0")
	require.NotNilf(t, e, "error should be thrown, error: %v", e)
}

// TestOptionsNoServices test the scenario when only "service" is mentioned and there are no multiple "services"
func TestOptionsNoServices(t *testing.T) {
	cfg, cfgAccount, _ := getConfig("data/sia_no_services", "-service", "http://localhost:80", false, "us-west-2")
	opts, e := setOptions(cfg, cfgAccount, nil, "/tmp", "1.0.0")
	require.Nilf(t, e, "error should not be thrown, error: %v", e)
	assert.Equal(t, 120, opts.RefreshInterval)
	assert.Equal(t, "us-west-2", opts.ZTSRegion)
	assert.Equal(t, "athenz.io", opts.SpiffeTrustDomain)

	// Make sure one service is set
	assert.Equal(t, 1, len(opts.Services))
	assert.Equal(t, "athenz", opts.Domain)
	assert.Equal(t, "athenz.api", opts.Name)
	assert.True(t, assertService(opts.Services[0], Service{Name: "api", User: "nobody", Uid: getUid("nobody"), Gid: getUserGid("nobody"), FileMode: 288, Threshold: DefaultThreshold}))
	assert.True(t, opts.FileDirectUpdate)
}

func TestOptionsWithGenerateRoleKeyConfig(t *testing.T) {
	cfg, cfgAccount, _ := getConfig("data/sia_generate_role_key", "-service", "http://localhost:80", false, "us-west-2")
	opts, e := setOptions(cfg, cfgAccount, nil, "/tmp", "1.0.0")
	require.Nilf(t, e, "error should not be thrown, error: %v", e)
	assert.True(t, opts.GenerateRoleKey)
	assert.Equal(t, 2, len(opts.Roles))
	count := 0
	for _, role := range opts.Roles {
		switch role.Name {
		case "sports:role.readers":
			assert.Equal(t, 0440, role.FileMode)
			assert.Equal(t, "/tmp/keys/sports:role.readers.key.pem", role.RoleKeyFilename)
			count += 1
		case "sports:role.writers":
			assert.Equal(t, 0440, role.FileMode)
			assert.Equal(t, "/tmp/keys/sports:role.writers.key.pem", role.RoleKeyFilename)
			count += 1
		}
	}
	assert.Equal(t, 2, count)
}

func TestOptionsWithRoles(t *testing.T) {
	cfg, cfgAccount, _ := getConfig("data/sia_with_roles", "-service", "http://localhost:80", false, "us-west-2")
	opts, e := setOptions(cfg, cfgAccount, nil, "/tmp", "1.0.0")
	require.Nilf(t, e, "error should not be thrown, error: %v", e)
	assert.False(t, opts.GenerateRoleKey)
	assert.Equal(t, 2, len(opts.Roles))
	count := 0
	for _, role := range opts.Roles {
		switch role.Name {
		case "sports:role.readers":
			assert.Equal(t, 0440, role.FileMode)
			assert.Equal(t, "", role.RoleKeyFilename)
			assert.Equal(t, "/tmp/certs/sports:role.readers.cert.pem", role.RoleCertFilename)
			assert.Equal(t, "/tmp/keys/athenz.api.key.pem", role.SvcKeyFilename)
			assert.Equal(t, "/tmp/certs/athenz.api.cert.pem", role.SvcCertFilename)
			count += 1
		case "sports:role.writers":
			assert.Equal(t, 0440, role.FileMode)
			assert.Equal(t, "", role.RoleKeyFilename)
			assert.Equal(t, "/tmp/certs/sports:role.writers.cert.pem", role.RoleCertFilename)
			assert.Equal(t, "/tmp/keys/athenz.api.key.pem", role.SvcKeyFilename)
			assert.Equal(t, "/tmp/certs/athenz.api.cert.pem", role.SvcCertFilename)
			count += 1
		}
	}
	assert.Equal(t, 2, count)
}

func TestOptionsWithRotateKeyConfig(t *testing.T) {
	cfg, cfgAccount, _ := getConfig("data/sia_rotate_key", "-service", "http://localhost:80", false, "us-west-2")
	opts, e := setOptions(cfg, cfgAccount, nil, "/tmp", "1.0.0")
	require.Nilf(t, e, "error should not be thrown, error: %v", e)
	assert.True(t, opts.RotateKey)
}

func TestGetRunsAsUidGid(t *testing.T) {

	tests := map[string]struct {
		filename       string
		uid            int
		gid            int
		dropPrivileges bool
	}{
		"single-user-with-roles1": {
			filename:       "data/sia_config_same_user_with_roles",
			uid:            getUid("nobody"),
			gid:            getUserGid("nobody"),
			dropPrivileges: true,
		},
		"multiple-users": {
			filename:       "data/sia_config",
			uid:            -1,
			gid:            -1,
			dropPrivileges: true,
		},
		"multiple-users-with-roles": {
			filename:       "data/sia_config_with_roles",
			uid:            -1,
			gid:            -1,
			dropPrivileges: true,
		},
		"single-user": {
			filename:       "data/sia_config_same_user",
			uid:            getUid("nobody"),
			gid:            getUserGid("nobody"),
			dropPrivileges: true,
		},
		"single-user-with-roles": {
			filename:       "data/sia_config_same_user_with_roles",
			uid:            getUid("nobody"),
			gid:            getUserGid("nobody"),
			dropPrivileges: true,
		},
		"single-user-keep": {
			filename:       "data/sia_config_same_user",
			uid:            -1,
			gid:            -1,
			dropPrivileges: false,
		},
		"single-user-role-mismatch": {
			filename:       "data/sia_config_same_user_role_mismatch",
			uid:            -1,
			gid:            -1,
			dropPrivileges: true,
		},
	}

	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			cfg, cfgAccount, _ := getConfig(tt.filename, "-service", "http://localhost:80", false, "us-west-2")
			cfg.DropPrivileges = tt.dropPrivileges
			opts, _ := setOptions(cfg, cfgAccount, nil, "/tmp", "1.0.0")
			uid, gid := GetRunsAsUidGid(opts)
			assert.True(t, uid == tt.uid)
			assert.True(t, gid == tt.gid)
		})
	}
}

func toServiceNames(services []Service) []string {
	var serviceNames []string

	for _, srv := range services {
		serviceNames = append(serviceNames, srv.Name)
	}

	return serviceNames
}

func TestOptionsWithAccessToken(t *testing.T) {
	a := assert.New(t)

	cfg, configAccount, _ := getConfig("data/sia_config.with-access-tokens", "-service", "http://localhost:80", false, "us-west-2")
	cfg.DropPrivileges = false
	siaDir := "/tmp"
	opts, err := setOptions(cfg, configAccount, nil, siaDir, "1.0.0")
	require.Nilf(t, err, "error should not be thrown, error: %v", err)

	a.Equal(opts.TokenDir, filepath.Join(siaDir, "tokens"))
	a.Equal(cfg.Service, "api")
	serviceNames := toServiceNames(opts.Services)
	a.Contains(serviceNames, "api")
	a.Contains(serviceNames, "splunk")
	a.Contains(serviceNames, "logger")

	a.True(assertToken(opts.AccessTokens, config.AccessToken{
		FileName:                 "reader",
		Service:                  "api",
		Domain:                   "athenz.demo",
		Roles:                    []string{"reader"},
		Expiry:                   DefaultTokenExpiry,
		User:                     "nobody",
		ProxyPrincipalSpiffeUris: "",
	}))

	a.True(assertToken(opts.AccessTokens, config.AccessToken{
		FileName:                 "poweruser",
		Service:                  "api",
		Domain:                   "athenz.demo",
		Roles:                    []string{"reader-admin"},
		Expiry:                   10800,
		User:                     "nobody",
		ProxyPrincipalSpiffeUris: "",
	}))

	a.True(assertToken(opts.AccessTokens, config.AccessToken{
		FileName:                 "consumer",
		Service:                  "api",
		Domain:                   "athenz.demo",
		Roles:                    []string{"reader", "reader-admin"},
		Expiry:                   DefaultTokenExpiry,
		User:                     "nobody",
		ProxyPrincipalSpiffeUris: "",
	}))

	a.True(assertToken(opts.AccessTokens, config.AccessToken{
		FileName:                 "writer",
		Service:                  "api",
		Domain:                   "athenz.demo",
		Roles:                    []string{"writer", "writer-admin"},
		Expiry:                   10800,
		User:                     "nobody",
		ProxyPrincipalSpiffeUris: "",
	}))

	a.True(assertToken(opts.AccessTokens, config.AccessToken{
		FileName:                 "splunk",
		Service:                  "logger",
		Domain:                   "athenz.demo",
		Roles:                    []string{"splunk"},
		Expiry:                   DefaultTokenExpiry,
		User:                     "nobody",
		ProxyPrincipalSpiffeUris: "",
	}))

	a.True(assertToken(opts.AccessTokens, config.AccessToken{
		FileName:                 "all",
		Service:                  "api",
		Domain:                   "athenz.demo",
		Roles:                    []string{"*"},
		Expiry:                   DefaultTokenExpiry,
		User:                     "nobody",
		ProxyPrincipalSpiffeUris: "",
	}))

	a.True(assertToken(opts.AccessTokens, config.AccessToken{
		FileName:                 "spiffe",
		Service:                  "api",
		Domain:                   "athenz.demo",
		Roles:                    []string{"writer", "writer-admin"},
		Expiry:                   10800,
		User:                     "nobody",
		ProxyPrincipalSpiffeUris: "spiffe://athenz/sa/api,spiffe://athenz/sa/logger",
	}))

	log.Print(opts)
}

func TestInvalidAccessTokenRole(t *testing.T) {
	cfg, configAccount, _ := getConfig("data/sia_config.invalid-role-access-token", "-service", "http://localhost:80", false, "us-west-2")
	siaDir := "/tmp"
	opts, err := setOptions(cfg, configAccount, nil, siaDir, "1.0.0")
	require.NotNilf(t, err, "error should be thrown, error: %v", err)
	require.Nil(t, opts)
}

func TestInvalidAccessTokenDomain(t *testing.T) {
	cfg, configAccount, _ := getConfig("data/sia_config.invalid-domain-access-token", "-service", "http://localhost:80", false, "us-west-2")
	siaDir := "/tmp"
	opts, err := setOptions(cfg, configAccount, nil, siaDir, "1.0.0")
	require.NotNilf(t, err, "error should be thrown, error: %v", err)
	require.Nil(t, opts)
}

func TestGetRoleServiceOwner(t *testing.T) {
	services := []Service{
		{
			Name: "svc1",
		},
		{
			Name: "svc2",
		},
	}
	svc := getRoleServiceOwner("", services)
	assert.True(t, svc.Name == "svc1")

	svc = getRoleServiceOwner("svc1", services)
	assert.True(t, svc.Name == "svc1")

	svc = getRoleServiceOwner("svc2", services)
	assert.True(t, svc.Name == "svc2")

	svc = getRoleServiceOwner("svc3", services)
	assert.True(t, svc.Name == "svc1")
}

func assertToken(tokens []config.AccessToken, token config.AccessToken) bool {
	log.Printf("Looking for Token: %+v", token)
	for _, t := range tokens {
		log.Printf("Token: %+v", t)
		if t.FileName == token.FileName &&
			t.Service == token.Service &&
			t.Domain == token.Domain &&
			reflect.DeepEqual(t.Roles, token.Roles) &&
			t.Expiry == token.Expiry &&
			t.User == token.User &&
			t.ProxyPrincipalSpiffeUris == token.ProxyPrincipalSpiffeUris {
			return true
		}
	}
	return false
}

func idCommandId(arg string) int {
	out, err := exec.Command(util.GetUtilPath("id"), arg).Output()
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

func TestInitEnvConfig(t *testing.T) {
	os.Setenv("ATHENZ_SIA_SANDNS_WILDCARD", "true")
	os.Setenv("ATHENZ_SIA_SANDNS_HOSTNAME", "true")
	os.Setenv("ATHENZ_SIA_HOSTNAME_SUFFIX", "zts.athenz.cloud")
	os.Setenv("ATHENZ_SIA_REGIONAL_STS", "true")
	os.Setenv("ATHENZ_SIA_GENERATE_ROLE_KEY", "true")
	os.Setenv("ATHENZ_SIA_ROTATE_KEY", "false")
	os.Setenv("ATHENZ_SIA_USER", "root")
	os.Setenv("ATHENZ_SIA_GROUP", "nobody")
	os.Setenv("ATHENZ_SIA_SDS_UDS_PATH", "/tmp/uds")
	os.Setenv("ATHENZ_SIA_SDS_UDS_UID", "1336")
	os.Setenv("ATHENZ_SIA_EXPIRY_TIME", "10001")
	os.Setenv("ATHENZ_SIA_REFRESH_INTERVAL", "120")
	os.Setenv("ATHENZ_SIA_ZTS_REGION", "us-west-3")
	os.Setenv("ATHENZ_SIA_DROP_PRIVILEGES", "true")
	os.Setenv("ATHENZ_SIA_FILE_DIRECT_UPDATE", "true")
	os.Setenv("ATHENZ_SIA_IAM_ROLE_ARN", "arn:aws:iam::123456789012:role/athenz.api")
	os.Setenv("ATHENZ_SIA_ACCOUNT_ROLES", "{\"sports:role.readers\":{\"service\":\"api\"},\"sports:role.writers\":{\"user\": \"nobody\"}}")
	os.Setenv("ATHENZ_SIA_ACCESS_TOKENS", "{\"sports/api\":{\"roles\":[\"sports:role.readers\"],\"expires_in\":3600}}")
	os.Setenv("ATHENZ_SIA_KEY_DIR", "/var/athenz/keys")
	os.Setenv("ATHENZ_SIA_CERT_DIR", "/var/athenz/certs")
	os.Setenv("ATHENZ_SIA_TOKEN_DIR", "/var/athenz/tokens")
	os.Setenv("ATHENZ_SIA_SSH_PRINCIPALS", "host1.athenz.io")
	os.Setenv("ATHENZ_SIA_FAIL_COUNT_FOR_EXIT", "10")
	os.Setenv("ATHENZ_SIA_SPIFFE_TRUST_DOMAIN", "athenz.io")
	os.Setenv("ATHENZ_SIA_STORE_TOKEN_OPTION", "2")
	os.Setenv("ATHENZ_SIA_OMIT_DOMAIN", "true")
	os.Setenv("ATHENZ_SIA_SANDNS_X509_CNAMES", "svc1.athenz.io,svc2.athenz.io")

	provider := MockAWSProvider{
		Name:     fmt.Sprintf("athenz.aws.us-west-2"),
		Hostname: "",
	}
	cfg, cfgAccount, err := InitEnvConfig(nil, provider)
	require.Nilf(t, err, "error should be empty, error: %v", err)
	assert.True(t, cfg.SanDnsWildcard)
	assert.True(t, cfg.SanDnsHostname)
	assert.True(t, cfg.UseRegionalSTS)
	assert.True(t, cfg.GenerateRoleKey)
	assert.True(t, cfg.FileDirectUpdate)
	assert.False(t, cfg.RotateKey)
	assert.Equal(t, "root", cfg.User)
	assert.Equal(t, "nobody", cfg.Group)
	assert.Equal(t, "/tmp/uds", cfg.SDSUdsPath)
	assert.Equal(t, 1336, cfg.SDSUdsUid)
	assert.Equal(t, 10001, cfg.ExpiryTime)
	assert.Equal(t, 120, cfg.RefreshInterval)
	assert.Equal(t, "us-west-3", cfg.ZTSRegion)
	assert.True(t, cfg.DropPrivileges)
	assert.Equal(t, "/var/athenz/keys", cfg.SiaKeyDir)
	assert.Equal(t, "/var/athenz/certs", cfg.SiaCertDir)
	assert.Equal(t, "/var/athenz/tokens", cfg.SiaTokenDir)
	assert.Equal(t, "zts.athenz.cloud", cfg.HostnameSuffix)
	assert.Equal(t, "athenz.io", cfg.SpiffeTrustDomain)
	assert.Equal(t, "svc1.athenz.io,svc2.athenz.io", cfg.SanDnsX509Cnames)

	assert.Equal(t, 1, len(cfg.AccessTokens))
	assert.Equal(t, cfg.AccessTokens["sports/api"].Service, "")
	assert.Equal(t, 1, len(cfg.AccessTokens["sports/api"].Roles))
	assert.Equal(t, "sports:role.readers", cfg.AccessTokens["sports/api"].Roles[0])
	assert.Equal(t, 3600, cfg.AccessTokens["sports/api"].Expiry)

	assert.Equal(t, "123456789012", cfgAccount.Account)
	assert.Equal(t, "athenz", cfgAccount.Domain)
	assert.Equal(t, "api", cfgAccount.Service)
	assert.Equal(t, "athenz.api", cfgAccount.Name)
	assert.Equal(t, 2, len(cfgAccount.Roles))
	assert.Equal(t, "host1.athenz.io", cfg.SshPrincipals)
	assert.Equal(t, 10, cfg.FailCountForExit)
	assert.Equal(t, 2, *cfg.StoreTokenOption)
	assert.True(t, cfgAccount.OmitDomain)

	os.Clearenv()
}

func TestGetConfigWithSshHostKeyType(t *testing.T) {

	tests := map[string]struct {
		filename    string
		parseFailed bool
		hostKeyType hostkey.KeyType
	}{
		"config-with-no-keytype": {
			filename:    "data/sia_config",
			parseFailed: false,
			hostKeyType: 0,
		},
		"config-with-rsa": {
			filename:    "data/sia_config_ssh_rsa",
			parseFailed: false,
			hostKeyType: hostkey.Rsa,
		},
		"config-with-ecdsa": {
			filename:    "data/sia_config_ssh_ecdsa",
			parseFailed: false,
			hostKeyType: hostkey.Ecdsa,
		},
		"config-with-ed25519": {
			filename:    "data/sia_config_ssh_ed25519",
			parseFailed: false,
			hostKeyType: hostkey.Ed25519,
		},
		"config-with-unknown": {
			filename:    "data/sia_config_ssh_unknown",
			parseFailed: true,
			hostKeyType: hostkey.Rsa,
		},
	}

	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			cfg, _, _ := getConfig(tt.filename, "-service", "http://localhost:80", false, "us-west-2")
			assert.Equal(t, cfg.SshHostKeyType, tt.hostKeyType)
		})
	}
}

func TestOptionsWithSiaDirs(t *testing.T) {
	cfg, cfgAccount, _ := getConfig("data/sia_config_ssh_ecdsa", "-service", "http://localhost:80", false, "us-west-2")
	assert.Equal(t, "/var/athenz/keys", cfg.SiaKeyDir)
	assert.Equal(t, "/var/athenz/certs", cfg.SiaCertDir)
	assert.Equal(t, "/var/athenz/tokens", cfg.SiaTokenDir)
	assert.Equal(t, "/var/athenz/backup", cfg.SiaBackupDir)

	opts, e := setOptions(cfg, cfgAccount, nil, "/tmp", "1.0.0")
	require.Nilf(t, e, "error should not be thrown, error: %v", e)
	assert.Equal(t, "/var/athenz/keys", opts.KeyDir)
	assert.Equal(t, "/var/athenz/certs", opts.CertDir)
	assert.Equal(t, "/var/athenz/tokens", opts.TokenDir)
	assert.Equal(t, "/var/athenz/backup", opts.BackupDir)
}

func TestOptionsWithServiceOnlySetup(t *testing.T) {
	// Mock the metadata endpoints
	router := httptreemux.New()
	router.GET("/latest/meta-data/iam/info", func(w http.ResponseWriter, r *http.Request, params map[string]string) {
		log.Println("Called /latest/dynamic/instance-identity/document")
		io.WriteString(w, iamAccessProfileJsonServiceNameOnly)
	})
	router.GET("/latest/meta-data/tags/instance/athenz-domain", func(w http.ResponseWriter, r *http.Request, params map[string]string) {
		log.Println("Called /latest/dynamic/instance-identity/document")
		io.WriteString(w, "athenz")
	})

	metaServer := &testServer{}
	metaServer.start(router)
	defer metaServer.stop()

	configAccount, profileConfig, err := InitProfileConfig(metaServer.httpUrl(), "-service", "@")
	require.Nilf(t, err, "error should be empty, error: %v", err)

	opts, e := setOptions(nil, configAccount, profileConfig, "/tmp", "1.0.0")
	require.Nilf(t, e, "error should be empty, error: %v", e)
	require.NotNil(t, opts, "should be able to get Options")

	// Make sure one service is set
	assert.Equal(t, len(opts.Services), 1)
	assert.True(t, opts.OmitDomain)
	assert.Equal(t, opts.Domain, "athenz")
	assert.Equal(t, opts.Name, "athenz.hockey")
	assert.Equal(t, opts.Profile, "test-profile")

	assert.Equal(t, opts.Threshold, DefaultThreshold)
	assert.Equal(t, opts.SshThreshold, DefaultThreshold)
}
