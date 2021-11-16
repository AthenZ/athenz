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

package util

import (
	"io"
	"log"
	"log/syslog"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"testing"
)

func TestGidForGroupCommand(t *testing.T) {
	var sysLogger io.Writer
	sysLogger, err := syslog.New(syslog.LOG_INFO|syslog.LOG_DAEMON, "siad")
	if err != nil {
		log.Printf("Unable to create sys logger: %v\n", err)
		sysLogger = os.Stdout
	}

	// Get current group name.
	grp, err := exec.Command("id", "-gn").Output()
	if err != nil {
		t.Errorf("Cannot exec 'id -gn': %v", err)
		return
	}
	group := strings.Trim(string(grp), "\n\r ")

	// Get current group id.
	gidBytes, err := exec.Command("id", "-g").Output()
	if err != nil {
		t.Errorf("Cannot exec 'id -gn': %v", err)
		return
	}
	gid, err := strconv.Atoi(strings.Trim(string(gidBytes), "\n\r "))
	if err != nil {
		t.Errorf("Unexpected GID format in user record: %s", string(gidBytes))
	}

	// Test if function returns expected gid.
	actualGid := gidForGroup(group, sysLogger)
	if actualGid != gid {
		t.Errorf("Unexpected group id: group=%s, expected=%d, got=%d", group, gid, actualGid)
		return
	}
}

func TestGidForInvalidGroupCommand(t *testing.T) {
	var sysLogger io.Writer
	sysLogger, err := syslog.New(syslog.LOG_INFO|syslog.LOG_DAEMON, "siad")
	if err != nil {
		log.Printf("Unable to create sys logger: %v\n", err)
		sysLogger = os.Stdout
	}

	// Test if function returns -1
	gid := gidForGroup("invalid-group-name", sysLogger)
	if gid != -1 {
		t.Errorf("Did not get expected -1 for gid, got=%d", gid)
		return
	}
}

func TestUidGidForUserGroupCommand(t *testing.T) {
	var sysLogger io.Writer
	sysLogger, err := syslog.New(syslog.LOG_INFO|syslog.LOG_DAEMON, "siad")
	if err != nil {
		log.Printf("Unable to create sys logger: %v\n", err)
		sysLogger = os.Stdout
	}

	// Get current user id
	usr, err := exec.Command("id", "-un").Output()
	if err != nil {
		t.Errorf("Cannot exec 'id -un': %v", err)
		return
	}
	user := strings.Trim(string(usr), "\n\r ")

	// Get current user id.
	uidBytes, err := exec.Command("id", "-u").Output()
	if err != nil {
		t.Errorf("Cannot exec 'id -un': %v", err)
		return
	}
	uid, err := strconv.Atoi(strings.Trim(string(uidBytes), "\n\r "))
	if err != nil {
		t.Errorf("Unexpected UID format in user record: %s", string(uidBytes))
	}

	// Get current group id.
	gidBytes, err := exec.Command("id", "-g").Output()
	if err != nil {
		t.Errorf("Cannot exec 'id -gn': %v", err)
		return
	}
	gid, err := strconv.Atoi(strings.Trim(string(gidBytes), "\n\r "))
	if err != nil {
		t.Errorf("Unexpected GID format in user record: %s", string(gidBytes))
	}

	testUid, testGid := uidGidForUser(user, sysLogger)
	if testUid != uid {
		t.Errorf("Unexpected uid value returned: %d, expected: %d", testUid, uid)
	}
	if testGid != gid {
		t.Errorf("Unexpected gid value returned: %d, expected: %d", testGid, gid)
	}
	testUid, testGid = uidGidForUser("root", sysLogger)
	if testUid != 0 {
		t.Errorf("Unexpected uid value returned: %d, expected: 0", testUid)
	}
	if testGid != 0 {
		t.Errorf("Unexpected gid value returned: %d, expected: 0", testGid)
	}
}
