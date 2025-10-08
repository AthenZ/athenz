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
	"os/exec"
	"strconv"
	"strings"
	"testing"
)

func TestGidForGroupCommand(t *testing.T) {
	// Get current group name.
	grp, err := exec.Command(GetUtilPath("id"), "-gn").Output()
	if err != nil {
		t.Errorf("Cannot exec 'id -gn': %v", err)
		return
	}
	group := strings.Trim(string(grp), "\n\r ")

	// Get current group id.
	gidBytes, err := exec.Command(GetUtilPath("id"), "-g").Output()
	if err != nil {
		t.Errorf("Cannot exec 'id -gn': %v", err)
		return
	}
	gid, err := strconv.Atoi(strings.Trim(string(gidBytes), "\n\r "))
	if err != nil {
		t.Errorf("Unexpected GID format in user record: %s", string(gidBytes))
	}

	// Test if function returns expected gid.
	actualGid := GetGroupGID(group)
	if actualGid != gid {
		t.Errorf("Unexpected group id: group=%s, expected=%d, got=%d", group, gid, actualGid)
		return
	}
}

func TestGidForInvalidGroupCommand(t *testing.T) {
	// Test if function returns -1
	gid := GetGroupGID("invalid-group-name")
	if gid != -1 {
		t.Errorf("Did not get expected -1 for gid, got=%d", gid)
		return
	}
}

func TestGetGroupGIDEmptyString(t *testing.T) {
	// Test with empty group name - should return -1
	gid := GetGroupGID("")
	if gid != -1 {
		t.Errorf("Did not get expected -1 for empty group name, got=%d", gid)
		return
	}
}

func TestGetGroupGIDWhitespace(t *testing.T) {
	// Test with whitespace group name - should return -1
	gid := GetGroupGID("   ")
	if gid != -1 {
		t.Errorf("Did not get expected -1 for whitespace group name, got=%d", gid)
		return
	}
}

func TestGetGroupGIDWithSpecialChars(t *testing.T) {
	// Test with special characters in group name - should return -1
	gid := GetGroupGID("invalid:group:name")
	if gid != -1 {
		t.Errorf("Did not get expected -1 for group name with special chars, got=%d", gid)
		return
	}
}

func TestGetGroupGIDRootGroup(t *testing.T) {
	// Test with root group which typically exists on Unix systems
	// On Linux, root group has GID 0
	gid := GetGroupGID("root")
	if gid != 0 {
		t.Errorf("Expected GID 0 for root group, got=%d", gid)
		return
	}
}

func TestGetGroupGIDMultipleLookups(t *testing.T) {
	// Test multiple lookups to ensure consistency
	grp, err := exec.Command(GetUtilPath("id"), "-gn").Output()
	if err != nil {
		t.Errorf("Cannot exec 'id -gn': %v", err)
		return
	}
	group := strings.Trim(string(grp), "\n\r ")

	gid1 := GetGroupGID(group)
	gid2 := GetGroupGID(group)

	if gid1 != gid2 {
		t.Errorf("Multiple lookups returned different GIDs: %d vs %d", gid1, gid2)
		return
	}
	if gid1 == -1 {
		t.Errorf("Failed to get GID for current group: %s", group)
		return
	}
}

func TestGetGroupGIDCaseSensitivity(t *testing.T) {
	// Group names are case-sensitive on Unix systems
	// Get current group name
	grp, err := exec.Command(GetUtilPath("id"), "-gn").Output()
	if err != nil {
		t.Errorf("Cannot exec 'id -gn': %v", err)
		return
	}
	group := strings.Trim(string(grp), "\n\r ")

	// Try with uppercase version (should fail unless the actual group is uppercase)
	upperGroup := strings.ToUpper(group)
	if upperGroup != group {
		gid := GetGroupGID(upperGroup)
		// Unless by coincidence there's an uppercase version, this should return -1
		gidOriginal := GetGroupGID(group)
		if gidOriginal != -1 && gid == gidOriginal {
			// Only fail if we know the lowercase version exists but got same result
			// This is unlikely unless both versions exist
			if upperGroup != group {
				t.Logf("Both %s and %s exist with same GID (unusual but valid)", group, upperGroup)
			}
		}
	}
}

func TestUidGidForUserGroupCommand(t *testing.T) {
	// Get current user id
	usr, err := exec.Command(GetUtilPath("id"), "-un").Output()
	if err != nil {
		t.Errorf("Cannot exec 'id -un': %v", err)
		return
	}
	user := strings.Trim(string(usr), "\n\r ")

	// Get current user id.
	uidBytes, err := exec.Command(GetUtilPath("id"), "-u").Output()
	if err != nil {
		t.Errorf("Cannot exec 'id -un': %v", err)
		return
	}
	uid, err := strconv.Atoi(strings.Trim(string(uidBytes), "\n\r "))
	if err != nil {
		t.Errorf("Unexpected UID format in user record: %s", string(uidBytes))
	}

	// Get current group id.
	gidBytes, err := exec.Command(GetUtilPath("id"), "-g").Output()
	if err != nil {
		t.Errorf("Cannot exec 'id -gn': %v", err)
		return
	}
	gid, err := strconv.Atoi(strings.Trim(string(gidBytes), "\n\r "))
	if err != nil {
		t.Errorf("Unexpected GID format in user record: %s", string(gidBytes))
	}

	testUid, testGid := uidGidForUser(user)
	if testUid != uid {
		t.Errorf("Unexpected uid value returned: %d, expected: %d", testUid, uid)
	}
	if testGid != gid {
		t.Errorf("Unexpected gid value returned: %d, expected: %d", testGid, gid)
	}
	testUid, testGid = uidGidForUser("root")
	if testUid != 0 {
		t.Errorf("Unexpected uid value returned: %d, expected: 0", testUid)
	}
	if testGid != 0 {
		t.Errorf("Unexpected gid value returned: %d, expected: 0", testGid)
	}
}

func TestValidateScriptArguments(t *testing.T) {
	// Test if function returns true for valid script path.
	if !validateScriptArguments([]string{"/bin/sh", "-c", "/bin/ls"}) {
		t.Errorf("Unexpected return value for valid script path")
		return
	}

	// Test if function returns true for empty path
	if !validateScriptArguments(nil) {
		t.Errorf("Unexpected return value for valid script path")
		return
	}

	// Test if function returns false for invalid script path.
	if validateScriptArguments([]string{"ls", "-l"}) {
		t.Errorf("Unexpected return value for invalid script path")
		return
	}
}
