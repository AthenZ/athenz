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
	"fmt"
	"io"
	"os"
)

func NewSysLogger() (io.Writer, error) {
	return os.Stdout, nil
}

func UpdateFile(fileName string, contents []byte, uid, gid int, perm os.FileMode, directUpdate, verbose bool) error {
	return UpdateFileContents(fileName, contents, perm, directUpdate, verbose)
}

func SvcAttrs(username, groupname string) (int, int, int) {
	return 0, 0, 0440
}

func UidGidForUserGroup(username, groupname string) (int, int) {
	return 0, 0
}

func SetupSIADirs(siaMainDir, siaLinkDir string, ownerUid, ownerGid int) error {
	// Create the certs directory, if it doesn't exist
	certDir := fmt.Sprintf("%s/certs", siaMainDir)
	if !FileExists(certDir) {
		err := os.MkdirAll(certDir, 0755)
		if err != nil {
			return fmt.Errorf("unable to create certs dir: %q, error: %v", certDir, err)
		}
	}

	// Create the keys directory, if it doesn't exist
	keyDir := fmt.Sprintf("%s/keys", siaMainDir)
	if !FileExists(keyDir) {
		err := os.MkdirAll(keyDir, 0755)
		if err != nil {
			return fmt.Errorf("unable to create keys dir: %q, error: %v", keyDir, err)
		}
	}
	return nil
}

func SyscallSetGid(gid int) error {
	return nil
}

func SyscallSetUid(uid int) error {
	return nil
}

func setupDirOwnership(siaDir string, ownerUid, ownerGid int) {
}

func validateScriptArguments(args []string) bool {
	return true
}
