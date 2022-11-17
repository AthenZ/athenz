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

package hostcert

import (
	"errors"
	"fmt"
	"github.com/AthenZ/athenz/libs/go/sia/futil"
	"os"
	"path"
	"strings"

	"github.com/AthenZ/athenz/libs/go/sia/verify"
	"golang.org/x/crypto/ssh"

	siafile "github.com/AthenZ/athenz/libs/go/sia/file"
)

const GENERIC_LINK = "ssh_host_cert.pub"

// Update writes the hostCert to disk at hostCertFile as long as it is signed by the same CA as existing one
func Update(hostCertFile, hostCert, sshDir, caKeyId string) error {
	// if we have no hostCert, we have nothing to update for ssh access
	if hostCert == "" {
		return errors.New("ZTS did not generate a host cert for this provider")
	}

	// Setting 644 as other public keys created by ssh-keygen -A on ssh start up have 644
	err := siafile.Update(hostCertFile, []byte(hostCert), 0, 0, 0644, verifyFn(caKeyId))
	if err != nil {
		return err
	}

	return futil.Symlink(hostCertFile, path.Join(sshDir, GENERIC_LINK))
}

func verifyFn(caKeyId string) verify.VerifyFn {
	return func(old, new string) error {
		if siafile.Exists(old) {
			cert, err := Load(old)
			if err != nil {
				return err
			}

			if !strings.Contains(cert.KeyId, caKeyId) {
				return fmt.Errorf("existing cert: %q is not signed by %q, use caution while replacing", old, caKeyId)
			}
		}

		// Add any new additional checks on new cert here
		return nil
	}
}

// Load takes in a filepath and returns a parsed ssh.Certificate
func Load(f string) (*ssh.Certificate, error) {
	bytes, err := os.ReadFile(f)
	if err != nil {
		return nil, fmt.Errorf("unable to read existing cert: %q, error: %v", f, err)
	}
	key, _, _, _, err := ssh.ParseAuthorizedKey(bytes)
	if err != nil {
		return nil, fmt.Errorf("unable to parse existing cert: %q, error: %v", f, err)
	}

	cert, ok := key.(*ssh.Certificate)
	if !ok {
		return nil, fmt.Errorf("unable to extract cert from key: %q", f)
	}

	return cert, nil
}
