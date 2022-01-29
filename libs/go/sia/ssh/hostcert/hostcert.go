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
	"io/ioutil"
	"os"
	"path"
	"strings"

	"golang.org/x/crypto/ssh"

	siafile "github.com/AthenZ/athenz/libs/go/sia/file"
)

const GENERIC_LINK = "ssh_host_cert.pub"

var sshcaKeyId = "AthenzSSHCA"

func Update(hostCertFile, hostCert, sshDir string) error {
	// if we have no hostCert, we have nothing to update for ssh access
	if hostCert == "" {
		return errors.New("ZTS did not generate a host cert for this provider")
	}

	// Setting 644 as other public keys created by ssh-keygen -A on ssh start up have 644
	err := siafile.Update(hostCertFile, []byte(hostCert), 0, 0, 0644, Verify)
	if err != nil {
		return err
	}

	return Symlink(hostCertFile, path.Join(sshDir, GENERIC_LINK))
}

// Symlink places the link file, if it doesn't exist or doesn't link to the source file
func Symlink(source, link string) error {
	// createLink, if the link doesn't exist (for any type of PathError)
	target, err := os.Readlink(link)
	if err != nil {
		return os.Symlink(source, link)
	}

	// if link exists and the linked file is not pointing to the source, delete and link it again
	if target != source {
		e := os.Remove(link)
		if e != nil {
			return e
		}
		return os.Symlink(source, link)
	}

	return nil
}

func Verify(old, new string) error {
	if siafile.Exists(old) {
		cert, err := Load(old)
		if err != nil {
			return err
		}

		if !strings.Contains(cert.KeyId, sshcaKeyId) {
			return fmt.Errorf("existing cert: %q is not signed by YahooSSHCA, use caution while replacing", old)
		}
	}

	// Add any new additional checks on new cert here
	return nil
}

func Load(f string) (*ssh.Certificate, error) {
	bytes, err := ioutil.ReadFile(f)
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
