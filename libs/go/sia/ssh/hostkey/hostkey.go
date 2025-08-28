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

package hostkey

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"
)

type KeyType int

const (
	_ KeyType = iota
	Rsa
	Ecdsa
	Ed25519
)

const DEFAULT_KEYTYPE = "rsa"

var toString = map[KeyType]string{
	Rsa:     "rsa",
	Ecdsa:   "ecdsa",
	Ed25519: "ed25519",
}

var toId = map[string]KeyType{
	"rsa":     Rsa,
	"ecdsa":   Ecdsa,
	"ed25519": Ed25519,
}

// MarshalJSON marshals the enum as a quoted json string
func (s KeyType) MarshalJSON() ([]byte, error) {
	buffer := bytes.NewBufferString(`"`)
	buffer.WriteString(toString[s])
	buffer.WriteString(`"`)
	return buffer.Bytes(), nil
}

// UnmarshalJSON unmashals a quoted json string to the enum value
func (s *KeyType) UnmarshalJSON(b []byte) error {
	var j string
	err := json.Unmarshal(b, &j)
	if err != nil {
		return err
	}

	if val, ok := toId[j]; ok {
		*s = val
	} else {
		*s = toId[DEFAULT_KEYTYPE]
	}
	return nil
}

// PubKey reads the content of file, until a non-nil error and upto n times
// each retry sleeps for a second
func PubKey(file string, n int) ([]byte, error) {
	var pubKey []byte
	var err error
	for i := 0; i < n; i++ {
		pubKey, err = os.ReadFile(file)
		// it's possible that we read the file right after it was created
		// but before the content was written to it so we check for
		// a non-nil error and also check if the length of the content is greater
		// than zero. If both conditions are satisfied, we return the content
		// otherwise we retry
		if err == nil && len(pubKey) > 0 {
			return pubKey, nil
		}
		time.Sleep(time.Second)
	}
	return nil, err
}

// PubKeyFile returns the path to the public key of the host key type passed in
func PubKeyFile(sshDir string, keyType KeyType) string {
	return filepath.Join(sshDir, fmt.Sprintf("ssh_host_%s_key.pub", toString[keyType]))
}

// CertFile returns the path to the ssh host certificate based on the keyType
func CertFile(sshDir string, keyType KeyType) string {
	return filepath.Join(sshDir, fmt.Sprintf("ssh_host_%s_key-cert.pub", toString[keyType]))
}
