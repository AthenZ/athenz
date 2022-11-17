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
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestPubKey(t *testing.T) {
	tmpSshDir := t.TempDir()

	sshPubFile := fmt.Sprintf(filepath.Join(tmpSshDir, "ssh_host_ed25519_key.pub"))

	var pubKey []byte
	var err error
	var wg sync.WaitGroup

	wg.Add(1)
	go func() {
		defer wg.Done()
		pubKey, err = PubKey(sshPubFile, 8)
	}()

	// when there is no file, PubKey will attempt to retry
	time.Sleep(1 * time.Second)
	assert.Nil(t, pubKey)

	// let's create a file now for testing
	os.WriteFile(sshPubFile, []byte("test key"), 0400)

	// wait for PubKey to finish
	wg.Wait()

	// let's give it an extra second
	time.Sleep(1 * time.Second)

	// error should be nil now
	assert.Nil(t, err)
	assert.True(t, string(pubKey) == "test key")
}

func TestKeyType_UnmarshalJSON(t *testing.T) {
	sample := `{ "ssh_host_key_type": "rsa" }`

	type config struct {
		SshHostKeyType KeyType `json:"ssh_host_key_type,omitempty"`
	}

	data := config{}

	err := json.Unmarshal([]byte(sample), &data)
	require.Nilf(t, err, "unexpected err: %v", err)
	assert.Equalf(t, Rsa, data.SshHostKeyType, "unexpected data: %+v", data)
}

func TestKeyType_UnmarshalJSON_Unknown(t *testing.T) {
	sample := `{ "ssh_host_key_type": "unknown" }`

	type config struct {
		SshHostKeyType KeyType `json:"ssh_host_key_type,omitempty"`
	}

	data := config{}

	err := json.Unmarshal([]byte(sample), &data)
	require.Nilf(t, err, "unexpected err: %v", err)
	assert.Equalf(t, Rsa, data.SshHostKeyType, "unexpected data: %+v", data)
}

func TestKeyType_UnmarshalJSON_Empty(t *testing.T) {
	type config struct {
		SshHostKeyType KeyType `json:"ssh_host_key_type,omitempty"`
	}

	data := config{}

	err := json.Unmarshal([]byte(`{}`), &data)
	require.Nilf(t, err, "unexpected err: %v", err)
	assert.Equalf(t, KeyType(0), data.SshHostKeyType, "unexpected data: %+v", data)
}

func TestKeyType_MarshalJSON(t *testing.T) {
	type config struct {
		SshHostKeyType KeyType `json:"ssh_host_key_type,omitempty"`
	}

	data := config{
		SshHostKeyType: Ecdsa,
	}

	expectedStr := `{"ssh_host_key_type":"ecdsa"}`

	s, err := json.Marshal(data)
	require.Nilf(t, err, "unexpected err: %v", err)
	assert.Equalf(t, []byte(expectedStr), s, "unexpected data: %q", s)
}

func TestPubKeyFile(t *testing.T) {
	for kt, s := range toString {
		assert.Equal(t, fmt.Sprintf("/tmp/ssh_host_%s_key.pub", s), PubKeyFile("/tmp", kt))
	}
}

func TestCertKeyFile(t *testing.T) {
	for kt, s := range toString {
		assert.Equal(t, fmt.Sprintf("/tmp/ssh_host_%s_key-cert.pub", s), CertFile("/tmp", kt))
	}
}
