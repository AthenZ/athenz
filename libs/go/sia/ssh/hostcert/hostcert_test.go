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
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"fmt"
	"io/fs"
	"io/ioutil"
	"log"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/ssh"
)

const EC_HOST_CERT = "ssh_host_ecdsa_key-cert.pub"

const sshcaKeyId = "AthenzSSHCA"

func makeSshDir() (string, string, error) {
	sshDir, err := ioutil.TempDir("", "ssh.")
	if err != nil {
		return "", "", err
	}

	defaultCert, err := makeHostCert(sshDir, sshcaKeyId, EC_HOST_CERT)
	if err != nil {
		return "", "", err
	}

	return sshDir, defaultCert, nil
}

func makeHostCert(sshDir, keyId, certBaseName string) (string, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return "", err
	}

	cert, err := makeHostCertFromKey(keyId, key, key.Public(), ssh.HostCert)
	if err != nil {
		return "", err
	}

	certFile := filepath.Join(sshDir, certBaseName)
	err = ioutil.WriteFile(certFile, ssh.MarshalAuthorizedKey(cert), 0444)
	if err != nil {
		return "", err
	}

	return certFile, nil
}

// makeHostCertFromKey works with both RSA and ECDSA keys
func makeHostCertFromKey(keyId string, prikey crypto.PrivateKey, pubkey crypto.PublicKey, certType uint32) (*ssh.Certificate, error) {
	pkey, _ := ssh.NewPublicKey(pubkey)
	cert := &ssh.Certificate{
		KeyId:       keyId,
		Key:         pkey,
		CertType:    certType,
		ValidAfter:  uint64(time.Now().Unix() - 100),
		ValidBefore: uint64(time.Now().Unix() + 100),
	}
	signer, err := ssh.NewSignerFromKey(prikey)
	if err != nil {
		return nil, fmt.Errorf("unable to generate new ssh signer, error: %v\n", err)
	}
	err = cert.SignCert(rand.Reader, signer)
	if err != nil {
		return nil, fmt.Errorf("unable to sign certificate, error: %v", err)
	}

	return cert, err
}

func TestLoad(t *testing.T) {
	sshDir, validCert, err := makeSshDir()
	defer os.RemoveAll(sshDir)
	require.Nilf(t, err, "unexpected err: %v", err)

	invalidCert := filepath.Join(sshDir, "invalid_cert")
	ioutil.WriteFile(invalidCert, []byte(`bad cert`), 0444)

	nonExistingCert := filepath.Join(sshDir, "nonexisting_cert")
	notHostCert := filepath.Join("testdata", "ssh_host_rsa_key.pub")

	tests := []struct {
		name    string
		file    string
		wantErr bool
	}{
		{
			name:    "valid ssh host cert",
			file:    validCert,
			wantErr: false,
		},
		{
			name:    "corrupted ssh host cert",
			file:    invalidCert,
			wantErr: true,
		},
		{
			name:    "non existing cert",
			file:    nonExistingCert,
			wantErr: true,
		},
		{
			name:    "non ssh host cert",
			file:    notHostCert,
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := Load(tt.file)
			if (err != nil) != tt.wantErr {
				t.Errorf("Load() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
		})
	}
}

func TestVerifyFn(t *testing.T) {
	sshDir, validCert, err := makeSshDir()
	defer os.RemoveAll(sshDir)
	require.Nilf(t, err, "unexpected err: %v", err)

	notHostCert := filepath.Join(sshDir, "ssh_host_rsa_key.pub")

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.Nilf(t, err, "unexpected err: %v", err)

	sshPubKey, err := ssh.NewPublicKey(key.Public())
	require.Nilf(t, err, "unexpected err: %v", err)

	err = ioutil.WriteFile(notHostCert, ssh.MarshalAuthorizedKey(sshPubKey), 0444)
	require.Nilf(t, err, "unexpected err: %v", err)

	nonAthenzHostCert, err := makeHostCert(sshDir, "fakeCA", "fake_ssh_host_rsa_key-cert.pub")
	require.Nilf(t, err, "unexpected err: %v", err)

	type args struct {
		old string
		new string
	}
	tests := []struct {
		name    string
		args    args
		wantErr bool
	}{
		{
			name: "valid old cert",
			args: args{
				old: validCert,
				new: "new-cert-file",
			},
			wantErr: false,
		},
		{
			name: "invalid old cert",
			args: args{
				old: notHostCert,
				new: "new-cert-file",
			},
			wantErr: true,
		},
		{
			name: "non yahoo old cert",
			args: args{
				old: nonAthenzHostCert,
				new: "new-cert-file",
			},
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fn := verifyFn(sshcaKeyId)
			if err := fn(tt.args.old, tt.args.new); (err != nil) != tt.wantErr {
				t.Errorf("Verify() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestUpdate(t *testing.T) {
	sshDir, hostCertFile, err := makeSshDir()
	defer os.RemoveAll(sshDir)
	require.Nilf(t, err, "unexpected err: %v", err)

	hostCertBytes, err := ioutil.ReadFile(hostCertFile)
	require.Nilf(t, err, "unexpected err: %v", err)

	type args struct {
		hostCertFile string
		hostCert     string
		sshDir       string
	}
	tests := []struct {
		name    string
		args    args
		wantErr bool
	}{
		{
			name: "valid host cert",
			args: args{
				hostCertFile: hostCertFile,
				hostCert:     string(hostCertBytes),
				sshDir:       sshDir,
			},
			wantErr: false,
		},
		{
			name: "invalid path",
			args: args{
				hostCertFile: filepath.Join("/i-donot-exist", EC_HOST_CERT),
				hostCert:     string(hostCertBytes),
				sshDir:       sshDir,
			},
			wantErr: true,
		},
		{
			name: "empty cert bytes",
			args: args{
				hostCertFile: filepath.Join("/i-donot-exist", EC_HOST_CERT),
				hostCert:     "",
				sshDir:       sshDir,
			},
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := Update(tt.args.hostCertFile, tt.args.hostCert, tt.args.sshDir, sshcaKeyId)
			if (err != nil) != tt.wantErr {
				t.Errorf("Update() error = %v, wantErr %v", err, tt.wantErr)
			}
			if err == nil {
				// Symlink should exist
				symlink := filepath.Join(tt.args.sshDir, GENERIC_LINK)
				fi, e := os.Lstat(symlink)
				if e != nil {
					t.Errorf("symlink error = %v", e)
				} else {
					mode := fi.Mode()
					if (mode & fs.ModeSymlink) != fs.ModeSymlink {
						t.Errorf("%s not a symlink, mode: %v", symlink, fi.Mode())
						log.Printf("found: %s", fi.Name())
					}
				}

				target, e := os.Readlink(symlink)
				if e != nil {
					t.Errorf("link stat error = %v", e)
				}

				if target != tt.args.hostCertFile {
					t.Errorf("linkTarget: %q not same as host cert file: %q", target, hostCertFile)
				}

			}
		})
	}
}

func TestSymlink(t *testing.T) {
	sshDir, err := ioutil.TempDir("", "ssh.")
	require.Nilf(t, err, "unexpected err: %v", err)
	log.Printf("sshDir: %q", sshDir)
	//defer os.RemoveAll(sshDir)

	source := filepath.Join(sshDir, "source")
	ioutil.WriteFile(source, []byte("source file"), 0400)

	existingLink := filepath.Join(sshDir, "existingLink")
	existingSource := filepath.Join(sshDir, "existingSource")
	ioutil.WriteFile(existingSource, []byte("earlier source file"), 0000)
	err = os.Symlink(existingSource, existingLink)
	require.Nilf(t, err, "unexpected err: %v", err)

	regularFile := filepath.Join(sshDir, "regular")
	ioutil.WriteFile(regularFile, []byte("regular file"), 0400)

	linkToSource := filepath.Join(sshDir, "link-to-source")
	err = os.Symlink(source, linkToSource)
	require.Nilf(t, err, "unexpected err: %v", err)

	type args struct {
		source string
		link   string
	}
	tests := []struct {
		name    string
		args    args
		wantErr bool
	}{
		{
			name: "link doesn't exist",
			args: args{
				source: source,
				link:   filepath.Join(sshDir, "link"),
			},
			wantErr: false,
		},
		{
			name: "existing link, target mismatch",
			args: args{
				source: source,
				link:   existingLink,
			},
			wantErr: false,
		},
		{
			name: "link is a regular file",
			args: args{
				source: source,
				link:   regularFile,
			},
			wantErr: true,
		},
		{
			name: "link and source match",
			args: args{
				source: source,
				link:   linkToSource,
			},
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := Symlink(tt.args.source, tt.args.link)
			if (err != nil) != tt.wantErr {
				t.Errorf("Symlink() error = %v, wantErr %v", err, tt.wantErr)
			}
			if !tt.wantErr {
				if target, e := os.Readlink(tt.args.link); e != nil || target != tt.args.source {
					t.Errorf("unexpected link: %q, source: %q, target: %q, err: %v", tt.args.link, tt.args.source, target, err)
				}
			}
		})
	}
}
