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

package futil

import (
	"os"
)

func Exists(path string) bool {
	if _, err := os.Stat(path); os.IsNotExist(err) {
		return false
	}
	return true
}

// MakeDirs creates dirs, if they don't exist
func MakeDirs(dirs []string, perm os.FileMode) error {
	for _, d := range dirs {
		if !Exists(d) {
			err := os.MkdirAll(d, perm)
			if err != nil {
				return err
			}
		}
	}

	return nil
}

// WriteFile is analogous to os.WriteFile, with an explicit call to Sync
// right after a successful Write operation
func WriteFile(name string, data []byte, perm os.FileMode) error {
	f, err := os.OpenFile(name, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, perm)
	if err != nil {
		return err
	}
	if _, err = f.Write(data); err == nil {
		err = f.Sync()
	}
	if err1 := f.Close(); err1 != nil && err == nil {
		err = err1
	}
	return err
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
