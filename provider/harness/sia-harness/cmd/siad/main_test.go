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

package main

import (
	"bytes"
	"testing"
)

func TestStripNewLinesFromData(test *testing.T) {

	tests := []struct {
		name     string
		data     []byte
		expected []byte
	}{
		{"no-new-lines", []byte("this is a test"), []byte("this is a test")},
		{"one-new-line", []byte("this is a test\n"), []byte("this is a test\\n")},
		{"multiple-new-lines", []byte("this \nis a \ntest"), []byte("this \\nis a \\ntest")},
	}
	for _, tt := range tests {
		test.Run(tt.name, func(t *testing.T) {
			result := stripNewLinesFromData(tt.data)
			if !bytes.Equal(result, tt.expected) {
				t.Errorf("stripNewLinesFromData returned invalid data: %s", string(result))
			}
		})
	}
}
