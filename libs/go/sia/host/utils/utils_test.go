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

package utils

import (
	"github.com/stretchr/testify/assert"
	"os"
	"strings"
	"testing"
)

func TestGetHostname(t *testing.T) {
	hostname, _ := os.Hostname()
	// with false flag we should get the exact same value
	assert.Equal(t, hostname, GetHostname(false))
	// with true flag our hostname is the extract string
	// or a subset of the response
	testHostname := GetHostname(true)
	assert.True(t, strings.HasPrefix(testHostname, hostname))
}
