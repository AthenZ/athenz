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
	"log"
	"os"
	"os/exec"
	"strings"
)

// GetHostname returns the hostname
func GetHostname(fqdn bool) string {
	// if the fqdn flag is passed we can't use the go api
	// since it doesn't provide an option for it. so we'll
	// just resolve calling the hostname directly.
	if fqdn {
		hostname, err := exec.Command("/bin/hostname", "-f").Output()
		if err != nil {
			log.Printf("Cannot exec '/bin/hostname -f': %v", err)
			return os.Getenv("HOSTNAME")
		}
		return strings.Trim(string(hostname), "\n\r ")
	} else {
		hostname, err := os.Hostname()
		if err != nil {
			log.Printf("Unable to obtain os hostname: %v\n", err)
			return os.Getenv("HOSTNAME")
		}
		return hostname
	}
}
