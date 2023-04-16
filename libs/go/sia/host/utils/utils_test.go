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

func TestGetK8SHostnames(test *testing.T) {

	tests := []struct {
		name            string
		siaPodName      string
		siaPodIP        string
		siaPodNamespace string
		siaPodService   string
		siaPodSubdomain string
		sanDNSList      []string
	}{
		{"no-entries", "", "", "", "", "", []string{}},
		{"pod-ip-no-ns", "", "10.11.12.13", "", "", "", []string{}},
		{"pod-ns-only", "", "", "api-ns", "", "", []string{}},
		{"pod-ip-only", "", "10.11.12.13", "api-ns", "", "", []string{"10-11-12-13.api-ns.pod.cluster.local"}},
		{"pod-ip-svc", "", "10.11.12.13", "api-ns", "api", "", []string{"10-11-12-13.api-ns.pod.cluster.local", "10-11-12-13.api.api-ns.pod.cluster.local"}},
		{"pod-name-no-ns", "pod-1", "", "", "", "", []string{}},
		{"pod-name-only", "pod-1", "", "api-ns", "", "", []string{"pod-1.api-ns.svc.cluster.local"}},
		{"pod-name-subdomain", "pod-1", "", "api-ns", "", "api-sub", []string{"pod-1.api-sub.api-ns.svc.cluster.local"}},
		{"pod-all-values", "pod-1", "10.11.12.13", "api-ns", "api", "api-sub", []string{"10-11-12-13.api-ns.pod.cluster.local", "10-11-12-13.api.api-ns.pod.cluster.local", "pod-1.api-sub.api-ns.svc.cluster.local"}},
	}
	for _, tt := range tests {
		test.Run(tt.name, func(t *testing.T) {
			_ = os.Setenv("ATHENZ_SIA_POD_NAME", tt.siaPodName)
			_ = os.Setenv("ATHENZ_SIA_POD_IP", tt.siaPodIP)
			_ = os.Setenv("ATHENZ_SIA_POD_NAMESPACE", tt.siaPodNamespace)
			_ = os.Setenv("ATHENZ_SIA_POD_SERVICE", tt.siaPodService)
			_ = os.Setenv("ATHENZ_SIA_POD_SUBDOMAIN", tt.siaPodSubdomain)
			sanList := GetK8SHostnames()
			assert.Equal(t, len(sanList), len(tt.sanDNSList))
			for i := 0; i < len(sanList); i++ {
				assert.Equal(t, sanList[i], tt.sanDNSList[i])
			}
			_ = os.Unsetenv("ATHENZ_SIA_POD_NAME")
			_ = os.Unsetenv("ATHENZ_SIA_POD_IP")
			_ = os.Unsetenv("ATHENZ_SIA_POD_NAMESPACE")
			_ = os.Unsetenv("ATHENZ_SIA_POD_SERVICE")
			_ = os.Unsetenv("ATHENZ_SIA_POD_SUBDOMAIN")
		})
	}
}

func TestGetK8SHostnamesWithHostname(test *testing.T) {

	hostname := os.Getenv("HOSTNAME")
	_ = os.Setenv("HOSTNAME", "pod-1")
	_ = os.Setenv("ATHENZ_SIA_POD_NAMESPACE", "pod-ns")

	sanList := GetK8SHostnames()
	assert.Equal(test, len(sanList), 1)
	assert.Equal(test, sanList[0], "pod-1.pod-ns.svc.cluster.local")

	_ = os.Setenv("HOSTNAME", hostname)
	_ = os.Unsetenv("ATHENZ_SIA_POD_NAMESPACE")
}
