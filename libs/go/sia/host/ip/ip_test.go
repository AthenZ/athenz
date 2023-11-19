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

package ip

import (
	"bytes"
	"fmt"
	"log"
	"net"
	"os"
	"os/exec"
	"reflect"
	"sort"
	"strings"
	"testing"

	"github.com/AthenZ/athenz/libs/go/sia/futil"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func ifConfigBin() string {
	if futil.Exists("/usr/sbin/ifconfig") {
		return "/usr/sbin/ifconfig"
	} else if futil.Exists("/sbin/ifconfig") {
		return "/sbin/ifconfig"
	} else {
		return ""
	}
}

func getIpsFromIfConfig(t *testing.T) ([]string, error) {
	isClassBPrivate := func(ip string) bool {
		octets := strings.Split(ip, ".")
		if len(octets) == 1 {
			return false
		}

		if octets[0] == "172" && octets[1] >= "16" && octets[1] <= "31" {
			return true
		}
		return false
	}
	o, err := exec.Command(ifConfigBin(), "-a").CombinedOutput()
	require.Nil(t, err, fmt.Sprintf("should be able to run ifconfig, error: %v", err))

	ips := []string{}
	for _, line := range strings.Split(string(o), "\n") {
		line := strings.TrimSpace(line)
		// automatically skip any autoconf entries that are created for docker/bridge
		if (strings.HasPrefix(line, "inet ") || strings.HasPrefix(line, "inet6 ")) &&
			!strings.Contains(line, "autoconf") {
			// Process the IP
			parts := strings.Split(line, " ")
			if len(parts) > 2 {
				ip := strings.TrimSpace(strings.TrimPrefix(parts[1], "addr:"))
				if ip != "" && ip != "127.0.0.1" && ip != "::1" &&
					!strings.HasPrefix(ip, "fe80::") &&
					!strings.HasPrefix(ip, "169.254.") &&
					!strings.HasPrefix(ip, "192.168.") && !isClassBPrivate(ip) {
					ips = append(ips, ip)
				}
			}
		}
	}

	return ips, err
}

func TestGetIps(t *testing.T) {
	a := assert.New(t)

	i, err := GetIps()
	a.Nil(err)

	ips := []string{}
	for _, ip := range i {
		ips = append(ips, ip.String())
	}

	log.Printf("IPs: %+v", ips)

	// Test independently using 'ifconfig -a'
	ifIps, err := getIpsFromIfConfig(t)
	log.Printf("IPs from ifconfig function: %+v", ifIps)
	require.Nil(t, err)

	sort.Strings(ips)
	sort.Strings(ifIps)
	a.True(reflect.DeepEqual(ips, ifIps))
}

func TestGetExcludeOpts(t *testing.T) {
	a := assert.New(t)

	f, err := os.CreateTemp("", "exclude_ips")
	require.Nil(t, err)
	defer os.Remove(f.Name())

	err = os.WriteFile(f.Name(), []byte("10.144.5.6/32,10.144.5.7/32\t \n10.144.4.0/30"), 0444)
	require.Nil(t, err)

	// Test for 'all'
	err = os.WriteFile(f.Name(), []byte("\t\n\nall\n\n"), 0444)
	require.Nil(t, err)

	o, err := GetExcludeOpts(f.Name())
	log.Printf("exclude ips: %#v", o)
	a.Nil(err)
	a.True(o.ExcludeAll)
	a.Nil(o.ExcludeNets)

	o, err = GetExcludeOpts(f.Name())
	log.Printf("exclude ips: %#v", o)
	a.Nil(err)
	a.True(o.ExcludeAll)
	a.Nil(o.ExcludeNets)
}

func interfaceStr(ifaces []net.Interface) string {
	b := bytes.Buffer{}

	for _, i := range ifaces {
		b.WriteString(i.Name)
	}
	return b.String()
}

func TestSkipLocalAndCni(t *testing.T) {
	tests := []struct {
		Name   string
		Input  []net.Interface
		Output []net.Interface
	}{
		{
			Name:   "Simple scenario",
			Input:  []net.Interface{{Name: "lo"}, {Name: "eth0"}},
			Output: []net.Interface{{Name: "eth0"}},
		},
		{
			Name:   "Multiple interfaces",
			Input:  []net.Interface{{Name: "lo"}, {Name: "eth0"}, {Name: "eth1"}},
			Output: []net.Interface{{Name: "eth0"}, {Name: "eth1"}},
		},
		{
			Name:   "Docker",
			Input:  []net.Interface{{Name: "docker0"}, {Name: "eth0"}, {Name: "lo"}},
			Output: []net.Interface{{Name: "eth0"}},
		},
		{
			Name:   "Docker Custom Name",
			Input:  []net.Interface{{Name: "dockerabc"}, {Name: "eth0"}, {Name: "lo"}},
			Output: []net.Interface{{Name: "dockerabc"}, {Name: "eth0"}},
		},
		{
			Name:   "Docker Digit and Name",
			Input:  []net.Interface{{Name: "docker0abc"}, {Name: "eth0"}, {Name: "lo"}},
			Output: []net.Interface{{Name: "docker0abc"}, {Name: "eth0"}},
		},
		{
			Name:   "Podman",
			Input:  []net.Interface{{Name: "cni0"}, {Name: "eth0"}, {Name: "lo"}},
			Output: []net.Interface{{Name: "eth0"}},
		},
		{
			Name:   "Podman (newer)",
			Input:  []net.Interface{{Name: "cni-podman0"}, {Name: "eth0"}, {Name: "lo"}},
			Output: []net.Interface{{Name: "eth0"}},
		},
		{
			Name:   "Podman Custom",
			Input:  []net.Interface{{Name: "cnixyz"}, {Name: "eth0"}, {Name: "lo"}},
			Output: []net.Interface{{Name: "cnixyz"}, {Name: "eth0"}},
		},
		{
			Name:   "Flannel",
			Input:  []net.Interface{{Name: "flannel.1"}, {Name: "eth0"}, {Name: "lo"}},
			Output: []net.Interface{{Name: "eth0"}},
		},
		{
			Name:   "Flannel",
			Input:  []net.Interface{{Name: "flannel0"}, {Name: "eth0"}, {Name: "lo"}},
			Output: []net.Interface{{Name: "eth0"}},
		},
		{
			Name:   "Podman Custom",
			Input:  []net.Interface{{Name: "flannelabc"}, {Name: "eth0"}, {Name: "lo"}},
			Output: []net.Interface{{Name: "flannelabc"}, {Name: "eth0"}},
		},
	}

	for _, tt := range tests {
		result := skipLocalAndCni(tt.Input)
		assert.Equalf(t, len(tt.Output), len(result), "unexpected number of network interfaces, test name: %q, expected: %+v, actual: %+v",
			tt.Name, tt.Output, result)
		assert.Equalf(t, interfaceStr(tt.Output), interfaceStr(result), "unexpected output, test name: %q, expected: %+v, actual: %+v",
			tt.Name, tt.Output, result)
	}
}

func TestFixCidr(t *testing.T) {
	tests := []struct {
		Name   string
		Cidr   string
		Result string
	}{
		{
			Name:   "Plain IP",
			Cidr:   "10.2.3.25",
			Result: "10.2.3.25/32",
		},
		{
			Name:   "IP in cidr",
			Cidr:   "10.2.3.25/32",
			Result: "10.2.3.25/32",
		},
		{
			Name:   "Cidr",
			Cidr:   "10.2.3.25/24",
			Result: "10.2.3.25/24",
		},
	}

	for _, tt := range tests {
		r := fixCidr(tt.Cidr)
		assert.Equalf(t, tt.Result, r, "unexpected result for test: %s, expected: %s, actual: %s", tt.Name, tt.Result, r)
	}
}

func TestUniqIps(t *testing.T) {
	ips := []string{
		"10.0.1.2/32",
		"10.0.1.3/32",
		"10.0.1.2/32",
		"2001:db8:a0b:12f0::1/32",
	}

	input := []net.IP{}

	for _, i := range ips {
		addr, _, e := net.ParseCIDR(i)
		assert.Nilf(t, e, "unexpected error: %v", e)
		input = append(input, addr)
	}

	result := UniqIps(input)
	assert.Lenf(t, result, 3, "unexpected result: %+v", result)
	resultStr := fmt.Sprintf("%v", result)
	assert.Truef(t, strings.Contains(resultStr, "10.0.1.2"), "unexpected result: %+v", result)
	assert.Truef(t, strings.Contains(resultStr, "10.0.1.3"), "unexpected result: %+v", result)
	assert.Truef(t, strings.Contains(resultStr, "2001:db8:a0b:12f0::1"), "unexpected result: %+v", result)
}
