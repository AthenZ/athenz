// Copyright The Athenz Authors
// Licensed under the terms of the Apache version 2.0 license. See LICENSE file for terms.

package ip

import (
	"bytes"
	"net"
	"testing"

	siafile "github.com/AthenZ/athenz/libs/go/sia/file"

	"fmt"
	"log"
	"os/exec"
	"reflect"
	"sort"
	"strings"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

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

func ifConfigBin() string {
	if siafile.Exists("/usr/sbin/ifconfig") {
		return "/usr/sbin/ifconfig"
	} else if siafile.Exists("/sbin/ifconfig") {
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
		if strings.HasPrefix(line, "inet ") || strings.HasPrefix(line, "inet6 ") {
			// Process the IP
			parts := strings.Split(line, " ")
			if len(parts) > 2 {
				ip := strings.TrimSpace(strings.TrimPrefix(parts[1], "addr:"))
				if ip != "" && ip != "127.0.0.1" && ip != "::1" &&
					!strings.HasPrefix(ip, "fe80::") &&
					!strings.HasPrefix(ip, "192.168.") && !isClassBPrivate(ip) {
					ips = append(ips, ip)
				}
			}
		}
	}

	return ips, err
}

func interfaceStr(ifaces []net.Interface) string {
	b := bytes.Buffer{}

	for _, i := range ifaces {
		b.WriteString(i.Name)
	}
	return b.String()
}
