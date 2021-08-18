// Copyright The Athenz Authors
// Licensed under the terms of the Apache version 2.0 license. See LICENSE file for terms.

package ip

import (
	"bytes"
	"net"
	"testing"

	"github.com/stretchr/testify/assert"
	"log"
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

func interfaceStr(ifaces []net.Interface) string {
	b := bytes.Buffer{}

	for _, i := range ifaces {
		b.WriteString(i.Name)
	}
	return b.String()
}
