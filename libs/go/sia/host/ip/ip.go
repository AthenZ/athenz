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
	"regexp"
	"strings"

	"github.com/AthenZ/athenz/libs/go/sia/futil"
)

// Opts holds options for openstack/non-openstack
type Opts struct {
	ExcludeAll  bool
	ExcludeNets []*net.IPNet
}

func skipLocalAndCni(ifaces []net.Interface) []net.Interface {
	result := []net.Interface{}
	r := regexp.MustCompile("^(?:docker|cni|cni-podman|flannel\\.?)\\d*$")

	for _, i := range ifaces {
		if i.Name == "lo" || strings.HasPrefix(i.Name, "lo:") {
			continue
		}
		if r.MatchString(i.Name) {
			continue
		}
		result = append(result, i)
	}

	return result
}

// GetIps returns an array of IPs found on the host. It skips loop back, link-local, private ips
func GetIps() ([]net.IP, error) {
	_, bNetwork, _ := net.ParseCIDR("172.16.0.0/12")
	_, cNetwork, _ := net.ParseCIDR("192.168.0.0/16")

	skipIp := func(ip net.IP) bool {
		// skip loop back
		if ip.IsLoopback() {
			return true
		}
		// skip link-local
		if ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() {
			return true
		}
		// skip IPv6 private IP,
		// Probably will never be used in Oath
		if strings.HasPrefix(ip.String(), "fd") {
			return true
		}
		// skip IPv4 class B, C private IP
		if bNetwork.Contains(ip) || cNetwork.Contains(ip) {
			return true
		}
		return false
	}

	ifaces, err := net.Interfaces()
	if err != nil {
		log.Printf("Unable to obtain ip interfaces, error: %v", err)
		return nil, err
	}

	ips := []net.IP{}
	for _, i := range skipLocalAndCni(ifaces) {
		addrs, _ := i.Addrs()
		for _, a := range addrs {
			switch v := a.(type) {
			case *net.IPAddr:
				if !skipIp(v.IP) {
					ips = append(ips, v.IP)
				}
			case *net.IPNet:
				if !skipIp(v.IP) {
					ips = append(ips, v.IP)
				}
			}
		}
	}

	return UniqIps(ips), nil
}

// UniqIps returns a uniq list of IPs from the input, as the name implies
func UniqIps(ips []net.IP) []net.IP {
	m := map[string]net.IP{}

	for _, i := range ips {
		m[i.String()] = i
	}

	result := []net.IP{}

	for _, v := range m {
		result = append(result, v)
	}

	return result
}

// GetExcludeOpts parses exclude_ip file at /var/lib/sia, and returns exclude ip options
func GetExcludeOpts(file string) (Opts, error) {
	if !futil.Exists(file) {
		return Opts{}, nil
	}

	b, err := os.ReadFile(file)
	if err != nil {
		return Opts{}, err
	}

	result := []*net.IPNet{}
	b = bytes.TrimSpace(b)

	if bytes.Equal(b, []byte("all")) {
		return Opts{ExcludeAll: true}, nil
	}

	for _, l := range strings.Split(string(b), "\n") {
		for _, w := range strings.Split(l, ",") {
			_, n, err := net.ParseCIDR(fixCidr(strings.TrimSpace(w)))
			if err != nil {
				return Opts{}, err
			}

			result = append(result, n)
		}
	}

	return Opts{
		ExcludeAll:  false,
		ExcludeNets: result,
	}, nil
}

// fixCidr adds /32 if missing in input
func fixCidr(cidr string) string {
	if !strings.Contains(cidr, "/") {
		return fmt.Sprintf("%s/32", cidr)
	}
	return cidr
}
