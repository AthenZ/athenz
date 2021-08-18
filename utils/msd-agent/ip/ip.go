// Copyright The Athenz Authors
// Licensed under the terms of the Apache version 2.0 license. See LICENSE file for terms.

package ip

import (
	"net"
	"regexp"
	"strings"

	"github.com/AthenZ/athenz/libs/go/athenz-common/log"
	siafile "github.com/AthenZ/athenz/libs/go/sia/file"

	"github.com/google/go-cmp/cmp"
)

type Opts struct {
	ExcludeAll  bool
	ExcludeNets []*net.IPNet
}

// GetIps returns an array of IPs. It skips loop back, link-local, private ips
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

	return ips, nil
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

func IpChanged(ipFile string, ips []net.IP) (bool, error) {
	prevIps := []net.IP{}
	err := siafile.ReadFile(ipFile, &prevIps)
	if err != nil {
		// try to write anyway for next run
		_ = siafile.WriteFile(ips, ipFile)
		return true, err
	}

	equalIps := cmp.Equal(prevIps, ips)
	err = siafile.WriteFile(ips, ipFile)

	log.Debugf("ips are equals: %v, errors: %v", equalIps, err)
	return equalIps, err
}
