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
	"fmt"
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

// GetK8SHostnames Generate pod/svc hostnames based on k8s spec:
// https://kubernetes.io/docs/concepts/services-networking/dns-pod-service/#pods
func GetK8SHostnames(clusterZone string) (string, []string) {
	k8sDnsEntries := []string{}
	// we're going to generate two sets of additional sanDNS entries for our
	// instances running within K8S - pod and service entries. it requires
	// that the container was configured with the expected env values
	// using the downward API.
	// the pod namespace may already be available in the container, but
	// we'll give preference to our env setting if it has been configured.
	podNamespace := os.Getenv("ATHENZ_SIA_POD_NAMESPACE")
	if podNamespace == "" {
		// use namespace associated with the service account
		if ns, err := os.ReadFile("/var/run/secrets/kubernetes.io/serviceaccount/namespace"); err == nil {
			podNamespace = strings.TrimSpace(string(ns))
		}
	}
	// in all of our components we need our namespace so if we don't
	// have one configured there is no need to fetch other settings,
	// and we'll just return an empty set
	if podNamespace == "" {
		return podNamespace, k8sDnsEntries
	}

	// this represents the value of spec.hostname
	podHostname := os.Getenv("ATHENZ_SIA_POD_HOSTNAME")
	// this represents the value of status.podIP (should be IPv4)
	podIP := os.Getenv("ATHENZ_SIA_POD_IP")
	// this represents the service name
	podService := os.Getenv("ATHENZ_SIA_POD_SERVICE")
	// this represents the value of spec.subdomain
	podSubdomain := os.Getenv("ATHENZ_SIA_POD_SUBDOMAIN")

	if podIP != "" {
		podIPWithDashes := strings.ReplaceAll(podIP, ".", "-")
		k8sDnsEntries = append(k8sDnsEntries, fmt.Sprintf("%s.%s.pod.%s", podIPWithDashes, podNamespace, clusterZone))
		if podService != "" {
			k8sDnsEntries = append(k8sDnsEntries, fmt.Sprintf("%s.%s.%s.pod.%s", podIPWithDashes, podService, podNamespace, clusterZone))
		}
	}
	if podHostname != "" {
		podSubdomainComp := ""
		if podSubdomain != "" {
			podSubdomainComp = "." + podSubdomain
		}
		k8sDnsEntries = append(k8sDnsEntries, fmt.Sprintf("%s%s.%s.svc.%s", podHostname, podSubdomainComp, podNamespace, clusterZone))
	}
	if podService != "" {
		k8sDnsEntries = append(k8sDnsEntries, fmt.Sprintf("%s.%s.svc.%s", podService, podNamespace, clusterZone))
		// K8S API server expects the san dns in this format if the certificate is to be used by a webhook
		k8sDnsEntries = append(k8sDnsEntries, fmt.Sprintf("%s.%s.svc", podService, podNamespace))
	}
	return podNamespace, k8sDnsEntries
}
