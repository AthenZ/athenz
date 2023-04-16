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

const PodClusterLocalDNSSuffix = "pod.cluster.local"
const ServiceClusterLocalDNSSuffix = "svc.cluster.local"

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

// GetK8SHostnames Generate pod hostname based on k8s spec:
//
//	https://kubernetes.io/docs/concepts/services-networking/dns-pod-service/#pods
func GetK8SHostnames() []string {
	k8sDnsEntries := []string{}
	// we're going to generate two additional sanDNS entries for our
	// instances running with K8S - pod and service entries. it requires
	// that the container was configured with the expected env values
	// using the downward API.
	// the pod name and namespace may already be available through other
	// variables/settings, but we'll give preference to our env settings
	// if they have been configured.
	podName := os.Getenv("ATHENZ_SIA_POD_NAME")
	if podName == "" {
		podName = os.Getenv("HOSTNAME")
	}
	podNamespace := os.Getenv("ATHENZ_SIA_POD_NAMESPACE")
	if podNamespace == "" {
		// use namespace associated with the service account
		if ns, err := os.ReadFile("/var/run/secrets/kubernetes.io/serviceaccount/namespace"); err == nil {
			podNamespace = strings.TrimSpace(string(ns))
		}
	}
	podIP := os.Getenv("ATHENZ_SIA_POD_IP")
	podService := os.Getenv("ATHENZ_SIA_POD_SERVICE")
	podSubdomain := os.Getenv("ATHENZ_SIA_POD_SUBDOMAIN")

	if podIP != "" && podNamespace != "" {
		podIPWithDashes := strings.ReplaceAll(podIP, ".", "-")
		k8sDnsEntries = append(k8sDnsEntries, fmt.Sprintf("%s.%s.%s", podIPWithDashes, podNamespace, PodClusterLocalDNSSuffix))
		if podService != "" {
			k8sDnsEntries = append(k8sDnsEntries, fmt.Sprintf("%s.%s.%s.%s", podIPWithDashes, podService, podNamespace, PodClusterLocalDNSSuffix))
		}
	}
	if podName != "" && podNamespace != "" {
		podSubdomainComp := ""
		if podSubdomain != "" {
			podSubdomainComp = "." + podSubdomain
		}
		k8sDnsEntries = append(k8sDnsEntries, fmt.Sprintf("%s%s.%s.%s", podName, podSubdomainComp, podNamespace, ServiceClusterLocalDNSSuffix))
	}
	return k8sDnsEntries
}
