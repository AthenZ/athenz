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

package meta

import (
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestGetMetadata(test *testing.T) {
	// Mock the metadata endpoints
	router := http.NewServeMux()
	router.HandleFunc("GET /computeMetadata/v1/instance/zone", func(w http.ResponseWriter, r *http.Request) {
		log.Println("Called /computeMetadata/v1/instance/zone")
		io.WriteString(w, "projects/1001234567890/zones/us-west1-a")
	})

	metaServer := httptest.NewServer(router)
	defer metaServer.Close()

	_, err := GetData(metaServer.URL, "/computeMetadata/v1/instance/zone")
	if err != nil {
		test.Errorf("Unable to retrieve zone - %v", err)
		return
	}
}

func TestGetRegion(test *testing.T) {
	// Mock the metadata endpoints
	router := http.NewServeMux()
	router.HandleFunc("GET /computeMetadata/v1/instance/zone", func(w http.ResponseWriter, r *http.Request) {
		log.Println("Called /computeMetadata/v1/instance/zone")
		io.WriteString(w, "projects/1001234567890/zones/us-west2-a")
	})

	metaServer := httptest.NewServer(router)
	defer metaServer.Close()

	region := GetRegion(metaServer.URL)
	if region != "us-west2" {
		test.Errorf("Unable to match expected region: %s", region)
	}
}

func TestGetZone(test *testing.T) {
	// Mock the metadata endpoints
	router := http.NewServeMux()
	router.HandleFunc("GET /computeMetadata/v1/instance/zone", func(w http.ResponseWriter, r *http.Request) {
		log.Println("Called /computeMetadata/v1/instance/zone")
		io.WriteString(w, "projects/1001234567890/zones/us-west2-a")
	})

	metaServer := httptest.NewServer(router)
	defer metaServer.Close()

	zone := GetZone(metaServer.URL)
	if zone != "us-west2-a" {
		test.Errorf("Unable to match expected zone: %s", zone)
	}
}

func TestGetDomain(test *testing.T) {
	// Mock the metadata endpoints
	router := http.NewServeMux()
	router.HandleFunc("GET /computeMetadata/v1/project/attributes/athenz-domain", func(w http.ResponseWriter, r *http.Request) {
		log.Println("Called /computeMetadata/v1/project/attributes/athenz-domain")
		io.WriteString(w, "athenz.test")
	})

	metaServer := httptest.NewServer(router)
	defer metaServer.Close()

	domain, _ := GetDomain(metaServer.URL)
	if domain != "athenz.test" {
		test.Errorf("want domain=athenz.test got domain=%s", domain)
	}
}

func TestGetProject(test *testing.T) {
	// Mock the metadata endpoints
	router := http.NewServeMux()
	router.HandleFunc("GET /computeMetadata/v1/project/project-id", func(w http.ResponseWriter, r *http.Request) {
		log.Println("Called /computeMetadata/v1/project/project-id")
		io.WriteString(w, "my-gcp-project")
	})

	metaServer := httptest.NewServer(router)
	defer metaServer.Close()

	project, _ := GetProject(metaServer.URL)
	if project != "my-gcp-project" {
		test.Errorf("want project=my-gcp-project got project=%s", project)
	}
}

func TestGetService(test *testing.T) {
	// Mock the metadata endpoints
	router := http.NewServeMux()
	router.HandleFunc("GET /computeMetadata/v1/instance/service-accounts/default/email", func(w http.ResponseWriter, r *http.Request) {
		log.Println("Called /computeMetadata/v1/instance/service-accounts/default/email")
		io.WriteString(w, "my-sa@my-gcp-project.iam.gserviceaccount.com")
	})

	metaServer := httptest.NewServer(router)
	defer metaServer.Close()

	service, _ := GetService(metaServer.URL)
	if service != "my-sa" {
		test.Errorf("want service=my-sa got service=%s", service)
	}
}

func TestGetProfile(test *testing.T) {
	// Mock the metadata endpoints
	router := http.NewServeMux()
	router.HandleFunc("GET /computeMetadata/v1/instance/attributes/accessProfile", func(w http.ResponseWriter, r *http.Request) {
		log.Println("Called /computeMetadata/v1/instance/attributes/accessProfile")
		io.WriteString(w, "access-profile")
	})

	metaServer := httptest.NewServer(router)
	defer metaServer.Close()

	profile, _ := GetProfile(metaServer.URL)
	if profile != "access-profile" {
		test.Errorf("want profile=access-profile got profile=%s", profile)
	}
}

func TestGetInstanceId(test *testing.T) {
	// Mock the metadata endpoints
	router := http.NewServeMux()
	router.HandleFunc("GET /computeMetadata/v1/instance/id", func(w http.ResponseWriter, r *http.Request) {
		log.Println("Called /computeMetadata/v1/instance/id")
		io.WriteString(w, "3692465022399257023")
	})

	metaServer := httptest.NewServer(router)
	defer metaServer.Close()

	instanceId, _ := GetInstanceId(metaServer.URL)
	if instanceId != "3692465022399257023" {
		test.Errorf("want instanceId=3692465022399257023 got instanceId=%s", instanceId)
	}
}

func TestGetInstancePrivateIp(test *testing.T) {
	// Mock the metadata endpoints
	router := http.NewServeMux()
	router.HandleFunc("GET /computeMetadata/v1/instance/network-interfaces/0/ip", func(w http.ResponseWriter, r *http.Request) {
		log.Println("Called /computeMetadata/v1/instance/network-interfaces/0/ip")
		io.WriteString(w, "10.10.10.10")
	})

	metaServer := httptest.NewServer(router)
	defer metaServer.Close()

	instanceIp, _ := GetInstancePrivateIp(metaServer.URL)
	if instanceIp != "10.10.10.10" {
		test.Errorf("want instanceIp=10.10.10.10 got instanceIp=%s", instanceIp)
	}
}

func TestGetInstancePublicIp(test *testing.T) {
	// Mock the metadata endpoints
	router := http.NewServeMux()
	router.HandleFunc("GET /computeMetadata/v1/instance/network-interfaces/0/access-configs/0/external-ip", func(w http.ResponseWriter, r *http.Request) {
		log.Println("Called /computeMetadata/v1/instance/network-interfaces/0/access-configs/0/external-ip")
		io.WriteString(w, "20.20.20.20")
	})

	metaServer := httptest.NewServer(router)
	defer metaServer.Close()

	instancePubIp, _ := GetInstancePublicIp(metaServer.URL)
	if instancePubIp != "20.20.20.20" {
		test.Errorf("want instancePubIp=20.20.20.20 got instancePubIp=%s", instancePubIp)
	}
}

func TestGetInstanceName(test *testing.T) {
	// Mock the metadata endpoints
	router := http.NewServeMux()
	router.HandleFunc("GET /computeMetadata/v1/instance/name", func(w http.ResponseWriter, r *http.Request) {
		log.Println("Called /computeMetadata/v1/instance/name")
		io.WriteString(w, "my-vm")
	})

	metaServer := httptest.NewServer(router)
	defer metaServer.Close()

	instanceName, _ := GetInstanceName(metaServer.URL)
	if instanceName != "my-vm" {
		test.Errorf("want instanceName=my-vm got instanceName=%s", instanceName)
	}
}
