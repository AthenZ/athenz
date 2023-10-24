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
	"fmt"
	"github.com/dimfeld/httptreemux"
	"io"
	"log"
	"net"
	"net/http"
	"testing"
)

type testServer struct {
	listener net.Listener
	addr     string
}

func (t *testServer) start(h http.Handler) {
	listener, err := net.Listen("tcp", ":0")
	if err != nil {
		log.Panicln("Unable to serve on randomly assigned port")
	}
	s := &http.Server{Handler: h}
	t.listener = listener
	t.addr = listener.Addr().String()

	go func() {
		s.Serve(listener)
	}()
}

func (t *testServer) stop() {
	t.listener.Close()
}

func (t *testServer) httpUrl() string {
	return fmt.Sprintf("http://%s", t.addr)
}

func TestGetMetadata(test *testing.T) {
	// Mock the metadata endpoints
	router := httptreemux.New()
	router.GET("/computeMetadata/v1/instance/zone", func(w http.ResponseWriter, r *http.Request, params map[string]string) {
		log.Println("Called /computeMetadata/v1/instance/zone")
		io.WriteString(w, "projects/1001234567890/zones/us-west1-a")
	})

	metaServer := &testServer{}
	metaServer.start(router)
	defer metaServer.stop()

	_, err := GetData(metaServer.httpUrl(), "/computeMetadata/v1/instance/zone")
	if err != nil {
		test.Errorf("Unable to retrieve zone - %v", err)
		return
	}
}

func TestGetRegion(test *testing.T) {
	// Mock the metadata endpoints
	router := httptreemux.New()
	router.GET("/computeMetadata/v1/instance/zone", func(w http.ResponseWriter, r *http.Request, params map[string]string) {
		log.Println("Called /computeMetadata/v1/instance/zone")
		io.WriteString(w, "projects/1001234567890/zones/us-west2-a")
	})

	metaServer := &testServer{}
	metaServer.start(router)
	defer metaServer.stop()

	region := GetRegion(metaServer.httpUrl())
	if region != "us-west2" {
		test.Errorf("Unable to match expected region: %s", region)
	}
}

func TestGetZone(test *testing.T) {
	// Mock the metadata endpoints
	router := httptreemux.New()
	router.GET("/computeMetadata/v1/instance/zone", func(w http.ResponseWriter, r *http.Request, params map[string]string) {
		log.Println("Called /computeMetadata/v1/instance/zone")
		io.WriteString(w, "projects/1001234567890/zones/us-west2-a")
	})

	metaServer := &testServer{}
	metaServer.start(router)
	defer metaServer.stop()

	zone := GetZone(metaServer.httpUrl())
	if zone != "us-west2-a" {
		test.Errorf("Unable to match expected zone: %s", zone)
	}
}

func TestGetDomain(test *testing.T) {
	// Mock the metadata endpoints
	router := httptreemux.New()
	router.GET("/computeMetadata/v1/project/attributes/athenz-domain", func(w http.ResponseWriter, r *http.Request, params map[string]string) {
		log.Println("Called /computeMetadata/v1/project/attributes/athenz-domain")
		io.WriteString(w, "athenz.test")
	})

	metaServer := &testServer{}
	metaServer.start(router)
	defer metaServer.stop()

	domain, _ := GetDomain(metaServer.httpUrl())
	if domain != "athenz.test" {
		test.Errorf("want domain=athenz.test got domain=%s", domain)
	}
}

func TestGetProject(test *testing.T) {
	// Mock the metadata endpoints
	router := httptreemux.New()
	router.GET("/computeMetadata/v1/project/project-id", func(w http.ResponseWriter, r *http.Request, params map[string]string) {
		log.Println("Called /computeMetadata/v1/project/project-id")
		io.WriteString(w, "my-gcp-project")
	})

	metaServer := &testServer{}
	metaServer.start(router)
	defer metaServer.stop()

	project, _ := GetProject(metaServer.httpUrl())
	if project != "my-gcp-project" {
		test.Errorf("want project=my-gcp-project got project=%s", project)
	}
}

func TestGetService(test *testing.T) {
	// Mock the metadata endpoints
	router := httptreemux.New()
	router.GET("/computeMetadata/v1/instance/service-accounts/default/email", func(w http.ResponseWriter, r *http.Request, params map[string]string) {
		log.Println("Called /computeMetadata/v1/instance/service-accounts/default/email")
		io.WriteString(w, "my-sa@my-gcp-project.iam.gserviceaccount.com")
	})

	metaServer := &testServer{}
	metaServer.start(router)
	defer metaServer.stop()

	service, _ := GetService(metaServer.httpUrl())
	if service != "my-sa" {
		test.Errorf("want service=my-sa got service=%s", service)
	}
}

func TestGetProfile(test *testing.T) {
	// Mock the metadata endpoints
	router := httptreemux.New()
	router.GET("/computeMetadata/v1/instance/attributes/accessProfile", func(w http.ResponseWriter, r *http.Request, params map[string]string) {
		log.Println("Called /computeMetadata/v1/instance/attributes/accessProfile")
		io.WriteString(w, "access-profile")
	})

	metaServer := &testServer{}
	metaServer.start(router)
	defer metaServer.stop()

	profile, _ := GetProfile(metaServer.httpUrl())
	if profile != "access-profile" {
		test.Errorf("want profile=access-profile got profile=%s", profile)
	}
}

func TestGetInstanceId(test *testing.T) {
	// Mock the metadata endpoints
	router := httptreemux.New()
	router.GET("/computeMetadata/v1/instance/id", func(w http.ResponseWriter, r *http.Request, params map[string]string) {
		log.Println("Called /computeMetadata/v1/instance/id")
		io.WriteString(w, "3692465022399257023")
	})

	metaServer := &testServer{}
	metaServer.start(router)
	defer metaServer.stop()

	instanceId, _ := GetInstanceId(metaServer.httpUrl())
	if instanceId != "3692465022399257023" {
		test.Errorf("want instanceId=3692465022399257023 got instanceId=%s", instanceId)
	}
}

func TestGetInstancePrivateIp(test *testing.T) {
	// Mock the metadata endpoints
	router := httptreemux.New()
	router.GET("/computeMetadata/v1/instance/network-interfaces/0/ip", func(w http.ResponseWriter, r *http.Request, params map[string]string) {
		log.Println("Called /computeMetadata/v1/instance/network-interfaces/0/ip")
		io.WriteString(w, "10.10.10.10")
	})

	metaServer := &testServer{}
	metaServer.start(router)
	defer metaServer.stop()

	instanceIp, _ := GetInstancePrivateIp(metaServer.httpUrl())
	if instanceIp != "10.10.10.10" {
		test.Errorf("want instanceIp=10.10.10.10 got instanceIp=%s", instanceIp)
	}
}

func TestGetInstancePublicIp(test *testing.T) {
	// Mock the metadata endpoints
	router := httptreemux.New()
	router.GET("/computeMetadata/v1/instance/network-interfaces/0/access-configs/0/external-ip", func(w http.ResponseWriter, r *http.Request, params map[string]string) {
		log.Println("Called /computeMetadata/v1/instance/network-interfaces/0/access-configs/0/external-ip")
		io.WriteString(w, "20.20.20.20")
	})

	metaServer := &testServer{}
	metaServer.start(router)
	defer metaServer.stop()

	instancePubIp, _ := GetInstancePublicIp(metaServer.httpUrl())
	if instancePubIp != "20.20.20.20" {
		test.Errorf("want instancePubIp=20.20.20.20 got instancePubIp=%s", instancePubIp)
	}
}

func TestGetInstanceName(test *testing.T) {
	// Mock the metadata endpoints
	router := httptreemux.New()
	router.GET("/computeMetadata/v1/instance/name", func(w http.ResponseWriter, r *http.Request, params map[string]string) {
		log.Println("Called /computeMetadata/v1/instance/name")
		io.WriteString(w, "my-vm")
	})

	metaServer := &testServer{}
	metaServer.start(router)
	defer metaServer.stop()

	instanceName, _ := GetInstanceName(metaServer.httpUrl())
	if instanceName != "my-vm" {
		test.Errorf("want instanceName=my-vm got instanceName=%s", instanceName)
	}
}
