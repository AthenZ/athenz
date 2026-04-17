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
	"sync/atomic"
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

	region, err := GetRegion(metaServer.URL)
	if err != nil {
		test.Errorf("Unable to get region: %v", err)
		return
	}
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

	zone, err := GetZone(metaServer.URL)
	if err != nil {
		test.Errorf("Unable to get zone: %v", err)
		return
	}
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

func TestGetServiceAccountInfo(test *testing.T) {
	router := http.NewServeMux()
	router.HandleFunc("GET /computeMetadata/v1/instance/service-accounts/default/email", func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, "my-sa@my-gcp-project.iam.gserviceaccount.com")
	})

	metaServer := httptest.NewServer(router)
	defer metaServer.Close()

	serviceName, servicePostfix, err := GetServiceAccountInfo(metaServer.URL)
	if err != nil {
		test.Errorf("Unexpected error: %v", err)
		return
	}
	if serviceName != "my-sa" {
		test.Errorf("want serviceName=my-sa got serviceName=%s", serviceName)
	}
	if servicePostfix != "@my-gcp-project.iam.gserviceaccount.com" {
		test.Errorf("want servicePostfix=@my-gcp-project.iam.gserviceaccount.com got servicePostfix=%s", servicePostfix)
	}
}

func TestGetServiceAccountInfoError(test *testing.T) {
	router := http.NewServeMux()
	router.HandleFunc("GET /computeMetadata/v1/instance/service-accounts/default/email", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	})

	metaServer := httptest.NewServer(router)
	defer metaServer.Close()

	_, _, err := GetServiceAccountInfo(metaServer.URL)
	if err == nil {
		test.Error("Expected error for failed metadata fetch")
	}
}

func TestGetServiceAccountInfoNoAtSign(test *testing.T) {
	router := http.NewServeMux()
	router.HandleFunc("GET /computeMetadata/v1/instance/service-accounts/default/email", func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, "invalid-service-account")
	})

	metaServer := httptest.NewServer(router)
	defer metaServer.Close()

	_, _, err := GetServiceAccountInfo(metaServer.URL)
	if err == nil {
		test.Error("Expected error for service account without @")
	}
}

func TestGetInstanceAttributeValue(test *testing.T) {
	router := http.NewServeMux()
	router.HandleFunc("GET /computeMetadata/v1/instance/attributes/my-key", func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, "my-value")
	})

	metaServer := httptest.NewServer(router)
	defer metaServer.Close()

	value, err := GetInstanceAttributeValue(metaServer.URL, "my-key")
	if err != nil {
		test.Errorf("Unexpected error: %v", err)
		return
	}
	if value != "my-value" {
		test.Errorf("want value=my-value got value=%s", value)
	}
}

func TestGetInstanceAttributeValueError(test *testing.T) {
	router := http.NewServeMux()

	metaServer := httptest.NewServer(router)
	defer metaServer.Close()

	_, err := GetInstanceAttributeValue(metaServer.URL, "nonexistent-key")
	if err == nil {
		test.Error("Expected error for missing attribute")
	}
}

func TestGetRegionError(test *testing.T) {
	router := http.NewServeMux()
	router.HandleFunc("GET /computeMetadata/v1/instance/zone", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	})

	metaServer := httptest.NewServer(router)
	defer metaServer.Close()

	_, err := GetRegion(metaServer.URL)
	if err == nil {
		test.Error("Expected error when zone fetch fails")
	}
}

func TestGetRegionBadZoneFormat(test *testing.T) {
	router := http.NewServeMux()
	router.HandleFunc("GET /computeMetadata/v1/instance/zone", func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, "projects/123/zones/uswest2a")
	})

	metaServer := httptest.NewServer(router)
	defer metaServer.Close()

	_, err := GetRegion(metaServer.URL)
	if err == nil {
		test.Error("Expected error when zone has no dash separator")
	}
}

func TestGetZoneError(test *testing.T) {
	router := http.NewServeMux()
	router.HandleFunc("GET /computeMetadata/v1/instance/zone", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	})

	metaServer := httptest.NewServer(router)
	defer metaServer.Close()

	_, err := GetZone(metaServer.URL)
	if err == nil {
		test.Error("Expected error when zone fetch fails")
	}
}

func TestGetZoneNoSlashInResponse(test *testing.T) {
	router := http.NewServeMux()
	router.HandleFunc("GET /computeMetadata/v1/instance/zone", func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, "us-west2-a")
	})

	metaServer := httptest.NewServer(router)
	defer metaServer.Close()

	zone, err := GetZone(metaServer.URL)
	if err != nil {
		test.Errorf("Unexpected error: %v", err)
		return
	}
	if zone != "" {
		test.Errorf("Expected empty zone when no slash in response, got: %s", zone)
	}
}

func TestGetServiceNoAtSign(test *testing.T) {
	router := http.NewServeMux()
	router.HandleFunc("GET /computeMetadata/v1/instance/service-accounts/default/email", func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, "invalid-service-account")
	})

	metaServer := httptest.NewServer(router)
	defer metaServer.Close()

	_, err := GetService(metaServer.URL)
	if err == nil {
		test.Error("Expected error for service account without @")
	}
}

func TestGetServiceError(test *testing.T) {
	router := http.NewServeMux()
	router.HandleFunc("GET /computeMetadata/v1/instance/service-accounts/default/email", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	})

	metaServer := httptest.NewServer(router)
	defer metaServer.Close()

	_, err := GetService(metaServer.URL)
	if err == nil {
		test.Error("Expected error for failed metadata fetch")
	}
}

func TestGetDomainError(test *testing.T) {
	router := http.NewServeMux()

	metaServer := httptest.NewServer(router)
	defer metaServer.Close()

	_, err := GetDomain(metaServer.URL)
	if err == nil {
		test.Error("Expected error for failed metadata fetch")
	}
}

func TestGetProjectError(test *testing.T) {
	router := http.NewServeMux()

	metaServer := httptest.NewServer(router)
	defer metaServer.Close()

	_, err := GetProject(metaServer.URL)
	if err == nil {
		test.Error("Expected error for failed metadata fetch")
	}
}

func TestGetProfileError(test *testing.T) {
	router := http.NewServeMux()

	metaServer := httptest.NewServer(router)
	defer metaServer.Close()

	_, err := GetProfile(metaServer.URL)
	if err == nil {
		test.Error("Expected error for failed metadata fetch")
	}
}

func TestGetInstanceIdError(test *testing.T) {
	router := http.NewServeMux()

	metaServer := httptest.NewServer(router)
	defer metaServer.Close()

	_, err := GetInstanceId(metaServer.URL)
	if err == nil {
		test.Error("Expected error for failed metadata fetch")
	}
}

func TestGetInstancePrivateIpError(test *testing.T) {
	router := http.NewServeMux()

	metaServer := httptest.NewServer(router)
	defer metaServer.Close()

	_, err := GetInstancePrivateIp(metaServer.URL)
	if err == nil {
		test.Error("Expected error for failed metadata fetch")
	}
}

func TestGetInstancePublicIpError(test *testing.T) {
	router := http.NewServeMux()

	metaServer := httptest.NewServer(router)
	defer metaServer.Close()

	_, err := GetInstancePublicIp(metaServer.URL)
	if err == nil {
		test.Error("Expected error for failed metadata fetch")
	}
}

func TestGetInstanceNameError(test *testing.T) {
	router := http.NewServeMux()

	metaServer := httptest.NewServer(router)
	defer metaServer.Close()

	_, err := GetInstanceName(metaServer.URL)
	if err == nil {
		test.Error("Expected error for failed metadata fetch")
	}
}

func TestGetDataConnectionRefused(test *testing.T) {
	metaServer := httptest.NewServer(http.NewServeMux())
	url := metaServer.URL
	metaServer.Close()

	_, err := GetData(url, "/computeMetadata/v1/instance/zone")
	if err == nil {
		test.Error("Expected error for closed server")
	}
}

func TestIsTransientError(test *testing.T) {
	tests := []struct {
		name       string
		statusCode int
		want       bool
	}{
		{"zero status is transient", 0, true},
		{"429 Too Many Requests is transient", http.StatusTooManyRequests, true},
		{"500 Internal Server Error is transient", http.StatusInternalServerError, true},
		{"502 Bad Gateway is transient", http.StatusBadGateway, true},
		{"503 Service Unavailable is transient", http.StatusServiceUnavailable, true},
		{"504 Gateway Timeout is transient", http.StatusGatewayTimeout, true},
		{"400 Bad Request is not transient", http.StatusBadRequest, false},
		{"401 Unauthorized is not transient", http.StatusUnauthorized, false},
		{"403 Forbidden is not transient", http.StatusForbidden, false},
		{"404 Not Found is not transient", http.StatusNotFound, false},
		{"200 OK is not transient", http.StatusOK, false},
	}
	for _, tt := range tests {
		test.Run(tt.name, func(t *testing.T) {
			got := isTransientError(tt.statusCode)
			if got != tt.want {
				t.Errorf("isTransientError(%d) = %v, want %v", tt.statusCode, got, tt.want)
			}
		})
	}
}

func TestGetDataRetryOnTransientError(test *testing.T) {
	var callCount int32
	router := http.NewServeMux()
	router.HandleFunc("GET /computeMetadata/v1/instance/zone", func(w http.ResponseWriter, r *http.Request) {
		count := atomic.AddInt32(&callCount, 1)
		if count <= 3 {
			w.WriteHeader(http.StatusServiceUnavailable)
			return
		}
		io.WriteString(w, "projects/123/zones/us-west1-a")
	})

	metaServer := httptest.NewServer(router)
	defer metaServer.Close()

	data, err := GetData(metaServer.URL, "/computeMetadata/v1/instance/zone")
	if err != nil {
		test.Errorf("Expected success after transient errors, got: %v", err)
		return
	}
	if string(data) != "projects/123/zones/us-west1-a" {
		test.Errorf("Unexpected data: %s", string(data))
	}
	if atomic.LoadInt32(&callCount) != 4 {
		test.Errorf("Expected 4 calls, got %d", atomic.LoadInt32(&callCount))
	}
}

func TestGetDataNoRetryOnNonTransientError(test *testing.T) {
	var callCount int32
	router := http.NewServeMux()
	router.HandleFunc("GET /computeMetadata/v1/instance/zone", func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&callCount, 1)
		w.WriteHeader(http.StatusNotFound)
	})

	metaServer := httptest.NewServer(router)
	defer metaServer.Close()

	_, err := GetData(metaServer.URL, "/computeMetadata/v1/instance/zone")
	if err == nil {
		test.Error("Expected error for 404 response")
		return
	}
	if atomic.LoadInt32(&callCount) != 1 {
		test.Errorf("Expected 1 call (no retries for 404), got %d", atomic.LoadInt32(&callCount))
	}
}

func TestGetDataExhaustsRetries(test *testing.T) {
	var callCount int32
	router := http.NewServeMux()
	router.HandleFunc("GET /computeMetadata/v1/instance/zone", func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&callCount, 1)
		w.WriteHeader(http.StatusInternalServerError)
	})

	metaServer := httptest.NewServer(router)
	defer metaServer.Close()

	_, err := GetData(metaServer.URL, "/computeMetadata/v1/instance/zone")
	if err == nil {
		test.Error("Expected error after exhausting retries")
		return
	}
	if atomic.LoadInt32(&callCount) != 10 {
		test.Errorf("Expected 10 calls (all retries exhausted), got %d", atomic.LoadInt32(&callCount))
	}
}
