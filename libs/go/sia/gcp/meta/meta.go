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

package meta

import (
	"fmt"
	"io"
	"log"
	"net/http"
	"strings"
	"time"
)

// GetData makes a http call to the local metadata end point and returns the metadata document as bytes.
// If the request fails with a transient error, it retries up to 10 times with a 1 second delay.
func GetData(base, path string) ([]byte, error) {
	headers := make(map[string]string)
	headers["Metadata-Flavor"] = "Google"
	var data []byte
	var lastErr error
	for i := range 10 {
		var statusCode int
		data, statusCode, lastErr = processHttpRequest(base, path, "GET", headers)
		if lastErr == nil {
			return data, nil
		}
		if !isTransientError(statusCode) {
			log.Printf("Error fetching metadata %s/%s: %v", base, path, lastErr)
			return nil, lastErr
		}
		log.Printf("Transient error fetching metadata %s/%s (attempt %d/10): %v", base, path, i+1, lastErr)
		time.Sleep(time.Second)
	}
	return nil, lastErr
}

func isTransientError(statusCode int) bool {
	if statusCode == 0 {
		return true
	}
	return statusCode == http.StatusTooManyRequests ||
		statusCode == http.StatusInternalServerError ||
		statusCode == http.StatusBadGateway ||
		statusCode == http.StatusServiceUnavailable ||
		statusCode == http.StatusGatewayTimeout
}

func processHttpRequest(base, path, method string, headers map[string]string) ([]byte, int, error) {
	c := &http.Client{}
	c.Timeout = 5 * time.Second
	req, err := http.NewRequest(method, base+path, nil)
	if err != nil {
		return nil, 0, err
	}
	for key, value := range headers {
		req.Header.Set(key, value)
	}
	res, err := c.Do(req)
	if err != nil {
		return nil, 0, err
	}
	body, err := io.ReadAll(res.Body)
	_ = res.Body.Close()
	if err != nil {
		return nil, 0, err
	}
	if res.StatusCode == 200 {
		return body, res.StatusCode, nil
	}
	return nil, res.StatusCode, fmt.Errorf("cannot get metadata, url: %q, headers: %v status code is %d", base+path, headers, res.StatusCode)
}

// GetRegion get current region from metadata server
func GetRegion(metaEndPoint string) (string, error) {
	var region string
	zone, err := GetZone(metaEndPoint)
	if err != nil {
		return "", err
	}
	if idx := strings.LastIndex(zone, "-"); idx > 0 {
		region = zone[:idx]
		return region, nil
	}
	return "", fmt.Errorf("unable to derive region from zone: %s", zone)
}

// GetZone get current zone from metadata server
func GetZone(metaEndPoint string) (string, error) {
	zone, err := getZoneFromMeta(metaEndPoint)
	if err != nil {
		return "", err
	}
	return zone, nil
}

func getZoneFromMeta(metaEndPoint string) (string, error) {
	var zone string
	log.Println("Trying to determine zone from metadata server ...")
	fullOutput, err := GetData(metaEndPoint, "/computeMetadata/v1/instance/zone")
	if err == nil {
		if idx := strings.LastIndex(string(fullOutput), "/"); idx > 0 {
			zone = string(fullOutput[idx+1:])
		}
	}
	return zone, err
}

// GetDomain get domain from metadata server
func GetDomain(metaEndpoint string) (string, error) {
	domainBytes, err := GetData(metaEndpoint, "/computeMetadata/v1/project/attributes/athenz-domain")
	if err != nil {
		return "", err
	}
	return string(domainBytes), nil
}

// GetProject get project from metadata server
func GetProject(metaEndpoint string) (string, error) {
	projectBytes, err := GetData(metaEndpoint, "/computeMetadata/v1/project/project-id")
	if err != nil {
		return "", err
	}
	return string(projectBytes), nil
}

// GetService get service from metadata server
func GetService(metaEndpoint string) (string, error) {
	service, _, err := getGCPService(metaEndpoint)
	return service, err
}

// GetServiceAccountInfo get service account info from metadata server
func GetServiceAccountInfo(metaEndpoint string) (string, string, error) {
	serviceName, servicePostfix, err := getGCPService(metaEndpoint)
	if err == nil {
		return serviceName, string(servicePostfix), nil
	}
	return "", "", err
}

func getGCPService(metaEndpoint string) (string, []byte, error) {
	serviceBytes, err := GetData(metaEndpoint, "/computeMetadata/v1/instance/service-accounts/default/email")
	if err != nil {
		return "", nil, err
	}
	if idx := strings.Index(string(serviceBytes), "@"); idx > 0 {
		service := string(serviceBytes[:idx])
		servicePostfix := serviceBytes[idx:]
		return service, servicePostfix, nil
	}
	return "", nil, fmt.Errorf("unable to derive service name from metadata")
}

// GetProfile get profile from metadata server
func GetProfile(metaEndpoint string) (string, error) {
	profileBytes, err := GetData(metaEndpoint, "/computeMetadata/v1/instance/attributes/accessProfile")
	if err != nil {
		return "", err
	}
	return string(profileBytes), nil
}

// GetInstanceAttributeValue get instance attribute value from metadata server
func GetInstanceAttributeValue(metaEndpoint, key string) (string, error) {
	tagBytes, err := GetData(metaEndpoint, "/computeMetadata/v1/instance/attributes/"+key)
	if err != nil {
		return "", err
	}
	return string(tagBytes), nil
}

// GetInstanceId get instance id from metadata server
func GetInstanceId(metaEndpoint string) (string, error) {
	instanceIdBytes, err := GetData(metaEndpoint, "/computeMetadata/v1/instance/id")
	if err != nil {
		return "", err
	}
	return string(instanceIdBytes), nil
}

// GetInstancePrivateIp get instance private ip from metadata server
func GetInstancePrivateIp(metaEndpoint string) (string, error) {
	instanceIdBytes, err := GetData(metaEndpoint, "/computeMetadata/v1/instance/network-interfaces/0/ip")
	if err != nil {
		return "", err
	}
	return string(instanceIdBytes), nil
}

// GetInstancePublicIp get instance public ip from metadata server
func GetInstancePublicIp(metaEndpoint string) (string, error) {
	pubIpBytes, err := GetData(metaEndpoint, "/computeMetadata/v1/instance/network-interfaces/0/access-configs/0/external-ip")
	if err != nil {
		return "", err
	}
	return string(pubIpBytes), nil
}

// GetInstanceName get instance name from metadata server
func GetInstanceName(metaEndpoint string) (string, error) {
	nameBytes, err := GetData(metaEndpoint, "/computeMetadata/v1/instance/name")
	if err != nil {
		return "", err
	}
	return string(nameBytes), nil
}
