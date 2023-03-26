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

// GetData makes a http call to the local metadata end point and returns the metadata document as bytes
func GetData(base, path string) ([]byte, error) {
	headers := make(map[string]string)
	headers["Metadata-Flavor"] = "Google"
	return processHttpRequest(base, path, "GET", headers)
}

func processHttpRequest(base, path, method string, headers map[string]string) ([]byte, error) {
	c := &http.Client{}
	c.Timeout = 5 * time.Second
	req, err := http.NewRequest(method, base+path, nil)
	if err != nil {
		return nil, err
	}
	if headers != nil {
		for key, value := range headers {
			req.Header.Set(key, value)
		}
	}
	res, err := c.Do(req)
	if err != nil {
		return nil, err
	}
	body, err := io.ReadAll(res.Body)
	_ = res.Body.Close()
	if err != nil {
		return nil, err
	}
	if res.StatusCode == 200 {
		return body, nil
	}
	return nil, fmt.Errorf("cannot get metadata, url: %q, headers: %v status code is %d", base+path, headers, res.StatusCode)
}

// GetRegion get current region from identity document
func GetRegion(metaEndPoint string) string {
	var region string
	region = getRegionFromMeta(metaEndPoint)
	if region == "" {
		log.Println("No region information available. Defaulting to us-west1")
		region = "us-west1"
	}
	return region
}

func getRegionFromMeta(metaEndPoint string) string {
	var region string
	log.Println("Trying to determine region from metadata server ...")
	fullOutput, err := GetData(metaEndPoint, "/computeMetadata/v1/instance/zone")
	if err == nil {
		if idx := strings.LastIndex(string(fullOutput), "/"); idx > 0 {
			zone := string(fullOutput[idx+1:])
			if idx := strings.LastIndex(zone, "-"); idx > 0 {
				region = zone[:idx]
			}
		}
	}
	return region
}

func GetDomain(metaEndpoint string) (string, error) {
	domainBytes, err := GetData(metaEndpoint, "/computeMetadata/v1/project/attributes/domain")
	if err != nil {
		return "", err
	}
	return string(domainBytes), nil
}

func GetProject(metaEndpoint string) (string, error) {
	projectBytes, err := GetData(metaEndpoint, "/computeMetadata/v1/project/project-id")
	if err != nil {
		return "", err
	}
	return string(projectBytes), nil
}

func GetService(metaEndpoint string) (string, error) {
	serviceBytes, err := GetData(metaEndpoint, "/computeMetadata/v1/instance/service-accounts/default/email")
	if err != nil {
		return "", err
	}
	if idx := strings.Index(string(serviceBytes), "@"); idx > 0 {
		service := string(serviceBytes[:idx])
		return service, nil
	}
	return "", fmt.Errorf("unable to derive service name from metadata")
}

func GetProfile(metaEndpoint string) (string, error) {
	profileBytes, err := GetData(metaEndpoint, "/computeMetadata/v1/instance/attributes/calypsoProfile")
	if err != nil {
		return "", err
	}
	return string(profileBytes), nil
}

func GetInstanceId(metaEndpoint string) (string, error) {
	instanceIdBytes, err := GetData(metaEndpoint, "/computeMetadata/v1/instance/id")
	if err != nil {
		return "", err
	}
	return string(instanceIdBytes), nil
}
