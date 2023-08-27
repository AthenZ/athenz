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
	"github.com/AthenZ/athenz/libs/go/sia/aws/doc"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/sts"
	"io"
	"log"
	"net/http"
	"os"
	"time"
)

// GetData makes a http call to the local metadata end point and returns the metadata document as bytes
func GetData(base, path string) ([]byte, error) {
	// first we're going to make a call using v2 api using tokens
	data, err := GetDataV2(base, path)
	if err == nil {
		return data, nil
	}
	log.Printf("failed to obtain metadata using v2 api: %v\n", err)
	// next, we'll try using v1 api
	data, err = GetDataV1(base, path)
	if err != nil {
		log.Printf("failed to obtain metadata using v1 api: %v\n", err)
	}
	return data, err
}

func GetDataV2(base, path string) ([]byte, error) {
	// let get our authentication token first
	token, err := getAuthToken(base)
	if err != nil {
		return nil, err
	}
	headers := make(map[string]string)
	headers["X-aws-ec2-metadata-token"] = string(token)
	return processHttpRequest(base, path, "GET", headers)
}

func getAuthToken(base string) ([]byte, error) {
	headers := make(map[string]string)
	headers["X-aws-ec2-metadata-token-ttl-seconds"] = "300"
	return processHttpRequest(base, "/latest/api/token", "PUT", headers)
}

func GetDataV1(base, path string) ([]byte, error) {
	return processHttpRequest(base, path, "GET", nil)
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
	return nil, fmt.Errorf("cannot get metadata, path: %q, status code is %d", path, res.StatusCode)
}

// GetRegion get current region from identity document
func GetRegion(metaEndPoint string, preferEnv bool) string {
	var region string
	if preferEnv {
		region = getRegionFromEnv()
		if region == "" {
			region = getRegionFromInstanceDocument(metaEndPoint)
		}
	} else {
		region = getRegionFromInstanceDocument(metaEndPoint)
		if region == "" {
			region = getRegionFromEnv()
		}
	}
	if region == "" {
		log.Println("No region information available. Defaulting to us-west-2")
		region = "us-west-2"
	}
	return region
}

func getRegionFromEnv() string {
	log.Println("Trying to determine region from AWS_REGION environment variable...")
	return os.Getenv("AWS_REGION")
}

func getRegionFromInstanceDocument(metaEndPoint string) string {
	var region string
	log.Println("Trying to determine region from identity document ...")
	document, err := GetData(metaEndPoint, "/latest/dynamic/instance-identity/document")
	if err == nil {
		region, _ = doc.GetDocumentEntry(document, "region")
	}
	return region
}

func GetAccountId() string {
	clientSession, err := session.NewSession()
	if err != nil {
		log.Printf("unable to create a new session: %v\n", err)
		return ""
	}
	stsSession := sts.New(clientSession)
	input := &sts.GetCallerIdentityInput{}
	result, err := stsSession.GetCallerIdentity(input)
	if err != nil {
		log.Printf("unable to extract caller identity: %v\n", err)
		return ""
	}
	return *result.Account
}
