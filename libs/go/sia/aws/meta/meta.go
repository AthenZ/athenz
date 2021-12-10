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
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"time"
)

// GetData makes a http call to the local metadata end point and returns the metadata document as bytes
func GetData(base, path string) ([]byte, error) {
	c := &http.Client{}
	c.Timeout = 2 * time.Second
	req, err := http.NewRequest("GET", base+path, nil)
	if err != nil {
		return nil, err
	}
	res, err := c.Do(req)
	if err != nil {
		return nil, err
	}
	body, err := ioutil.ReadAll(res.Body)
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
func GetRegion(metaEndPoint string) string {
	var region string
	document, err := GetData(metaEndPoint, "/latest/dynamic/instance-identity/document")
	if err == nil {
		log.Println("Trying to determine region from identity document ...")
		region, _ = doc.GetDocumentEntry(document, "region")
	}
	if region == "" {
		log.Println("Trying to determine region from AWS_REGION environment variable...")
		region = os.Getenv("AWS_REGION")
	}
	if region == "" {
		log.Println("No region information available. Defaulting to us-west-2")
		region = "us-west-2"
	}
	return region
}
