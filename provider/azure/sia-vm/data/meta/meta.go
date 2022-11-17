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
	"io"
	"net/http"
	"time"
)

// GetData makes a http call to the local metadata end point and returns the metadata document as bytes
func GetData(base, path string) ([]byte, error) {
	c := &http.Client{}
	c.Timeout = 10 * time.Second
	req, err := http.NewRequest("GET", base+path, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Metadata", "true")
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
	return nil, fmt.Errorf("cannot get metadata, path: %q, status code is %d/%s", base+path, res.StatusCode, res.Status)
}
