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
	router.HandleFunc("GET /metadata/instance", func(w http.ResponseWriter, r *http.Request) {
		log.Println("Called /metadata/instance?api-version=2020-06-01")
		io.WriteString(w, "{ \"test\": \"document\"}")
	})

	metaServer := httptest.NewServer(router)
	defer metaServer.Close()

	_, err := GetData(metaServer.URL, "/metadata/instance?api-version=2020-06-01")
	if err != nil {
		test.Errorf("Unable to retrieve instance document - %v", err)
		return
	}
}
