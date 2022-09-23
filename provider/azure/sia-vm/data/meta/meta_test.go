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
	router.GET("/metadata/instance", func(w http.ResponseWriter, r *http.Request, params map[string]string) {
		log.Println("Called /metadata/instance?api-version=2020-06-01")
		io.WriteString(w, "{ \"test\": \"document\"}")
	})

	metaServer := &testServer{}
	metaServer.start(router)
	defer metaServer.stop()

	_, err := GetData(metaServer.httpUrl(), "/metadata/instance?api-version=2020-06-01")
	if err != nil {
		test.Errorf("Unable to retrieve instance document - %v", err)
		return
	}
}
