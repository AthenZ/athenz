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
	"os"
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
	router.GET("/latest/dynamic/instance-identity/document", func(w http.ResponseWriter, r *http.Request, params map[string]string) {
		log.Println("Called /latest/dynamic/instance-identity/document")
		io.WriteString(w, "{ \"test\": \"document\" }")
	})

	router.GET("/latest/dynamic/instance-identity/pkcs7", func(w http.ResponseWriter, r *http.Request, params map[string]string) {
		log.Println("Called /latest/dynamic/instance-identity/pkcs7")
		io.WriteString(w, "{ \"test\": \"pkcs7\"}")
	})

	metaServer := &testServer{}
	metaServer.start(router)
	defer metaServer.stop()

	// we are going to fail on v2 and fall back to v1
	_, err := GetData(metaServer.httpUrl(), "/latest/dynamic/instance-identity/document")
	if err != nil {
		test.Errorf("Unable to retrieve instance document - %v", err)
		return
	}

	_, err = GetData(metaServer.httpUrl(), "/latest/dynamic/instance-identity/pkcs7")
	if err != nil {
		test.Errorf("Unable to retrieve document signature - %v", err)
		return
	}
}

func TestGetMetadataV1(test *testing.T) {
	// Mock the metadata endpoints
	router := httptreemux.New()
	router.GET("/latest/dynamic/instance-identity/document", func(w http.ResponseWriter, r *http.Request, params map[string]string) {
		log.Println("Called /latest/dynamic/instance-identity/document")
		io.WriteString(w, "{ \"test\": \"document\" }")
	})

	router.GET("/latest/dynamic/instance-identity/pkcs7", func(w http.ResponseWriter, r *http.Request, params map[string]string) {
		log.Println("Called /latest/dynamic/instance-identity/pkcs7")
		io.WriteString(w, "{ \"test\": \"pkcs7\"}")
	})

	metaServer := &testServer{}
	metaServer.start(router)
	defer metaServer.stop()

	_, err := GetDataV1(metaServer.httpUrl(), "/latest/dynamic/instance-identity/document")
	if err != nil {
		test.Errorf("Unable to retrieve instance document - %v", err)
		return
	}

	_, err = GetData(metaServer.httpUrl(), "/latest/dynamic/instance-identity/pkcs7")
	if err != nil {
		test.Errorf("Unable to retrieve document signature - %v", err)
		return
	}
}

func TestGetRegionFromDoc(test *testing.T) {
	// Mock the metadata endpoints
	router := httptreemux.New()
	router.GET("/latest/dynamic/instance-identity/document", func(w http.ResponseWriter, r *http.Request, params map[string]string) {
		log.Println("Called /latest/dynamic/instance-identity/document")
		io.WriteString(w, "{ \"test\": \"document\", \"region\": \"us-west-1\"}")
	})

	metaServer := &testServer{}
	metaServer.start(router)
	defer metaServer.stop()

	region := GetRegion(metaServer.httpUrl(), false)
	if region != "us-west-1" {
		test.Errorf("Unable to match expected region: %s", region)
	}
}

func TestGetRegionPreferEnv(test *testing.T) {
	// Mock the metadata endpoints
	router := httptreemux.New()
	router.GET("/latest/dynamic/instance-identity/document", func(w http.ResponseWriter, r *http.Request, params map[string]string) {
		log.Println("Called /latest/dynamic/instance-identity/document")
		io.WriteString(w, "{ \"test\": \"document\", \"region\": \"us-west-1\"}")
	})
	os.Setenv("AWS_REGION", "us-east-1")

	metaServer := &testServer{}
	metaServer.start(router)
	defer metaServer.stop()

	region := GetRegion(metaServer.httpUrl(), true)
	if region != "us-east-1" {
		test.Errorf("Unable to match expected region: %s", region)
	}
	region = GetRegion(metaServer.httpUrl(), false)
	if region != "us-west-1" {
		test.Errorf("Unable to match expected region: %s", region)
	}
}

func TestGetRegionFromEnv(test *testing.T) {

	os.Setenv("AWS_REGION", "us-east-1")
	// Mock the metadata endpoints
	router := httptreemux.New()
	router.GET("/latest/dynamic/instance-identity/document", func(w http.ResponseWriter, r *http.Request, params map[string]string) {
		log.Println("Called /latest/dynamic/instance-identity/document")
		io.WriteString(w, "{ \"test\": \"document\"}")
	})

	metaServer := &testServer{}
	metaServer.start(router)
	defer metaServer.stop()

	region := GetRegion(metaServer.httpUrl(), false)
	if region != "us-east-1" {
		test.Errorf("Unable to match expected region: %s", region)
	}
	region = GetRegion(metaServer.httpUrl(), true)
	if region != "us-east-1" {
		test.Errorf("Unable to match expected region: %s", region)
	}
	os.Setenv("AWS_REGION", "")

	//without doc/env we should default to us-west-2
	region = GetRegion(metaServer.httpUrl(), false)
	if region != "us-west-2" {
		test.Errorf("Unable to match expected region: %s", region)
	}
	region = GetRegion(metaServer.httpUrl(), true)
	if region != "us-west-2" {
		test.Errorf("Unable to match expected region: %s", region)
	}
}

func TestGetMetadataV2(test *testing.T) {
	// Mock the metadata endpoints
	router := httptreemux.New()
	router.PUT("/latest/api/token", func(w http.ResponseWriter, r *http.Request, params map[string]string) {
		log.Println("Called /latest/api/token")
		if r.Header.Get("X-aws-ec2-metadata-token-ttl-seconds") != "300" {
			log.Println("request does not have expected X-aws-ec2-metadata-token-ttl-seconds header")
			w.WriteHeader(500)
		}
		io.WriteString(w, "imdsv2-token")
	})
	router.GET("/latest/dynamic/instance-identity/document", func(w http.ResponseWriter, r *http.Request, params map[string]string) {
		log.Println("Called /latest/dynamic/instance-identity/document")
		if r.Header.Get("X-aws-ec2-metadata-token") != "imdsv2-token" {
			log.Println("request does not have expected X-aws-ec2-metadata-token header")
			w.WriteHeader(500)
		}
		io.WriteString(w, "{ \"test\": \"document\" }")
	})

	metaServer := &testServer{}
	metaServer.start(router)
	defer metaServer.stop()

	_, err := GetDataV2(metaServer.httpUrl(), "/latest/dynamic/instance-identity/document")
	if err != nil {
		test.Errorf("Unable to retrieve instance document - %v", err)
		return
	}
}
