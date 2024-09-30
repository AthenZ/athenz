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

package attestation

import (
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"strings"
	"testing"

	"github.com/dimfeld/httptreemux"
	"golang.org/x/oauth2"
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

func TestGetIdentityTokenWithInvalidAuthError(t *testing.T) {
	router := httptreemux.New()
	router.POST(fmt.Sprintf("/v1/projects/-/serviceAccounts/%s:generateIdToken", "unkown-service@myproject.iam.gserviceaccount.com"), func(w http.ResponseWriter, r *http.Request, params map[string]string) {
		log.Printf("/v1/projects/-/serviceAccounts/%s:generateIdToken", "unkown-service@myproject.iam.gserviceaccount.com")
		w.WriteHeader(http.StatusUnauthorized)
		io.WriteString(w, `{
          "error": {
            "code": 401,
            "message": "Request had invalid authentication credentials. Expected OAuth 2 access token, login cookie or other valid authentication credential. See https://developers.google.com/identity/sign-in/web/devconsole-project.",
            "status": "UNAUTHENTICATED",
            "details": [
              {
                "@type": "type.googleapis.com/google.rpc.ErrorInfo",
                "reason": "ACCESS_TOKEN_TYPE_UNSUPPORTED",
                "metadata": {
                  "method": "google.iam.credentials.v1.IAMCredentials.GenerateIdToken",
                  "service": "iamcredentials.googleapis.com"
                }
              }
            ]
          }
        }`)
	})

	metaServer := &testServer{}
	metaServer.start(router)
	defer metaServer.stop()

	_, err := getServiceAccountIdentityToken(metaServer.httpUrl(),
		"unkown-service@myproject.iam.gserviceaccount.com",
		"https://zts.athenz.io",
		&oauth2.Token{AccessToken: "mock-access-token"},
	)
	if err == nil || !strings.Contains(err.Error(), "UNAUTHENTICATED") {
		t.Fatalf("expected error, got: %v", err)
	}
}

func TestGetIdentityTokenSuccess(t *testing.T) {
	router := httptreemux.New()
	router.POST(fmt.Sprintf("/v1/projects/-/serviceAccounts/%s:generateIdToken", "unkown-service@myproject.iam.gserviceaccount.com"), func(w http.ResponseWriter, r *http.Request, params map[string]string) {
		log.Printf("/v1/projects/-/serviceAccounts/%s:generateIdToken", "unkown-service@myproject.iam.gserviceaccount.com")
		w.WriteHeader(http.StatusOK)
		io.WriteString(w, `{"token": "yJhbGciOiJSUzI1NiIsImtpZCI6IjVhYWZmNDdjMjFkMDZlMjY..."}`)
	})

	metaServer := &testServer{}
	metaServer.start(router)
	defer metaServer.stop()

	token, err := getServiceAccountIdentityToken(metaServer.httpUrl(),
		"unkown-service@myproject.iam.gserviceaccount.com",
		"https://zts.athenz.io",
		&oauth2.Token{AccessToken: "mock-access-token"},
	)
	if err != nil {
		t.Fatalf("expected no error, got: %v", err)
	}
	expectedIdentityToken := "yJhbGciOiJSUzI1NiIsImtpZCI6IjVhYWZmNDdjMjFkMDZlMjY..."
	if string(token) != expectedIdentityToken {
		t.Fatalf("expected identity token %s, got: %s", expectedIdentityToken, token)
	}
}
