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

package metamock

import (
	"io"
	"log"
	"net/http"
)

var (
	identityToken = `eyJhbGciOiJFUzI1NiIsInR5cCI6IkpXVCIsImtpZCI6InYxIn0.eyJhdWQiOiJodHRwczovL3p0cy5hdGhlbnouaW8iLCJhenAiOiIxMDIwMjM4OTY5MDQyODExMDU1NjkiLCJlbWFpbCI6Im15LXNhQG15LWdjcC1wcm9qZWN0LmlhbS5nc2VydmljZWFjY291bnQuY29tIiwiZW1haWxfdmVyaWZpZWQiOnRydWUsImV4cCI6MTY3ODI1OTEzMSwiaWF0IjoxNjc4MjU1NTMxLCJpc3MiOiJodHRwczovL2drZS1tZXRhLW1vY2siLCJzdWIiOiIxMDIwMjM4OTY5MDQyODExMDU1NjkifQ.sRQdLhNm8WvYQynpshGRtgcngj0XERF3PjywyXfNP_0ivP6nszQvMZIqp9_SysfeYX7VrPPil4OGVfvEbkiyEQ`
	domain        = `athenz.test`
	projectId     = `my-gcp-project`
	sa            = `my-sa@my-gcp-project.iam.gserviceaccount.com`
)

func StartMetaServer(EndPoint string) {
	http.HandleFunc("/computeMetadata/v1/instance/service-accounts/default/identity?audience=https://zts.athenz.io", func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, identityToken)
	})
	http.HandleFunc("/computeMetadata/v1/project/attributes/athenz-domain", func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, domain)
	})
	http.HandleFunc("/computeMetadata/v1/project/project-id", func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, projectId)
	})
	http.HandleFunc("/computeMetadata/v1/instance/service-accounts/default/email", func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, sa)
	})

	log.Println("Starting GKE Meta Mock listening on: " + EndPoint)
	err := http.ListenAndServe(EndPoint, nil)
	if err != nil {
		log.Fatalf("ListenAndServe: %v\n", err)
	}
}
