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
	iamInfoJson = `{
		"Code" : "Success",
		"LastUpdated" : "2016-05-03T21:17:35Z",
		"InstanceProfileArn" : "arn:aws:iam::000000000000:instance-profile/athenz.api-service",
		"InstanceProfileId" : "AIPAIPOZZZPUCOOOOOOOO"
	}`

	instanceIdentityJson = `{
		"devpayProductCodes" : null,
		"privateIp" : "172.31.30.74",
		"availabilityZone" : "us-west-2a",
		"version" : "2010-08-31",
		"instanceId" : "i-03d1ae7035f931a90",
		"billingProducts" : null,
		"instanceType" : "t2.micro",
		"accountId" : "000000000001",
		"imageId" : "ami-527b8832",
		"pendingTime" : "2016-05-02T22:23:14Z",
		"architecture" : "x86_64",
		"kernelId" : null,
		"ramdiskId" : null,
		"region" : "us-west-2"
	}`

	signature = `aws-signature`
)

func StartMetaServer(EndPoint string) {
	http.HandleFunc("/latest/meta-data/iam/info", func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, iamInfoJson)
	})
	http.HandleFunc("/latest/dynamic/instance-identity/document", func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, instanceIdentityJson)
	})
	http.HandleFunc("/latest/dynamic/instance-identity/pkcs7", func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, signature)
	})
	http.HandleFunc("/latest/meta-data/public-ipv4", func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, "172.31.30.75")
	})
	log.Println("Starting Meta Mock listening on: " + EndPoint)
	err := http.ListenAndServe(EndPoint, nil)
	if err != nil {
		log.Fatalf("ListenAndServe: %v\n", err)
	}
}
