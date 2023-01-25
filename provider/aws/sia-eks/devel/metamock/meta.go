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
        "LastUpdated" : "2019-05-06T15:35:48Z",
        "InstanceProfileArn" : "arn:aws:iam::123456789012:instance-profile/athenz.hockey-service@stage",
        "InstanceProfileId" : "XXXXPROFILEIDYYYY"
	}`

	instanceIdentityJson = `{
		"devpayProductCodes" : null,
		"privateIp" : "172.31.30.74",
		"availabilityZone" : "us-west-2a",
		"version" : "2010-08-31",
		"instanceId" : "i-03d1ae7035f931a90",
		"billingProducts" : null,
		"instanceType" : "t2.micro",
		"accountId" : "123456789012",
		"imageId" : "ami-527b8832",
		"pendingTime" : "2016-05-02T22:23:14Z",
		"architecture" : "x86_64",
		"kernelId" : null,
		"ramdiskId" : null,
		"region" : "us-east-1"
	}`

	signature = `MIAGCSqGSIb3DQEHAqCAMIACAQExCzAJBgUrDgMCGgUAMIAGCSqGSIb3DQEHAaCAJIAEggGvewog
ICJkZXZwYXlQcm9kdWN0Q29kZXMiIDogbnVsbCwKICAicHJpdmF0ZUlwIiA6ICIxNzIuMzEuMzAu
NzQiLAogICJhdmFpbGFiaWxpdHlab25lIiA6ICJ1cy13ZXN0LTJhIiwKICAidmVyc2lvbiIgOiAi
MjAxMC0wOC0zMSIsCiAgImluc3RhbmNlSWQiIDogImktMDNkMWFlNzAzNWY5MzFhOTAiLAogICJi
aWxsaW5nUHJvZHVjdHMiIDogbnVsbCwKICAiaW5zdGFuY2VUeXBlIiA6ICJ0Mi5taWNybyIsCiAg
ImFjY291bnRJZCIgOiAiNzk5NDA0NDUxMzQ3IiwKICAiaW1hZ2VJZCIgOiAiYW1pLTUyN2I4ODMy
IiwKICAicGVuZGluZ1RpbWUiIDogIjIwMTYtMDUtMDJUMjI6MjM6MTRaIiwKICAiYXJjaGl0ZWN0
dXJlIiA6ICJ4ODZfNjQiLAogICJrZXJuZWxJZCIgOiBudWxsLAogICJyYW1kaXNrSWQiIDogbnVs
bCwKICAicmVnaW9uIiA6ICJ1cy13ZXN0LTIiCn0AAAAAAAAxggEXMIIBEwIBATBpMFwxCzAJBgNV
BAYTAlVTMRkwFwYDVQQIExBXYXNoaW5ndG9uIFN0YXRlMRAwDgYDVQQHEwdTZWF0dGxlMSAwHgYD
VQQKExdBbWF6b24gV2ViIFNlcnZpY2VzIExMQwIJAJa6SNnlXhpnMAkGBSsOAwIaBQCgXTAYBgkq
hkiG9w0BCQMxCwYJKoZIhvcNAQcBMBwGCSqGSIb3DQEJBTEPFw0xNjA1MDIyMjIzMjFaMCMGCSqG
SIb3DQEJBDEWBBQ2jzQ/7D3aqBgC9Pxf4e4n0dSXfjAJBgcqhkjOOAQDBC4wLAIUPrfh6MGm56KI
yEcux31ojNlFqigCFDiVEXqe7vQ5mJ5D+T6bhZz7soavAAAAAAAA`
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

	log.Println("Starting Meta Mock listening on: " + EndPoint)
	err := http.ListenAndServe(EndPoint, nil)
	if err != nil {
		log.Fatalf("ListenAndServe: %v\n", err)
	}
}
