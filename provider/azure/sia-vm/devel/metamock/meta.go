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
	instanceComputeIdentityJson = `{
		"location": "westus2",
		"name": "athenz-client",
		"offer": "CentOS",
		"osType": "Linux",
		"placementGroupId": "",
		"platformFaultDomain": "0",
		"platformUpdateDomain": "0",
		"publisher": "OpenLogic",
		"resourceGroupName": "Athenz",
		"sku": "8_2",
		"subscriptionId": "1111111-1111-1111-1111-111111111111",
		"tags": "athenz:athenz.backend",
		"version": "8.2.2020062400",
		"vmId": "22222222-2222-2222-2222-222222222222",
		"vmScaleSetName": "",
		"vmSize": "Standard_B1s",
		"zone": ""
	}`
	instanceIpAddressJson = `{
		"privateIpAddress": "10.0.0.4",
		"publicIpAddress": ""
	}`
	accessTokenJson = `{
		"access_token": "test-access-token",
		"client_id": "333-4444",
		"expires_in": "86368",
		"expires_on": "1603755035",
		"ext_expires_in": "86399",
		"not_before": "1603668335",
		"resource": "https://test.athenz.io/",
		"token_type": "Bearer"
	}`
)

func StartMetaServer(EndPoint string) {
	http.HandleFunc("/metadata/instance/compute", func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, instanceComputeIdentityJson)
	})
	http.HandleFunc("/metadata/instance/network/interface/0/ipv4/ipAddress/0", func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, instanceIpAddressJson)
	})
	http.HandleFunc("/metadata/identity/oauth2/token", func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, accessTokenJson)
	})

	log.Println("Starting Meta Mock listening on: " + EndPoint)
	err := http.ListenAndServe(EndPoint, nil)
	if err != nil {
		log.Fatalf("ListenAndServe: %v\n", err)
	}
}
