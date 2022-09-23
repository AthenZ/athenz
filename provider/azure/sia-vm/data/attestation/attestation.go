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
	"encoding/json"
	"fmt"
	"github.com/AthenZ/athenz/provider/azure/sia-vm/data/meta"
	"log"
)

type IdentityDocument struct {
	Location          string `json:"location,omitempty"`
	Name              string `json:"name,omitempty"`
	ResourceGroupName string `json:"resourceGroupName,omitempty"`
	SubscriptionId    string `json:"subscriptionId,omitempty"`
	VmId              string `json:"vmId,omitempty"`
	OsType            string `json:"osType,omitempty"`
	Tags              string `json:"tags,omitempty"`
	Document          []byte `json:"document,omitempty"`
	PrivateIp         string `json:"privateIp,omitempty"`
	PublicIp          string `json:"publicIp,omitempty"`
}

type Data struct {
	Location          string `json:"location,omitempty"`
	Name              string `json:"name,omitempty"`
	ResourceGroupName string `json:"resourceGroupName,omitempty"`
	SubscriptionId    string `json:"subscriptionId,omitempty"`
	VmId              string `json:"vmId,omitempty"`
	Token             string `json:"token,omitempty"`
}

// New creates a new AttestationData with values fed to it
func New(domain, service, metaEndPoint, apiVersion, resourceUri string, identityDocument *IdentityDocument) (*Data, error) {

	// obtain the access token for our service resource

	accessToken, err := getAccessToken(metaEndPoint, apiVersion, resourceUri)
	if err != nil {
		return nil, err
	}

	return &Data{
		Location:          identityDocument.Location,
		Name:              identityDocument.Name,
		ResourceGroupName: identityDocument.ResourceGroupName,
		SubscriptionId:    identityDocument.SubscriptionId,
		VmId:              identityDocument.VmId,
		Token:             accessToken,
	}, nil
}

func getAccessToken(metaEndPoint, apiVersion, resourceUri string) (string, error) {

	uri := fmt.Sprintf("/metadata/identity/oauth2/token?api-version=%s&resource=%s", apiVersion, resourceUri)
	document, err := meta.GetData(metaEndPoint, uri)
	if err != nil {
		log.Fatalf("Unable to get the identity access token, error: %v\n", err)
		return "", err
	}

	var docMap map[string]interface{}
	err = json.Unmarshal(document, &docMap)
	if err != nil {
		log.Fatalf("Unable to parse access token document: %v\n", err)
		return "", err
	}
	return docMap["access_token"].(string), nil
}

func GetIdentityDocument(metaEndPoint, apiVersion string) (*IdentityDocument, error) {

	uri := fmt.Sprintf("/metadata/instance/compute?api-version=%s", apiVersion)
	computeData, err := meta.GetData(metaEndPoint, uri)
	if err != nil {
		log.Fatalf("Unable to get the instance identity document, error: %v\n", err)
		return nil, err
	}
	var compute map[string]interface{}
	err = json.Unmarshal(computeData, &compute)
	if err != nil {
		log.Printf("unable to parse host info document: %v\n", err)
		return nil, err
	}

	privateIp := ""
	publicIp := ""
	uri = fmt.Sprintf("/metadata/instance/network/interface/0/ipv4/ipAddress/0?api-version=%s", apiVersion)
	ipv4Data, err := meta.GetData(metaEndPoint, uri)
	if err == nil {
		var ipv4 map[string]interface{}
		err = json.Unmarshal(ipv4Data, &ipv4)
		if err == nil {
			privateIp = ipv4["privateIpAddress"].(string)
			publicIp = ipv4["publicIpAddress"].(string)
		} else {
			log.Printf("unable to unmarshall ipv4 document: %v\n", err)
		}
	} else {
		log.Printf("unable to parse ipv4 document: %v\n", err)
	}

	return &IdentityDocument{
		Location:          compute["location"].(string),
		Name:              compute["name"].(string),
		ResourceGroupName: compute["resourceGroupName"].(string),
		SubscriptionId:    compute["subscriptionId"].(string),
		VmId:              compute["vmId"].(string),
		OsType:            compute["osType"].(string),
		Tags:              compute["tags"].(string),
		PrivateIp:         privateIp,
		PublicIp:          publicIp,
		Document:          computeData,
	}, nil
}
