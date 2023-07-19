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
	"github.com/AthenZ/athenz/libs/go/sia/gcp/meta"
)

type GoogleAttestationData struct {
	IdentityToken string `json:"identityToken,omitempty"` //the instance identity token obtained from the metadata server
}

// New creates a new AttestationData by getting instance identity token
// from the Google metadata server
func New(base, service, ztsUrl string) (string, error) {

	tok, err := meta.GetData(base,
		"/computeMetadata/v1/instance/service-accounts/default/identity?audience="+ztsUrl+"&format=full")
	if err != nil {
		return "", err
	}
	data, err := json.Marshal(&GoogleAttestationData{
		IdentityToken: string(tok),
	})
	if err != nil {
		return "", err
	}

	return string(data), nil
}
