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
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"strings"
	"time"

	"github.com/AthenZ/athenz/libs/go/sia/gcp/meta"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/google"
)

type GoogleAttestationData struct {
	IdentityToken string `json:"identityToken,omitempty"` //the instance identity token obtained from the metadata server
}

// New creates a new AttestationData by getting instance identity token
// from the Google metadata server
func New(base, service, ztsUrl string) (string, error) {
	var (
		tok          []byte
		err          error
		serviceName  string
		emailPostfix string
	)
	serviceName, emailPostfix, err = meta.GetServiceAccountInfo(base)
	if err != nil {
		return "", err
	}
	// If the service name is the same as the service account attached with the instance, use the metadata to get the identity token.
	// Otherwise retrieve an identity token for one or more services by having the instance's service account
	// impersonate the target service account, assuming it has the necessary permissions to issue the identity token.
	if service == serviceName {
		tok, err = meta.GetData(base,
			"/computeMetadata/v1/instance/service-accounts/default/identity?audience="+ztsUrl+"&format=full")
	} else {
		serviceAccountEmail := strings.Join([]string{service, emailPostfix}, "")
		token, err := getOauth2TokenFromDefaultCredentials(context.Background())
		if err != nil {
			return "", err
		}

		tok, err = getServiceAccountIdentityToken("https://iamcredentials.googleapis.com", serviceAccountEmail, ztsUrl, token)
	}
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

// Retrieve an identity token for one or more services by having the instance's service account
// impersonate the target service account, assuming it has the necessary permissions to issue the identity token.
func getServiceAccountIdentityToken(base string, serviceAccountEmail string, audience string, token *oauth2.Token) ([]byte, error) {
	payload := map[string]interface{}{
		"audience":     audience,
		"includeEmail": true,
	}
	payloadJSON, err := json.Marshal(payload)
	if err != nil {
		return nil, err
	}
	url := fmt.Sprintf("%s/v1/projects/-/serviceAccounts/%s:generateIdToken", base, serviceAccountEmail)
	log.Printf("Obtain identity token for service account: %s, url: %s", serviceAccountEmail, url)
	req, err := http.NewRequest("POST", url, bytes.NewBuffer(payloadJSON))
	if err != nil {
		return nil, err
	}

	req.Header.Set("Authorization", "Bearer "+token.AccessToken)
	req.Header.Set("Content-Type", "application/json")
	client := &http.Client{}
	client.Timeout = 5 * time.Second
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("Unexpected status code: %d\nResponse Body: %s\n", resp.StatusCode, string(body))
	}

	var responseData map[string]interface{}
	err = json.Unmarshal(body, &responseData)
	if err != nil {
		return nil, err
	}
	identityToken, ok := responseData["token"].(string)
	if !ok {
		return nil, fmt.Errorf("Unable to extract identity token from response for service account: %s", serviceAccountEmail)
	}
	return []byte(identityToken), nil
}

// A helper function that calls `google.FindDefaultCredentials` to issue oauth2 token
func getOauth2TokenFromDefaultCredentials(ctx context.Context) (*oauth2.Token, error) {
	creds, err := google.FindDefaultCredentials(ctx)
	if err != nil {
		return nil, err
	}
	token, err := creds.TokenSource.Token()
	if err != nil {
		return nil, err
	}
	return token, nil
}
