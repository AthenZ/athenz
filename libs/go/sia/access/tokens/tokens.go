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

package tokens

import (
	"crypto/tls"
	"encoding/json"
	"fmt"
	"github.com/AthenZ/athenz/clients/go/zts"
	"github.com/AthenZ/athenz/libs/go/sia/access/config"
	siafile "github.com/AthenZ/athenz/libs/go/sia/file"
	tlsconfig "github.com/AthenZ/athenz/libs/go/tls/config"
	"io/ioutil"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"time"
)

const USER_AGENT = "User-Agent"

// ToBeRefreshed looks into /var/lib/sia/tokens folder and returns the list of tokens whose
// age is half of their validity
func ToBeRefreshed(tokenDir string, tokens []config.AccessToken) ([]config.AccessToken, []error) {
	file := func(domain, name string) string {
		return filepath.Join(tokenDir, domain, name)
	}
	refresh := []config.AccessToken{}
	errs := []error{}
	for _, t := range tokens {
		tpath := file(t.Domain, t.FileName)
		f, err := os.Stat(tpath)
		if err != nil {
			if os.IsNotExist(err) {
				refresh = append(refresh, t)
			} else {
				// Unknown stat error
				errs = append(errs, fmt.Errorf("unable to stat token: %s, err: %v", tpath, err))
				continue
			}
		} else {
			content, err := ioutil.ReadFile(tpath)
			if err != nil {
				errs = append(errs, fmt.Errorf("token: %s exists, but could not read it, err: %v", tpath, err))
				continue
			}
			atr := zts.AccessTokenResponse{}
			err = json.Unmarshal(content, &atr)
			if err != nil {
				errs = append(errs, fmt.Errorf("token: %s not unmarshallable, err: %v", tpath, err))
				continue
			}
			if atr.Expires_in == nil {
				errs = append(errs, fmt.Errorf("invalid token: %s, expires_in key is not found", tpath))
				continue
			}
			// If the token age is more than half of token's total validity, refresh the token
			if time.Now().After(f.ModTime().Add(time.Duration(*atr.Expires_in/2) * time.Second)) {
				refresh = append(refresh, t)
			}
		}
	}
	return refresh, errs
}

// Fetch retrieves the configured set of access tokens from the ZTS Server
func Fetch(opts *config.TokenOptions) []error {
	errs := []error{}
	tlsConfigs, e := loadSvcCerts(opts)
	if len(e) != 0 {
		errs = append(errs, e...)
	}

	client := zts.NewClient(opts.ZtsUrl, nil)

	toRefresh, e := ToBeRefreshed(opts.TokenDir, opts.Tokens)
	if len(e) != 0 {
		errs = append(errs, e...)
	}

	for _, t := range toRefresh {
		c, ok := tlsConfigs[t.Service]
		if !ok {
			errs = append(errs, fmt.Errorf("unable to find identity for principal: %q", t.Service))
			continue
		}

		client.Transport = &http.Transport{
			TLSClientConfig: c,
		}
		client.AddCredentials(USER_AGENT, opts.UserAgent)

		res, err := client.PostAccessTokenRequest(zts.AccessTokenRequest(makeTokenRequest(t.Domain, t.Roles, t.Expiry)))
		if err != nil {
			errs = append(errs, fmt.Errorf("unable to post access token request for domain: %q, roles: %v, err: %v", t.Domain, t.Roles, err))
			continue
		}

		fileName := filepath.Join(opts.TokenDir, t.Domain, t.FileName)
		bytes, err := json.Marshal(res)
		if err != nil {
			// note: since it was just unmarshalled into AccessTokenResponse by the ZTS client library, re-marshalling should never be an issue
			errs = append(errs, fmt.Errorf("unable to marshall the token response for domain: %q, roles: %v, response: %v, err: %v", t.Domain, t.Roles, res, err))
			continue
		}

		err = siafile.Update(fileName, bytes, t.Uid, t.Gid, 0440, nil)
		if err != nil {
			errs = append(errs, fmt.Errorf("unable to write to file: %q for access token request for domain: %q, roles: %v, err: %v", fileName, t.Domain, t.Roles, err))
			continue
		}
	}

	return errs
}

// loadSvcCerts goes through the services found on the host, and loads the corresponding cert/key into map of tls.Config and returns the map
func loadSvcCerts(opts *config.TokenOptions) (map[string]*tls.Config, []error) {
	configs := map[string]*tls.Config{}
	errors := []error{}
	for _, svc := range opts.Services {
		certFile := filepath.Join(opts.CertDir, fmt.Sprintf("%s.%s.cert.pem", opts.Domain, svc))
		keyFile := filepath.Join(opts.KeyDir, fmt.Sprintf("%s.%s.key.pem", opts.Domain, svc))
		c, err := tlsconfig.GetTLSConfigFromFiles(certFile, keyFile)
		if err != nil {
			errors = append(errors, err)
			continue
		}
		configs[svc] = c
	}

	return configs, errors
}

// TokenDirs returns an array of token folders with domain in them
func TokenDirs(root string, tokens []config.AccessToken) []string {
	dirs := []string{}
	for _, t := range tokens {
		dirs = append(dirs, filepath.Join(root, t.Domain))
	}
	return dirs
}

func makeTokenRequest(domain string, roles []string, expiryTime int) string {
	params := url.Values{}
	params.Add("grant_type", "client_credentials")
	params.Add("expires_in", strconv.Itoa(expiryTime))

	var scope string
	if roles[0] == "*" {
		scope = domain + ":domain"
	} else {
		for idx, role := range roles {
			if idx != 0 {
				scope += " "
			}
			scope += domain + ":role." + role
		}
	}
	params.Add("scope", scope)
	return params.Encode()
}
