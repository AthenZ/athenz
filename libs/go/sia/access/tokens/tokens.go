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
	"gopkg.in/square/go-jose.v2/jwt"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"time"

	"github.com/AthenZ/athenz/libs/go/sia/util"

	"github.com/AthenZ/athenz/clients/go/zts"
	"github.com/AthenZ/athenz/libs/go/sia/access/config"
	"github.com/AthenZ/athenz/libs/go/sia/aws/options"
	siafile "github.com/AthenZ/athenz/libs/go/sia/file"
	"github.com/AthenZ/athenz/libs/go/sia/futil"
	tlsconfig "github.com/AthenZ/athenz/libs/go/tls/config"
)

const (
	UserAgent              = "User-Agent"
	TokenRefreshPeriodProp = "TOKEN_REFRESH_PERIOD"
	DefaultRefreshDuration = "1.5h"
)

// ToBeRefreshed looks into /var/lib/sia/tokens folder and returns the list of tokens whose
// age is half of their validity
func ToBeRefreshed(opts *config.TokenOptions) ([]config.AccessToken, []error) {
	return ToBeRefreshedBasedOnTime(opts, time.Now())
}

// ToBeRefreshedBasedOnTime looks into /var/lib/sia/tokens folder and returns the list of tokens whose
// age is half of their validity (given the current time)
func ToBeRefreshedBasedOnTime(opts *config.TokenOptions, currentTime time.Time) ([]config.AccessToken, []error) {
	tokenDir := opts.TokenDir
	tokens := opts.Tokens

	file := func(domain, name string) string {
		return filepath.Join(tokenDir, domain, name)
	}
	refresh := []config.AccessToken{}
	errs := []error{}
	for _, t := range tokens {
		tpath := file(t.Domain, t.FileName)
		_, err := os.Stat(tpath)
		if err != nil {
			if os.IsNotExist(err) {
				refresh = append(refresh, t)
			} else {
				// Unknown stat error
				errs = append(errs, fmt.Errorf("unable to stat token: %s, err: %v", tpath, err))
				continue
			}
		} else {
			content, err := os.ReadFile(tpath)
			if err != nil {
				errs = append(errs, fmt.Errorf("token: %s exists, but could not read it, err: %v", tpath, err))
				continue
			}

			// if the token is being stored without expiration property (i.e - not AccessTokenResponse
			// but AccessTokenResponse::Access_token only), we should refresh immediately
			if opts.StoreOptions != config.ZtsResponse {
				refresh = append(refresh, t)
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
			//  Extract expiration claim from token and compare with AccessTokenResponse
			claims, err := GetClaimsFromAccessTokenUnverified(atr)
			if err != nil {
				errs = append(errs, fmt.Errorf("token: %s exists, but failed to extract claims, err: %v", tpath, err))
				continue
			}

			validityDuration, validityDurationRemaining, err := CheckExpiry(claims, currentTime)
			if err != nil {
				// token expired - refresh immediately
				refresh = append(refresh, t)
				continue
			}

			// If the token age is more than half of token's total validity, refresh the token
			if (validityDurationRemaining * 2) < validityDuration {
				refresh = append(refresh, t)
			}
			// if we have a threshold specified, also verify that the token is valid for
			// the given number of minutes
			if opts.ExpiryThreshold > 0 && validityDurationRemaining <= float64(opts.ExpiryThreshold) {
				refresh = append(refresh, t)
			}
		}
	}
	return refresh, errs
}

func Fetch(opts *config.TokenOptions) ([]string, []error) {
	errs := []error{}
	refreshed := []string{}
	tlsConfigs, e := loadSvcCerts(opts)
	if len(e) != 0 {
		errs = append(errs, e...)
	}

	client := zts.NewClient(opts.ZtsUrl, nil)

	toRefresh, e := ToBeRefreshed(opts)
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
		client.AddCredentials(UserAgent, opts.UserAgent)

		res, err := client.PostAccessTokenRequest(zts.AccessTokenRequest(makeTokenRequest(t.Domain, t.Roles, t.Expiry, t.ProxyPrincipalSpiffeUris)))
		if err != nil {
			errs = append(errs, fmt.Errorf("unable to post access token request for domain: %q, roles: %v, err: %v", t.Domain, t.Roles, err))
			continue
		}

		fileName := filepath.Join(opts.TokenDir, t.Domain, t.FileName)

		tokenBytesToStore := func(res *zts.AccessTokenResponse, opts *config.TokenOptions) ([]byte, error) {
			if opts.StoreOptions == config.ZtsResponse {
				return json.Marshal(res)
			} else if opts.StoreOptions == config.AccessTokenWithoutQuotesProp {
				return []byte(res.Access_token), nil
			} else {
				return json.Marshal(res.Access_token)
			}
		}

		bytes, err := tokenBytesToStore(res, opts)

		if err != nil {
			// note: since it was just unmarshalled into AccessTokenResponse by the ZTS client library, re-marshalling should never be an issue
			errs = append(errs, fmt.Errorf("unable to marshall the token response for domain: %q, roles: %v, response: %v, err: %v", t.Domain, t.Roles, res, err))
			continue
		}
		err = siafile.Update(fileName, bytes, t.Uid, t.Gid, 0440, nil)
		if err != nil {
			errs = append(errs, fmt.Errorf("unable to write to file: %q for access token request for domain: %q, roles: %v, err: %v", fileName, t.Domain, t.Roles, err))
			continue
		} else {
			refreshed = append(refreshed, fileName)
		}
	}

	return refreshed, errs
}

// loadSvcCerts goes through the services found on the host, and loads the corresponding cert/key into map of tls.Config and returns the map
func loadSvcCerts(opts *config.TokenOptions) (map[string]*tls.Config, []error) {
	configs := map[string]*tls.Config{}
	errors := []error{}
	for _, svc := range opts.Services {
		certFile := util.GetSvcCertFileName(opts.CertDir, svc.CertFilename, opts.Domain, svc.Name)
		keyFile := util.GetSvcKeyFileName(opts.KeyDir, svc.KeyFilename, opts.Domain, svc.Name)
		c, err := tlsconfig.GetTLSConfigFromFiles(certFile, keyFile)
		if err != nil {
			errors = append(errors, err)
			continue
		}
		configs[svc.Name] = c
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

func makeTokenRequest(domain string, roles []string, expiryTime int, proxyPrincipalSpiffeUris string) string {
	params := url.Values{}
	params.Add("grant_type", "client_credentials")
	params.Add("expires_in", strconv.Itoa(expiryTime))
	if proxyPrincipalSpiffeUris != "" {
		params.Add("proxy_principal_spiffe_uris", proxyPrincipalSpiffeUris)
	}

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

func NewTokenOptions(options *options.Options, ztsUrl string, userAgent string) (*config.TokenOptions, error) {
	if options.AccessTokens == nil {
		return nil, fmt.Errorf("not configured to fetch access tokens")
	}
	dirs := []string{options.CertDir, options.KeyDir, options.BackupDir}
	dirs = append(dirs, TokenDirs(options.TokenDir, options.AccessTokens)...)

	err := futil.MakeDirs(dirs, 0755)
	if err != nil {
		return nil, fmt.Errorf("unable to create access-token directories, err: %v", err)
	}

	tokenRefreshPeriod := util.EnvOrDefault(TokenRefreshPeriodProp, DefaultRefreshDuration)
	tokenRefresh, err := time.ParseDuration(tokenRefreshPeriod)
	if err != nil {
		return nil, fmt.Errorf("invalid token refresh period %q, %v", tokenRefreshPeriod, err)
	}

	tokenOpts := &config.TokenOptions{
		Domain:          options.Domain,
		Services:        toTokenServices(options.Services),
		TokenDir:        options.TokenDir,
		Tokens:          options.AccessTokens,
		CertDir:         options.CertDir,
		KeyDir:          options.KeyDir,
		ZtsUrl:          ztsUrl,
		UserAgent:       userAgent,
		TokenRefresh:    tokenRefresh,
		ExpiryThreshold: 0,
	}
	return tokenOpts, nil
}

func toTokenServices(services []options.Service) []config.TokenService {
	var tokenServices []config.TokenService

	for _, svc := range services {
		tokenService := config.TokenService{
			Name:         svc.Name,
			KeyFilename:  svc.KeyFilename,
			CertFilename: svc.CertFilename,
		}
		tokenServices = append(tokenServices, tokenService)
	}

	return tokenServices
}

// GetClaimsFromAccessTokenUnverified extract the token claims.
// The claims will not be verified (as the public key isn't provided)
func GetClaimsFromAccessTokenUnverified(accessTokenResponse zts.AccessTokenResponse) (map[string]interface{}, error) {
	tok, err := jwt.ParseSigned(accessTokenResponse.Access_token)
	if err != nil {
		return nil, fmt.Errorf("Unable to validate access token: %v\n", err)
	}

	var claims map[string]interface{}
	if err := tok.UnsafeClaimsWithoutVerification(&claims); err != nil {
		return nil, fmt.Errorf("Unable to validate access token: %v\n", err)
	}

	return claims, nil
}

func CheckExpiry(claims map[string]interface{}, now time.Time) (float64, float64, error) {
	expiry := claims["exp"]
	issue := claims["iat"]
	tokenExpiry := dateClaimToTime(expiry)
	tokenIssue := dateClaimToTime(issue)
	validityDuration := tokenExpiry.Sub(tokenIssue).Minutes()
	validityDurationRemaining := tokenExpiry.Sub(now).Minutes()

	if validityDurationRemaining < 0 {
		return 0, 0, fmt.Errorf("access token expired: %v, CurrentTime: %v", tokenExpiry, now)
	}

	return validityDuration, validityDurationRemaining, nil
}

func dateClaimToTime(timeClaim interface{}) time.Time {
	var timeVal time.Time
	switch iat := timeClaim.(type) {
	case float64:
		timeVal = time.Unix(int64(iat), 0)
	case json.Number:
		v, _ := iat.Int64()
		timeVal = time.Unix(v, 0)
	}
	return timeVal
}
