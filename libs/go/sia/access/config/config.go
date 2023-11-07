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

package config

import "time"

// Role models the configuration to be specified in sia_config
type Role struct {
	Service                  string   `json:"service,omitempty"`                     // principal service with role access
	Roles                    []string `json:"roles,omitempty"`                       // the roles in the domain in which principal is a member
	Expiry                   int      `json:"expires_in,omitempty"`                  // requested expiry time for access token in seconds
	ProxyPrincipalSpiffeUris string   `json:"proxy_principal_spiffe_uris,omitempty"` // Proxy Principal Spiffe URIs to be included in the token
}

// AccessToken is the type that holds information AFTER processing the configuration
type AccessToken struct {
	FileName                 string   // FileName under /var/lib/sia/tokens
	Service                  string   // Principal service that is a member of the roles
	Domain                   string   // Domain in which principal is a member of
	Roles                    []string // Roles under the Domain for which access tokens are being requested
	User                     string   // Owner of the access token file on disc
	Uid                      int      // Uid of the Owner of file on disc
	Gid                      int      // Gid of the file on disc
	Expiry                   int      // Expiry of the access token
	ProxyPrincipalSpiffeUris string   // Proxy Principal Spiffe URIs to be included in the token
}

type StoreTokenOptions int

const (
	ZtsResponse                  StoreTokenOptions = iota // Default - store the entire AccessTokenResponse from ZTS
	AccessTokenProp                                       // Store only the access_token property
	AccessTokenWithoutQuotesProp                          // Store only the access_token without enclosing in quotes
)

// TokenService service definition with key/cert filenames
type TokenService struct {
	Name         string
	KeyFilename  string
	CertFilename string
}

// TokenOptions holds all the configurable options for driving Access Tokens functionality
type TokenOptions struct {
	Domain          string            // Domain of the instance
	Services        []TokenService    // Services set on the instance
	TokenDir        string            // Directory where tokens will be saved, typically /var/lib/sia/tokens
	Tokens          []AccessToken     // List of Access Tokens with their configuration
	CertDir         string            // Directory where certs can be found, typically /var/lib/sia/certs
	KeyDir          string            // Directory where keys can be found, typically /var/lib/sia/keys
	ZtsUrl          string            // ZTS endpoint
	UserAgent       string            // User Agent string to be sent in the client call to ZTS, typically a client version
	TokenRefresh    time.Duration     // Token refresh interval
	StoreOptions    StoreTokenOptions // Store token option
	ExpiryThreshold int               // Called specified expiry in minutes for refresh
}
