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

package options

// package options contains types for parsing sia_config file and options to carry those config values

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/AthenZ/athenz/libs/go/sia/util"
	"github.com/AthenZ/athenz/provider/azure/sia-vm/data/attestation"
	vmutil "github.com/AthenZ/athenz/provider/azure/sia-vm/util"
	"log"
	"strings"
)

// ConfigService represents a service to be specified by user, and specify User/Group attributes for the service
type ConfigService struct {
	KeyFilename  string `json:"key_filename,omitempty"`
	CertFilename string `json:"cert_filename,omitempty"`
	User         string `json:"user,omitempty"`
	Group        string `json:"group,omitempty"`
}

// ConfigRole represents a role to be specified by user, and specify attributes for the role
type ConfigRole struct {
	Filename string `json:"filename,omitempty"`
}

// ConfigAccount represents each of the accounts that can be specified in the config file
type ConfigAccount struct {
	Provider string                `json:"provider,omitempty"` //name of the provider
	Name     string                `json:"name,omitempty"`     //name of the service identity
	User     string                `json:"user,omitempty"`     //the user name to chown the cert/key dirs to. If absent, then root.
	Group    string                `json:"group,omitempty"`    //the group name to chown the cert/key dirs to. If absent, then athenz.
	Domain   string                `json:"domain,omitempty"`   //name of the domain for the identity
	Account  string                `json:"account,omitempty"`  //name of the account
	Service  string                `json:"service,omitempty"`  //name of the service for the identity
	Zts      string                `json:"zts,omitempty"`      //the ZTS to contact
	Roles    map[string]ConfigRole `json:"roles,omitempty"`    //map of roles to retrieve certificates for
	Version  string                `json:"version,omitempty"`  // sia version number
}

// Config represents entire sia_config file
type Config struct {
	Version          string                   `json:"version,omitempty"`            //name of the provider
	Service          string                   `json:"service,omitempty"`            //name of the service for the identity
	Services         map[string]ConfigService `json:"services,omitempty"`           //names of the multiple services for the identity
	Ssh              *bool                    `json:"ssh,omitempty"`                //ssh certificate support
	Accounts         []ConfigAccount          `json:"accounts,omitempty"`           //array of configured accounts
	SanDnsWildcard   bool                     `json:"sandns_wildcard,omitempty"`    //san dns wildcard support
	SanDnsHostname   bool                     `json:"sandns_hostname,omitempty"`    //san dns hostname support
	FileDirectUpdate bool                     `json:"file_direct_update,omitempty"` //update key/cert files directly instead of using rename
}

// Role contains role details. Attributes are set based on the config values
type Role struct {
	Name     string
	Service  string
	Filename string
	User     string
	Uid      int
	Gid      int
}

// Service represents service details. Attributes are filled in based on the config values
type Service struct {
	Name         string
	KeyFilename  string
	CertFilename string
	User         string
	Group        string
	Uid          int
	Gid          int
}

// Options represents settings that are derived from config file and application defaults
type Options struct {
	Provider          string                //name of the provider
	Name              string                //name of the service identity
	User              string                //the user name to chown the cert/key dirs to. If absent, then root
	Group             string                //the group name to chown the cert/key dirs to. If absent, then athenz
	Domain            string                //name of the domain for the identity
	Account           string                //name of the account
	Services          []Service             //array of configured services
	Ssh               bool                  //ssh certificate support
	Zts               string                //the ZTS to contact
	Roles             map[string]ConfigRole //list of configured roles
	Version           string                //sia version number
	KeyDir            string                //private key directory path
	CertDir           string                //x.509 certificate directory path
	CountryName       string                //country name
	AthenzCACertFile  string                //filename to store Athenz CA certs
	ZTSCACertFile     string                //filename for CA certs when communicating with ZTS
	ZTSServerName     string                //ZTS server name, if necessary for tls
	ZTSAzureDomains   []string              //list of domain prefixes for sanDNS entries
	SanDnsWildcard    bool                  //san dns wildcard support
	SanDnsHostname    bool                  //san dns hostname support
	FileDirectUpdate  bool                  //update key/cert files directly instead of using rename
	AddlSanDNSEntries []string              //additional san dns entries to be added to the CSR
}

func initProfileConfig(identityDocument *attestation.IdentityDocument) (*ConfigAccount, error) {

	if identityDocument.Tags == "" {
		return nil, fmt.Errorf("no tags available in the identity document")
	}
	domain, service, err := vmutil.ExtractServiceName(identityDocument.Tags)
	if err != nil {
		return nil, err
	}
	return &ConfigAccount{
		Domain:  domain,
		Service: service,
		Name:    fmt.Sprintf("%s.%s", domain, service),
	}, nil
}

func initFileConfig(bytes []byte, identityDocument *attestation.IdentityDocument) (*Config, *ConfigAccount, error) {
	if len(bytes) == 0 {
		return nil, nil, errors.New("empty config bytes")
	}
	var config Config
	err := json.Unmarshal(bytes, &config)
	if err != nil {
		return nil, nil, err
	}
	if config.Version != "1.0.0" {
		return nil, nil, fmt.Errorf("unknown version number")
	}
	if config.Service == "" {
		return nil, nil, fmt.Errorf("missing required Service field from the config file")
	}
	for _, configAccount := range config.Accounts {
		if configAccount.Account == identityDocument.SubscriptionId {
			if configAccount.Domain == "" {
				return nil, nil, fmt.Errorf("missing required Domain from the config file")
			}
			configAccount.Service = config.Service
			configAccount.Name = fmt.Sprintf("%s.%s", configAccount.Domain, configAccount.Service)
			return &config, &configAccount, nil
		}
	}
	return nil, nil, fmt.Errorf("missing account %s details from config file", identityDocument.SubscriptionId)
}

// NewOptions takes in sia_config bytes and returns a pointer to Options after parsing and initializing the defaults
// It uses identity document defaults when sia_config is empty or non-parsable. It populates "services" array
func NewOptions(bytes []byte, identityDocument *attestation.IdentityDocument, siaDir, version, ztsCaCert, ztsServerName string, ztsAzureDomains []string, countryName, azureProvider string) (*Options, error) {
	// Parse config bytes first, and if that fails, load values from Identity document
	config, account, err := initFileConfig(bytes, identityDocument)
	if err != nil {
		log.Printf("unable to parse configuration file, error: %v\n", err)
		log.Println("trying to determine service name from identity document tags...")
		account, err = initProfileConfig(identityDocument)
		if err != nil {
			return nil, fmt.Errorf("config non-parsable and unable to determine service name from identity tags, error: %v", err)
		}
	}

	ssh := true
	if config != nil && config.Ssh != nil && *config.Ssh == false {
		ssh = false
	}

	sanDnsWildcard := false
	sanDnsHostname := false
	fileDirectUpdate := false
	if config != nil {
		sanDnsWildcard = config.SanDnsWildcard
		sanDnsHostname = config.SanDnsHostname
		fileDirectUpdate = config.FileDirectUpdate
	}

	var services []Service
	if config == nil || len(config.Services) == 0 {
		// There is no sia_config, or multiple services are not configured. Populate services with the account information we gathered
		s := Service{
			Name: account.Service,
			User: account.User,
		}
		s.Uid, s.Gid = util.UidGidForUserGroup(account.User, account.Group)
		services = append(services, s)
	} else {
		// sia_config and services are found
		if _, ok := config.Services[config.Service]; !ok {
			return nil, fmt.Errorf("services: %+v mentioned, service: %q needs to be part of services", config.Services, config.Service)
		}
		// Populate config.Service into first
		first := Service{
			Name: config.Service,
		}

		// Populate the remaining into tail
		var tail []Service
		for name, s := range config.Services {
			if name == config.Service {
				first.KeyFilename = s.KeyFilename
				first.CertFilename = s.CertFilename
				first.User = s.User
				first.Group = s.Group
				// If User/Group are not specified, apply the User/Group settings from Config Account
				// This is for backwards compatibility - For other multiple services, the User/Group need to be explicityly mentioned in config
				if first.User == "" {
					first.User = account.User
				}
				if first.Group == "" {
					first.Group = account.Group
				}
				first.Uid, first.Gid = util.UidGidForUserGroup(first.User, first.Group)
			} else {
				ts := Service{
					Name:         name,
					KeyFilename:  s.KeyFilename,
					CertFilename: s.CertFilename,
					User:         s.User,
					Group:        s.Group,
				}
				ts.Uid, ts.Gid = util.UidGidForUserGroup(s.User, s.Group)
				tail = append(tail, ts)
			}
		}
		services = append(services, first)
		services = append(services, tail...)
	}

	return &Options{
		Provider:         azureProvider,
		Name:             account.Name,
		User:             account.User,
		Group:            account.Group,
		Domain:           account.Domain,
		Account:          account.Account,
		Zts:              account.Zts,
		Version:          fmt.Sprintf("SIA-Azure %s", version),
		Ssh:              ssh,
		Services:         services,
		Roles:            account.Roles,
		CertDir:          fmt.Sprintf("%s/certs", siaDir),
		KeyDir:           fmt.Sprintf("%s/keys", siaDir),
		AthenzCACertFile: fmt.Sprintf("%s/certs/ca.cert.pem", siaDir),
		ZTSCACertFile:    ztsCaCert,
		ZTSServerName:    ztsServerName,
		ZTSAzureDomains:  ztsAzureDomains,
		CountryName:      countryName,
		SanDnsWildcard:   sanDnsWildcard,
		SanDnsHostname:   sanDnsHostname,
		FileDirectUpdate: fileDirectUpdate,
	}, nil
}

// GetSvcNames returns command separated list of service names
func GetSvcNames(svcs []Service) string {
	var b bytes.Buffer
	for _, svc := range svcs {
		b.WriteString(fmt.Sprintf("%s,", svc.Name))
	}
	return strings.TrimSuffix(b.String(), ",")
}
