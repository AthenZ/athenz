//
// Copyright 2020 Verizon Media
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
	"encoding/json"
	"errors"
	"fmt"
	"github.com/AthenZ/athenz/provider/aws/sia-ec2/data/doc"
	"github.com/AthenZ/athenz/provider/aws/sia-ec2/data/meta"
	"github.com/AthenZ/athenz/provider/aws/sia-ec2/logutil"
	"github.com/AthenZ/athenz/provider/aws/sia-ec2/util"
	"io"
)

const (
	CentOS7 = iota
	CentOS6
	Ubuntu14
	Ubuntu16
	Ubuntu18
	Unknown
)

// ConfigService represents a service to be specified by user, and specify User/Group attributes for the service
type ConfigService struct {
	Filename string `json:"filename,omitempty"`
	User     string `json:"user,omitempty"`
	Group    string `json:"group,omitempty"`
}

// ConfigRole represents a role to be specified by user, and specify attributes for the role
type ConfigRole struct {
	Filename string `json:"filename,omitempty"`
}

// ConfigAccount represts each of the accounts that can be specified in the config file
type ConfigAccount struct {
	Provider string                `json:"provider,omitempty"` //name of the provider
	Name     string                `json:"name,omitempty"`     //name of the service identity
	User     string                `json:"user,omitempty"`     //the user name to chown the cert/key dirs to. If absent, then root.
	Group    string                `json:"group,omitempty"`    //the group name to chown the cert/key dirs to. If absent, then athenz.
	Domain   string                `json:"domain,omitempty"`   //name of the domain for the identity
	Account  string                `json:"account,omitempty"`  //name of the account
	Service  string                `json:"service,omitempty"`  //name of the service for the identity
	Zts      string                `json:"zts,omitempty"`      //the ZTS to contact
	Filename string                `json:"filename,omitempty"` //filename to put the service certificate
	Roles    map[string]ConfigRole `json:"roles,omitempty"`    //map of roles to retrieve certificates for
	OsType   int                   `json:"ostype,omitempty"`   //current operating system
	Version  string                `json:"version,omitempty"`  // sia version number
}

// Config represents entire sia_config file
type Config struct {
	Version         string                   `json:"version,omitempty"`           //name of the provider
	Service         string                   `json:"service,omitempty"`           //name of the service for the identity
	Services        map[string]ConfigService `json:"services,omitempty"`          //names of the multiple services for the identity
	Ssh             *bool                    `json:"ssh,omitempty"`               //ssh certificate support
	UseRegionalSTS  bool                     `json:"regionalsts,omitempty"`       //whether to use a regional STS endpoint (default is false)
	Accounts        []ConfigAccount          `json:"accounts,omitempty"`          //array of configured accounts
	GenerateRoleKey bool                     `json:"generate_role_key,omitempty"` //private key to be generated for role certificate
	RotateKey       bool                     `json:"rotate_key,omitempty"`        //rotate private key support
}

// Role contains role details. Attributes are set based on the config values
type Role struct {
	Name     string
	Service  string
	Filename string
	User     string
	Uid      int
	Gid      int
	FileMode int
}

// Service represents service details. Attributes are filled in based on the config values
type Service struct {
	Name     string
	Filename string
	User     string
	Group    string
	Uid      int
	Gid      int
	FileMode int
}

// Options represents settings that are derived from config file and application defaults
type Options struct {
	Provider             string
	Name                 string
	User                 string
	Group                string
	Domain               string
	Account              string
	Services             []Service
	Ssh                  bool
	UseRegionalSTS       bool
	Zts                  string
	Filename             string
	Roles                map[string]ConfigRole
	OsType               int
	Version              string
	KeyDir               string
	CertDir              string
	AthenzCACertFile     string
	ZTSCACertFile        string
	ZTSServerName        string
	ZTSAWSDomain         string
	GenerateRoleKey      bool
	RotateKey            bool
	BackUpDir            string
	ProviderParentDomain string
}

func initProfileConfig(metaEndPoint string) (*ConfigAccount, error) {
	info, err := meta.GetData(metaEndPoint, "/latest/meta-data/iam/info")
	if err != nil {
		return nil, err
	}
	arn, err := doc.GetDocumentEntry(info, "InstanceProfileArn")
	if err != nil {
		return nil, err
	}
	domain, service, err := util.ExtractServiceName(arn, ":instance-profile/")
	if err != nil {
		return nil, err
	}

	return &ConfigAccount{
		Domain:  domain,
		Service: service,
		Name:    fmt.Sprintf("%s.%s", domain, service),
	}, nil
}

func initFileConfig(bytes []byte, accountId string) (*Config, *ConfigAccount, error) {
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
		if configAccount.Account == accountId {
			if configAccount.Domain == "" {
				return nil, nil, fmt.Errorf("missing required Domain from the config file")
			}
			configAccount.Service = config.Service
			configAccount.Name = fmt.Sprintf("%s.%s", configAccount.Domain, configAccount.Service)
			return &config, &configAccount, nil
		}
	}
	return nil, nil, fmt.Errorf("missing account %s details from config file", accountId)
}

// NewOptions takes in sia_config bytes and returns a pointer to Options after parsing and initializing the defaults
// It uses profile arn for defaults when sia_config is empty or non-parsable. It populates "services" array
func NewOptions(bytes []byte, accountId, metaEndPoint, siaDir, version, ztsCaCert, ztsServerName, ztsAwsDomain, providerParentDomain string, sysLogger io.Writer) (*Options, error) {
	// Parse config bytes first, and if that fails, load values from Instance Profile and IAM info
	config, account, err := initFileConfig(bytes, accountId)
	if err != nil {
		logutil.LogInfo(sysLogger, "unable to parse configuration file, error: %v", err)
		// if we do not have a configuration file, we're going
		// to use fallback to <domain>.<service>-service
		// naming structure
		logutil.LogInfo(sysLogger, "trying to determine service name from profile arn...")
		account, err = initProfileConfig(metaEndPoint)
		if err != nil {
			return nil, fmt.Errorf("config non-parsable and unable to determine service name from profile arn, error: %v", err)
		}
	}

	ssh := true
	if config != nil && config.Ssh != nil && *config.Ssh == false {
		ssh = false
	}

	useRegionalSTS := false
	if config != nil {
		useRegionalSTS = config.UseRegionalSTS
	}

	var services []Service

	generateRoleKey := false
	rotateKey := false

	if config != nil {
		generateRoleKey = config.GenerateRoleKey
		rotateKey = config.RotateKey
		if len(account.Roles) != 0 && generateRoleKey == false && rotateKey == true {
			logutil.LogInfo(sysLogger, "Cannot set rotate_key to true, with generate_role_key as false,"+
				" when there are one or more roles defined in config\n")
			generateRoleKey = false
			rotateKey = false
		}
	}

	if config == nil || len(config.Services) == 0 {
		// There is no sia_config, or multiple services are not configured. Populate services with the account information we gathered
		s := Service{
			Name:     account.Service,
			Filename: account.Filename,
			User:     account.User,
		}
		s.Uid, s.Gid, s.FileMode = util.SvcAttrs(account.User, account.Group, sysLogger)
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
		tail := []Service{}
		for name, s := range config.Services {
			if name == config.Service {
				first.Filename = s.Filename
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
				first.Uid, first.Gid, first.FileMode = util.SvcAttrs(first.User, first.Group, sysLogger)
			} else {
				ts := Service{
					Name:     name,
					Filename: s.Filename,
					User:     s.User,
					Group:    s.Group,
				}
				ts.Uid, ts.Gid, ts.FileMode = util.SvcAttrs(s.User, s.Group, sysLogger)
				tail = append(tail, ts)
			}
			if s.Filename != "" && s.Filename[0] == '/' {
				logutil.LogInfo(sysLogger, "when custom filepaths are specified, rotate_key and generate_role_key are not supported")
				generateRoleKey = false
				rotateKey = false
			}
		}
		services = append(services, first)
		services = append(services, tail...)
	}

	for _, r := range account.Roles {
		if r.Filename != "" && r.Filename[0] == '/' {
			logutil.LogInfo(sysLogger, "when custom filepaths are specified, rotate_key and generate_role_key are not supported")
			generateRoleKey = false
			rotateKey = false
			break
		}
	}

	return &Options{
		Provider:             account.Provider,
		Name:                 account.Name,
		User:                 account.User,
		Group:                account.Group,
		Domain:               account.Domain,
		Account:              account.Account,
		Zts:                  account.Zts,
		Filename:             account.Filename,
		OsType:               GetOSType(),
		Version:              fmt.Sprintf("SIA-AWS %s", version),
		Ssh:                  ssh,
		UseRegionalSTS:       useRegionalSTS,
		Services:             services,
		Roles:                account.Roles,
		CertDir:              fmt.Sprintf("%s/certs", siaDir),
		KeyDir:               fmt.Sprintf("%s/keys", siaDir),
		AthenzCACertFile:     fmt.Sprintf("%s/certs/ca.cert.pem", siaDir),
		ZTSCACertFile:        ztsCaCert,
		ZTSServerName:        ztsServerName,
		ZTSAWSDomain:         ztsAwsDomain,
		GenerateRoleKey:      generateRoleKey,
		RotateKey:            rotateKey,
		BackUpDir:            fmt.Sprintf("%s/backup", siaDir),
		ProviderParentDomain: providerParentDomain,
	}, nil
}

func GetOSType() int {
	// this is only needed if sshd on the given os
	// needs something special for the restart
	// typically one would parse the /etc/os-release
	// for now we have a single method for restarting
	// sshd so we'll just return unknown os type

	return Unknown
}
