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

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	legacy "github.com/AthenZ/athenz/libs/go/sia/aws/options"

	"log"
	"os"
	"strings"
	"syscall"
	"time"

	ac "github.com/AthenZ/athenz/libs/go/sia/access/config"
	"github.com/AthenZ/athenz/libs/go/sia/aws/doc"
	"github.com/AthenZ/athenz/libs/go/sia/aws/meta"
	"github.com/AthenZ/athenz/libs/go/sia/aws/stssession"
	"github.com/AthenZ/athenz/libs/go/sia/host/provider"
	"github.com/AthenZ/athenz/libs/go/sia/ssh/hostkey"
	"github.com/AthenZ/athenz/libs/go/sia/util"
)

// package options contains types for parsing sia_config file and options to carry those config values

// ConfigService represents a service to be specified by user, and specify User/Group attributes for the service
type ConfigService struct {
	KeyFilename    string  `json:"key_filename,omitempty"`
	CertFilename   string  `json:"cert_filename,omitempty"`
	User           string  `json:"user,omitempty"`
	Group          string  `json:"group,omitempty"`
	ExpiryTime     int     `json:"expiry_time,omitempty"`
	SDSUdsUid      int     `json:"sds_uds_uid,omitempty"`
	SDSNodeId      string  `json:"sds_node_id,omitempty"`
	SDSNodeCluster string  `json:"sds_node_cluster,omitempty"`
	Threshold      float64 `json:"cert_threshold_to_check,omitempty"`
}

// ConfigRole represents a role to be specified by user, and specify attributes for the role
type ConfigRole struct {
	Filename   string  `json:"filename,omitempty"`    //filename for the generated role certificate file
	ExpiryTime int     `json:"expiry_time,omitempty"` //requested expiry time for the role certificate
	Service    string  `json:"service,omitempty"`     //principal with role access
	User       string  `json:"user,omitempty"`        //user owner on the role identity key
	Group      string  `json:"group,omitempty"`       //group owner on the role identity key
	Threshold  float64 `json:"cert_threshold_to_check,omitempty"`
}

// ConfigAccount represents each of the accounts that can be specified in the config file
type ConfigAccount struct {
	Name         string                `json:"name,omitempty"`                       //name of the service identity
	User         string                `json:"user,omitempty"`                       //the username to chown the cert/key dirs to. If absent, then root.
	Group        string                `json:"group,omitempty"`                      //the group name to chown the cert/key dirs to. If absent, then athenz.
	Domain       string                `json:"domain,omitempty"`                     //name of the domain for the identity
	Account      string                `json:"account,omitempty"`                    //name of the account
	Service      string                `json:"service,omitempty"`                    //name of the service for the identity
	Zts          string                `json:"zts,omitempty"`                        //the ZTS to contact
	Roles        map[string]ConfigRole `json:"roles,omitempty"`                      //map of roles to retrieve certificates for
	Version      string                `json:"version,omitempty"`                    //sia version number
	Threshold    float64               `json:"cert_threshold_to_check,omitempty"`    //Threshold to verify for all certs
	SshThreshold float64               `json:"sshcert_threshold_to_check,omitempty"` //Threshold to verify for ssh certs
	OmitDomain   bool                  `json:"omit_domain,omitempty"`                //attestation role only includes service name
}

// Config represents entire sia_config file
type Config struct {
	Version           string                   `json:"version,omitempty"`                    //config version
	Domain            string                   `json:"domain,omitempty"`                     //name of the domain for the identity
	Service           string                   `json:"service,omitempty"`                    //name of the service for the identity
	Services          map[string]ConfigService `json:"services,omitempty"`                   //names of the multiple services for the identity
	Ssh               *bool                    `json:"ssh,omitempty"`                        //ssh certificate support
	SshHostKeyType    hostkey.KeyType          `json:"ssh_host_key_type,omitempty"`          //ssh host key type - rsa, ecdsa, etc
	SshPrincipals     string                   `json:"ssh_principals,omitempty"`             //ssh additional principals
	SanDnsWildcard    bool                     `json:"sandns_wildcard,omitempty"`            //san dns wildcard support
	SanDnsHostname    bool                     `json:"sandns_hostname,omitempty"`            //san dns hostname support
	SanDnsX509Cnames  string                   `json:"sandns_x509_cnames,omitempty"`         //additional san dns entries to be added to the CSR
	UseRegionalSTS    bool                     `json:"regionalsts,omitempty"`                //whether to use a regional STS endpoint (default is false)
	Account           string                   `json:"aws_account,omitempty"`                //name of the AWS account for the identity ( only applicable in AWS environment )
	Accounts          []ConfigAccount          `json:"accounts,omitempty"`                   //array of configured accounts ( kept for backward compatibility sake )
	GenerateRoleKey   bool                     `json:"generate_role_key,omitempty"`          //private key to be generated for role certificate
	RotateKey         bool                     `json:"rotate_key,omitempty"`                 //rotate private key support
	User              string                   `json:"user,omitempty"`                       //the username to chown the cert/key dirs to. If absent, then root
	Group             string                   `json:"group,omitempty"`                      //the group name to chown the cert/key dirs to. If absent, then athenz
	SDSUdsPath        string                   `json:"sds_uds_path,omitempty"`               //uds path if the agent should support uds connections
	SDSUdsUid         int                      `json:"sds_uds_uid,omitempty"`                //uds connections must be from the given user uid
	ExpiryTime        int                      `json:"expiry_time,omitempty"`                //service and role certificate expiry in minutes
	RefreshInterval   int                      `json:"refresh_interval,omitempty"`           //specifies refresh interval in minutes
	ZTSRegion         string                   `json:"zts_region,omitempty"`                 //specifies zts region for the requests
	DropPrivileges    bool                     `json:"drop_privileges,omitempty"`            //drop privileges to configured user instead of running as root
	AccessTokens      map[string]ac.Role       `json:"access_tokens,omitempty"`              //map of role name to token attributes
	FileDirectUpdate  bool                     `json:"file_direct_update,omitempty"`         //update key/cert files directly instead of using rename
	SiaKeyDir         string                   `json:"sia_key_dir,omitempty"`                //sia keys directory to override /var/lib/sia/keys
	SiaCertDir        string                   `json:"sia_cert_dir,omitempty"`               //sia certs directory to override /var/lib/sia/certs
	SiaTokenDir       string                   `json:"sia_token_dir,omitempty"`              //sia tokens directory to override /var/lib/sia/tokens
	SiaBackupDir      string                   `json:"sia_backup_dir,omitempty"`             //sia backup directory to override /var/lib/sia/backup
	HostnameSuffix    string                   `json:"hostname_suffix,omitempty"`            //hostname suffix in case we need to auto-generate hostname
	Zts               string                   `json:"zts,omitempty"`                        //the ZTS to contact
	Roles             map[string]ConfigRole    `json:"roles,omitempty"`                      //map of roles to retrieve certificates for
	Threshold         float64                  `json:"cert_threshold_to_check,omitempty"`    //threshold to verify for all certs
	SshThreshold      float64                  `json:"sshcert_threshold_to_check,omitempty"` //threshold to verify for ssh certs
	AccessManagement  bool                     `json:"access_management,omitempty"`          //access management support
	FailCountForExit  int                      `json:"fail_count_for_exit,omitempty"`        //number of failed counts before exiting program
	RunAfter          string                   `json:"run_after,omitempty"`                  //execute the command mentioned after certs are created
	RunAfterTokens    string                   `json:"run_after_tokens,omitempty"`           //execute the command mentioned after tokens are created
	SpiffeTrustDomain string                   `json:"spiffe_trust_domain,omitempty"`        //spiffe trust domain - if configured generate full spiffe uri with namespace
	StoreTokenOption  *int                     `json:"store_token_option,omitempty"`         //store access token option
}

type AccessProfileConfig struct {
	Profile           string `json:"profile,omitempty"`
	ProfileRestrictTo string `json:"profile_restrict_to,omitempty"`
}

// Role contains role details. Attributes are set based on the config values
type Role struct {
	Name             string
	Service          string
	SvcKeyFilename   string
	SvcCertFilename  string
	ExpiryTime       int
	RoleCertFilename string
	RoleKeyFilename  string
	User             string
	Uid              int
	Gid              int
	FileMode         int
	Threshold        float64
}

// Service represents service details. Attributes are filled in based on the config values
type Service struct {
	Name           string
	KeyFilename    string
	CertFilename   string
	User           string
	Group          string
	Uid            int
	Gid            int
	FileMode       int
	ExpiryTime     int
	SDSUdsUid      int
	SDSNodeId      string
	SDSNodeCluster string
	Threshold      float64
}

// Options represents settings that are derived from config file and application defaults
type Options struct {
	Provider            provider.Provider //provider instance
	MetaEndPoint        string            //meta data service endpoint
	Name                string            //name of the service identity
	User                string            //the username to chown the cert/key dirs to. If absent, then root
	Group               string            //the group name to chown the cert/key dirs to. If absent, then athenz
	Domain              string            //name of the domain for the identity
	Account             string            //name of the account
	Service             string            //name of the service for the identity
	Zts                 string            //the ZTS to contact
	InstanceId          string            //instance id if ec2/vm, task id if running within eks/ecs/gke
	InstanceName        string            //instance name if ec2/vm
	Roles               []Role            //map of roles to retrieve certificates for
	Region              string            //region name
	SanDnsWildcard      bool              //san dns wildcard support
	SanDnsHostname      bool              //san dns hostname support
	Version             string            //sia version number
	ZTSDomains          []string          //zts domain prefixes
	Services            []Service         //array of configured services
	Ssh                 bool              //ssh certificate support
	UseRegionalSTS      bool              //use regional sts endpoint
	KeyDir              string            //private key directory path
	CertDir             string            //x.509 certificate directory path
	AthenzCACertFile    string            //filename to store Athenz CA certs
	ZTSCACertFile       string            //filename for CA certs when communicating with ZTS
	ZTSServerName       string            //ZTS server name, if necessary for tls
	ZTSAWSDomains       []string          //list of domain prefixes for sanDNS entries
	GenerateRoleKey     bool              //option to generate a separate key for role certificates
	RotateKey           bool              //rotate the private key when refreshing certificates
	BackupDir           string            //backup directory for key/cert rotation
	CertCountryName     string            //generated x.509 certificate country name
	CertOrgName         string            //generated x.509 certificate organization name
	SshPubKeyFile       string            //ssh host public key file path
	SshCertFile         string            //ssh host certificate file path
	SshConfigFile       string            //sshd config file path
	SshHostKeyType      hostkey.KeyType   //ssh host key type - rsa or ecdsa
	PrivateIp           string            //instance private ip
	EC2Document         string            //EC2 instance identity document
	EC2Signature        string            //EC2 instance identity document pkcs7 signature
	EC2StartTime        *time.Time        //EC2 instance start time
	InstanceIdSanDNS    bool              //include instance id in a san dns entry (backward compatible option)
	RolePrincipalEmail  bool              //include role principal in a san email field (backward compatible option)
	SDSUdsPath          string            //UDS path if the agent should support uds connections
	SDSUdsUid           int               //UDS connections must be from the given user uid
	RefreshInterval     int               //refresh interval for certificates - default 24 hours
	ZTSRegion           string            //ZTS region in case the client needs this information
	DropPrivileges      bool              //Drop privileges to configured user instead of running as root
	TokenDir            string            //Access tokens directory
	AccessTokens        []ac.AccessToken  //Access tokens object
	Profile             string            //Access profile name
	ProfileRestrictTo   string            //Tag associated with access profile roles
	Threshold           float64           //threshold in number of days for cert expiry checks
	SshThreshold        float64           //threshold in number of days for ssh cert expiry checks
	FileDirectUpdate    bool              //update key/cert files directly instead of using rename
	HostnameSuffix      string            //hostname suffix in case we need to auto-generate hostname
	SshPrincipals       string            //ssh additional principals
	AccessManagement    bool              //access management support
	ZTSCloudDomains     []string          //list of domain prefixes for sanDNS entries
	AddlSanDNSEntries   []string          //additional san dns entries to be added to the CSR
	FailCountForExit    int               //number of failed counts before exiting program
	RunAfterParts       []string          //run after parsed parts
	RunAfterTokensParts []string          //run after token parsed parts
	SpiffeTrustDomain   string            //spiffe uri trust domain
	SpiffeNamespace     string            //spiffe uri namespace
	OmitDomain          bool              //attestation role only includes service name
	StoreTokenOption    *int              //store access token option
}

const (
	DefaultTokenExpiry = 28800       // 8 hrs
	DefaultThreshold   = float64(15) // 15 days
)

func GetInstanceTagValue(metaEndPoint, tagKey string) (string, error) {
	tagValue, err := meta.GetData(metaEndPoint, "/latest/meta-data/tags/instance/"+tagKey)
	return string(tagValue), err
}

func GetAccountId(metaEndPoint string, useRegionalSTS bool, region string) (string, error) {
	// first try to get the account from our creds and if
	// fails we'll fall back to identity document
	configAccount, _, err := InitCredsConfig("", "@", useRegionalSTS, region)
	if err == nil {
		return configAccount.Account, nil
	}
	document, err := meta.GetData(metaEndPoint, "/latest/dynamic/instance-identity/document")
	if err != nil {
		return "", err
	}
	return doc.GetDocumentEntry(document, "accountId")
}

func InitCredsConfig(roleSuffix, accessProfileSeparator string, useRegionalSTS bool, region string) (*ConfigAccount, *AccessProfileConfig, error) {
	account, domain, service, profile, err := stssession.GetMetaDetailsFromCreds(roleSuffix, accessProfileSeparator, useRegionalSTS, region)
	if err != nil {
		return nil, nil, fmt.Errorf("unable to parse role arn: %v", err)
	}
	return &ConfigAccount{
			Domain:       domain,
			Service:      service,
			Account:      account,
			Name:         fmt.Sprintf("%s.%s", domain, service),
			Threshold:    DefaultThreshold,
			SshThreshold: DefaultThreshold,
		}, &AccessProfileConfig{
			Profile:           profile,
			ProfileRestrictTo: "",
		}, nil
}

func InitProfileConfig(metaEndPoint, roleSuffix, accessProfileSeparator string) (*ConfigAccount, *AccessProfileConfig, error) {

	info, err := meta.GetData(metaEndPoint, "/latest/meta-data/iam/info")
	if err != nil {
		return nil, nil, err
	}
	arn, err := doc.GetDocumentEntry(info, "InstanceProfileArn")
	if err != nil {
		return nil, nil, err
	}
	athenzDomain, _ := meta.GetData(metaEndPoint, "/latest/meta-data/tags/instance/athenz-domain")
	roleServiceNameOnly := string(athenzDomain) != ""
	account, domain, service, profile, err := util.ParseRoleArn(arn, "instance-profile/", roleSuffix, accessProfileSeparator, roleServiceNameOnly)
	if err != nil {
		return nil, nil, err
	}
	omitDomain := false
	if domain == "" {
		domain = string(athenzDomain)
		omitDomain = true
	}
	return &ConfigAccount{
			Domain:       domain,
			Service:      service,
			Account:      account,
			Name:         fmt.Sprintf("%s.%s", domain, service),
			Threshold:    DefaultThreshold,
			SshThreshold: DefaultThreshold,
			OmitDomain:   omitDomain,
		}, &AccessProfileConfig{
			Profile:           profile,
			ProfileRestrictTo: "",
		}, nil
}

func InitGenericProfileConfig(metaEndPoint, roleSuffix, accessProfileSeparator string, provider provider.Provider) (*Config, *AccessProfileConfig, error) {

	account, domain, service, err := provider.GetAccountDomainServiceFromMeta(metaEndPoint)
	if err != nil {
		return nil, nil, err
	}
	profile, err := provider.GetAccessManagementProfileFromMeta(metaEndPoint)
	if err != nil {
		// access profile error can be ignored for now.
		return &Config{
			Account: account,
			Domain:  domain,
			Service: service,
		}, nil, nil
	}
	return &Config{
			Account: account,
			Domain:  domain,
			Service: service,
		}, &AccessProfileConfig{
			Profile:           profile,
			ProfileRestrictTo: "",
		}, nil
}

func InitFileConfig(fileName, metaEndPoint string, useRegionalSTS bool, region, account string, provider provider.Provider) (*Config, *ConfigAccount, error) {
	confBytes, err := os.ReadFile(fileName)
	if err != nil {
		return nil, nil, err
	}
	if len(confBytes) == 0 {
		return nil, nil, errors.New("empty config bytes")
	}
	var config Config
	err = json.Unmarshal(confBytes, &config)
	if err != nil {
		return nil, nil, err
	}
	if config.Service == "" {
		return &config, nil, fmt.Errorf("missing required Service field from the config file")
	}
	if config.Domain == "" {
		return &config, nil, fmt.Errorf("missing required Domain field from the config file")
	}

	// if we have more than one account block defined (not recommended)
	// then we need to determine our account id
	// Mar-2023: [refactor-sia] This block is kept for backward compatibility reasons
	if isAWSEnvironment(provider) {
		if len(config.Accounts) > 1 && account == "" {
			account, _ = GetAccountId(metaEndPoint, useRegionalSTS || config.UseRegionalSTS, region)
		}
		for _, configAccount := range config.Accounts {
			if configAccount.Account == account || len(config.Accounts) == 1 {
				if configAccount.Domain == "" || configAccount.Account == "" {
					return &config, nil, fmt.Errorf("missing required Domain and/or Account from the config file")
				}
				configAccount.Service = config.Service
				configAccount.Name = fmt.Sprintf("%s.%s", configAccount.Domain, configAccount.Service)
				configAccount.Threshold = nonZeroValue(configAccount.Threshold, DefaultThreshold)
				configAccount.SshThreshold = nonZeroValue(configAccount.SshThreshold, DefaultThreshold)
				return &config, &configAccount, nil
			}
		}
		return nil, nil, fmt.Errorf("missing account %s details from config file", account)
	}

	config.Threshold = nonZeroValue(config.Threshold, DefaultThreshold)
	config.SshThreshold = nonZeroValue(config.SshThreshold, DefaultThreshold)

	return &config, nil, nil
}

func InitAccessProfileFileConfig(fileName string) (*AccessProfileConfig, error) {
	confBytes, err := os.ReadFile(fileName)
	if err != nil {
		return nil, err
	}
	if len(confBytes) == 0 {
		return nil, errors.New("empty config bytes")
	}
	var config AccessProfileConfig
	err = json.Unmarshal(confBytes, &config)
	if err != nil {
		return nil, err
	}
	if config.Profile == "" {
		return nil, fmt.Errorf("missing required Profile field from the config file")
	}

	return &AccessProfileConfig{
		Profile:           config.Profile,
		ProfileRestrictTo: config.ProfileRestrictTo,
	}, nil
}

func InitEnvConfig(config *Config, provider provider.Provider) (*Config, *ConfigAccount, error) {
	// it is possible that the config object was already created the
	// config file in which case we're not going to override any
	// of the settings.
	if config == nil {
		config = &Config{}
	}
	if !config.SanDnsWildcard {
		config.SanDnsWildcard = util.ParseEnvBooleanFlag("ATHENZ_SIA_SANDNS_WILDCARD")
	}
	if !config.SanDnsHostname {
		config.SanDnsHostname = util.ParseEnvBooleanFlag("ATHENZ_SIA_SANDNS_HOSTNAME")
	}
	if config.SanDnsX509Cnames == "" {
		config.SanDnsX509Cnames = os.Getenv("ATHENZ_SIA_SANDNS_X509_CNAMES")
	}
	if config.HostnameSuffix == "" {
		config.HostnameSuffix = os.Getenv("ATHENZ_SIA_HOSTNAME_SUFFIX")
	}
	if !config.UseRegionalSTS {
		config.UseRegionalSTS = util.ParseEnvBooleanFlag("ATHENZ_SIA_REGIONAL_STS")
	}
	if !config.GenerateRoleKey {
		config.GenerateRoleKey = util.ParseEnvBooleanFlag("ATHENZ_SIA_GENERATE_ROLE_KEY")
	}
	if !config.RotateKey {
		config.RotateKey = util.ParseEnvBooleanFlag("ATHENZ_SIA_ROTATE_KEY")
	}
	if config.User == "" {
		config.User = os.Getenv("ATHENZ_SIA_USER")
	}
	if config.Group == "" {
		config.Group = os.Getenv("ATHENZ_SIA_GROUP")
	}
	if config.SDSUdsPath == "" {
		config.SDSUdsPath = os.Getenv("ATHENZ_SIA_SDS_UDS_PATH")
	}
	if config.SDSUdsUid == 0 {
		uid := util.ParseEnvIntFlag("ATHENZ_SIA_SDS_UDS_UID", 0)
		if uid > 0 {
			config.SDSUdsUid = uid
		}
	}
	if config.ExpiryTime == 0 {
		expiryTime := util.ParseEnvIntFlag("ATHENZ_SIA_EXPIRY_TIME", 0)
		if expiryTime > 0 {
			config.ExpiryTime = expiryTime
		}
	}
	if config.RefreshInterval == 0 {
		refreshInterval := util.ParseEnvIntFlag("ATHENZ_SIA_REFRESH_INTERVAL", 0)
		if refreshInterval > 0 {
			config.RefreshInterval = refreshInterval
		}
	}
	if config.FailCountForExit == 0 {
		failCount := util.ParseEnvIntFlag("ATHENZ_SIA_FAIL_COUNT_FOR_EXIT", 0)
		if failCount > 0 {
			config.FailCountForExit = failCount
		}
	}
	if config.ZTSRegion == "" {
		config.ZTSRegion = os.Getenv("ATHENZ_SIA_ZTS_REGION")
	}
	if !config.DropPrivileges {
		config.DropPrivileges = util.ParseEnvBooleanFlag("ATHENZ_SIA_DROP_PRIVILEGES")
	}
	if !config.FileDirectUpdate {
		config.FileDirectUpdate = util.ParseEnvBooleanFlag("ATHENZ_SIA_FILE_DIRECT_UPDATE")
	}
	if config.SiaKeyDir == "" {
		config.SiaKeyDir = os.Getenv("ATHENZ_SIA_KEY_DIR")
	}
	if config.SiaCertDir == "" {
		config.SiaCertDir = os.Getenv("ATHENZ_SIA_CERT_DIR")
	}
	if config.SiaTokenDir == "" {
		config.SiaTokenDir = os.Getenv("ATHENZ_SIA_TOKEN_DIR")
	}
	if config.SiaBackupDir == "" {
		config.SiaBackupDir = os.Getenv("ATHENZ_SIA_BACKUP_DIR")
	}
	if config.SshPrincipals == "" {
		config.SshPrincipals = os.Getenv("ATHENZ_SIA_SSH_PRINCIPALS")
	}
	if config.RunAfter == "" {
		config.RunAfter = os.Getenv("ATHENZ_SIA_RUN_AFTER")
	}
	if config.RunAfterTokens == "" {
		config.RunAfterTokens = os.Getenv("ATHENZ_SIA_RUN_AFTER_TOKENS")
	}
	if config.SpiffeTrustDomain == "" {
		config.SpiffeTrustDomain = os.Getenv("ATHENZ_SIA_SPIFFE_TRUST_DOMAIN")
	}
	if !config.AccessManagement {
		config.AccessManagement = util.ParseEnvBooleanFlag("ATHENZ_SIA_ACCESS_MANAGEMENT")
	}

	config.Threshold = util.ParseEnvFloatFlag("ATHENZ_SIA_ACCOUNT_THRESHOLD", DefaultThreshold)
	config.SshThreshold = util.ParseEnvFloatFlag("ATHENZ_SIA_ACCOUNT_SSH_THRESHOLD", DefaultThreshold)
	omitDomain := util.ParseEnvBooleanFlag("ATHENZ_SIA_OMIT_DOMAIN")

	acEnv := os.Getenv("ATHENZ_SIA_ACCESS_TOKENS")
	if acEnv != "" {
		err := json.Unmarshal([]byte(acEnv), &config.AccessTokens)
		if err != nil {
			return config, nil, fmt.Errorf("unable to parse athenz access tokens '%s': %v", acEnv, err)
		}
	}
	if config.StoreTokenOption == nil {
		tokenOption := util.ParseEnvIntFlag("ATHENZ_SIA_STORE_TOKEN_OPTION", -1)
		if tokenOption >= 0 {
			config.StoreTokenOption = &tokenOption
		}
	}

	if isAWSEnvironment(provider) {
		roleArn := os.Getenv("ATHENZ_SIA_IAM_ROLE_ARN")
		if roleArn == "" {
			return config, nil, fmt.Errorf("athenz role arn env variable not configured")
		}
		account, domain, service, _, err := util.ParseRoleArn(roleArn, "role/", "", "", false)
		if err != nil {
			return config, nil, fmt.Errorf("unable to parse athenz role arn: %v", err)
		}
		if account == "" || domain == "" || service == "" {
			return config, nil, fmt.Errorf("invalid role arn - missing components: %s", roleArn)
		}

		var configRoles map[string]ConfigRole
		rolesEnv := os.Getenv("ATHENZ_SIA_ACCOUNT_ROLES")
		if rolesEnv != "" {
			err = json.Unmarshal([]byte(rolesEnv), &configRoles)
			if err != nil {
				return config, nil, fmt.Errorf("unable to parse athenz account roles '%s': %v", rolesEnv, err)
			}
		}
		config.Account = account
		config.Domain = domain
		config.Service = service
		config.Roles = configRoles

		return config, &ConfigAccount{
			Account:      account,
			Domain:       domain,
			Service:      service,
			Roles:        configRoles,
			Name:         fmt.Sprintf("%s.%s", domain, service),
			Threshold:    config.Threshold,
			SshThreshold: config.SshThreshold,
			OmitDomain:   omitDomain,
		}, nil
	} else {
		// TODO add gcp specific new env var names
		if config.Domain == "" || config.Service == "" {
			return config, nil, fmt.Errorf("one or more required settings can not be retrieved from env variables")
		}
	}

	return config, nil, nil
}

func InitAccessProfileEnvConfig() (*AccessProfileConfig, error) {

	accessProfile := os.Getenv("ATHENZ_SIA_ACCESS_PROFILE")
	if accessProfile == "" {
		return nil, fmt.Errorf("athenz accessProfile variable not configured")
	}

	return &AccessProfileConfig{
		Profile:           accessProfile,
		ProfileRestrictTo: "",
	}, nil
}

// setOptions takes in sia_config objects and returns a pointer to Options after parsing and initializing the defaults
// It uses profile arn for defaults when sia_config is empty or non-parsable. It populates "services" array
func setOptions(config *Config, account *ConfigAccount, profileConfig *AccessProfileConfig, siaDir, version string) (*Options, error) {

	//update regional sts and wildcard settings based on config settings
	useRegionalSTS := false
	sanDnsWildcard := false
	sanDnsHostname := false
	hostnameSuffix := ""
	sdsUdsPath := ""
	sdsUdsUid := 0
	generateRoleKey := false
	rotateKey := false
	expiryTime := 0
	refreshInterval := 24 * 60
	ztsRegion := ""
	dropPrivileges := false
	profile := ""
	profileRestrictTo := ""
	fileDirectUpdate := false
	tokenDir := fmt.Sprintf("%s/tokens", siaDir)
	certDir := fmt.Sprintf("%s/certs", siaDir)
	keyDir := fmt.Sprintf("%s/keys", siaDir)
	backupDir := fmt.Sprintf("%s/backup", siaDir)
	sshHostKeyType := hostkey.Rsa
	sshPrincipals := ""
	accessManagement := false
	failCountForExit := 2
	runAfter := ""
	runAfterTokens := ""
	spiffeTrustDomain := ""
	addlSanDNSEntries := make([]string, 0)

	var storeTokenOption *int
	if config != nil {
		useRegionalSTS = config.UseRegionalSTS
		sanDnsWildcard = config.SanDnsWildcard
		sanDnsHostname = config.SanDnsHostname
		hostnameSuffix = config.HostnameSuffix
		sdsUdsPath = config.SDSUdsPath
		sdsUdsUid = config.SDSUdsUid
		expiryTime = config.ExpiryTime
		ztsRegion = config.ZTSRegion
		dropPrivileges = config.DropPrivileges
		fileDirectUpdate = config.FileDirectUpdate
		accessManagement = config.AccessManagement
		storeTokenOption = config.StoreTokenOption

		if config.RefreshInterval > 0 {
			refreshInterval = config.RefreshInterval
		}
		// sia key/cert/token directories if the config has values specified
		if config.SiaKeyDir != "" {
			keyDir = config.SiaKeyDir
		}
		if config.SiaCertDir != "" {
			certDir = config.SiaCertDir
		}
		if config.SiaTokenDir != "" {
			tokenDir = config.SiaTokenDir
		}
		if config.SiaBackupDir != "" {
			backupDir = config.SiaBackupDir
		}

		//update account user/group settings if override provided at the config level
		if account.User == "" && config.User != "" {
			account.User = config.User
		}
		if account.Group == "" && config.Group != "" {
			account.Group = config.Group
		}
		if config.SshHostKeyType != 0 {
			sshHostKeyType = config.SshHostKeyType
		}
		if config.SshPrincipals != "" {
			sshPrincipals = config.SshPrincipals
		}
		if config.RunAfter != "" {
			runAfter = config.RunAfter
		}
		if config.RunAfterTokens != "" {
			runAfterTokens = config.RunAfterTokens
		}
		if config.FailCountForExit > 0 {
			failCountForExit = config.FailCountForExit
		}
		if config.SpiffeTrustDomain != "" {
			spiffeTrustDomain = config.SpiffeTrustDomain
		}
		if config.SanDnsX509Cnames != "" {
			sanDSNSEntries := strings.Split(config.SanDnsX509Cnames, ",")
			addlSanDNSEntries = append(addlSanDNSEntries, sanDSNSEntries...)
		}
		//update generate role and rotate key options if config is provided
		generateRoleKey = config.GenerateRoleKey
		rotateKey = config.RotateKey
		if len(config.Roles) != 0 && generateRoleKey == false && rotateKey == true {
			log.Println("Cannot set rotate_key to true, with generate_role_key as false, when there are one or more roles defined in config")
			generateRoleKey = false
			rotateKey = false
		}
	}

	var services []Service
	if config == nil || len(config.Services) == 0 {
		//There is no sia_config, or multiple services are not configured.
		//Populate services with the account information we gathered
		s := Service{
			Name:      account.Service,
			User:      account.User,
			Threshold: account.Threshold,
		}
		s.Uid, s.Gid, s.FileMode = util.SvcAttrs(account.User, account.Group)
		s.SDSUdsUid = sdsUdsUid
		s.ExpiryTime = expiryTime
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
			svcExpiryTime := expiryTime
			if s.ExpiryTime > 0 {
				svcExpiryTime = s.ExpiryTime
			}
			svcSDSUdsUid := sdsUdsUid
			if s.SDSUdsUid != 0 {
				svcSDSUdsUid = s.SDSUdsUid
			}
			if name == config.Service {
				first.KeyFilename = s.KeyFilename
				first.CertFilename = s.CertFilename
				first.User = s.User
				first.Group = s.Group
				// If User/Group are not specified, apply the User/Group settings from Config Account
				// This is for backwards compatibility - For other multiple services, the User/Group need
				// to be explicitly mentioned in config
				if first.User == "" {
					first.User = account.User
				}
				if first.Group == "" {
					first.Group = account.Group
				}
				first.Uid, first.Gid, first.FileMode = util.SvcAttrs(first.User, first.Group)
				first.ExpiryTime = svcExpiryTime
				first.SDSNodeId = s.SDSNodeId
				first.SDSNodeCluster = s.SDSNodeCluster
				first.SDSUdsUid = svcSDSUdsUid
				first.Threshold = nonZeroValue(s.Threshold, account.Threshold)
			} else {
				ts := Service{
					Name:         name,
					KeyFilename:  s.KeyFilename,
					CertFilename: s.CertFilename,
					User:         s.User,
					Group:        s.Group,
					Threshold:    nonZeroValue(s.Threshold, account.Threshold),
				}
				ts.Uid, ts.Gid, ts.FileMode = util.SvcAttrs(s.User, s.Group)
				ts.ExpiryTime = svcExpiryTime
				ts.SDSNodeId = s.SDSNodeId
				ts.SDSNodeCluster = s.SDSNodeCluster
				ts.SDSUdsUid = svcSDSUdsUid
				tail = append(tail, ts)
			}
		}
		services = append(services, first)
		services = append(services, tail...)
	}

	// Process all access_tokens
	accessTokens, err := processAccessTokens(config, services)
	if err != nil {
		return nil, err
	}

	var roles []Role
	if config != nil {

		if account.Roles != nil {
			config.Roles = account.Roles
		}
		for name, r := range config.Roles {
			if r.Filename != "" && r.Filename[0] == '/' {
				log.Println("when custom filepaths are specified, rotate_key and generate_role_key are not supported")
				generateRoleKey = false
				rotateKey = false
			}
			roleService := getRoleServiceOwner(r.Service, services)
			role := Role{
				Name:             name,
				Service:          roleService.Name,
				SvcKeyFilename:   util.GetSvcKeyFileName(keyDir, roleService.KeyFilename, account.Domain, roleService.Name),
				SvcCertFilename:  util.GetSvcCertFileName(certDir, roleService.CertFilename, account.Domain, roleService.Name),
				RoleCertFilename: util.GetRoleCertFileName(certDir, r.Filename, name),
				RoleKeyFilename:  util.GetRoleKeyFileName(keyDir, r.Filename, name, generateRoleKey),
				ExpiryTime:       r.ExpiryTime,
				FileMode:         roleService.FileMode,
				Threshold:        nonZeroValue(r.Threshold, config.Threshold),
			}
			role.Uid = roleService.Uid
			role.Gid = roleService.Gid
			// override the uid/gid values if specified at role level
			if r.User != "" || r.Group != "" {
				rUid, rGid, fileMode := util.SvcAttrs(r.User, r.Group)
				if r.User != "" {
					role.Uid = rUid
				}
				if r.Group != "" {
					role.Gid = rGid
					role.FileMode = fileMode
				}
			}
			roles = append(roles, role)
		}
	}

	if profileConfig != nil {
		profile = profileConfig.Profile
		profileRestrictTo = profileConfig.ProfileRestrictTo
	}

	return &Options{
		Name:                account.Name,
		User:                account.User,
		Group:               account.Group,
		Domain:              account.Domain,
		Account:             account.Account,
		Zts:                 account.Zts,
		Version:             fmt.Sprintf("SIA %s", version),
		UseRegionalSTS:      useRegionalSTS,
		SanDnsWildcard:      sanDnsWildcard,
		SanDnsHostname:      sanDnsHostname,
		HostnameSuffix:      hostnameSuffix,
		Services:            services,
		Roles:               roles,
		TokenDir:            tokenDir,
		CertDir:             certDir,
		KeyDir:              keyDir,
		AthenzCACertFile:    fmt.Sprintf("%s/ca.cert.pem", certDir),
		GenerateRoleKey:     generateRoleKey,
		RotateKey:           rotateKey,
		BackupDir:           backupDir,
		SDSUdsPath:          sdsUdsPath,
		RefreshInterval:     refreshInterval,
		ZTSRegion:           ztsRegion,
		DropPrivileges:      dropPrivileges,
		AccessTokens:        accessTokens,
		Profile:             profile,
		ProfileRestrictTo:   profileRestrictTo,
		Threshold:           account.Threshold,
		SshThreshold:        account.SshThreshold,
		FileDirectUpdate:    fileDirectUpdate,
		SshHostKeyType:      sshHostKeyType,
		SshPrincipals:       sshPrincipals,
		AccessManagement:    accessManagement,
		FailCountForExit:    failCountForExit,
		RunAfterParts:       util.ParseScriptArguments(runAfter),
		RunAfterTokensParts: util.ParseScriptArguments(runAfterTokens),
		SpiffeTrustDomain:   spiffeTrustDomain,
		OmitDomain:          account.OmitDomain,
		StoreTokenOption:    storeTokenOption,
		AddlSanDNSEntries:   addlSanDNSEntries,
	}, nil
}

func getRoleServiceOwner(serviceName string, services []Service) Service {
	if serviceName == "" {
		return services[0]
	}
	for _, s := range services {
		if s.Name == serviceName {
			return s
		}
	}
	log.Printf("unknown service %s specified for role, defaulting to primary service\n", serviceName)
	return services[0]
}

func processAccessTokens(config *Config, processedSvcs []Service) ([]ac.AccessToken, error) {
	if config == nil || config.AccessTokens == nil {
		return nil, nil
	}

	var accessTokens []ac.AccessToken

	for k, t := range config.AccessTokens {
		parts := strings.Split(k, "/")
		if len(parts) <= 1 || strings.TrimSpace(parts[0]) == "" || strings.TrimSpace(parts[1]) == "" {
			return nil, fmt.Errorf("invalid access-token role, domain: %v, role: %v", k, t.Roles)
		}
		domain := parts[0]
		fileName := parts[1]
		roles := t.Roles
		if len(roles) == 0 {
			roles = []string{fileName}
		}
		expiry := DefaultTokenExpiry
		if t.Expiry != 0 {
			expiry = t.Expiry
		}
		service := t.Service

		// if service is not presented, choose the main service
		if service == "" {
			service = config.Service
		}

		processedSvc, err := getSvc(service, processedSvcs)
		if err != nil {
			return nil, err
		}

		accessTokens = append(accessTokens, ac.AccessToken{
			FileName:                 fileName,
			Service:                  service,
			Domain:                   domain,
			Roles:                    roles,
			Expiry:                   expiry,
			User:                     processedSvc.User,
			Uid:                      processedSvc.Uid,
			Gid:                      processedSvc.Gid,
			ProxyPrincipalSpiffeUris: t.ProxyPrincipalSpiffeUris,
		})
	}
	return accessTokens, nil
}

func getSvc(name string, services []Service) (Service, error) {
	for _, s := range services {
		if s.Name == name {
			return s, nil
		}
	}
	return Service{}, fmt.Errorf("%q not found in processed services", name)
}

// GetSvcNames returns comma separated list of service names
func GetSvcNames(svcs []Service) string {
	var b bytes.Buffer
	for _, svc := range svcs {
		b.WriteString(fmt.Sprintf("%s,", svc.Name))
	}
	return strings.TrimSuffix(b.String(), ",")
}

// GetRunsAsUidGid returns the uid/gid that the tool should
// continue to run as based on the configured setup. For example,
// if all services have been configured to have the same uid/gid
// for keys and certs, then the tool can drop its access from root
// to the specified user. If they're multiple users defined then
// the return values would be -1/-1
func GetRunsAsUidGid(opts *Options) (int, int) {
	// first we want to check if the caller has specifically indicated
	// that they want to keep the privileges and not drop to another user
	if !opts.DropPrivileges {
		log.Println("Configured to keep run as privileges")
		return -1, -1
	}
	// if the os does not support uid/gid values, or the unix domain
	// socket path is configured then we're not going to make any
	// changes
	if syscall.Getuid() == -1 || syscall.Getgid() == -1 || opts.SDSUdsPath != "" {
		log.Println("OS does not support setuid/setgid or UDS path is configured - keeping run as privileges")
		return -1, -1
	}
	uid := -1
	gid := -1
	for i, svc := range opts.Services {
		if i == 0 {
			uid = svc.Uid
			gid = svc.Gid
		} else {
			// if we have a mismatch with our current
			// set then we cannot change our run-as user
			if svc.Uid != uid || svc.Gid != gid {
				return -1, -1
			}
		}
	}
	// if we have a mismatch with any of our roles then
	// we cannot change our run-as user either
	for _, role := range opts.Roles {
		if role.Uid != uid || role.Gid != gid {
			return -1, -1
		}
	}
	// if our uid is equivalent to our running process uid
	// there is no need to change it
	if uid == syscall.Getuid() {
		uid = -1
	}
	// if our gid is equivalent to our running process gid
	// there is no need to change it
	if gid == syscall.Getgid() {
		gid = -1
	}
	log.Printf("RunAs configuration - uid: %d, gid: %d\n", uid, gid)
	return uid, gid
}

func NewOptions(config *Config, configAccount *ConfigAccount, profileConfig *AccessProfileConfig, siaDir, siaVersion string, useRegionalSTS bool, region string) (*Options, error) {

	opts, err := setOptions(config, configAccount, profileConfig, siaDir, siaVersion)
	if err != nil {
		log.Printf("Unable to formulate options, error: %v\n", err)
		return nil, err
	}

	opts.Region = region
	if useRegionalSTS {
		opts.UseRegionalSTS = true
	}
	return opts, nil
}

func nonZeroValue(t, base float64) float64 {
	if t != 0 {
		return t
	}
	return base
}

func LegacyOptions(opts *Options) *legacy.Options {
	lopts := &legacy.Options{
		Provider:           opts.Provider,
		Name:               opts.Name,
		User:               opts.User,
		Group:              opts.Group,
		Domain:             opts.Domain,
		Account:            opts.Account,
		Service:            opts.Service,
		Zts:                opts.Zts,
		InstanceId:         opts.InstanceId,
		Region:             opts.Region,
		SanDnsWildcard:     opts.SanDnsWildcard,
		SanDnsHostname:     opts.SanDnsHostname,
		Version:            opts.Version,
		ZTSDomains:         opts.ZTSDomains,
		Ssh:                opts.Ssh,
		UseRegionalSTS:     opts.UseRegionalSTS,
		KeyDir:             opts.KeyDir,
		CertDir:            opts.CertDir,
		AthenzCACertFile:   opts.AthenzCACertFile,
		ZTSCACertFile:      opts.ZTSCACertFile,
		ZTSServerName:      opts.ZTSServerName,
		ZTSAWSDomains:      opts.ZTSAWSDomains,
		GenerateRoleKey:    opts.GenerateRoleKey,
		RotateKey:          opts.RotateKey,
		BackupDir:          opts.BackupDir,
		CertCountryName:    opts.CertCountryName,
		CertOrgName:        opts.CertOrgName,
		SshPubKeyFile:      opts.SshPubKeyFile,
		SshCertFile:        opts.SshCertFile,
		SshConfigFile:      opts.SshConfigFile,
		PrivateIp:          opts.PrivateIp,
		EC2Document:        opts.EC2Document,
		EC2Signature:       opts.EC2Signature,
		EC2StartTime:       opts.EC2StartTime,
		InstanceIdSanDNS:   opts.InstanceIdSanDNS,
		RolePrincipalEmail: opts.RolePrincipalEmail,
		SDSUdsPath:         opts.SDSUdsPath,
		SDSUdsUid:          opts.SDSUdsUid,
		RefreshInterval:    opts.RefreshInterval,
		ZTSRegion:          opts.ZTSRegion,
		DropPrivileges:     opts.DropPrivileges,
		TokenDir:           opts.TokenDir,
		AccessTokens:       opts.AccessTokens,
		Profile:            opts.Profile,
		ProfileRestrictTo:  opts.ProfileRestrictTo,
		Threshold:          opts.Threshold,
		SshThreshold:       opts.SshThreshold,
		FileDirectUpdate:   opts.FileDirectUpdate,
		HostnameSuffix:     opts.HostnameSuffix,
	}

	for _, s := range opts.Services {
		svc := legacy.Service{
			Name:           s.Name,
			KeyFilename:    s.KeyFilename,
			CertFilename:   s.CertFilename,
			User:           s.User,
			Group:          s.Group,
			Uid:            s.Uid,
			Gid:            s.Gid,
			FileMode:       s.FileMode,
			ExpiryTime:     s.ExpiryTime,
			SDSUdsUid:      s.SDSUdsUid,
			SDSNodeId:      s.SDSNodeId,
			SDSNodeCluster: s.SDSNodeCluster,
			Threshold:      s.Threshold,
		}
		lopts.Services = append(lopts.Services, svc)
	}

	for _, r := range opts.Roles {
		role := legacy.Role{
			Name:             r.Name,
			Service:          r.Service,
			RoleKeyFilename:  r.RoleKeyFilename,
			RoleCertFilename: r.RoleCertFilename,
			SvcKeyFilename:   r.SvcKeyFilename,
			SvcCertFilename:  r.SvcCertFilename,
			ExpiryTime:       r.ExpiryTime,
			User:             r.User,
			Uid:              r.Uid,
			Gid:              r.Gid,
			FileMode:         r.FileMode,
			Threshold:        r.Threshold,
		}
		lopts.Roles = append(lopts.Roles, role)
	}

	return lopts
}

func isAWSEnvironment(provider provider.Provider) bool {
	return strings.Contains(provider.GetName(), "aws")
}

func isGCPEnvironment(provider provider.Provider) bool {
	return strings.Contains(provider.GetName(), "gcp")
}
