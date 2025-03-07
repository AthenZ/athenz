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

import (
	"time"

	ac "github.com/AthenZ/athenz/libs/go/sia/access/config"
	"github.com/AthenZ/athenz/libs/go/sia/host/provider"
	"github.com/AthenZ/athenz/libs/go/sia/ssh/hostkey"
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
	RunAfterCerts     string                   `json:"run_after,omitempty"`                  //execute the command mentioned after certs are created
	RunAfterCertsErr  string                   `json:"run_after_certs_err,omitempty"`        //execute the command mentioned after role certs fail to refresh
	RunAfterTokens    string                   `json:"run_after_tokens,omitempty"`           //execute the command mentioned after tokens are created
	RunAfterTokensErr string                   `json:"run_after_tokens_err,omitempty"`       //execute the command mentioned after tokens fail to refresh
	SpiffeTrustDomain string                   `json:"spiffe_trust_domain,omitempty"`        //spiffe trust domain - if configured generate full spiffe uri with namespace
	StoreTokenOption  *int                     `json:"store_token_option,omitempty"`         //store access token option
	RunAfterFailExit  bool                     `json:"run_after_fail_exit,omitempty"`        //exit process if run_after script fails
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
	Provider               provider.Provider //provider instance
	MetaEndPoint           string            //meta data service endpoint
	Name                   string            //name of the service identity
	User                   string            //the username to chown the cert/key dirs to. If absent, then root
	Group                  string            //the group name to chown the cert/key dirs to. If absent, then athenz
	Domain                 string            //name of the domain for the identity
	Account                string            //name of the account
	Service                string            //name of the service for the identity
	Zts                    string            //the ZTS to contact
	InstanceId             string            //instance id if ec2/vm, task id if running within eks/ecs/gke
	InstanceName           string            //instance name if ec2/vm
	Roles                  []Role            //map of roles to retrieve certificates for
	Region                 string            //region name
	SanDnsWildcard         bool              //san dns wildcard support
	SanDnsHostname         bool              //san dns hostname support
	Version                string            //sia version number
	ZTSDomains             []string          //zts domain prefixes
	Services               []Service         //array of configured services
	Ssh                    bool              //ssh certificate support
	UseRegionalSTS         bool              //use regional sts endpoint
	KeyDir                 string            //private key directory path
	CertDir                string            //x.509 certificate directory path
	AthenzCACertFile       string            //filename to store Athenz CA certs
	ZTSCACertFile          string            //filename for CA certs when communicating with ZTS
	ZTSServerName          string            //ZTS server name, if necessary for tls
	GenerateRoleKey        bool              //option to generate a separate key for role certificates
	RotateKey              bool              //rotate the private key when refreshing certificates
	BackupDir              string            //backup directory for key/cert rotation
	CertCountryName        string            //generated x.509 certificate country name
	CertOrgName            string            //generated x.509 certificate organization name
	SshPubKeyFile          string            //ssh host public key file path
	SshCertFile            string            //ssh host certificate file path
	SshConfigFile          string            //sshd config file path
	SshHostKeyType         hostkey.KeyType   //ssh host key type - rsa or ecdsa
	PrivateIp              string            //instance private ip
	EC2Document            string            //EC2 instance identity document
	EC2Signature           string            //EC2 instance identity document pkcs7 signature
	EC2StartTime           *time.Time        //EC2 instance start time
	InstanceIdSanDNS       bool              //include instance id in a san dns entry (backward compatible option)
	RolePrincipalEmail     bool              //include role principal in a san email field (backward compatible option)
	SDSUdsPath             string            //UDS path if the agent should support uds connections
	SDSUdsUid              int               //UDS connections must be from the given user uid
	RefreshInterval        int               //refresh interval for certificates - default 24 hours
	ZTSRegion              string            //ZTS region in case the client needs this information
	DropPrivileges         bool              //Drop privileges to configured user instead of running as root
	TokenDir               string            //Access tokens directory
	AccessTokens           []ac.AccessToken  //Access tokens object
	Profile                string            //Access profile name
	ProfileRestrictTo      string            //Tag associated with access profile roles
	Threshold              float64           //threshold in number of days for cert expiry checks
	SshThreshold           float64           //threshold in number of days for ssh cert expiry checks
	FileDirectUpdate       bool              //update key/cert files directly instead of using rename
	HostnameSuffix         string            //hostname suffix in case we need to auto-generate hostname
	SshPrincipals          string            //ssh additional principals
	AccessManagement       bool              //access management support
	ZTSCloudDomains        []string          //list of domain prefixes for sanDNS entries
	AddlSanDNSEntries      []string          //additional san dns entries to be added to the CSR
	FailCountForExit       int               //number of failed counts before exiting program
	RunAfterCertsOkParts   []string          //run after certificate parsed parts for success
	RunAfterCertsErrParts  []string          //run after certificate parsed parts for errors
	RunAfterTokensOkParts  []string          //run after token parsed parts for success
	RunAfterTokensErrParts []string          //run after token parsed parts for errors
	SpiffeTrustDomain      string            //spiffe uri trust domain
	SpiffeNamespace        string            //spiffe uri namespace
	OmitDomain             bool              //attestation role only includes service name
	StoreTokenOption       *int              //store access token option
	RunAfterFailExit       bool              //exit process if run_after script fails
}

const (
	DefaultTokenExpiry = 28800       // 8 hrs
	DefaultThreshold   = float64(15) // 15 days
)
