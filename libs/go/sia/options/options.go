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
	"log"
	"os"
	"strconv"
	"strings"
	"syscall"

	ac "github.com/AthenZ/athenz/libs/go/sia/access/config"
	"github.com/AthenZ/athenz/libs/go/sia/aws/doc"
	"github.com/AthenZ/athenz/libs/go/sia/aws/meta"
	"github.com/AthenZ/athenz/libs/go/sia/aws/stssession"
	sc "github.com/AthenZ/athenz/libs/go/sia/config"
	"github.com/AthenZ/athenz/libs/go/sia/host/provider"
	"github.com/AthenZ/athenz/libs/go/sia/ssh/hostkey"
	"github.com/AthenZ/athenz/libs/go/sia/util"
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

func InitCredsConfig(roleSuffix, accessProfileSeparator string, useRegionalSTS bool, region string) (*sc.ConfigAccount, *sc.AccessProfileConfig, error) {
	account, domain, service, profile, err := stssession.GetMetaDetailsFromCreds(roleSuffix, accessProfileSeparator, useRegionalSTS, region)
	if err != nil {
		return nil, nil, fmt.Errorf("unable to parse role arn: %v", err)
	}
	return &sc.ConfigAccount{
			Domain:       domain,
			Service:      service,
			Account:      account,
			Name:         fmt.Sprintf("%s.%s", domain, service),
			Threshold:    sc.DefaultThreshold,
			SshThreshold: sc.DefaultThreshold,
		}, &sc.AccessProfileConfig{
			Profile:           profile,
			ProfileRestrictTo: "",
		}, nil
}

func InitProfileConfig(metaEndPoint, roleSuffix, accessProfileSeparator string) (*sc.ConfigAccount, *sc.AccessProfileConfig, error) {

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
	return &sc.ConfigAccount{
			Domain:       domain,
			Service:      service,
			Account:      account,
			Name:         fmt.Sprintf("%s.%s", domain, service),
			Threshold:    sc.DefaultThreshold,
			SshThreshold: sc.DefaultThreshold,
			OmitDomain:   omitDomain,
		}, &sc.AccessProfileConfig{
			Profile:           profile,
			ProfileRestrictTo: "",
		}, nil
}

func InitGenericProfileConfig(metaEndPoint, roleSuffix, accessProfileSeparator string, provider provider.Provider) (*sc.Config, *sc.AccessProfileConfig, error) {

	account, domain, service, err := provider.GetAccountDomainServiceFromMeta(metaEndPoint)
	if err != nil {
		return nil, nil, err
	}
	profile, err := provider.GetAccessManagementProfileFromMeta(metaEndPoint)
	if err != nil {
		// access profile error can be ignored for now.
		return &sc.Config{
			Account: account,
			Domain:  domain,
			Service: service,
		}, nil, nil
	}
	return &sc.Config{
			Account: account,
			Domain:  domain,
			Service: service,
		}, &sc.AccessProfileConfig{
			Profile:           profile,
			ProfileRestrictTo: "",
		}, nil
}

func InitFileConfig(fileName, metaEndPoint string, useRegionalSTS bool, region, account string, provider provider.Provider) (*sc.Config, *sc.ConfigAccount, error) {
	confBytes, err := os.ReadFile(fileName)
	if err != nil {
		return nil, nil, err
	}
	if len(confBytes) == 0 {
		return nil, nil, errors.New("empty config bytes")
	}
	var config sc.Config
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
				configAccount.Threshold = nonZeroValue(configAccount.Threshold, sc.DefaultThreshold)
				configAccount.SshThreshold = nonZeroValue(configAccount.SshThreshold, sc.DefaultThreshold)
				return &config, &configAccount, nil
			}
		}
		return nil, nil, fmt.Errorf("missing account %s details from config file", account)
	}

	config.Threshold = nonZeroValue(config.Threshold, sc.DefaultThreshold)
	config.SshThreshold = nonZeroValue(config.SshThreshold, sc.DefaultThreshold)

	return &config, nil, nil
}

func InitAccessProfileFileConfig(fileName string) (*sc.AccessProfileConfig, error) {
	confBytes, err := os.ReadFile(fileName)
	if err != nil {
		return nil, err
	}
	if len(confBytes) == 0 {
		return nil, errors.New("empty config bytes")
	}
	var config sc.AccessProfileConfig
	err = json.Unmarshal(confBytes, &config)
	if err != nil {
		return nil, err
	}
	if config.Profile == "" {
		return nil, fmt.Errorf("missing required Profile field from the config file")
	}

	return &sc.AccessProfileConfig{
		Profile:           config.Profile,
		ProfileRestrictTo: config.ProfileRestrictTo,
	}, nil
}

func InitEnvConfig(config *sc.Config, provider provider.Provider) (*sc.Config, *sc.ConfigAccount, error) {
	// it is possible that the config object was already created the
	// config file in which case we're not going to override any
	// of the settings.
	if config == nil {
		config = &sc.Config{}
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
	if config.RunAfterCerts == "" {
		config.RunAfterCerts = os.Getenv("ATHENZ_SIA_RUN_AFTER")
	}
	if config.RunAfterTokens == "" {
		config.RunAfterTokens = os.Getenv("ATHENZ_SIA_RUN_AFTER_TOKENS")
	}
	if config.RunAfterCertsErr == "" {
		config.RunAfterCertsErr = os.Getenv("ATHENZ_SIA_RUN_AFTER_CERTS_ERROR")
	}
	if config.RunAfterTokensErr == "" {
		config.RunAfterTokensErr = os.Getenv("ATHENZ_SIA_RUN_AFTER_TOKENS_ERROR")
	}
	if config.SpiffeTrustDomain == "" {
		config.SpiffeTrustDomain = os.Getenv("ATHENZ_SIA_SPIFFE_TRUST_DOMAIN")
	}
	if !config.AccessManagement {
		config.AccessManagement = util.ParseEnvBooleanFlag("ATHENZ_SIA_ACCESS_MANAGEMENT")
	}
	if !config.RunAfterFailExit {
		config.RunAfterFailExit = util.ParseEnvBooleanFlag("ATHENZ_SIA_RUN_AFTER_FAIL_EXIT")
	}

	config.Threshold = util.ParseEnvFloatFlag("ATHENZ_SIA_ACCOUNT_THRESHOLD", sc.DefaultThreshold)
	config.SshThreshold = util.ParseEnvFloatFlag("ATHENZ_SIA_ACCOUNT_SSH_THRESHOLD", sc.DefaultThreshold)
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

	var configRoles map[string]sc.ConfigRole
	rolesEnv := os.Getenv("ATHENZ_SIA_ACCOUNT_ROLES")
	if rolesEnv != "" {
		err := json.Unmarshal([]byte(rolesEnv), &configRoles)
		if err != nil {
			return config, nil, fmt.Errorf("unable to parse athenz account roles '%s': %v", rolesEnv, err)
		}
	}
	config.Roles = configRoles

	var configAccount *sc.ConfigAccount
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
		if config.Account == "" {
			config.Account = account
		}
		if config.Domain == "" {
			config.Domain = domain
		}
		if config.Service == "" {
			config.Service = service
		}

		configAccount = &sc.ConfigAccount{
			Account:      account,
			Domain:       domain,
			Service:      service,
			Roles:        configRoles,
			Name:         fmt.Sprintf("%s.%s", domain, service),
			Threshold:    config.Threshold,
			SshThreshold: config.SshThreshold,
			OmitDomain:   omitDomain,
		}

	} else if isGCPEnvironment(provider) {

		if config.Domain == "" {
			config.Domain = os.Getenv("ATHENZ_SIA_DOMAIN_NAME")
		}
		if config.Service == "" {
			config.Service = os.Getenv("ATHENZ_SIA_SERVICE_NAME")
		}
		if config.Domain == "" || config.Service == "" {
			return config, nil, fmt.Errorf("one or more required settings can not be retrieved from env variables")
		}
	}

	if config.OTel.CollectorEndpoint == "" {
		config.OTel.CollectorEndpoint = os.Getenv("OTEL_COLLECTOR_ENDPOINT")
	}
	if !config.OTel.MTLS {
		config.OTel.MTLS, _ = strconv.ParseBool(os.Getenv("OTEL_MTLS"))
	}
	if config.OTel.ClientKeyPath == "" {
		config.OTel.ClientKeyPath = os.Getenv("OTEL_CLIENT_KEY_PATH")
	}
	if config.OTel.ClientCertPath == "" {
		config.OTel.ClientCertPath = os.Getenv("OTEL_CLIENT_CERT_PATH")
	}
	if config.OTel.CACertPath == "" {
		config.OTel.CACertPath = os.Getenv("OTEL_CA_CERT_PATH")
	}
	if config.OTel.ServiceInstanceID == "" {
		config.OTel.ServiceInstanceID = os.Getenv("OTEL_SERVICE_INSTANCE_ID")
	}
	if config.HttpPort == 0 {
		config.HttpPort = util.ParseEnvIntFlag("ATHENZ_SIA_HTTP_PORT", 0)
	}

	return config, configAccount, nil
}

func InitAccessProfileEnvConfig() (*sc.AccessProfileConfig, error) {

	accessProfile := os.Getenv("ATHENZ_SIA_ACCESS_PROFILE")
	if accessProfile == "" {
		return nil, fmt.Errorf("athenz accessProfile variable not configured")
	}

	return &sc.AccessProfileConfig{
		Profile:           accessProfile,
		ProfileRestrictTo: "",
	}, nil
}

// setOptions takes in sia_config objects and returns a pointer to Options after parsing and initializing the defaults
// It uses profile arn for defaults when sia_config is empty or non-parsable. It populates "services" array
func setOptions(config *sc.Config, account *sc.ConfigAccount, profileConfig *sc.AccessProfileConfig, siaDir, version string) (*sc.Options, error) {

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
	runAfterCerts := ""
	runAfterCertsErr := ""
	runAfterTokens := ""
	runAfterTokensErr := ""
	spiffeTrustDomain := ""
	addlSanDNSEntries := make([]string, 0)
	runAfterFailExit := false
	roleCertsRequired := false
	httpPort := 0

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
		runAfterFailExit = config.RunAfterFailExit
		roleCertsRequired = config.RoleCertsRequired
		httpPort = config.HttpPort

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
		if config.RunAfterCerts != "" {
			runAfterCerts = config.RunAfterCerts
		}
		if config.RunAfterTokens != "" {
			runAfterTokens = config.RunAfterTokens
		}
		if config.RunAfterCertsErr != "" {
			runAfterCertsErr = config.RunAfterCertsErr
		}
		if config.RunAfterTokensErr != "" {
			runAfterTokensErr = config.RunAfterTokensErr
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

	var services []sc.Service
	if config == nil || len(config.Services) == 0 {
		//There is no sia_config, or multiple services are not configured.
		//Populate services with the account information we gathered
		s := sc.Service{
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
		first := sc.Service{
			Name: config.Service,
		}

		// Populate the remaining into tail
		var tail []sc.Service
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
				ts := sc.Service{
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

	var roles []sc.Role
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
			role := sc.Role{
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

	// Process oTel options
	var oTelCfg sc.OTel
	if config != nil {
		oTelCfg = config.OTel
	}
	if oTelCfg.MTLS && oTelCfg.ClientKeyPath == "" {
		if len(services) < 1 {
			return nil, fmt.Errorf("no service identiy defined in options for OTel TLS config")
		}
		// Use the first service identity to authenticate the OTel client.
		oTelCfg.ClientKeyPath = util.GetSvcKeyFileName(keyDir, services[0].KeyFilename, account.Domain, services[0].Name)
	}
	if oTelCfg.MTLS && oTelCfg.ClientCertPath == "" {
		if len(services) < 1 {
			return nil, fmt.Errorf("no service identiy defined in options for OTel TLS config")
		}
		// Use the first service identity to authenticate the OTel client.
		oTelCfg.ClientCertPath = util.GetSvcCertFileName(certDir, services[0].CertFilename, account.Domain, services[0].Name)
	}

	if oTelCfg.CACertPath == "" {
		oTelCfg.CACertPath = fmt.Sprintf("%s/ca.cert.pem", certDir)
	}

	return &sc.Options{
		Name:                   account.Name,
		User:                   account.User,
		Group:                  account.Group,
		Domain:                 account.Domain,
		Account:                account.Account,
		Zts:                    account.Zts,
		Version:                fmt.Sprintf("SIA %s", version),
		UseRegionalSTS:         useRegionalSTS,
		SanDnsWildcard:         sanDnsWildcard,
		SanDnsHostname:         sanDnsHostname,
		HostnameSuffix:         hostnameSuffix,
		Services:               services,
		Roles:                  roles,
		TokenDir:               tokenDir,
		CertDir:                certDir,
		KeyDir:                 keyDir,
		AthenzCACertFile:       fmt.Sprintf("%s/ca.cert.pem", certDir),
		GenerateRoleKey:        generateRoleKey,
		RotateKey:              rotateKey,
		BackupDir:              backupDir,
		SDSUdsPath:             sdsUdsPath,
		RefreshInterval:        refreshInterval,
		ZTSRegion:              ztsRegion,
		DropPrivileges:         dropPrivileges,
		AccessTokens:           accessTokens,
		Profile:                profile,
		ProfileRestrictTo:      profileRestrictTo,
		Threshold:              account.Threshold,
		SshThreshold:           account.SshThreshold,
		FileDirectUpdate:       fileDirectUpdate,
		SshHostKeyType:         sshHostKeyType,
		SshPrincipals:          sshPrincipals,
		AccessManagement:       accessManagement,
		FailCountForExit:       failCountForExit,
		RunAfterCertsOkParts:   util.ParseScriptArguments(runAfterCerts),
		RunAfterCertsErrParts:  util.ParseScriptArguments(runAfterCertsErr),
		RunAfterTokensOkParts:  util.ParseScriptArguments(runAfterTokens),
		RunAfterTokensErrParts: util.ParseScriptArguments(runAfterTokensErr),
		SpiffeTrustDomain:      spiffeTrustDomain,
		OmitDomain:             account.OmitDomain,
		StoreTokenOption:       storeTokenOption,
		AddlSanDNSEntries:      addlSanDNSEntries,
		RunAfterFailExit:       runAfterFailExit,
		RoleCertsRequired:      roleCertsRequired,
		OTel:                   oTelCfg,
		HttpPort:               httpPort,
	}, nil
}

func getRoleServiceOwner(serviceName string, services []sc.Service) sc.Service {
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

func processAccessTokens(config *sc.Config, processedSvcs []sc.Service) ([]ac.AccessToken, error) {
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
		expiry := sc.DefaultTokenExpiry
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

func getSvc(name string, services []sc.Service) (sc.Service, error) {
	for _, s := range services {
		if s.Name == name {
			return s, nil
		}
	}
	return sc.Service{}, fmt.Errorf("%q not found in processed services", name)
}

// GetSvcNames returns comma separated list of service names
func GetSvcNames(svcs []sc.Service) string {
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
func GetRunsAsUidGid(opts *sc.Options) (int, int) {
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

func NewOptions(config *sc.Config, configAccount *sc.ConfigAccount, profileConfig *sc.AccessProfileConfig, siaDir, siaVersion string, useRegionalSTS bool, region string) (*sc.Options, error) {

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

func isAWSEnvironment(provider provider.Provider) bool {
	return strings.Contains(provider.GetName(), "aws")
}

func isGCPEnvironment(provider provider.Provider) bool {
	return strings.Contains(provider.GetName(), "gcp")
}
