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

package sia

import (
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"io/ioutil"
	"strings"

	"github.com/AthenZ/athenz/libs/go/sia/aws/attestation"
	"github.com/AthenZ/athenz/libs/go/sia/aws/doc"
	"github.com/AthenZ/athenz/libs/go/sia/aws/logutil"
	"github.com/AthenZ/athenz/libs/go/sia/aws/meta"
	"github.com/AthenZ/athenz/libs/go/sia/aws/stssession"
	"github.com/AthenZ/athenz/provider/aws/sia-ec2/options"
	"github.com/AthenZ/athenz/provider/aws/sia-ec2/util"

	"github.com/AthenZ/athenz/clients/go/zts"
	"github.com/aws/aws-sdk-go/service/sts"
)

var (
	ECSMetaEndPoint = "http://169.254.170.2"
)

func GetECSFargateData(metaEndPoint string) (string, string, string, error) {
	// now we're going to check if we're running within
	// ECS Fargate and retrieve our account number and
	// task id from our data
	document, err := meta.GetData(metaEndPoint, "/task")
	if err != nil {
		return "", "", "", err
	}
	taskArn, err := doc.GetDocumentEntry(document, "TaskARN")
	if err != nil {
		return "", "", "", err
	}
	// fargate task arn has the following format (old and new):
	// arn:aws:ecs:us-west-2:012345678910:task/9781c248-0edd-4cdb-9a93-f63cb662a5d3
	// arn:aws:ecs:us-west-2:012345678910:task/cluster-name/9781c248-0edd-4cdb-9a93-f63cb662a5d3
	if !strings.HasPrefix(taskArn, "arn:aws:ecs:") {
		return "", "", "", fmt.Errorf("unable to parse task arn (ecs prefix error): %s", taskArn)
	}
	arn := strings.Split(taskArn, ":")
	if len(arn) < 6 {
		return "", "", "", fmt.Errorf("unable to parse task arn (number of components): %s", taskArn)
	}
	region := arn[3]
	account := arn[4]
	taskComps := strings.Split(arn[5], "/")
	if taskComps[0] != "task" {
		return "", "", "", fmt.Errorf("unable to parse task arn (task prefix): %s", taskArn)
	}
	var taskId string
	lenComps := len(taskComps)
	if lenComps == 2 || lenComps == 3 {
		taskId = taskComps[lenComps-1]
	} else {
		return "", "", "", fmt.Errorf("unable to parse task arn (task prefix): %s", taskArn)
	}
	return account, taskId, region, nil
}

// New creates a new AttestationData with values fed to it and from the result of STS Assume Role

func GetAttestationData(domain, service, account, region, taskId string, useRegionalSTS bool, sysLogger io.Writer) (*attestation.AttestationData, error) {

	role := fmt.Sprintf("%s.%s", domain, service)

	// Attempt STS AssumeRole
	stsSession, err := stssession.New(useRegionalSTS, region, sysLogger)
	if err != nil {
		logutil.LogInfo(sysLogger, "unable to create new session: %v\n", err)
		return nil, err
	}
	stsService := sts.New(stsSession)
	roleArn := fmt.Sprintf("arn:aws:iam::%s:role/%s", account, role)
	logutil.LogInfo(sysLogger, "trying to assume role: %v\n", roleArn)
	tok, err := stsService.AssumeRole(&sts.AssumeRoleInput{
		RoleArn:         &roleArn,
		RoleSessionName: &role,
	})
	if err != nil {
		return nil, err
	}

	return &attestation.AttestationData{
		Role:   role,
		Access: *tok.Credentials.AccessKeyId,
		Secret: *tok.Credentials.SecretAccessKey,
		Token:  *tok.Credentials.SessionToken,
		TaskId: taskId,
	}, nil
}

func extractProviderFromCert(certFile string) string {
	data, err := ioutil.ReadFile(certFile)
	if err != nil {
		return ""
	}
	var block *pem.Block
	block, _ = pem.Decode(data)
	if block == nil {
		return ""
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return ""
	}
	if len(cert.Subject.OrganizationalUnit) > 0 {
		return cert.Subject.OrganizationalUnit[0]
	}
	return ""
}

func GetRoleCertificate(ztsUrl, svcKeyFile, svcCertFile string, opts *options.Options, sysLogger io.Writer) bool {
	client, err := util.ZtsClient(ztsUrl, opts.ZTSServerName, svcKeyFile, svcCertFile, opts.ZTSCACertFile, sysLogger)
	if err != nil {
		logutil.LogInfo(sysLogger, "unable to initialize ZTS Client for %s, err: %v\n", ztsUrl, err)
		return false
	}
	client.AddCredentials("User-Agent", opts.Version)

	//extract the provider from the certificate file
	provider := extractProviderFromCert(svcCertFile)
	key, err := util.PrivateKeyFromFile(svcKeyFile)
	if err != nil {
		logutil.LogInfo(sysLogger, "unable to read private key from %s, err: %v\n", svcKeyFile, err)
		return false
	}

	//initialize our return state to success
	failures := 0

	var roleRequest = new(zts.RoleCertificateRequest)
	for roleName, role := range opts.Roles {
		domainNameRequest, roleNameRequest, err := util.SplitRoleName(roleName)
		if err != nil {
			logutil.LogInfo(sysLogger, "invalid role name: %s, err: %v\n", roleName, err)
			failures += 1
			continue
		}
		certFilePem := util.GetRoleCertFileName(opts.CertDir, role.Filename, roleName)
		spiffe := fmt.Sprintf("spiffe://%s/ra/%s", domainNameRequest, roleNameRequest)
		csr, err := util.GenerateCSR(key, opts.Domain, opts.Services[0].Name, roleName, "", provider, spiffe, opts.ZTSAWSDomain, true)
		if err != nil {
			logutil.LogInfo(sysLogger, "unable to generate CSR for %s, err: %v\n", roleName, err)
			failures += 1
			continue
		}
		roleRequest.Csr = csr
		//"rolename": "athenz.fp:role.readers"
		//from the rolename, domain is athenz.fp
		//role is readers
		roleToken, err := client.PostRoleCertificateRequest(zts.DomainName(domainNameRequest), zts.EntityName(roleNameRequest), roleRequest)
		if err != nil {
			logutil.LogInfo(sysLogger, "PostRoleCertificateRequest failed for %s, err: %v\n", roleName, err)
			failures += 1
			continue
		}

		// get the Uid and Gid
		uid, gid := util.UidGidForUserGroup(opts.User, opts.Group, sysLogger)
		//we have the roletoken
		//write the cert to pem file using Role.Filename
		err = util.UpdateFile(certFilePem, roleToken.Token, uid, gid, 0444, sysLogger)
		if err != nil {
			failures += 1
			continue
		}
	}
	logutil.LogInfo(sysLogger, "SIA processed %d (failures %d) role certificate requests\n", len(opts.Roles), failures)
	return failures == 0
}

func RegisterInstance(data []*attestation.AttestationData, ztsUrl string, opts *options.Options, region string, sysLogger io.Writer) error {
	for i, svc := range opts.Services {
		err := registerSvc(svc, data[i], ztsUrl, opts, region, sysLogger)
		if err != nil {
			return fmt.Errorf("unable to register identity for svc: %q, error: %v", svc.Name, err)
		}
	}
	return nil
}

func RefreshInstance(data []*attestation.AttestationData, ztsUrl string, opts *options.Options, region string, sysLogger io.Writer) error {
	for i, svc := range opts.Services {
		err := refreshSvc(svc, data[i], ztsUrl, opts, region, sysLogger)
		if err != nil {
			return fmt.Errorf("unable to refresh identity for svc: %q, error: %v", svc.Name, err)
		}
	}
	return nil
}

func getProviderName(providerPrefix, region string) string {
	if providerPrefix != "" {
		return providerPrefix + "." + region
	} else {
		return "athenz.aws." + region
	}
}

func getCertFileName(file, domain, service, certDir string) string {
	switch {
	case file == "":
		return fmt.Sprintf("%s/%s.%s.cert.pem", certDir, domain, service)
	case file[0] == '/':
		return file
	default:
		return fmt.Sprintf("%s/%s", certDir, file)
	}
}

func registerSvc(svc options.Service, data *attestation.AttestationData, ztsUrl string, opts *options.Options, region string, sysLogger io.Writer) error {

	instanceId := data.TaskId

	key, err := util.GenerateKeyPair(2048)
	if err != nil {
		return err
	}

	provider := getProviderName(opts.Provider, region)
	spiffe := fmt.Sprintf("spiffe://%s/sa/%s", opts.Domain, svc.Name)
	csr, err := util.GenerateCSR(key, opts.Domain, svc.Name, data.Role, instanceId, provider, spiffe, opts.ZTSAWSDomain, false)
	if err != nil {
		return err
	}

	var info zts.InstanceRegisterInformation
	info.Provider = zts.ServiceName(provider)
	info.Domain = zts.DomainName(opts.Domain)
	info.Service = zts.SimpleName(svc.Name)
	info.Csr = csr
	attestData, err := json.Marshal(data)
	if err != nil {
		return err
	}
	info.AttestationData = string(attestData)

	client, err := util.ZtsClient(ztsUrl, opts.ZTSServerName, "", "", opts.ZTSCACertFile, sysLogger)
	if err != nil {
		return err
	}
	client.AddCredentials("User-Agent", opts.Version)

	instIdent, _, err := client.PostInstanceRegisterInformation(&info)
	if err != nil {
		logutil.LogInfo(sysLogger, "Unable to do PostInstanceRegisterInformation, err: %v\n", err)
		return err
	}
	svcKeyFile := fmt.Sprintf("%s/%s.%s.key.pem", opts.KeyDir, opts.Domain, svc.Name)
	err = util.UpdateFile(svcKeyFile, util.PrivatePem(key), svc.Uid, svc.Gid, 0440, sysLogger)
	if err != nil {
		return err
	}
	certFile := getCertFileName(svc.Filename, opts.Domain, svc.Name, opts.CertDir)
	err = util.UpdateFile(certFile, instIdent.X509Certificate, svc.Uid, svc.Gid, 0444, sysLogger)
	if err != nil {
		return err
	}

	if opts.Services[0].Name == svc.Name {
		err = util.UpdateFile(opts.AthenzCACertFile, instIdent.X509CertificateSigner, svc.Uid, svc.Gid, 0444, sysLogger)
		if err != nil {
			return err
		}
	}
	return nil
}

func refreshSvc(svc options.Service, data *attestation.AttestationData, ztsUrl string, opts *options.Options, region string, sysLogger io.Writer) error {
	keyFile := fmt.Sprintf("%s/%s.%s.key.pem", opts.KeyDir, opts.Domain, svc.Name)
	key, err := util.PrivateKeyFromFile(keyFile)
	if err != nil {
		logutil.LogInfo(sysLogger, "Unable to read private key from %s, err: %v\n", keyFile, err)
		return err
	}

	certFile := fmt.Sprintf("%s/%s.%s.cert.pem", opts.CertDir, opts.Domain, svc.Name)

	client, err := util.ZtsClient(ztsUrl, opts.ZTSServerName, keyFile, certFile, opts.ZTSCACertFile, sysLogger)
	if err != nil {
		logutil.LogInfo(sysLogger, "Unable to get ZTS Client for %s, err: %v\n", ztsUrl, err)
		return err
	}
	client.AddCredentials("User-Agent", opts.Version)

	instanceId := data.TaskId

	attestData, err := json.Marshal(data)
	if err != nil {
		return err
	}
	provider := getProviderName(opts.Provider, region)
	spiffe := fmt.Sprintf("spiffe://%s/sa/%s", opts.Domain, svc.Name)
	csr, err := util.GenerateCSR(key, opts.Domain, svc.Name, data.Role, instanceId, provider, spiffe, opts.ZTSAWSDomain, false)
	if err != nil {
		logutil.LogInfo(sysLogger, "Unable to generate CSR for %s, err: %v\n", opts.Name, err)
		return err
	}
	info := &zts.InstanceRefreshInformation{AttestationData: string(attestData), Csr: csr}
	ident, err := client.PostInstanceRefreshInformation(zts.ServiceName(provider), zts.DomainName(opts.Domain), zts.SimpleName(svc.Name), zts.PathElement(instanceId), info)
	if err != nil {
		logutil.LogInfo(sysLogger, "Unable to refresh instance service certificate for %s, err: %v\n", opts.Name, err)
		return err
	}

	err = util.UpdateFile(certFile, ident.X509Certificate, svc.Uid, svc.Gid, 0444, sysLogger)
	if err != nil {
		return err
	}

	if opts.Services[0].Name == svc.Name {
		err = util.UpdateFile(opts.AthenzCACertFile, ident.X509CertificateSigner, svc.Uid, svc.Gid, 0444, sysLogger)
		if err != nil {
			return err
		}
	}
	return nil
}
