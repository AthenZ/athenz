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

package sia

import (
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"github.com/yahoo/athenz/clients/go/zts"
	"github.com/yahoo/athenz/provider/aws/sia-ec2/data/attestation"
	"github.com/yahoo/athenz/provider/aws/sia-ec2/logutil"
	"github.com/yahoo/athenz/provider/aws/sia-ec2/options"
	"github.com/yahoo/athenz/provider/aws/sia-ec2/util"
	"io"
	"io/ioutil"
	"log"
	"os/exec"
	"strings"
	"time"
)

const sshPubKeyFile = "/etc/ssh/ssh_host_rsa_key.pub"
const sshCertFile = "/etc/ssh/ssh_host_rsa_key-cert.pub"
const sshConfigFile = "/etc/ssh/sshd_config"

type Identity struct {
	Name       string
	InstanceId string
	Ip         string
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
		certFilePem := util.GetRoleCertFileName(mkDirPath(opts.CertDir), role.Filename, roleName)
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

		//we have the roletoken
		//write the cert to pem file using Role.Filename
		err = util.UpdateFile(certFilePem, roleToken.Token, 0, 0, 0444, sysLogger)
		if err != nil {
			failures += 1
			continue
		}
	}
	logutil.LogInfo(sysLogger, "SIA processed %d (failures %d) role certificate requests\n", len(opts.Roles), failures)
	return failures == 0
}

func getInstanceId(data *attestation.AttestationData, docMap map[string]interface{}) string {
	//if we're running within ecs we're going to use task id
	//otherwise we'll use our instance id for the csr
	if data.TaskId != "" {
		return data.TaskId
	}
	return docMap["instanceId"].(string)
}

func isDocumentExpired(docMap map[string]interface{}) bool {
	timeCheck, err := time.Parse(time.RFC3339, docMap["pendingTime"].(string))
	if err != nil {
		return false
	}
	duration := time.Since(timeCheck)
	//our server timeout is 30 mins = 1800 secs
	if duration.Seconds() > 1800 {
		return true
	}
	return false
}

func registerSvc(svc options.Service, data *attestation.AttestationData, ztsUrl string, document []byte, opts *options.Options, docExpiryCheck bool, sysLogger io.Writer) error {
	var docMap map[string]interface{}
	err := json.Unmarshal(document, &docMap)
	if err != nil {
		return err
	}
	ip := docMap["privateIp"].(string)
	region := docMap["region"].(string)
	instanceId := getInstanceId(data, docMap)

	key, err := util.GenerateKeyPair(2048)
	if err != nil {
		return err
	}

	//if we're running within ecs then we're not going
	//include a csr for the host ssh certificate
	var ssh string
	if data.TaskId == "" {
		ssh, err = generateSSHHostCSR(opts.Ssh, opts.Domain, svc.Name, ip, opts.ZTSAWSDomain, sysLogger)
		if err != nil {
			return err
		}
	}

	provider, ec2Provider := getProviderName(opts.Provider, region, data.TaskId)
	spiffe := fmt.Sprintf("spiffe://%s/sa/%s", opts.Domain, svc.Name)
	csr, err := util.GenerateCSR(key, opts.Domain, svc.Name, data.Role, instanceId, provider, spiffe, opts.ZTSAWSDomain, false)
	if err != nil {
		return err
	}

	//before we process our register event we need to check to
	//see if our timestamp in our document is less than 30 mins
	//ago otherwise ZTS server will reject the request and there
	//is no point of processing the request
	if docExpiryCheck && ec2Provider && isDocumentExpired(docMap) {
		return fmt.Errorf("identity document has expired (30 min timeout). ZTS will not register this instance. Please relaunch or restart your instance to refesh its identity document")
	}

	var info zts.InstanceRegisterInformation
	info.Provider = zts.ServiceName(provider)
	info.Domain = zts.DomainName(opts.Domain)
	info.Service = zts.SimpleName(svc.Name)
	info.Csr = csr
	info.Ssh = ssh
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
		//we're not going to count ssh updates as fatal since the primary
		//task for sia to get service identity certs but we'll log
		//the failure
		err = updateSSH(instIdent.SshCertificate, instIdent.SshCertificateSigner, opts.OsType, sysLogger)
		if err != nil {
			logutil.LogInfo(sysLogger, "Unable to update ssh certificate, err: %v\n", err)
		}
	}
	return nil
}

func RegisterInstance(data []*attestation.AttestationData, document []byte, ztsUrl string, opts *options.Options, docExpiryCheck bool, sysLogger io.Writer) error {
	for i, svc := range opts.Services {
		err := registerSvc(svc, data[i], ztsUrl, document, opts, docExpiryCheck, sysLogger)
		if err != nil {
			return fmt.Errorf("unable to register identity for svc: %q, error: %v", svc.Name, err)
		}
	}
	return nil
}

func RefreshInstance(data []*attestation.AttestationData, ztsUrl string, opts *options.Options, sysLogger io.Writer) error {
	for i, svc := range opts.Services {
		err := refreshSvc(svc, data[i], ztsUrl, opts, sysLogger)
		if err != nil {
			return fmt.Errorf("unable to refresh identity for svc: %q, error: %v", svc.Name, err)
		}
	}
	return nil
}

func refreshSvc(svc options.Service, data *attestation.AttestationData, ztsUrl string, opts *options.Options, sysLogger io.Writer) error {
	keyFile := fmt.Sprintf("%s/%s.%s.key.pem", opts.KeyDir, opts.Domain, svc.Name)
	key, err := util.PrivateKeyFromFile(keyFile)
	if err != nil {
		log.Printf("Unable to read private key from %s, err: %v\n", keyFile, err)
		return err
	}

	certFile := fmt.Sprintf("%s/%s.%s.cert.pem", opts.CertDir, opts.Domain, svc.Name)

	client, err := util.ZtsClient(ztsUrl, opts.ZTSServerName, keyFile, certFile, opts.ZTSCACertFile, sysLogger)
	if err != nil {
		logutil.LogInfo(sysLogger, "Unable to get ZTS Client for %s, err: %v\n", ztsUrl, err)
		return err
	}
	client.AddCredentials("User-Agent", opts.Version)

	var docMap map[string]interface{}
	err = json.Unmarshal([]byte(data.Document), &docMap)
	if err != nil {
		return err
	}
	ip := docMap["privateIp"].(string)
	region := docMap["region"].(string)
	instanceId := getInstanceId(data, docMap)
	//if we're running within ecs then we're not going
	//include a csr for the host ssh certificate
	var ssh string
	if data.TaskId == "" {
		ssh, err = generateSSHHostCSR(opts.Ssh, opts.Domain, svc.Name, ip, opts.ZTSAWSDomain, sysLogger)
		if err != nil {
			return err
		}
	}
	attestData, err := json.Marshal(data)
	if err != nil {
		return err
	}
	provider, _ := getProviderName(opts.Provider, region, data.TaskId)
	spiffe := fmt.Sprintf("spiffe://%s/sa/%s", opts.Domain, svc.Name)
	csr, err := util.GenerateCSR(key, opts.Domain, svc.Name, data.Role, instanceId, provider, spiffe, opts.ZTSAWSDomain, false)
	if err != nil {
		logutil.LogInfo(sysLogger, "Unable to generate CSR for %s, err: %v\n", opts.Name, err)
		return err
	}
	info := &zts.InstanceRefreshInformation{AttestationData: string(attestData), Csr: csr, Ssh: ssh}
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
		//we're not going to count ssh updates as fatal since the primary
		//task for sia to get service identity certs but we'll log
		//the failure
		err = updateSSH(ident.SshCertificate, ident.SshCertificateSigner, opts.OsType, sysLogger)
		if err != nil {
			logutil.LogInfo(sysLogger, "Unable to update ssh certificate, err: %v\n", err)
		}
	}
	return nil
}

func updateSSH(hostCert, hostSigner string, ostype int, sysLogger io.Writer) error {
	// if we have no hostCert and hostSigner then
	// we have nothing to update for ssh access

	if hostCert == "" && hostSigner == "" {
		logutil.LogInfo(sysLogger, "No host ssh certificate available to update")
		return nil
	}

	//write the host cert file
	err := util.UpdateFile(sshCertFile, hostCert, 0, 0, 0644, sysLogger)
	if err != nil {
		return err
	}

	//Now update the config file, if needed
	data, err := ioutil.ReadFile(sshConfigFile)
	if err != nil {
		return err
	}
	conf := string(data)
	i := strings.Index(conf, "#HostCertificate /etc/ssh/ssh_host_rsa_key-cert.pub")
	if i >= 0 {
		conf = conf[:i] + conf[i+1:]
		err = util.UpdateFile(sshConfigFile, conf, 0, 0, 0644, sysLogger)
		if err != nil {
			return err
		}
		//and restart sshd to notice the changes.
		return restartSshdService(ostype)
	}
	return nil
}

func restartSshdService(ostype int) error {
	return exec.Command("systemctl", "restart", "sshd").Run()
}

// SSHKeyReq - congruent with certsign-rdl/certsign.rdl
type SSHKeyReq struct {
	Principals []string `json:"principals"`
	Ips        []string `json:"ips,omitempty" rdl:"optional"` //not used
	Pubkey     string   `json:"pubkey"`
	Reqip      string   `json:"reqip"`
	Requser    string   `json:"requser"`
	Certtype   string   `json:"certtype"`
	Transid    string   `json:"transid"`
	Command    string   `json:"command,omitempty" rdl:"optional"` //not used
}

func generateSSHHostCSR(sshCert bool, domain, service, ip, ztsAwsDomain string, sysLogger io.Writer) (string, error) {
	if !sshCert {
		return "", nil
	}
	pubkey, err := ioutil.ReadFile(sshPubKeyFile)
	if err != nil {
		logutil.LogInfo(sysLogger, "Skipping SSH CSR Request - Unable to read SSH Public Key File: %v\n", err)
		return "", nil
	}
	identity := domain + "." + service
	transId := fmt.Sprintf("%x", time.Now().Unix())
	hyphenDomain := strings.Replace(domain, ".", "-", -1)
	host := fmt.Sprintf("%s.%s.%s", service, hyphenDomain, ztsAwsDomain)
	req := &SSHKeyReq{
		Principals: []string{host},
		Pubkey:     string(pubkey),
		Reqip:      ip,
		Requser:    identity,
		Certtype:   "host",
		Transid:    transId,
	}
	csr, err := json.Marshal(req)
	if err != nil {
		return "", err
	}
	return string(csr), err
}

func getProviderName(provider, region, taskId string) (string, bool) {
	if provider != "" {
		return provider, false
	}
	if taskId == "" {
		return "athenz.aws." + region, true
	} else {
		return "athenz.aws-ecs." + region, false
	}
}

func extractProviderFromCert(certFile string) string {
	data, err := ioutil.ReadFile(certFile)
	if err != nil {
		return ""
	}
	var block *pem.Block
	block, _ = pem.Decode(data)
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return ""
	}
	if len(cert.Subject.OrganizationalUnit) > 0 {
		return cert.Subject.OrganizationalUnit[0]
	}
	return ""
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

// mkDirPath appends "/" if missing at the end
func mkDirPath(dir string) string {
	if !strings.HasSuffix(dir, "/") {
		return fmt.Sprintf("%s/", dir)
	}
	return dir
}
