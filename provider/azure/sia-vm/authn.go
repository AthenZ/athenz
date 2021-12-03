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
	"github.com/AthenZ/athenz/clients/go/zts"
	"github.com/AthenZ/athenz/libs/go/sia/logutil"
	"github.com/AthenZ/athenz/libs/go/sia/util"
	"github.com/AthenZ/athenz/provider/azure/sia-vm/data/attestation"
	"github.com/AthenZ/athenz/provider/azure/sia-vm/options"
	"github.com/ardielle/ardielle-go/rdl"
	"io"
	"io/ioutil"
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

func GetPrevRoleCertDates(certFile string, sysLogger io.Writer) (*rdl.Timestamp, *rdl.Timestamp, error) {
	prevRolCert, err := readCertificate(certFile)
	if err != nil {
		return nil, nil, err
	}

	notBefore := &rdl.Timestamp{
		Time: prevRolCert.NotBefore,
	}

	notAfter := &rdl.Timestamp{
		Time: prevRolCert.NotAfter,
	}

	logutil.LogInfo(sysLogger, "Existing role cert %s, not before: %s, not after: %s", certFile, notBefore.String(), notAfter.String())
	return notBefore, notAfter, nil
}

func GetRoleCertificate(ztsUrl, svcKeyFile, svcCertFile string, opts *options.Options, sysLogger io.Writer) bool {
	client, err := util.ZtsClient(ztsUrl, opts.ZTSServerName, svcKeyFile, svcCertFile, opts.ZTSCACertFile, sysLogger)
	if err != nil {
		logutil.LogInfo(sysLogger, "unable to initialize ZTS Client for %s, err: %v\n", ztsUrl, err)
		return false
	}
	client.AddCredentials("User-Agent", opts.Version)

	// extract the provider from the certificate file
	provider := extractProviderFromCert(svcCertFile)
	key, err := util.PrivateKeyFromFile(svcKeyFile)
	if err != nil {
		logutil.LogInfo(sysLogger, "unable to read private key from %s, err: %v\n", svcKeyFile, err)
		return false
	}

	// initialize our return state to success
	failures := 0

	var roleRequest = new(zts.RoleCertificateRequest)
	for roleName, role := range opts.Roles {
		certFilePem := util.GetRoleCertFileName(mkDirPath(opts.CertDir), role.Filename, roleName)
		csr, err := util.GenerateRoleCertCSR(key, opts.CountryName, "", opts.Domain, opts.Services[0].Name, roleName, opts.Services[0].Name, provider, "")
		if err != nil {
			logutil.LogInfo(sysLogger, "unable to generate CSR for %s, err: %v\n", roleName, err)
			failures += 1
			continue
		}
		roleRequest.Csr = csr

		notBefore, notAfter, _ := GetPrevRoleCertDates(certFilePem, sysLogger)
		roleRequest.PrevCertNotBefore = notBefore
		roleRequest.PrevCertNotAfter = notAfter
		if notBefore != nil && notAfter != nil {
			logutil.LogInfo(sysLogger, "Previous Role Cert Not Before date: %s, Not After date: %s", notBefore, notAfter)
		}

		// "rolename": "athenz.fp:role.readers"
		// from the rolename, domain is athenz.fp and role is readers
		roleCert, err := client.PostRoleCertificateRequestExt(roleRequest)
		if err != nil {
			logutil.LogInfo(sysLogger, "PostRoleCertificateRequest failed for %s, err: %v\n", roleName, err)
			failures += 1
			continue
		}

		// we have the role certificate
		// write the cert to pem file using Role.Filename
		err = util.UpdateFile(certFilePem, []byte(roleCert.X509Certificate), 0, 0, 0444, sysLogger)
		if err != nil {
			failures += 1
			continue
		}
	}
	logutil.LogInfo(sysLogger, "SIA processed %d (failures %d) role certificate requests\n", len(opts.Roles), failures)
	return failures == 0
}

func RegisterInstance(data []*attestation.Data, ztsUrl string, identityDocument *attestation.IdentityDocument, opts *options.Options, sysLogger io.Writer) error {
	for i, svc := range opts.Services {
		err := registerSvc(svc, data[i], ztsUrl, identityDocument, opts, sysLogger)
		if err != nil {
			return fmt.Errorf("unable to register identity for svc: %q, error: %v", svc.Name, err)
		}
	}
	return nil
}

func registerSvc(svc options.Service, data *attestation.Data, ztsUrl string, identityDocument *attestation.IdentityDocument, opts *options.Options, sysLogger io.Writer) error {

	key, err := util.GenerateKeyPair(2048)
	if err != nil {
		return err
	}

	// include a csr for the host ssh certificate if requested
	ssh, err := generateSSHHostCSR(opts.Ssh, opts.Domain, svc.Name, identityDocument.PrivateIp, opts.ZTSAzureDomains, sysLogger)
	if err != nil {
		return err
	}

	provider := getProviderName(opts.Provider, identityDocument.Location)
	commonName := fmt.Sprintf("%s.%s", opts.Domain, svc.Name)
	csr, err := util.GenerateSvcCertCSR(key, opts.CountryName, "", opts.Domain, svc.Name, commonName, identityDocument.VmId, provider, opts.ZTSAzureDomains, opts.SanDnsWildcard, false)
	if err != nil {
		return err
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
	err = util.UpdateFile(svcKeyFile, []byte(util.PrivatePem(key)), svc.Uid, svc.Gid, 0440, sysLogger)
	if err != nil {
		return err
	}
	certFile := getCertFileName(svc.Filename, opts.Domain, svc.Name, opts.CertDir)
	err = util.UpdateFile(certFile, []byte(instIdent.X509Certificate), svc.Uid, svc.Gid, 0444, sysLogger)
	if err != nil {
		return err
	}

	if opts.Services[0].Name == svc.Name {
		err = util.UpdateFile(opts.AthenzCACertFile, []byte(instIdent.X509CertificateSigner), svc.Uid, svc.Gid, 0444, sysLogger)
		if err != nil {
			return err
		}
		// we're not going to count ssh updates as fatal since the primary
		// task for sia to get service identity certs but we'll log the failure
		err = updateSSH(instIdent.SshCertificate, instIdent.SshCertificateSigner, sysLogger)
		if err != nil {
			logutil.LogInfo(sysLogger, "Unable to update ssh certificate, err: %v\n", err)
		}
	}
	return nil
}

func RefreshInstance(data []*attestation.Data, ztsUrl string, identityDocument *attestation.IdentityDocument, opts *options.Options, sysLogger io.Writer) error {
	for i, svc := range opts.Services {
		err := refreshSvc(svc, data[i], ztsUrl, identityDocument, opts, sysLogger)
		if err != nil {
			return fmt.Errorf("unable to refresh identity for svc: %q, error: %v", svc.Name, err)
		}
	}
	return nil
}

func refreshSvc(svc options.Service, data *attestation.Data, ztsUrl string, identityDocument *attestation.IdentityDocument, opts *options.Options, sysLogger io.Writer) error {
	keyFile := fmt.Sprintf("%s/%s.%s.key.pem", opts.KeyDir, opts.Domain, svc.Name)
	key, err := util.PrivateKeyFromFile(keyFile)
	if err != nil {
		logutil.LogInfo(sysLogger, "Unable to read private key from %s, err: %v\n", keyFile, err)
		return err
	}

	certFile := fmt.Sprintf("%s/%s.%s.cert.pem", opts.CertDir, opts.Domain, svc.Name)

	// include a csr for the host ssh certificate if requested
	ssh, err := generateSSHHostCSR(opts.Ssh, opts.Domain, svc.Name, identityDocument.PrivateIp, opts.ZTSAzureDomains, sysLogger)
	if err != nil {
		return err
	}

	attestData, err := json.Marshal(data)
	if err != nil {
		return err
	}
	provider := getProviderName(opts.Provider, identityDocument.Location)
	commonName := fmt.Sprintf("%s.%s", opts.Domain, svc.Name)
	csr, err := util.GenerateSvcCertCSR(key, opts.CountryName, "", opts.Domain, svc.Name, commonName, identityDocument.VmId, provider, opts.ZTSAzureDomains, opts.SanDnsWildcard, false)
	if err != nil {
		logutil.LogInfo(sysLogger, "Unable to generate CSR for %s, err: %v\n", opts.Name, err)
		return err
	}
	info := &zts.InstanceRefreshInformation{AttestationData: string(attestData), Csr: csr, Ssh: ssh}

	infoData, err := json.Marshal(info)
	logutil.LogInfo(sysLogger, "attestation data: \n%s\n", infoData)

	client, err := util.ZtsClient(ztsUrl, opts.ZTSServerName, keyFile, certFile, opts.ZTSCACertFile, sysLogger)
	if err != nil {
		logutil.LogInfo(sysLogger, "Unable to get ZTS Client for %s, err: %v\n", ztsUrl, err)
		return err
	}
	client.AddCredentials("User-Agent", opts.Version)

	ident, err := client.PostInstanceRefreshInformation(zts.ServiceName(provider), zts.DomainName(opts.Domain), zts.SimpleName(svc.Name), zts.PathElement(identityDocument.VmId), info)
	if err != nil {
		logutil.LogInfo(sysLogger, "Unable to refresh instance service certificate for %s, err: %v\n", opts.Name, err)
		return err
	}

	err = util.UpdateFile(certFile, []byte(ident.X509Certificate), svc.Uid, svc.Gid, 0444, sysLogger)
	if err != nil {
		return err
	}

	if opts.Services[0].Name == svc.Name {
		err = util.UpdateFile(opts.AthenzCACertFile, []byte(ident.X509CertificateSigner), svc.Uid, svc.Gid, 0444, sysLogger)
		if err != nil {
			return err
		}
		// we're not going to count ssh updates as fatal since the primary
		// task for sia to get service identity certs but we'll log the failure
		err = updateSSH(ident.SshCertificate, ident.SshCertificateSigner, sysLogger)
		if err != nil {
			logutil.LogInfo(sysLogger, "Unable to update ssh certificate, err: %v\n", err)
		}
	}
	return nil
}

func updateSSH(hostCert, hostSigner string, sysLogger io.Writer) error {
	// if we have no hostCert and hostSigner then
	// we have nothing to update for ssh access
	if hostCert == "" && hostSigner == "" {
		logutil.LogInfo(sysLogger, "No host ssh certificate available to update\n")
		return nil
	}

	// write the host cert file
	err := util.UpdateFile(sshCertFile, []byte(hostCert), 0, 0, 0644, sysLogger)
	if err != nil {
		return err
	}

	// Now update the config file, if needed
	data, err := ioutil.ReadFile(sshConfigFile)
	if err != nil {
		return err
	}
	conf := string(data)
	i := strings.Index(conf, "#HostCertificate /etc/ssh/ssh_host_rsa_key-cert.pub")
	if i >= 0 {
		conf = conf[:i] + conf[i+1:]
		err = util.UpdateFile(sshConfigFile, []byte(conf), 0, 0, 0644, sysLogger)
		if err != nil {
			return err
		}
		// and restart sshd to notice the changes.
		return restartSshdService()
	}
	return nil
}

func restartSshdService() error {
	return exec.Command("systemctl", "restart", "sshd").Run()
}

// SSHKeyReq ssh key request object
type SSHKeyReq struct {
	Principals []string `json:"principals"`
	Ips        []string `json:"ips,omitempty" rdl:"optional"`
	Pubkey     string   `json:"pubkey"`
	Reqip      string   `json:"reqip"`
	Requser    string   `json:"requser"`
	Certtype   string   `json:"certtype"`
	Transid    string   `json:"transid"`
	Command    string   `json:"command,omitempty" rdl:"optional"`
}

func generateSSHHostCSR(sshCert bool, domain, service, ip string, ztsAzureDomains []string, sysLogger io.Writer) (string, error) {
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
	principals := []string{}
	for _, ztsDomain := range ztsAzureDomains {
		host := fmt.Sprintf("%s.%s.%s", service, hyphenDomain, ztsDomain)
		principals = append(principals, host)
	}
	req := &SSHKeyReq{
		Principals: principals,
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

func getProviderName(provider, region string) string {
	if provider != "" {
		return provider
	}
	return "athenz.azure." + region
}

func extractProviderFromCert(certFile string) string {
	cert, err := readCertificate(certFile)
	if err != nil || cert == nil {
		return ""
	}
	if len(cert.Subject.OrganizationalUnit) > 0 {
		return cert.Subject.OrganizationalUnit[0]
	}
	return ""
}

func readCertificate(certFile string) (*x509.Certificate, error) {
	data, err := ioutil.ReadFile(certFile)
	if err != nil {
		return nil, err
	}
	var block *pem.Block
	block, _ = pem.Decode(data)
	if block == nil {
		return nil, nil
	}
	return x509.ParseCertificate(block.Bytes)
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
