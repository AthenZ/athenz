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

package agent

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"io/ioutil"
	"os"
	"os/exec"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/AthenZ/athenz/clients/go/zts"
	"github.com/AthenZ/athenz/libs/go/sia/aws/attestation"
	"github.com/AthenZ/athenz/libs/go/sia/aws/options"
	"github.com/AthenZ/athenz/libs/go/sia/logutil"
	"github.com/AthenZ/athenz/libs/go/sia/util"
	"github.com/ardielle/ardielle-go/rdl"
)

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

func RoleKey(rotateKey bool, svcKey string) (*rsa.PrivateKey, error) {
	if rotateKey == true {
		return util.GenerateKeyPair(2048)
	}
	return util.PrivateKeyFromFile(svcKey)
}

func GetRoleCertificate(ztsUrl, svcKeyFile, svcCertFile string, opts *options.Options, sysLogger io.Writer) bool {
	client, err := util.ZtsClient(ztsUrl, opts.ZTSServerName, svcKeyFile, svcCertFile, opts.ZTSCACertFile, sysLogger)
	if err != nil {
		logutil.LogInfo(sysLogger, "unable to initialize ZTS Client for %s, err: %v\n", ztsUrl, err)
		return false
	}
	client.AddCredentials("User-Agent", opts.Version)

	key, err := util.PrivateKeyFromFile(svcKeyFile)
	if err != nil {
		logutil.LogInfo(sysLogger, "unable to read private key from %s, err: %v\n", svcKeyFile, err)
		return false
	}

	//initialize our return state to success
	failures := 0

	var roleRequest = new(zts.RoleCertificateRequest)
	for roleName, role := range opts.Roles {

		if opts.GenerateRoleKey {
			var err error
			key, err = RoleKey(opts.RotateKey, svcKeyFile)
			if err != nil {
				logutil.LogInfo(sysLogger, "unable to read generate/read key from %s, err: %v\n", role.Filename, err)
				failures += 1
				continue
			}
		}

		csr, err := util.GenerateRoleCertCSR(key, opts.CertCountryName, opts.CertOrgName, opts.Domain, opts.Services[0].Name, roleName, opts.InstanceId, opts.Provider, opts.ZTSAWSDomains[0])
		if err != nil {
			logutil.LogInfo(sysLogger, "unable to generate CSR for %s, err: %v\n", roleName, err)
			failures += 1
			continue
		}
		roleRequest.Csr = csr

		certFilePem := util.GetRoleCertFileName(opts.CertDir, role.Filename, roleName)
		notBefore, notAfter, _ := GetPrevRoleCertDates(certFilePem, sysLogger)
		roleRequest.PrevCertNotBefore = notBefore
		roleRequest.PrevCertNotAfter = notAfter
		if notBefore != nil && notAfter != nil {
			logutil.LogInfo(sysLogger, "Previous Role Cert Not Before date: %s, Not After date: %s", notBefore, notAfter)
		}

		//"rolename": "athenz.fp:role.readers"
		//from the rolename, domain is athenz.fp
		//role is readers
		roleCert, err := client.PostRoleCertificateRequestExt(roleRequest)
		if err != nil {
			logutil.LogInfo(sysLogger, "PostRoleCertificateRequest failed for %s, err: %v\n", roleName, err)
			failures += 1
			continue
		}

		roleKeyBytes := util.PrivatePem(key)
		optsRole := options.Role{
			Name:     roleName,
			Service:  opts.Services[0].Name,
			Filename: role.Filename,
			User:     "",
			Uid:      opts.Services[0].Uid,
			Gid:      opts.Services[0].Gid,
			FileMode: 0444,
		}
		err = SaveRoleCertKey([]byte(roleKeyBytes), []byte(roleCert.X509Certificate), optsRole, opts, sysLogger)
		if err != nil {
			failures += 1
			continue
		}
	}
	logutil.LogInfo(sysLogger, "SIA processed %d (failures %d) role certificate requests\n", len(opts.Roles), failures)
	return failures == 0
}

func RegisterInstance(data []*attestation.AttestationData, ztsUrl string, opts *options.Options, docExpiryCheck bool, sysLogger io.Writer) error {

	//special handling for EC2 instances
	//before we process our register event we need to check to
	//see if our timestamp in our document is less than 30 mins
	//ago otherwise ZTS server will reject the request and there
	//is no point of processing the request
	if docExpiryCheck && shouldSkipRegister(opts) {
		return fmt.Errorf("identity document has expired (30 min timeout). ZTS will not register this instance. Please relaunch or stop and start your instance to refesh its identity document")
	}

	for i, svc := range opts.Services {
		err := registerSvc(svc, data[i], ztsUrl, opts, sysLogger)
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

func registerSvc(svc options.Service, data *attestation.AttestationData, ztsUrl string, opts *options.Options, sysLogger io.Writer) error {

	key, err := util.GenerateKeyPair(2048)
	if err != nil {
		return err
	}

	//if ssh support is enabled then we need to generate the csr
	//it is also generated for the primary service only
	var sshCsr string
	if opts.Ssh && opts.Services[0].Name == svc.Name {
		sshCsr, err = util.GenerateSSHHostCSR(opts.SshPubKeyFile, opts.Domain, svc.Name, opts.PrivateIp, opts.ZTSAWSDomains, sysLogger)
		if err != nil {
			return err
		}
	}
	csr, err := util.GenerateSvcCertCSR(key, opts.CertCountryName, opts.CertOrgName, opts.Domain, svc.Name, data.Role, opts.InstanceId, opts.Provider, opts.ZTSAWSDomains, opts.SanDnsWildcard)
	if err != nil {
		return err
	}
	attestData, err := json.Marshal(data)
	if err != nil {
		return err
	}
	info := &zts.InstanceRegisterInformation{
		Provider:        zts.ServiceName(opts.Provider),
		Domain:          zts.DomainName(opts.Domain),
		Service:         zts.SimpleName(svc.Name),
		Csr:             csr,
		Ssh:             sshCsr,
		AttestationData: string(attestData),
	}

	client, err := util.ZtsClient(ztsUrl, opts.ZTSServerName, "", "", opts.ZTSCACertFile, sysLogger)
	if err != nil {
		return err
	}
	client.AddCredentials("User-Agent", opts.Version)

	ident, _, err := client.PostInstanceRegisterInformation(info)
	if err != nil {
		logutil.LogInfo(sysLogger, "Unable to do PostInstanceRegisterInformation, err: %v\n", err)
		return err
	}
	svcKeyFile := fmt.Sprintf("%s/%s.%s.key.pem", opts.KeyDir, opts.Domain, svc.Name)
	err = util.UpdateFile(svcKeyFile, []byte(util.PrivatePem(key)), svc.Uid, svc.Gid, 0440, sysLogger)
	if err != nil {
		return err
	}
	certFile := util.GetSvcCertFileName(opts.CertDir, svc.Filename, opts.Domain, svc.Name)
	err = util.UpdateFile(certFile, []byte(ident.X509Certificate), svc.Uid, svc.Gid, 0444, sysLogger)
	if err != nil {
		return err
	}

	if opts.Services[0].Name == svc.Name {
		err = util.UpdateFile(opts.AthenzCACertFile, []byte(ident.X509CertificateSigner), svc.Uid, svc.Gid, 0444, sysLogger)
		if err != nil {
			return err
		}
	}
	//we're not going to count ssh updates as fatal since the primary
	//task for sia to get service identity certs but we'll log the failure
	if ident.SshCertificate != "" {
		err = updateSSH(opts.SshCertFile, opts.SshConfigFile, ident.SshCertificate, sysLogger)
		if err != nil {
			logutil.LogInfo(sysLogger, "Unable to update ssh certificate, err: %v\n", err)
		}
	}
	return nil
}

func refreshSvc(svc options.Service, data *attestation.AttestationData, ztsUrl string, opts *options.Options, sysLogger io.Writer) error {
	keyFile := fmt.Sprintf("%s/%s.%s.key.pem", opts.KeyDir, opts.Domain, svc.Name)
	certFile := fmt.Sprintf("%s/%s.%s.cert.pem", opts.CertDir, opts.Domain, svc.Name)

	client, err := util.ZtsClient(ztsUrl, opts.ZTSServerName, keyFile, certFile, opts.ZTSCACertFile, sysLogger)
	if err != nil {
		logutil.LogInfo(sysLogger, "Unable to get ZTS Client for %s, err: %v\n", ztsUrl, err)
		return err
	}
	client.AddCredentials("User-Agent", opts.Version)

	attestData, err := json.Marshal(data)
	if err != nil {
		return err
	}

	key, err := util.PrivateKey(keyFile, opts.RotateKey)
	if err != nil {
		logutil.LogInfo(sysLogger, "Unable to read private key from %s, err: %v\n", keyFile, err)
		return err
	}
	csr, err := util.GenerateSvcCertCSR(key, opts.CertCountryName, opts.CertOrgName, opts.Domain, svc.Name, data.Role, opts.InstanceId, opts.Provider, opts.ZTSAWSDomains, opts.SanDnsWildcard)
	if err != nil {
		logutil.LogInfo(sysLogger, "Unable to generate CSR for %s, err: %v\n", opts.Name, err)
		return err
	}
	//if ssh support is enabled then we need to generate the csr
	//it is also generated for the primary service only
	var sshCsr string
	if opts.Ssh && opts.Services[0].Name == svc.Name {
		sshCsr, err = util.GenerateSSHHostCSR(opts.SshPubKeyFile, opts.Domain, svc.Name, opts.PrivateIp, opts.ZTSAWSDomains, sysLogger)
		if err != nil {
			return err
		}
	}

	info := &zts.InstanceRefreshInformation{
		AttestationData: string(attestData),
		Csr:      csr,
		Ssh:      sshCsr,
	}
	ident, err := client.PostInstanceRefreshInformation(zts.ServiceName(opts.Provider), zts.DomainName(opts.Domain), zts.SimpleName(svc.Name), zts.PathElement(opts.InstanceId), info)
	if err != nil {
		logutil.LogInfo(sysLogger, "Unable to refresh instance service certificate for %s, err: %v\n", opts.Name, err)
		return err
	}

	svcKeyBytes := util.PrivatePem(key)
	svcCertBytes := []byte(ident.X509Certificate)
	err = SaveSvcCertKey([]byte(svcKeyBytes), svcCertBytes, svc, opts, sysLogger)
	if err != nil {
		return err
	}

	if opts.Services[0].Name == svc.Name {
		err = util.UpdateFile(opts.AthenzCACertFile, []byte(ident.X509CertificateSigner), svc.Uid, svc.Gid, 0444, sysLogger)
		if err != nil {
			return err
		}
	}
	//we're not going to count ssh updates as fatal since the primary
	//task for sia to get service identity certs but we'll log the failure
	if ident.SshCertificate != "" {
		err = updateSSH(opts.SshCertFile, opts.SshConfigFile, ident.SshCertificate, sysLogger)
		if err != nil {
			logutil.LogInfo(sysLogger, "Unable to update ssh certificate, err: %v\n", err)
		}
	}
	return nil
}

func SaveSvcCertKey(key, cert []byte, svc options.Service, opts *options.Options, sysLogger io.Writer) error {
	prefix := fmt.Sprintf("%s.%s", opts.Domain, svc.Name)
	return util.SaveCertKey(key, cert, svc.Filename, prefix, prefix, svc.Uid, svc.Gid, svc.FileMode, false, false, opts.KeyDir, opts.CertDir, opts.BackUpDir, sysLogger)
}

func SaveRoleCertKey(key, cert []byte, role options.Role, opts *options.Options, sysLogger io.Writer) error {
	certPrefix := role.Name
	if role.Filename != "" {
		certPrefix = strings.TrimSuffix(role.Filename, ".cert.pem")
	}
	keyPrefix := fmt.Sprintf("%s.%s", opts.Domain, role.Service)
	if opts.GenerateRoleKey == true {
		keyPrefix = role.Name
		if role.Filename != "" {
			keyPrefix = strings.TrimSuffix(role.Filename, ".cert.pem")
		}
	}
	return util.SaveCertKey(key, cert, role.Filename, keyPrefix, certPrefix, role.Uid, role.Gid, role.FileMode, opts.GenerateRoleKey, opts.RotateKey, opts.KeyDir, opts.CertDir, opts.BackUpDir, sysLogger)
}

func restartSshdService() error {
	return exec.Command("systemctl", "restart", "sshd").Run()
}

func updateSSH(sshCertFile, sshConfigFile, hostCert string, sysLogger io.Writer) error {

	//write the host cert file
	err := util.UpdateFile(sshCertFile, []byte(hostCert), 0, 0, 0644, sysLogger)
	if err != nil {
		return err
	}

	//Now update the config file, if needed. The format of the line we're going
	//to comment is #HostCertificate <sshCertFile> and we'll just remove the #
	if sshConfigFile != "" {
		data, err := ioutil.ReadFile(sshConfigFile)
		if err != nil {
			return err
		}
		conf := string(data)
		certLine := fmt.Sprintf("#HostCertificate %s", sshCertFile)
		i := strings.Index(conf, certLine)
		if i >= 0 {
			conf = conf[:i] + conf[i+1:]
			err = util.UpdateFile(sshConfigFile, []byte(conf), 0, 0, 0644, sysLogger)
			if err != nil {
				return err
			}
			//and restart sshd to notice the changes.
			return restartSshdService()
		}
	}
	return nil
}

func RunAgent(siaCmd, siaDir, ztsUrl string, opts *options.Options, sysLogger io.Writer) {

	_ = util.SetupSIADirs(siaDir, "", sysLogger)

	//for now we're going to rotate once every day
	//since our server and role certs are valid for
	//30 days by default
	rotationInterval := 24 * 60 * time.Minute

	data, err := attestation.GetAttestationData(opts, sysLogger)
	if err != nil {
		logutil.LogFatal(sysLogger, "Cannot determine identity to run as, err:%v\n", err)
	}
	svcs := options.GetSvcNames(opts.Services)

	switch siaCmd {
	case "rolecert":
		GetRoleCertificate(ztsUrl,
			fmt.Sprintf("%s/%s.%s.key.pem", opts.KeyDir, opts.Domain, opts.Services[0].Name),
			fmt.Sprintf("%s/%s.%s.cert.pem", opts.CertDir, opts.Domain, opts.Services[0].Name),
			opts,
			sysLogger,
		)
	case "post":
	case "register":
		err := RegisterInstance(data, ztsUrl, opts, false, sysLogger)
		if err != nil {
			logutil.LogFatal(sysLogger, "Unable to register identity, err: %v\n", err)
		}
		logutil.LogInfo(sysLogger, "identity registered for services: %s\n", svcs)
	case "rotate":
	case "refresh":
		err = RefreshInstance(data, ztsUrl, opts, sysLogger)
		if err != nil {
			logutil.LogFatal(sysLogger, "Refresh identity failed, err: %v\n", err)
		}
		logutil.LogInfo(sysLogger, "Identity successfully refreshed for services: %s\n", svcs)
	default:
		// if we already have a cert file then we're not going to
		// prove our identity since most likely it will not succeed
		// due to boot time check (this could be just a regular
		// service restart for any reason). Instead, we'll just skip
		// over and try to rotate the certs

		initialSetup := true
		if files, err := ioutil.ReadDir(opts.CertDir); err != nil || len(files) <= 0 {
			err := RegisterInstance(data, ztsUrl, opts, true, sysLogger)
			if err != nil {
				logutil.LogFatal(sysLogger, "Register identity failed, error: %v\n", err)
			}
		} else {
			initialSetup = false
			logutil.LogInfo(sysLogger, "Identity certificate file already exists. Retrieving identity details...\n")
		}
		logutil.LogInfo(sysLogger, "Identity established for services: %s\n", svcs)

		stop := make(chan bool, 1)
		errors := make(chan error, 1)

		go func() {
			for {
				logutil.LogInfo(sysLogger, "Identity being used: %s\n", opts.Name)

				// if we just did our initial setup there is no point
				// to refresh the certs again. so we are going to skip
				// this time around and refresh certs next time

				if !initialSetup {
					data, err := attestation.GetAttestationData(opts, sysLogger)
					if err != nil {
						errors <- fmt.Errorf("Cannot get attestation data: %v\n", err)
						return
					}
					err = RefreshInstance(data, ztsUrl, opts, sysLogger)
					if err != nil {
						errors <- fmt.Errorf("refresh identity failed: %v\n", err)
						return
					}
					logutil.LogInfo(sysLogger, "identity successfully refreshed for services: %s\n", svcs)
				} else {
					initialSetup = false
				}
				GetRoleCertificate(ztsUrl,
					fmt.Sprintf("%s/%s.%s.key.pem", opts.KeyDir, opts.Domain, opts.Services[0].Name),
					fmt.Sprintf("%s/%s.%s.cert.pem", opts.CertDir, opts.Domain, opts.Services[0].Name),
					opts,
					sysLogger,
				)
				select {
				case <-stop:
					errors <- nil
					return
				case <-time.After(rotationInterval):
					break
				}
			}
		}()

		go func() {
			signals := make(chan os.Signal, 2)
			signal.Notify(signals, os.Interrupt, syscall.SIGTERM)
			sig := <-signals
			logutil.LogInfo(sysLogger, "Received signal %v, stopping rotation\n", sig)
			stop <- true
		}()

		err = <-errors
		if err != nil {
			logutil.LogInfo(sysLogger, "%v", err)
		}
	}
	os.Exit(0)
}

func shouldSkipRegister(opts *options.Options) bool {
	if opts.EC2StartTime == nil {
		return false
	}
	duration := time.Since(*opts.EC2StartTime)
	//our server timeout is 30 mins = 1800 secs
	if duration.Seconds() > 1800 {
		return true
	}
	return false
}
