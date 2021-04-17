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

package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"github.com/AthenZ/athenz/libs/go/sia/aws/attestation"
	"github.com/AthenZ/athenz/libs/go/sia/aws/doc"
	"github.com/AthenZ/athenz/provider/aws/sia-ec2/options"
	"io"
	"io/ioutil"
	"log"
	"log/syslog"
	"os"
	"strings"
	"time"

	"flag"
	"os/signal"
	"syscall"

	"github.com/AthenZ/athenz/libs/go/sia/aws/logutil"
	"github.com/AthenZ/athenz/libs/go/sia/aws/meta"
	"github.com/AthenZ/athenz/provider/aws/sia-ec2/util"

	"github.com/AthenZ/athenz/provider/aws/sia-fargate"
)

// Following can be set by the build script using LDFLAGS

var Version string
var ZtsEndPoint string
var DnsDomain string
var ProviderPrefix string

// End

var CmdOpt bool
var MetaEndPoint = os.Getenv("ECS_CONTAINER_METADATA_URI_V4")

const siaMainDir = "/var/lib/sia"

// getAttestationData fetches attestation data for all the services mentioned in the config file
func getAttestationData(opts *options.Options, region, taskId string, sysLogger io.Writer) ([]*attestation.AttestationData, error) {
	data := []*attestation.AttestationData{}
	for _, svc := range opts.Services {
		a, err := sia.GetAttestationData(opts.Domain, svc.Name, opts.Account, region, taskId, opts.UseRegionalSTS, sysLogger)
		if err != nil {
			return nil, err
		}
		data = append(data, a)
	}
	return data, nil
}

// getSvcNames returns command separated list of service names
func getSvcNames(svcs []options.Service) string {
	var b bytes.Buffer
	for _, svc := range svcs {
		b.WriteString(fmt.Sprintf("%s,", svc.Name))
	}
	return strings.TrimSuffix(b.String(), ",")
}

func getTaskConfig(metaEndPoint string) (string, string, string, error) {
	account, taskId, region, err := sia.GetECSFargateData(metaEndPoint)
	if err != nil {
		return "", "", "", err
	}
	return account, taskId, region, nil
}

func getDomainServiceFromTaskRole() (string, string, error) {
	uri := os.Getenv("AWS_CONTAINER_CREDENTIALS_RELATIVE_URI")
	if uri == "" {
		return "", "", fmt.Errorf("cannot fetch AWS_CONTAINER_CREDENTIALS_RELATIVE_URI env variable")
	}
	document, err := meta.GetData(sia.ECSMetaEndPoint, uri)
	if err != nil {
		return "", "", err
	}
	roleArn, err := doc.GetDocumentEntry(document, "RoleArn")
	if err != nil {
		return "", "", err
	}
	domain, service, err := util.ExtractServiceName(roleArn, ":role/")
	if err != nil {
		return "", "", err
	}
	return domain, service, nil
}

func main() {
	cmd := flag.String("cmd", "", "optional sub command to run")
	metaEndPoint := flag.String("meta", "", "optional meta endpoint to use for debugging")
	ztsEndPoint := flag.String("zts", "", "Athenz Token Service (ZTS) endpoint")
	ztsServerName := flag.String("ztsservername", "", "zts server name for tls connections")
	ztsCACert := flag.String("ztscacert", "", "zts CA certificate file")
	dnsDomain := flag.String("dnsdomain", "", "DNS Domain associated with the provider")
	ztsPort := flag.Int("ztsport", 4443, "Athenz Token Service (ZTS) port number")
	pConf := flag.String("config", "/etc/sia/sia_config", "The config file to run against")
	useRegionalSTS := flag.Bool("regionalsts", false, "Use regional STS endpoint instead of global")
	providerPrefix := flag.String("providerprefix", "", "Provider name prefix e.g athenz.aws")
	flag.BoolVar(&CmdOpt, "version", false, "Display version information")

	flag.Parse()

	if CmdOpt && len(flag.Args()) == 0 {
		fmt.Println(Version)
		os.Exit(0)
	}

	var sysLogger io.Writer
	sysLogger, err := syslog.New(syslog.LOG_INFO|syslog.LOG_DAEMON, "siad")
	if err != nil {
		log.Printf("Unable to create sys logger: %v\n", err)
		sysLogger = os.Stdout
	}

	if ZtsEndPoint == "" && *ztsEndPoint == "" {
		logutil.LogFatal(sysLogger, "missing zts!\n")
	}

	if *ztsEndPoint != "" {
		// run time param takes precedence over build time
		ZtsEndPoint = *ztsEndPoint
	}

	if DnsDomain == "" && *dnsDomain == "" {
		logutil.LogFatal(sysLogger, "missing dnsdomain!\n")
	}

	if *dnsDomain != "" {
		// run time param takes precedence over build time
		DnsDomain = *dnsDomain
	}

	if ProviderPrefix == "" && *providerPrefix == "" {
		logutil.LogFatal(sysLogger, "missing providerprefix!\n")
	}

	if *providerPrefix != "" {
		// run time param takes precedence over build time
		ProviderPrefix = *providerPrefix
	}

	if *metaEndPoint != "" {
		// run time param takes precedence over build time
		MetaEndPoint = *metaEndPoint
	}

	logutil.LogInfo(sysLogger, "Using ZTS: %s with DNS domain: %s & Provider prefix: %s\n", ZtsEndPoint, DnsDomain, ProviderPrefix)

	accountId, taskId, region, err := getTaskConfig(MetaEndPoint)
	if err != nil {
		logutil.LogFatal(sysLogger, "Unable to get account, task id from available credentials, error: %v\n", err)
	}
	logutil.LogInfo(sysLogger, "Got accountId: %s, region: %s, taskId: %s from Fargate MetaEndPoint\n", accountId, region, taskId)

	domain, service, err := getDomainServiceFromTaskRole()
	if err != nil {
		logutil.LogFatal(sysLogger, "Unable to get domain, service from IAM task role, error: %v\n", err)
	}
	confBytes, err := ioutil.ReadFile(*pConf)
	if err != nil {
		var config options.Config
		config.Version = "1.0.0"
		config.Service = service
		config.Accounts = make([]options.ConfigAccount, 1)
		config.Accounts[0] = options.ConfigAccount{Domain: domain, Account: accountId}
		confBytes, _ = json.Marshal(config)
	}
	opts, err := options.NewOptions(confBytes, accountId, MetaEndPoint, siaMainDir, Version, *ztsCACert, *ztsServerName, DnsDomain, sysLogger)
	if err != nil {
		logutil.LogFatal(sysLogger, "Unable to formulate options, error: %v\n", err)
	}

	// if useRegionalSTS flag is provided then override config value
	if useRegionalSTS != nil && *useRegionalSTS {
		opts.UseRegionalSTS = *useRegionalSTS
	}

	opts.Provider = ProviderPrefix

	opts.Ssh = false
	logutil.LogInfo(sysLogger, "Request SSH Certificates is always false for Fargate: %t\n", opts.Ssh)

	opts.Version = fmt.Sprintf("SIA-FARGATE %s", Version)

	log.Printf("options: %+v", opts)

	data, err := getAttestationData(opts, region, taskId, sysLogger)
	if err != nil {
		logutil.LogFatal(sysLogger, "Unable to formulate attestation data, error: %v\n", err)
	}

	//for now we're going to rotate once every day
	//since our server and role certs are valid for
	//30 days by default
	rotationInterval := 24 * 60 * time.Minute

	ztsUrl := fmt.Sprintf("https://%s:%d/zts/v1", ZtsEndPoint, *ztsPort)

	err = util.SetupSIADirs(siaMainDir, "", sysLogger)
	if err != nil {
		logutil.LogFatal(sysLogger, "Unable to setup sia directories, error: %v\n", err)
	}

	svcs := getSvcNames(opts.Services)

	switch *cmd {
	case "rolecert":
		sia.GetRoleCertificate(ztsUrl,
			fmt.Sprintf("%s/%s.%s.key.pem", opts.KeyDir, opts.Domain, opts.Services[0].Name),
			fmt.Sprintf("%s/%s.%s.cert.pem", opts.CertDir, opts.Domain, opts.Services[0].Name),
			opts,
			sysLogger,
		)
	case "post":
		err := sia.RegisterInstance(data, ztsUrl, opts, region, sysLogger)
		if err != nil {
			logutil.LogFatal(sysLogger, "Register identity failed, err: %v\n", err)
		}
		logutil.LogInfo(sysLogger, "identity registered for services: %s\n", svcs)
	case "rotate":
		err = sia.RefreshInstance(data, ztsUrl, opts, region, sysLogger)
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
			err := sia.RegisterInstance(data, ztsUrl, opts, region, sysLogger)
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
					data, err = getAttestationData(opts, region, taskId, sysLogger)
					if err != nil {
						errors <- fmt.Errorf("Cannot get attestation data: %v\n", err)
						return
					}
					err = sia.RefreshInstance(data, ztsUrl, opts, region, sysLogger)
					if err != nil {
						errors <- fmt.Errorf("refresh identity failed: %v\n", err)
						return
					}
					logutil.LogInfo(sysLogger, "identity successfully refreshed for services: %s\n", svcs)
				} else {
					initialSetup = false
				}
				sia.GetRoleCertificate(ztsUrl,
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
			logutil.LogInfo(sysLogger, "%v\n", err)
		}
	}
	os.Exit(0)
}
