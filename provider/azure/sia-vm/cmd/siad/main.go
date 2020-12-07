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

package main

import (
	"fmt"
	"github.com/yahoo/athenz/provider/azure/sia-vm"
	"github.com/yahoo/athenz/provider/azure/sia-vm/data/attestation"
	"github.com/yahoo/athenz/provider/azure/sia-vm/logutil"
	"github.com/yahoo/athenz/provider/azure/sia-vm/options"
	"github.com/yahoo/athenz/provider/azure/sia-vm/util"
	"io"
	"io/ioutil"
	"log"
	"log/syslog"
	"os"
	"time"

	"flag"
	"os/signal"
	"syscall"
)

var MetaEndPoint = "http://169.254.169.254"
var ApiVersion = "2020-06-01"

const siaMainDir = "/var/lib/sia"
const siaLinkDir = "/var/run/sia"
const siaVersion = "1.0"

func main() {
	cmd := flag.String("cmd", "", "optional sub command to run")
	metaEndPoint := flag.String("meta", "", "optional meta endpoint to use for debugging")
	ztsEndPoint := flag.String("zts", "", "optional zts endpoint")
	ztsServerName := flag.String("ztsservername", "", "zts server name for tls connections")
	ztsCACert := flag.String("ztscacert", "", "zts CA certificate file")
	ztsAzureDomain := flag.String("ztsazuredomain", "", "ZTS Azure Domain")
	ztsResourceUri := flag.String("ztsresourceuri", "", "ZTS AD App Resource URI")
	countryName := flag.String("countryname", "US", "X.509 Certificate Country Value")
	pConf := flag.String("config", "/etc/sia/sia_config", "The config file to run against")
	noSysLog := flag.Bool("nosyslog", false, "turn off syslog, log to stdout")

	flag.Parse()

	var sysLogger io.Writer
	if *noSysLog {
		sysLogger = os.Stdout
	} else {
		var err error
		sysLogger, err = syslog.New(syslog.LOG_INFO|syslog.LOG_DAEMON, "siad")
		if err != nil {
			log.Printf("Unable to create sys logger: %v\n", err)
			sysLogger = os.Stdout
		}
	}

	if *ztsEndPoint == "" {
		logutil.LogFatal(sysLogger, "ztsEndPoint argument must be specified\n")
	}
	if *ztsAzureDomain == "" {
		logutil.LogFatal(sysLogger, "ztsazuredomain argument must be specified\n")
	}
	if *ztsResourceUri == "" {
		logutil.LogFatal(sysLogger, "ztsresourceuri argument must be specified\n")
	}
	if *metaEndPoint != "" {
		MetaEndPoint = *metaEndPoint
	}

	identityDocument, err := attestation.GetIdentityDocument(MetaEndPoint, ApiVersion, sysLogger)
	if err != nil {
		logutil.LogFatal(sysLogger, "Unable to get the instance identity document, error: %v\n", err)
	}

	confBytes, _ := ioutil.ReadFile(*pConf)
	opts, err := options.NewOptions(confBytes, identityDocument, siaMainDir, siaVersion, *ztsCACert, *ztsServerName, *ztsAzureDomain, *countryName, sysLogger)
	if err != nil {
		logutil.LogFatal(sysLogger, "Unable to formulate options, error: %v\n", err)
	}

	logutil.LogInfo(sysLogger, "options: %+v\n", opts)

	data, err := getAttestationData(*ztsResourceUri, identityDocument, opts, sysLogger)
	if err != nil {
		logutil.LogFatal(sysLogger, "Unable to formulate attestation data, error: %v\n", err)
	}

	// for now we're going to rotate once every day
	// since our server and role certs are valid for
	// 30 days by default
	rotationInterval := 24 * 60 * time.Minute

	ztsUrl := fmt.Sprintf("https://%s:4443/zts/v1", *ztsEndPoint)

	err = util.SetupSIADirs(siaMainDir, siaLinkDir, sysLogger)
	if err != nil {
		logutil.LogFatal(sysLogger, "Unable to setup sia directories, error: %v\n", err)
	}

	logutil.LogInfo(sysLogger, "Request SSH Certificates: %t\n", opts.Ssh)

	svcs := options.GetSvcNames(opts.Services)

	switch *cmd {
	case "rolecert":
		sia.GetRoleCertificate(ztsUrl,
			fmt.Sprintf("%s/%s.%s.key.pem", opts.KeyDir, opts.Domain, opts.Services[0].Name),
			fmt.Sprintf("%s/%s.%s.cert.pem", opts.CertDir, opts.Domain, opts.Services[0].Name),
			opts,
			sysLogger,
		)
	case "post":
		err := sia.RegisterInstance(data, ztsUrl, identityDocument, opts, sysLogger)
		if err != nil {
			logutil.LogFatal(sysLogger, "Register identity failed, err: %v\n", err)
		}
		logutil.LogInfo(sysLogger, "identity registered for services: %s\n", svcs)
	case "rotate":
		err = sia.RefreshInstance(data, ztsUrl, identityDocument, opts, sysLogger)
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
			err := sia.RegisterInstance(data, ztsUrl, identityDocument, opts, sysLogger)
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
					data, err := getAttestationData(*ztsResourceUri, identityDocument, opts, sysLogger)
					if err != nil {
						errors <- fmt.Errorf("Cannot get attestation data: %v\n", err)
						return
					}
					err = sia.RefreshInstance(data, ztsUrl, identityDocument, opts, sysLogger)
					if err != nil {
						errors <- fmt.Errorf("refresh identity failed, error: %v", err)
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

// getAttestationData fetches attestation data for all the services mentioned in the config file
func getAttestationData(resourceUri string, identityDocument *attestation.IdentityDocument, opts *options.Options, sysLogger io.Writer) ([]*attestation.Data, error) {
	var data []*attestation.Data
	for _, svc := range opts.Services {
		a, err := attestation.New(opts.Domain, svc.Name, MetaEndPoint, ApiVersion, resourceUri, identityDocument, sysLogger)
		if err != nil {
			return nil, err
		}
		data = append(data, a)
	}
	return data, nil
}
