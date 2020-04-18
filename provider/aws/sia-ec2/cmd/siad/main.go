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
	"bytes"
	"fmt"
	"github.com/yahoo/athenz/provider/aws/sia-ec2"
	"github.com/yahoo/athenz/provider/aws/sia-ec2/data/attestation"
	"github.com/yahoo/athenz/provider/aws/sia-ec2/data/doc"
	"github.com/yahoo/athenz/provider/aws/sia-ec2/data/meta"
	"github.com/yahoo/athenz/provider/aws/sia-ec2/logutil"
	"github.com/yahoo/athenz/provider/aws/sia-ec2/options"
	"github.com/yahoo/athenz/provider/aws/sia-ec2/util"
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
)

var MetaEndPoint = "http://169.254.169.254:80"

const siaMainDir = "/var/lib/sia"
const siaLinkDir = "/var/run/sia"
const siaVersion = "1.0"

func main() {
	cmd := flag.String("cmd", "", "optional sub command to run")
	metaEndPoint := flag.String("meta", "", "optional meta endpoint to use for debugging")
	ztsEndPoint := flag.String("zts", "", "optional zts endpoint")
	ztsServerName := flag.String("ztsservername", "", "zts server name for tls connections")
	ztsCACert := flag.String("ztscacert", "", "zts CA certificate file")
	ztsAwsDomain := flag.String("ztsawsdomain", "", "ZTS AWS Domain")
	pConf := flag.String("config", "/etc/sia/sia_config", "The config file to run against")

	flag.Parse()

	var sysLogger io.Writer
	sysLogger, err := syslog.New(syslog.LOG_INFO|syslog.LOG_DAEMON, "siad")
	if err != nil {
		log.Printf("Unable to create sys logger: %v\n", err)
		sysLogger = os.Stdout
	}

	if *ztsAwsDomain == "" {
		logutil.LogFatal(sysLogger, "ztsawsdomain argument must be specified")
	}

	document, err := meta.GetData(MetaEndPoint, "/latest/dynamic/instance-identity/document")
	if err != nil {
		logutil.LogFatal(sysLogger, "Unable to get the instance identity document, error: %v", err)
	}

	signature, err := meta.GetData(MetaEndPoint, "/latest/dynamic/instance-identity/pkcs7")
	if err != nil {
		logutil.LogFatal(sysLogger, "Unable to get the instance document signature, error: %v", err)
	}

	accountId, err := doc.GetAccountId(document)
	if err != nil {
		logutil.LogFatal(sysLogger, "Unable to get the instance account id, error: %v", err)
	}

	if *metaEndPoint != "" {
		MetaEndPoint = *metaEndPoint
	}

	confBytes, _ := ioutil.ReadFile(*pConf)
	opts, err := options.NewOptions(confBytes, accountId, MetaEndPoint, siaMainDir, siaVersion, *ztsCACert, *ztsServerName, *ztsAwsDomain, sysLogger)
	if err != nil {
		logutil.LogFatal(sysLogger, "Unable to formulate options, error: %v", err)
	}

	log.Printf("options: %+v", opts)

	data, err := getAttestationData(document, signature, opts, sysLogger)
	if err != nil {
		logutil.LogFatal(sysLogger, "Unable to formulate attestation data, error: %v", err)
	}

	//for now we're going to rotate once every day
	//since our server and role certs are valid for
	//30 days by default
	rotationInterval := 24 * 60 * time.Minute

	ztsUrl := fmt.Sprintf("https://%s:4443/zts/v1", *ztsEndPoint)

	err = util.SetupSIADirs(siaMainDir, siaLinkDir, sysLogger)
	if err != nil {
		logutil.LogFatal(sysLogger, "Unable to setup sia directories, error: %v", err)
	}

	logutil.LogInfo(sysLogger, "Request SSH Certificates: %t", opts.Ssh)

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
		err := sia.RegisterInstance(data, document, ztsUrl, opts, false, sysLogger)
		if err != nil {
			logutil.LogFatal(sysLogger, "Register identity failed, err: %v", err)
		}
		logutil.LogInfo(sysLogger, "identity registered for services: %s", svcs)
	case "rotate":
		err = sia.RefreshInstance(data, ztsUrl, opts, sysLogger)
		if err != nil {
			logutil.LogFatal(sysLogger, "Refresh identity failed, err: %v", err)
		}
		logutil.LogInfo(sysLogger, "Identity successfully refreshed for services: %s", svcs)
	default:
		// if we already have a cert file then we're not going to
		// prove our identity since most likely it will not succeed
		// due to boot time check (this could be just a regular
		// service restart for any reason). Instead, we'll just skip
		// over and try to rotate the certs

		initialSetup := true
		if files, err := ioutil.ReadDir(opts.CertDir); err != nil || len(files) <= 0 {
			err := sia.RegisterInstance(data, document, ztsUrl, opts, false, sysLogger)
			if err != nil {
				logutil.LogFatal(sysLogger, "Register identity failed, error: %v", err)
			}
		} else {
			initialSetup = false
			logutil.LogInfo(sysLogger, "Identity certificate file already exists. Retrieving identity details...")
		}
		logutil.LogInfo(sysLogger, "Identity established for services: %s", svcs)

		stop := make(chan bool, 1)
		errors := make(chan error, 1)

		go func() {
			for {
				logutil.LogInfo(sysLogger, "Identity being used: %s\n", opts.Name)

				// if we just did our initial setup there is no point
				// to refresh the certs again. so we are going to skip
				// this time around and refresh certs next time

				if !initialSetup {
					data, err := getAttestationData(document, signature, opts, sysLogger)
					if err != nil {
						errors <- fmt.Errorf("Cannot get attestation data: %v\n", err)
						return
					}
					err = sia.RefreshInstance(data, ztsUrl, opts, sysLogger)
					if err != nil {
						errors <- fmt.Errorf("refresh identity failed, error: %v", err)
						return
					}
					logutil.LogInfo(sysLogger, "identity successfully refreshed for services: %s", svcs)
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
			logutil.LogInfo(sysLogger, "Received signal %v, stopping rotation", sig)
			stop <- true
		}()

		err = <-errors
		if err != nil {
			logutil.LogInfo(sysLogger, "%v", err)
		}
	}
	os.Exit(0)
}

// getSvcNames returns command separated list of service names
func getSvcNames(svcs []options.Service) string {
	var b bytes.Buffer
	for _, svc := range svcs {
		b.WriteString(fmt.Sprintf("%s,", svc.Name))
	}
	return strings.TrimSuffix(b.String(), ",")
}

// getAttestationData fetches attestation data for all the services mentioned in the config file
func getAttestationData(document, signature []byte, opts *options.Options, sysLogger io.Writer) ([]*attestation.AttestationData, error) {
	data := []*attestation.AttestationData{}
	for _, svc := range opts.Services {
		a, err := attestation.New(opts.Domain, svc.Name, document, signature, opts.UseRegionalSTS, sysLogger)
		if err != nil {
			return nil, err
		}
		data = append(data, a)
	}
	return data, nil
}
