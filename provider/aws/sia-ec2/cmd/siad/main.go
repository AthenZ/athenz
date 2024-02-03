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
	"flag"
	"fmt"
	"github.com/AthenZ/athenz/libs/go/sia/aws/options"
	"github.com/AthenZ/athenz/libs/go/sia/util"
	"github.com/AthenZ/athenz/provider/aws/sia-ec2"
	"log"
	"os"
	"strings"

	"github.com/AthenZ/athenz/libs/go/sia/aws/agent"
)

// Following can be set by the build script using LDFLAGS

var Version string

const siaMainDir = "/var/lib/sia"

func main() {
	cmd := flag.String("cmd", "", "optional sub command to run")
	ec2MetaEndPoint := flag.String("meta", "http://169.254.169.254:80", "meta endpoint")
	ztsEndPoint := flag.String("zts", "", "Athenz Token Service (ZTS) endpoint")
	ztsServerName := flag.String("ztsservername", "", "ZTS server name for tls connections (optional)")
	ztsCACert := flag.String("ztscacert", "", "Athenz Token Service (ZTS) CA certificate file (optional)")
	dnsDomains := flag.String("dnsdomains", "", "DNS Domains associated with the provider")
	ztsPort := flag.Int("ztsport", 4443, "Athenz Token Service (ZTS) port number")
	pConf := flag.String("config", "/etc/sia/sia_config", "The config file to run against")
	useRegionalSTS := flag.Bool("regionalsts", false, "Use regional STS endpoint instead of global")
	providerPrefix := flag.String("providerprefix", "", "Provider name prefix e.g athenz.aws")
	displayVersion := flag.Bool("version", false, "Display version information")
	udsPath := flag.String("uds", "", "uds path")
	noSysLog := flag.Bool("nosyslog", false, "turn off syslog, log to stdout")
	accessProfileConf := flag.String("profileconfig", "/etc/sia/profile_config", "The access profile config file")
	accessProfileTagKey := flag.String("profiletagkey", "profile:Tag", "The tag associated with access profile roles")
	flag.Parse()

	if *displayVersion {
		fmt.Println(Version)
		os.Exit(0)
	}

	if !*noSysLog {
		sysLogger, err := util.NewSysLogger()
		if err == nil {
			log.SetOutput(sysLogger)
			log.SetFlags(0)
		} else {
			log.SetFlags(log.LstdFlags)
			log.Printf("Unable to create sys logger: %v\n", err)
		}
	} else {
		log.SetFlags(log.LstdFlags)
	}

	if *ztsEndPoint == "" {
		log.Fatalf("missing zts argument\n")
	}
	ztsUrl := fmt.Sprintf("https://%s:%d/zts/v1", *ztsEndPoint, *ztsPort)

	if *dnsDomains == "" {
		log.Fatalf("missing dnsdomains argument\n")
	}

	if *providerPrefix == "" {
		log.Fatalf("missing providerprefix argument\n")
	}

	log.Printf("SIA-EC2 version: %s \n", Version)

	//obtain the ec2 document details
	document, signature, account, instanceId, region, privateIp, startTime, err := sia.GetEC2DocumentDetails(*ec2MetaEndPoint)
	if err != nil {
		log.Fatalf("Unable to extract document details: %v\n", err)
	}

	config, configAccount, accessProfileConfig, err := sia.GetEC2Config(*pConf, *accessProfileConf, *accessProfileTagKey, *ec2MetaEndPoint, *useRegionalSTS, region, account)
	if err != nil {
		log.Fatalf("Unable to formulate configuration objects, error: %v\n", err)
	}

	opts, err := options.NewOptions(config, configAccount, accessProfileConfig, siaMainDir, Version, *useRegionalSTS, region)
	if err != nil {
		log.Fatalf("Unable to formulate options, error: %v\n", err)
	}

	opts.MetaEndPoint = *ec2MetaEndPoint
	opts.Ssh = false
	opts.EC2Document = string(document)
	opts.EC2Signature = string(signature)
	opts.PrivateIp = privateIp
	opts.ZTSCACertFile = *ztsCACert
	opts.ZTSServerName = *ztsServerName
	opts.ZTSAWSDomains = strings.Split(*dnsDomains, ",")
	opts.SpiffeNamespace = "default"

	provider := sia.EC2Provider{
		Name: fmt.Sprintf("%s.%s", *providerPrefix, region),
	}
	opts.Provider = provider

	//check to see if this is ecs on ec2 and update instance id
	//for ec2 instances we also need to set the start time so
	//can check the expiry check if requested
	taskId := sia.GetECSOnEC2TaskId()
	if taskId != "" {
		opts.InstanceId = taskId
	} else {
		opts.EC2StartTime = startTime
		opts.InstanceId = instanceId
	}

	if *udsPath != "" {
		opts.SDSUdsPath = *udsPath
	}

	agent.SetupAgent(opts, siaMainDir, "")
	agent.RunAgent(*cmd, ztsUrl, opts)
}
