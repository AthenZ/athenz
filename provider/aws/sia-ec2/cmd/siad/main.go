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
	"flag"
	"fmt"
	"log"
	"os"
	"strings"

	"github.com/AthenZ/athenz/libs/go/sia/aws/agent"
	"github.com/AthenZ/athenz/libs/go/sia/aws/options"
	"github.com/AthenZ/athenz/libs/go/sia/logutil"
	"github.com/AthenZ/athenz/libs/go/sia/util"
	"github.com/AthenZ/athenz/provider/aws/sia-ec2"
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

	flag.Parse()

	if *displayVersion {
		fmt.Println(Version)
		os.Exit(0)
	}

	if *ztsEndPoint == "" {
		logutil.LogFatal(os.Stderr, "missing zts argument\n")
	}
	ztsUrl := fmt.Sprintf("https://%s:%d/zts/v1", *ztsEndPoint, *ztsPort)

	if *dnsDomains == "" {
		logutil.LogFatal(os.Stderr, "missing dnsdomains argument\n")
	}

	if *providerPrefix == "" {
		logutil.LogFatal(os.Stderr, "missing providerprefix argument\n")
	}

	sysLogger, err := util.NewSysLogger()
	if err != nil {
		log.Printf("Unable to create sys logger: %v\n", err)
		sysLogger = os.Stdout
	}

	//obtain the ec2 document details
	document, signature, account, instanceId, region, startTime, err := sia.GetEC2DocumentDetails(*ec2MetaEndPoint)
	if err != nil {
		logutil.LogFatal(sysLogger, "Unable to extract document details: %v", err)
	}

	config, configAccount, err := sia.GetEC2Config(*pConf, *ec2MetaEndPoint, *useRegionalSTS, region, account, sysLogger)
	if err != nil {
		logutil.LogFatal(sysLogger, "Unable to formulate configuration objects, error: %v", err)
	}

	opts, err := options.NewOptions(config, configAccount, siaMainDir, Version, *useRegionalSTS, region, sysLogger)
	if err != nil {
		logutil.LogFatal(sysLogger, "Unable to formulate options, error: %v", err)
	}

	opts.Ssh = false
	opts.EC2Document = string(document)
	opts.EC2Signature = string(signature)
	opts.ZTSCACertFile = *ztsCACert
	opts.ZTSServerName = *ztsServerName
	opts.ZTSAWSDomains = strings.Split(*dnsDomains, ",")
	opts.Provider = fmt.Sprintf("%s.%s", *providerPrefix, region)

	//check to see if this is ecs on ec2 and update instance id
	//for ec2 instances we also need to set the start time so
	//can check the expiry check if requested
	taskId := sia.GetECSOnEC2TaskId(sysLogger)
	if taskId != "" {
		opts.InstanceId = taskId
	} else {
		opts.EC2StartTime = startTime
		opts.InstanceId = instanceId
	}

	if *udsPath != "" {
		opts.SDSUdsPath = *udsPath
	}

	agent.RunAgent(*cmd, siaMainDir, ztsUrl, opts, sysLogger)
}
