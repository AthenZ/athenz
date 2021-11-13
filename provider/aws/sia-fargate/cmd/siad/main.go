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
	"io"
	"log"
	"log/syslog"
	"os"
	"strings"

	"github.com/AthenZ/athenz/libs/go/sia/aws/agent"
	"github.com/AthenZ/athenz/libs/go/sia/aws/options"
	"github.com/AthenZ/athenz/libs/go/sia/logutil"
	"github.com/AthenZ/athenz/provider/aws/sia-fargate"
)

// Following can be set by the build script using LDFLAGS

var Version string

const siaMainDir = "/var/lib/sia"

func main() {
	cmd := flag.String("cmd", "", "optional sub command to run")
	ecsMetaEndPoint := flag.String("meta", "http://169.254.170.2", "meta endpoint")
	ztsEndPoint := flag.String("zts", "", "Athenz Token Service (ZTS) endpoint")
	ztsServerName := flag.String("ztsservername", "", "ZTS server name for tls connections (optional)")
	ztsCACert := flag.String("ztscacert", "", "Athenz Token Service (ZTS) CA certificate file (optional)")
	dnsDomains := flag.String("dnsdomains", "", "DNS Domains associated with the provider")
	ztsPort := flag.Int("ztsport", 4443, "Athenz Token Service (ZTS) port number")
	pConf := flag.String("config", "/etc/sia/sia_config", "The config file to run against")
	useRegionalSTS := flag.Bool("regionalsts", false, "Use regional STS endpoint instead of global")
	providerPrefix := flag.String("providerprefix", "", "Provider name prefix e.g athenz.aws")
	displayVersion := flag.Bool("version", false, "Display version information")

	flag.Parse()

	if *displayVersion {
		fmt.Println(Version)
		os.Exit(0)
	}

	var sysLogger io.Writer
	sysLogger, err := syslog.New(syslog.LOG_INFO|syslog.LOG_DAEMON, "siad")
	if err != nil {
		log.Printf("Unable to create sys logger: %v\n", err)
		sysLogger = os.Stdout
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

	account, taskId, region, err := sia.GetFargateData(*ecsMetaEndPoint)
	if err != nil {
		logutil.LogFatal(sysLogger, "Unable to extract fargate task details: %v", err)
	}

	config, configAccount, err := sia.GetFargateConfig(*pConf, *ecsMetaEndPoint, *useRegionalSTS, account, region, sysLogger)
	if err != nil {
		logutil.LogFatal(sysLogger, "Unable to formulate configuration objects, error: %v", err)
	}

	opts, err := options.NewOptions(config, configAccount, siaMainDir, Version, *useRegionalSTS, region, sysLogger)
	if err != nil {
		logutil.LogFatal(sysLogger, "Unable to formulate options, error: %v", err)
	}

	opts.ZTSCACertFile = *ztsCACert
	opts.ZTSServerName = *ztsServerName
	opts.ZTSAWSDomains = strings.Split(*dnsDomains, ",")
	opts.ProviderDomain = *providerPrefix
	opts.TaskId = taskId

	agent.RunAgent(*cmd, siaMainDir, ztsUrl, opts, sysLogger)
}
