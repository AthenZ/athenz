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
	"log"
	"os"
	"strings"

	"github.com/AthenZ/athenz/libs/go/sia/aws/agent"
	"github.com/AthenZ/athenz/libs/go/sia/aws/options"
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
	udsPath := flag.String("uds", "", "uds path")

	flag.Parse()

	if *displayVersion {
		fmt.Println(Version)
		os.Exit(0)
	}

	log.SetFlags(log.LstdFlags)

	if *ztsEndPoint == "" {
		log.Fatalln("missing zts argument")
	}
	ztsUrl := fmt.Sprintf("https://%s:%d/zts/v1", *ztsEndPoint, *ztsPort)

	if *dnsDomains == "" {
		log.Fatalln("missing dnsdomains argument")
	}

	if *providerPrefix == "" {
		log.Fatalln("missing providerprefix argument")
	}

	log.Printf("SIA-Fargate version: %s \n", Version)

	account, taskId, region, err := sia.GetFargateData(*ecsMetaEndPoint)
	if err != nil {
		log.Fatalf("Unable to extract fargate task details: %v\n", err)
	}

	config, configAccount, err := sia.GetFargateConfig(*pConf, *ecsMetaEndPoint, *useRegionalSTS, account, region)
	if err != nil {
		log.Fatalf("Unable to formulate configuration objects, error: %v\n", err)
	}

	opts, err := options.NewOptions(config, configAccount, nil, siaMainDir, Version, *useRegionalSTS, region)
	if err != nil {
		log.Fatalf("Unable to formulate options, error: %v\n", err)
	}

	opts.MetaEndPoint = *ecsMetaEndPoint
	opts.Ssh = false
	opts.ZTSCACertFile = *ztsCACert
	opts.ZTSServerName = *ztsServerName
	opts.ZTSAWSDomains = strings.Split(*dnsDomains, ",")
	opts.InstanceId = taskId

	if *udsPath != "" {
		opts.SDSUdsPath = *udsPath
	}

	provider := sia.FargateProvider{
		Name: fmt.Sprintf("%s.%s", *providerPrefix, region),
	}
	opts.Provider = provider

	agent.SetupAgent(opts, siaMainDir, "")
	agent.RunAgent(*cmd, ztsUrl, opts)
}
