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
	"github.com/AthenZ/athenz/libs/go/sia/ssh/hostkey"
	"github.com/AthenZ/athenz/libs/go/sia/util"
	"log"
	"os"
	"strings"

	"github.com/AthenZ/athenz/libs/go/sia/agent"
	"github.com/AthenZ/athenz/libs/go/sia/gcp/meta"
	"github.com/AthenZ/athenz/libs/go/sia/options"
	"github.com/AthenZ/athenz/provider/gcp/sia-gce"
)

// Following can be set by the build script using LDFLAGS

var Version string

const siaMainDir = "/var/lib/sia"
const sshDir = "/etc/ssh"

func main() {
	cmd := flag.String("cmd", "", "optional sub command to run")
	gceMetaEndPoint := flag.String("meta", "http://169.254.169.254:80", "meta endpoint")
	ztsEndPoint := flag.String("zts", "", "Athenz Token Service (ZTS) endpoint")
	ztsServerName := flag.String("ztsservername", "", "ZTS server name for tls connections (optional)")
	ztsCACert := flag.String("ztscacert", "", "Athenz Token Service (ZTS) CA certificate file (optional)")
	dnsDomains := flag.String("dnsdomains", "", "DNS Domains associated with the provider")
	ztsPort := flag.Int("ztsport", 4443, "Athenz Token Service (ZTS) port number")
	pConf := flag.String("config", "/etc/sia/sia_config", "The config file to run against")
	providerPrefix := flag.String("providerprefix", "", "Provider name prefix e.g athenz.gcp")
	udsPath := flag.String("uds", "", "uds path")
	noSysLog := flag.Bool("nosyslog", false, "turn off syslog, log to stdout")
	displayVersion := flag.Bool("version", false, "Display version information")
	accessProfileConf := flag.String("profileconfig", "/etc/sia/profile_config", "The user access management profile config file")

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
		log.Fatalln("missing zts argument")
	}
	ztsUrl := fmt.Sprintf("https://%s:%d/zts/v1", *ztsEndPoint, *ztsPort)

	if *dnsDomains == "" {
		log.Fatalln("missing dnsdomains argument")
	}

	if *providerPrefix == "" {
		log.Fatalln("missing providerprefix argument")
	}

	log.Printf("SIA-GCE version: %s \n", Version)
	region := meta.GetRegion(*gceMetaEndPoint)

	provider := sia.GCEProvider{
		Name: fmt.Sprintf("%s.%s", *providerPrefix, region),
	}

	config, accessProfileConfig, err := sia.GetGCEConfig(*pConf, *accessProfileConf, *gceMetaEndPoint, region, provider)
	if err != nil {
		log.Fatalf("Unable to formulate configuration objects, error: %v\n", err)
	}

	// backward compatibility sake, keeping the ConfigAccount struct
	configAccount := &options.ConfigAccount{
		Name:         fmt.Sprintf("%s.%s", config.Domain, config.Service),
		User:         config.User,
		Group:        config.Group,
		Domain:       config.Domain,
		Account:      config.Account,
		Service:      config.Service,
		Zts:          config.Zts,
		Threshold:    config.Threshold,
		SshThreshold: config.SshThreshold,
		Roles:        config.Roles,
	}

	opts, err := options.NewOptions(config, configAccount, accessProfileConfig, siaMainDir, Version, false, region)
	if err != nil {
		log.Fatalf("Unable to formulate options, error: %v\n", err)
	}

	instanceId, err := meta.GetInstanceId(*gceMetaEndPoint)
	if err != nil {
		log.Fatalf("Unable to get instance id, error: %v\n", err)
	}

	// not being able to get an instance name is not a fatal error
	instanceName, err := meta.GetInstanceName(*gceMetaEndPoint)
	if err != nil {
		instanceName = ""
		log.Printf("Unable to get instance name, error: %v\n", err)
	}

	privateIp, err := meta.GetInstancePrivateIp(*gceMetaEndPoint)
	if err != nil {
		log.Fatalf("Unable to get instance private ip, error: %v\n", err)
	}

	if *udsPath != "" {
		opts.SDSUdsPath = *udsPath
	}

	opts.MetaEndPoint = *gceMetaEndPoint
	opts.Ssh = true
	opts.ZTSCACertFile = *ztsCACert
	opts.ZTSServerName = *ztsServerName
	opts.ZTSCloudDomains = strings.Split(*dnsDomains, ",")
	opts.InstanceId = instanceId
	opts.InstanceName = instanceName
	opts.Provider = provider
	opts.PrivateIp = privateIp
	opts.SpiffeNamespace = "default"

	// Better defaults
	opts.RotateKey = true
	opts.GenerateRoleKey = true
	opts.SshHostKeyType = hostkey.Ecdsa
	opts.SshCertFile = hostkey.CertFile(sshDir, opts.SshHostKeyType)
	opts.SshPubKeyFile = hostkey.PubKeyFile(sshDir, opts.SshHostKeyType)

	agent.SetupAgent(opts, siaMainDir, "")
	agent.RunAgent(*cmd, ztsUrl, opts)
}
