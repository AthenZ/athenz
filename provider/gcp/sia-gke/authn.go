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

package sia

import (
	"log"
	"os"

	"github.com/AthenZ/athenz/libs/go/sia/host/provider"
	"github.com/AthenZ/athenz/libs/go/sia/options"
)

func GetGKEPodId() string {
	podId := os.Getenv("HOSTNAME")
	if podId == "" {
		podIdBytes, err := os.ReadFile("/etc/hostname")
		if err != nil {
			podId = "gkePod"
		} else {
			podId = string(podIdBytes)
		}
	}
	return podId
}

func GetGKEConfig(configFile, profileConfigFile, metaEndpoint, region string, provider provider.Provider) (*options.Config, *options.AccessProfileConfig, error) {

	config, _, err := options.InitFileConfig(configFile, metaEndpoint, false, region, "", provider)
	if err != nil {
		log.Printf("Unable to process configuration file '%s': %v\n", configFile, err)
		log.Println("Trying to determine service details from the environment variables...")
		config, _, err = options.InitEnvConfig(config, provider)
		if err != nil {
			log.Printf("Unable to process environment settings: %v\n", err)
			// if we do not have settings in our environment, we're going
			// to use fallback to retrieve values from the context ( metadata etc )
			config, _, err = options.InitGenericProfileConfig(metaEndpoint, "-service", "@", provider)
			if err != nil && config == nil {
				log.Printf("Unable to determine project, domain, service etc. from context err=%v\n", err)
				return nil, nil, err
			}
		}
	}

	if config.AccessManagement {
		profileConfig, err := GetGKEAccessProfile(profileConfigFile, metaEndpoint, false, region)
		if err != nil {
			log.Printf("Unable to determine user access management profile information: %v\n", err)
		}
		return config, profileConfig, nil
	}
	return config, nil, nil
}

func GetGKEAccessProfile(configFile, metaEndpoint string, useRegionalSTS bool, region string) (*options.AccessProfileConfig, error) {
	accessProfileConfig, err := options.InitAccessProfileFileConfig(configFile)
	if err != nil {
		log.Printf("Unable to process user access management configuration file '%s': %v\n", configFile, err)
		log.Println("Trying to determine user access management profile details from the environment variables...")
		accessProfileConfig, err = options.InitAccessProfileEnvConfig()
		if err != nil {
			log.Printf("Unable to process environment settings: %v\n", err)
			// if we do not have settings in our environment, we're going
			// to use fallback to <domain>.<service>-service@access-profile naming structure
			log.Println("Trying to determine user access management profile name from security credentials...")
			_, accessProfileConfig, err = options.InitCredsConfig("-service", "@", useRegionalSTS, region)
			// if the profile is empty try to determine access profile info from instance profile
			if accessProfileConfig == nil || accessProfileConfig.Profile == "" {
				if err != nil {
					log.Printf("Unable to obtain user access management profile info from security credentials, err: %v\n", err)
				}
				log.Println("Trying to determine user access management profile details from instance profile arn...")
				_, accessProfileConfig, err = options.InitProfileConfig(metaEndpoint, "-service", "@")
				if err != nil {
					return nil, err
				}
			}
		}
	}
	return accessProfileConfig, err
}
