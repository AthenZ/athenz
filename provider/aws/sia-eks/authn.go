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

	"github.com/AthenZ/athenz/libs/go/sia/aws/options"
)

func GetEKSPodId() string {
	podId := os.Getenv("HOSTNAME")
	if podId == "" {
		podId = "eksPod"
	}
	return podId
}

func GetEKSConfig(configFile, profileConfigFile, metaEndpoint string, useRegionalSTS bool, region string) (*options.Config, *options.ConfigAccount, *options.AccessProfileConfig, error) {

	config, configAccount, err := options.InitFileConfig(configFile, metaEndpoint, useRegionalSTS, region, "")
	if err != nil {
		log.Printf("Unable to process configuration file '%s': %v\n", configFile, err)
		log.Println("Trying to determine service details from the environment variables...")
		config, configAccount, err = options.InitEnvConfig(config)
		if err != nil {
			log.Printf("Unable to process environment settings: %v\n", err)
			// if we do not have settings in our environment, we're going
			// to use fallback to <domain>.<service>-service naming structure
			log.Println("Trying to determine service name from security credentials...")
			configAccount, _, err = options.InitCredsConfig("-service", "@", useRegionalSTS, region)
			if err != nil {
				log.Printf("Unable to process security credentials: %v\n", err)
				log.Println("Trying to determine service name from profile arn...")
				configAccount, _, err = options.InitProfileConfig(metaEndpoint, "-service", "@")
				if err != nil {
					log.Printf("Unable to determine service name: %v\n", err)
					return config, nil, nil, err
				}
			}
		}
	}
	if config.AccessManagement {
		profileConfig, err := GetEKSAccessProfile(profileConfigFile, metaEndpoint, useRegionalSTS, region)
		if err != nil {
			log.Printf("Unable to determine user access management profile information: %v\n", err)
		}

		return config, configAccount, profileConfig, nil
	}
	return config, configAccount, nil, nil
}

func GetEKSAccessProfile(configFile, metaEndpoint string, useRegionalSTS bool, region string) (*options.AccessProfileConfig, error) {
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
