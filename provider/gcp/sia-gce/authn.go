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

	sc "github.com/AthenZ/athenz/libs/go/sia/config"
	"github.com/AthenZ/athenz/libs/go/sia/host/provider"
	"github.com/AthenZ/athenz/libs/go/sia/options"
)

func GetGCEConfig(configFile, profileConfigFile, profileRestrictToKey, metaEndpoint, region string, provider provider.Provider) (*sc.Config, *sc.AccessProfileConfig, error) {

	var profileConfig *sc.AccessProfileConfig
	config, _, err := options.InitFileConfig(configFile, metaEndpoint, false, region, "", provider)
	if err != nil {
		log.Printf("Unable to process configuration file '%s': %v\n", configFile, err)
		log.Println("Trying to determine service details from the environment variables...")
		config, _, err = options.InitEnvConfig(config, provider)
		if err != nil {
			log.Printf("Unable to process environment settings: %v\n", err)
			// if we do not have settings in our environment, we're going
			// to use fallback to retrieve values from the context ( metadata etc )
			config, profileConfig, err = options.InitGenericProfileConfig(metaEndpoint, "", "", provider)
			if err != nil {
				log.Printf("Unable to determine project, domain, service etc. from context err=%v\n", err)
				return nil, nil, err
			}
		}
	}
	if profileConfig == nil {
		profileConfig, err = GetGCEAccessProfile(profileConfigFile, profileRestrictToKey, metaEndpoint, provider)
		if err != nil {
			log.Printf("Unable to determine user access management profile information: %v\n", err)
		}
	}
	if profileConfig != nil && profileConfig.ProfileRestrictTo == "" && profileRestrictToKey != "" {
		log.Printf("Trying to determine profile tag value %v from instance tags\n", profileRestrictToKey)
		value, err := provider.GetInstanceAttributeValueFromMeta(metaEndpoint, profileRestrictToKey)
		if err == nil {
			profileConfig.ProfileRestrictTo = value
		}
	}

	return config, profileConfig, nil
}

func GetGCEAccessProfile(configFile, profileRestrictToKey, metaEndpoint string, provider provider.Provider) (*sc.AccessProfileConfig, error) {
	accessProfileConfig, err := options.InitAccessProfileFileConfig(configFile)
	if err != nil {
		log.Printf("Unable to process user access management configuration file '%s': %v\n", configFile, err)
		log.Println("Trying to determine user access management profile details from the environment variables...")
		accessProfileConfig, err = options.InitAccessProfileEnvConfig()
		if err != nil {
			log.Printf("Unable to process environment settings: %v\n", err)
			// if we do not have settings in our environment, we're going
			// to use fallback to retrieving access profile from meta
			log.Println("Trying to determine user access management profile details from GCP context")
			_, accessProfileConfig, err = options.InitGenericProfileConfig(metaEndpoint, "", "", provider)
			if err != nil {
				return nil, err
			}
		}
	}

	return accessProfileConfig, err
}
