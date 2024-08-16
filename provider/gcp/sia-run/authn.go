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
	"github.com/AthenZ/athenz/libs/go/sia/host/provider"
	"github.com/AthenZ/athenz/libs/go/sia/options"
	"log"
)

func GetRunConfig(configFile, metaEndpoint, region string, provider provider.Provider) (*options.Config, error) {

	config, _, err := options.InitFileConfig(configFile, metaEndpoint, false, region, "", provider)
	if err != nil {
		log.Printf("Unable to process configuration file '%s': %v\n", configFile, err)
		log.Println("Trying to determine service details from the environment variables...")
		config, _, err = options.InitEnvConfig(config, provider)
		if err != nil {
			log.Printf("Unable to process environment settings: %v\n", err)
			// if we do not have settings in our environment, we're going
			// to use fallback to retrieve values from the context ( metadata etc. )
			config, _, err = options.InitGenericProfileConfig(metaEndpoint, "", "", provider)
			if err != nil {
				log.Printf("Unable to determine project, domain, service etc. from context err=%v\n", err)
				return nil, err
			}
		}
	}
	return config, nil
}
