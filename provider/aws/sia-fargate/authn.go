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
	"fmt"
	"log"
	"os"

	"github.com/AthenZ/athenz/libs/go/sia/aws/doc"
	"github.com/AthenZ/athenz/libs/go/sia/aws/meta"
	"github.com/AthenZ/athenz/libs/go/sia/aws/options"
	"github.com/AthenZ/athenz/libs/go/sia/util"
)

func GetFargateData(metaEndPoint string) (string, string, string, error) {
	// now we're going to check if we're running within
	// ECS Fargate and retrieve our account number and
	// task id from our data. we're going to use v4 and
	// then fallback to v3 and v2 endpoints
	document, err := meta.GetDataV1(os.Getenv("ECS_CONTAINER_METADATA_URI_V4"), "/task")
	if err != nil {
		document, err = meta.GetDataV1(os.Getenv("ECS_CONTAINER_METADATA_URI"), "/task")
		if err != nil {
			document, err = meta.GetDataV1(metaEndPoint, "/v2/metadata")
			if err != nil {
				return "", "", "", err
			}
		}
	}
	taskArn, err := doc.GetDocumentEntry(document, "TaskARN")
	if err != nil {
		return "", "", "", err
	}
	return util.ParseTaskArn(taskArn)
}

func initTaskConfig(config *options.Config, metaEndpoint string) (*options.Config, *options.ConfigAccount, error) {
	uri := os.Getenv("AWS_CONTAINER_CREDENTIALS_RELATIVE_URI")
	if uri == "" {
		return nil, nil, fmt.Errorf("cannot fetch AWS_CONTAINER_CREDENTIALS_RELATIVE_URI env variable")
	}
	document, err := meta.GetDataV1(metaEndpoint, uri)
	if err != nil {
		return nil, nil, err
	}
	roleArn, err := doc.GetDocumentEntry(document, "RoleArn")
	if err != nil {
		return nil, nil, err
	}
	account, domain, service, _, err := util.ParseRoleArn(roleArn, "role/", "-service", "", false)
	if err != nil {
		return nil, nil, fmt.Errorf("unable to parse athenz role arn: %v", err)
	}
	if account == "" || domain == "" || service == "" {
		return nil, nil, fmt.Errorf("invalid role arn - missing components: %s", roleArn)
	}
	// it is possible that the config object was already created the
	// config file in which case we're not going to override any
	// of the settings.
	if config == nil {
		config = &options.Config{}
	}
	config.Service = service
	return config, &options.ConfigAccount{
		Account: account,
		Domain:  domain,
		Service: service,
		Name:    fmt.Sprintf("%s.%s", domain, service),
	}, nil
}

func GetFargateConfig(configFile, metaEndpoint string, useRegionalSTS bool, account, region string) (*options.Config, *options.ConfigAccount, error) {

	config, configAccount, err := options.InitFileConfig(configFile, metaEndpoint, useRegionalSTS, account, region)
	if err != nil {
		log.Printf("Unable to process configuration file '%s': %v\n", configFile, err)
		log.Println("Trying to determine service details from the environment variables...")
		config, configAccount, err = options.InitEnvConfig(config)
		if err != nil {
			log.Printf("Unable to process environment settings: %v\n", err)
			// if we do not have settings in our environment, we're going
			// to use fallback to <domain>.<service>-service naming structure
			log.Println("Trying to determine service name from task role arn...")
			config, configAccount, err = initTaskConfig(config, metaEndpoint)
			if err != nil {
				log.Printf("Unable to determine service name: %v\n", err)
				return config, nil, err
			}
		}
	}
	return config, configAccount, nil
}
