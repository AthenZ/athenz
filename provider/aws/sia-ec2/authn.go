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
	"encoding/json"
	"github.com/AthenZ/athenz/libs/go/sia/aws/options"
	"github.com/AthenZ/athenz/libs/go/sia/util"
	"log"
	"os"
	"time"

	"github.com/AthenZ/athenz/libs/go/sia/aws/meta"
)

func getDocValue(docMap map[string]interface{}, key string) string {
	value := docMap[key]
	if value == nil {
		return ""
	} else {
		return value.(string)
	}
}

func GetEC2DocumentDetails(metaEndPoint string) ([]byte, []byte, string, string, string, string, *time.Time, error) {
	document, err := meta.GetData(metaEndPoint, "/latest/dynamic/instance-identity/document")
	if err != nil {
		return nil, nil, "", "", "", "", nil, err
	}
	signature, err := meta.GetData(metaEndPoint, "/latest/dynamic/instance-identity/pkcs7")
	if err != nil {
		return nil, nil, "", "", "", "", nil, err
	}
	var docMap map[string]interface{}
	err = json.Unmarshal(document, &docMap)
	if err != nil {
		return nil, nil, "", "", "", "", nil, err
	}
	account := getDocValue(docMap, "accountId")
	region := getDocValue(docMap, "region")
	instanceId := getDocValue(docMap, "instanceId")
	privateIp := getDocValue(docMap, "privateIp")

	timeCheck, _ := time.Parse(time.RFC3339, getDocValue(docMap, "pendingTime"))
	return document, signature, account, instanceId, region, privateIp, &timeCheck, err
}

func GetEC2PublicIP(metaEndPoint string) (string, error) {
	publicIP, err := meta.GetData(metaEndPoint, "/latest/meta-data/public-ipv4")
	if err != nil {
		return "", err
	}
	return string(publicIP), nil
}

func GetECSOnEC2TaskId() string {
	ecs := os.Getenv("ECS_CONTAINER_METADATA_FILE")
	if ecs == "" {
		log.Println("Not ECS on EC2 instance")
		return ""
	}
	ecsMetaData, err := os.ReadFile(ecs)
	if err != nil {
		log.Printf("Unable to read ECS on EC2 instance metadata: %s - %v\n", ecs, err)
		return ""
	}
	var docMap map[string]interface{}
	err = json.Unmarshal(ecsMetaData, &docMap)
	if err != nil {
		log.Printf("Unable to parse ECS on EC2 instance metadata: %s - %v\n", ecs, err)
		return ""
	}
	taskArn := getDocValue(docMap, "TaskARN")
	_, taskId, _, err := util.ParseTaskArn(taskArn)
	if err != nil {
		log.Printf("Unable to parse ECS on EC2 task id: %s - %v\n", taskArn, err)
		return ""
	}
	return taskId
}

func GetEC2Config(configFile, profileConfigFile, profileRestrictToKey, metaEndpoint string, useRegionalSTS bool, region, account string) (*options.Config, *options.ConfigAccount, *options.AccessProfileConfig, error) {
	config, configAccount, err := options.InitFileConfig(configFile, metaEndpoint, useRegionalSTS, region, account)
	if err != nil {
		log.Printf("Unable to process configuration file '%s': %v\n", configFile, err)
		log.Println("Trying to determine service details from the environment variables...")
		config, configAccount, err = options.InitEnvConfig(config)
		if err != nil {
			log.Printf("Unable to process environment settings: %v\n", err)
			// if we do not have settings in our environment, we're going
			// to use fallback to <domain>.<service>-service naming structure
			log.Println("Trying to determine service name security credentials...")
			configAccount, _, err = options.InitCredsConfig("-service", "@", useRegionalSTS, region)
			if err != nil {
				log.Printf("Unable to process security credentials: %v\n", err)
				log.Println("Trying to determine service name from profile arn...")
				configAccount, _, err = options.InitProfileConfig(metaEndpoint, "-service", "@")
				if err != nil {
					return config, nil, nil, err
				}
			}
		}
	}

	profileConfig, err := GetEC2AccessProfile(profileConfigFile, profileRestrictToKey, metaEndpoint, useRegionalSTS, region)
	if err != nil {
		log.Printf("Unable to determine profile information: %v\n", err)
	}

	return config, configAccount, profileConfig, nil
}

func GetEC2AccessProfile(configFile, profileRestrictToKey, metaEndpoint string, useRegionalSTS bool, region string) (*options.AccessProfileConfig, error) {
	accessProfileConfig, err := options.InitAccessProfileFileConfig(configFile)
	if err != nil {
		log.Printf("Unable to process configuration file '%s': %v\n", configFile, err)
		log.Println("Trying to determine profile details from the environment variables...")
		accessProfileConfig, err = options.InitAccessProfileEnvConfig()
		if err != nil {
			log.Printf("Unable to process environment settings: %v\n", err)
			// if we do not have settings in our environment, we're going
			// to use fallback to <domain>.<service>-service@access-profile naming structure
			log.Println("Trying to determine profile name from security credentials...")
			_, accessProfileConfig, err = options.InitCredsConfig("-service", "@", useRegionalSTS, region)
			// if the profile is empty try to determine access profile info from instance profile
			if accessProfileConfig == nil || accessProfileConfig.Profile == "" {
				if err != nil {
					log.Printf("Unable to obtain access profile info from security credentials, err: %v\n", err)
				}
				log.Println("Trying to determine access profile details from instance profile arn...")
				_, accessProfileConfig, err = options.InitProfileConfig(metaEndpoint, "-service", "@")
				if err != nil {
					return nil, err
				}
			}
		}
	}

	// If tags is not provided through file then check if value is provided through ec2 instance tags
	if accessProfileConfig.ProfileRestrictTo == "" && profileRestrictToKey != "" {
		log.Printf("Trying to determine profile tag value %v from instance tags\n", profileRestrictToKey)
		value, err := options.GetInstanceTagValue(metaEndpoint, profileRestrictToKey)
		if err == nil {
			accessProfileConfig.ProfileRestrictTo = value
		}
	}

	return accessProfileConfig, err
}
