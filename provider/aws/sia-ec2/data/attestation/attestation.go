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

package attestation

import (
	"encoding/json"
	"fmt"
	"github.com/aws/aws-sdk-go/service/sts"
	"github.com/yahoo/athenz/provider/aws/sia-ec2/logutil"
	"github.com/yahoo/athenz/provider/aws/sia-ec2/stssession"
	"io"
	"io/ioutil"
	"log"
	"os"
	"strings"
)

type AttestationData struct {
	Role      string `json:"role,omitempty"`      //the IAM role. This must match the athenz service identity
	Access    string `json:"access,omitempty"`    //the temp creds access key id
	Secret    string `json:"secret,omitempty"`    //the temp creds secret key
	Token     string `json:"token,omitempty"`     //the temp creds session token
	Document  string `json:"document,omitempty"`  //for EC2 instance document
	Signature string `json:"signature,omitempty"` //for EC2 instance document pkcs7 signature
	TaskId    string `json:"taskid,omitempty"`    //for ECS Task Id
}

// New creates a new AttestationData with values fed to it and from the result of STS Assume Role
func New(domain, service string, document, signature []byte, useRegionalSTS bool, sysLogger io.Writer) (*AttestationData, error) {

	role := fmt.Sprintf("%s.%s", domain, service)

	// Extract the accountId from document
	var docMap map[string]interface{}
	err := json.Unmarshal(document, &docMap)
	if err != nil {
		logutil.LogInfo(sysLogger, "unable to parse host info document: %v\n", err)
		return nil, err
	}
	account := docMap["accountId"].(string)

	// Attempt STS AssumeRole
	stsSession, err := stssession.New(useRegionalSTS, docMap["region"].(string), sysLogger)
	if err != nil {
		logutil.LogInfo(sysLogger, "unable to create new session: %v\n", err)
		return nil, err
	}
	stsService := sts.New(stsSession)
	roleArn := fmt.Sprintf("arn:aws:iam::%s:role/%s", account, role)
	logutil.LogInfo(sysLogger, "trying to assume role: %v\n", roleArn)
	tok, err := stsService.AssumeRole(&sts.AssumeRoleInput{
		RoleArn:         &roleArn,
		RoleSessionName: &role,
	})
	if err != nil {
		return nil, err
	}

	return &AttestationData{
		Role:      role,
		Document:  string(document),
		Signature: string(signature),
		Access:    *tok.Credentials.AccessKeyId,
		Secret:    *tok.Credentials.SecretAccessKey,
		Token:     *tok.Credentials.SessionToken,
		TaskId:    getECSTaskId(),
	}, nil
}

func getECSTaskId() string {
	ecs := os.Getenv("ECS_CONTAINER_METADATA_FILE")
	if ecs == "" {
		return ""
	}
	ecsMetaData, err := ioutil.ReadFile(ecs)
	if err != nil {
		return ""
	}
	log.Printf("Content: %s", ecsMetaData)
	var docMap map[string]interface{}
	err = json.Unmarshal(ecsMetaData, &docMap)
	if err != nil {
		return ""
	}
	taskArn := docMap["TaskARN"].(string)
	arn := strings.Split(taskArn, ":")
	if len(arn) < 6 {
		return ""
	}
	taskComps := strings.Split(arn[5], "/")
	if taskComps[0] != "task" {
		return ""
	}
	var taskId string
	lenComps := len(taskComps)
	if lenComps == 2 || lenComps == 3 {
		taskId = taskComps[lenComps-1]
	} else {
		return ""
	}
	return taskId
}
