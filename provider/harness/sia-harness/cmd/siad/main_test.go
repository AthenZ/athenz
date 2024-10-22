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
	"github.com/stretchr/testify/assert"
	"testing"
)

func TestGetInstanceId(t *testing.T) {
	claims := map[string]interface{}{
		"organization_id": "org",
		"project_id":      "project",
		"pipeline_id":     "pipeline",
		"context":         "triggerType:manual/triggerId:trigger/sequenceId:1",
	}
	instanceId, err := getInstanceId(claims)
	assert.Nil(t, err)
	assert.Equal(t, "org:project:pipeline:1", instanceId)
}

func TestGetInstanceIdMissingOrgId(t *testing.T) {
	claims := map[string]interface{}{
		"project_id":  "project",
		"pipeline_id": "pipeline",
		"context":     "triggerType:manual/triggerId:trigger/sequenceId:1",
	}
	_, err := getInstanceId(claims)
	assert.NotNil(t, err)
	assert.Equal(t, "unable to extract organization_id from oidc token claims", err.Error())
}

func TestGetInstanceIdMissingProjectId(t *testing.T) {
	claims := map[string]interface{}{
		"organization_id": "org",
		"pipeline_id":     "pipeline",
		"context":         "triggerType:manual/triggerId:trigger/sequenceId:1",
	}
	_, err := getInstanceId(claims)
	assert.NotNil(t, err)
	assert.Equal(t, "unable to extract project_id from oidc token claims", err.Error())
}

func TestGetInstanceIdMissingPipelineId(t *testing.T) {
	claims := map[string]interface{}{
		"organization_id": "org",
		"project_id":      "project",
		"context":         "triggerType:manual/triggerId:trigger/sequenceId:1",
	}
	_, err := getInstanceId(claims)
	assert.NotNil(t, err)
	assert.Equal(t, "unable to extract pipeline_id from oidc token claims", err.Error())
}

func TestGetInstanceIdMissingContext(t *testing.T) {
	claims := map[string]interface{}{
		"organization_id": "org",
		"project_id":      "project",
		"pipeline_id":     "pipeline",
	}
	_, err := getInstanceId(claims)
	assert.NotNil(t, err)
	assert.Equal(t, "unable to extract context from oidc token claims", err.Error())
}

func TestGetInstanceIdMissingOrg(t *testing.T) {
	claims := map[string]interface{}{
		"organization_id": "org",
		"project_id":      "project",
		"pipeline_id":     "pipeline",
		"context":         "triggerType:manual",
	}
	_, err := getInstanceId(claims)
	assert.NotNil(t, err)
	assert.Equal(t, "unable to extract sequenceId from context: triggerType:manual", err.Error())
}

func TestExtractFieldFromContext(t *testing.T) {
	field := extractFieldFromContext("triggerType:manual/triggerId:trigger/sequenceId:1", "sequenceId")
	assert.Equal(t, "1", field)
	field = extractFieldFromContext("triggerType:manual/triggerId:trigger/sequenceId:1", "triggerId")
	assert.Equal(t, "trigger", field)
	field = extractFieldFromContext("triggerType:manual/triggerId:trigger/sequenceId:1", "accountId")
	assert.Equal(t, "", field)
}
