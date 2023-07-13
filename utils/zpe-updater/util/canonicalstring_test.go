// Copyright The Athenz Authors
// Licensed under the terms of the Apache version 2.0 license. See LICENSE file for terms.

package util

import (
	"encoding/json"
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/AthenZ/athenz/clients/go/zts"
)

var signedPolicyData *zts.SignedPolicyData
var policyData *zts.PolicyData

func TestToCanonicalString_SignedPolicyData(t *testing.T) {
	input := `{"policyData":{"domain":"test","policies":[{"name":"policy1","modified":"2017-06-02T06:11:12.125Z","assertions":[{"role":"sys.auth:role.admin","resource":"*","action":"*","effect":"ALLOW"},{"role":"sys.auth:role.non-admin","resource":"*","action":"*","effect":"DENY"}]}]},"zmsSignature":"zms_signature","zmsKeyId":"0","modified":"2017-06-02T06:11:12.125Z","expires":"2017-06-09T06:11:12.125Z"}`
	err := json.Unmarshal([]byte(input), &signedPolicyData)
	assert.Nil(t, err)
	j, err := ToCanonicalString(signedPolicyData)
	assertEqual(t, `{"expires":"2017-06-09T06:11:12.125Z","modified":"2017-06-02T06:11:12.125Z","policyData":{"domain":"test","policies":[{"assertions":[{"action":"*","effect":"ALLOW","resource":"*","role":"sys.auth:role.admin"},{"action":"*","effect":"DENY","resource":"*","role":"sys.auth:role.non-admin"}],"modified":"2017-06-02T06:11:12.125Z","name":"policy1"}]},"zmsKeyId":"0","zmsSignature":"zms_signature"}`, j, "Canonical output string is not as expected, ")
	assert.Nil(t, err, "Canonical String conversion failed")
}

func TestToCanonicalString_PolicyData(t *testing.T) {
	input := `{"domain":"test","policies":[{"name":"policy1","modified":"2017-06-02T06:11:12.125Z","assertions":[{"role":"sys.auth:role.admin","resource":"*","action":"*","effect":"ALLOW"},{"role":"sys.auth:role.non-admin","resource":"*","action":"*","effect":"DENY"}]}]}`
	err := json.Unmarshal([]byte(input), &policyData)
	assert.Nil(t, err)
	j, err := ToCanonicalString(policyData)
	assertEqual(t, `{"domain":"test","policies":[{"assertions":[{"action":"*","effect":"ALLOW","resource":"*","role":"sys.auth:role.admin"},{"action":"*","effect":"DENY","resource":"*","role":"sys.auth:role.non-admin"}],"modified":"2017-06-02T06:11:12.125Z","name":"policy1"}]}`, j, "Canonical output string is not as expected, ")
	assert.Nil(t, err, "Canonical String conversion failed")
}

func TestToCanonicalString_NoAssertionSignedPolicyData(t *testing.T) {
	input := `{"policyData":{"domain":"test","policies":[{"name":"policy1","modified":"2017-06-02T06:11:12.125Z"}]},"zmsSignature":"zms_signature","zmsKeyId":"0","modified":"2017-06-02T06:11:12.125Z","expires":"2017-06-09T06:11:12.125Z"}`
	err := json.Unmarshal([]byte(input), &signedPolicyData)
	assert.Nil(t, err)
	j, err := ToCanonicalString(signedPolicyData)
	assertEqual(t, `{"expires":"2017-06-09T06:11:12.125Z","modified":"2017-06-02T06:11:12.125Z","policyData":{"domain":"test","policies":[{"modified":"2017-06-02T06:11:12.125Z","name":"policy1"}]},"zmsKeyId":"0","zmsSignature":"zms_signature"}`, j, "Canonical output string is not as expected, ")
	assert.Nil(t, err, "Canonical String conversion failed")
}

func TestToCanonicalString_EmptyAsssertionPolicyData(t *testing.T) {
	policyData := &zts.PolicyData{
		Domain: "sample.domain.go",
		Policies: []*zts.Policy{
			&zts.Policy{
				Name: "PolicyName",
				Assertions: []*zts.Assertion{
					&zts.Assertion{},
				},
			},
		},
	}
	j, err := ToCanonicalString(policyData)
	assertEqual(t, "{\"domain\":\"sample.domain.go\",\"policies\":[{\"assertions\":[{}],\"name\":\"PolicyName\"}]}", j, "Canonical output string is not as expected, ")
	assert.Nil(t, err, "Canonical String conversion failed")
}

func assertEqual(t *testing.T, a interface{}, b interface{}, message string) {
	if a == b {
		return
	}

	message += fmt.Sprintf("%v != %v", a, b)

	t.Fatalf(message)
}
