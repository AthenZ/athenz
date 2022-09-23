// Copyright The Athenz Authors
// Licensed under the terms of the Apache version 2.0 license. See LICENSE file for terms.

package util

import (
	"encoding/json"
	"fmt"
	"reflect"

	"github.com/ardielle/ardielle-go/rdl"
)

type DomainSignedPolicyData struct {
	KeyId            string            `json:"keyId"`
	Signature        string            `json:"signature"`
	SignedPolicyData *SignedPolicyData `json:"signedPolicyData"`
}

type SignedPolicyData struct {
	Expires      *rdl.Timestamp `json:"expires"`
	Modified     *rdl.Timestamp `json:"modified"`
	PolicyData   *PolicyData    `json:"policyData"`
	ZmsKeyId     string         `json:"zmsKeyId"`
	ZmsSignature string         `json:"zmsSignature"`
}

type PolicyData struct {
	Domain   string    `json:"domain,omitempty"`
	Policies []*Policy `json:"policies,omitempty"`
}

type Policy struct {
	Assertions []*Assertion   `json:"assertions,omitempty"`
	Modified   *rdl.Timestamp `json:"modified,omitempty"`
	Name       string         `json:"name,omitempty"`
}

type Assertion struct {
	Action   string `json:"action,omitempty"`
	Effect   string `json:"effect,omitempty"`
	Id       int64  `json:"id,omitempty"`
	Resource string `json:"resource,omitempty"`
	Role     string `json:"role,omitempty"`
}

type AssertionEffect struct {
	value string
}

func ToCanonicalString(obj interface{}) (string, error) {
	t := reflect.TypeOf(obj).String()
	j, err := json.Marshal(obj)
	if err != nil {
		return "", fmt.Errorf("Failed to Marshal Json for converting to canonical form, Error:%v", err)
	}
	switch t {
	case "*zts.SignedPolicyData":
		{
			var signedPolicyData *SignedPolicyData
			err := json.Unmarshal(j, &signedPolicyData)
			if err != nil {
				return "", fmt.Errorf("Failed to Unmarshal Json for converting signed policy data to canonical form, Error:%v", err)
			}
			canonicalStr, err := json.Marshal(signedPolicyData)
			if err != nil {
				return "", fmt.Errorf("Failed to Marshal Json for converting signed policy data to canonical form, Error:%v", err)
			}
			return string(canonicalStr), nil
		}
	case "*zts.PolicyData":
		{

			var policyData *PolicyData
			err := json.Unmarshal(j, &policyData)
			if err != nil {
				return "", fmt.Errorf("Failed to Unmarshal Json for converting policy data to canonical form, Error:%v", err)
			}
			canonicalStr, err := json.Marshal(policyData)
			if err != nil {
				return "", fmt.Errorf("Failed to Marshal Json for converting policy data to canonical form, Error:%v", err)
			}
			return string(canonicalStr), nil
		}
	case "*zts.Policy":
		{
			var policy *Policy
			err := json.Unmarshal(j, &policy)
			if err != nil {
				return "", fmt.Errorf("Failed to Unmarshal Json for converting policies to canonical form, Error:%v", err)
			}
			canonicalStr, err := json.Marshal(policy)
			if err != nil {
				return "", fmt.Errorf("Failed to Marshal Json for converting policies to canonical form, Error:%v", err)
			}
			return string(canonicalStr), nil
		}
	default:
		return "", fmt.Errorf("Unrecognized input for converting to Canonical form")
	}
}
