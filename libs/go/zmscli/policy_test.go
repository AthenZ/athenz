// Copyright The Athenz Authors
// Licensed under the terms of the Apache version 2.0 license. See LICENSE file for terms.

package zmscli

import (
	"fmt"
	"strings"
	"testing"

	"github.com/AthenZ/athenz/clients/go/zms"
)

func TestDeletePolicies(t *testing.T) {
	transport := &deleteRequestTransport{
		t:             t,
		path:          "/domain/domain1/policies/policy1,policy2",
		auditRef:      "audit",
		resourceOwner: "owner",
	}

	cli := Zms{
		AuditRef:      "audit",
		ResourceOwner: "owner",
		OutputFormat:  DefaultOutputFormat,
		Zms:           zms.NewClient("http://zms", transport),
	}

	output, err := cli.DeletePolicies("domain1", []string{"policy1", "policy2"})
	if err != nil {
		t.Fatal(err)
	}
	transport.assertCalled()
	if *output != "[Deleted policies: policy1, policy2]" {
		t.Errorf("unexpected output: %s", *output)
	}
}

func TestDeletePoliciesChunks(t *testing.T) {
	policyNames := make([]string, bulkDeleteChunkSize+1)
	for idx := range policyNames {
		policyNames[idx] = fmt.Sprintf("policy%d", idx)
	}

	transport := &deleteRequestTransport{
		t: t,
		paths: []string{
			"/domain/domain1/policies/" + strings.Join(policyNames[:bulkDeleteChunkSize], ","),
			"/domain/domain1/policies/" + policyNames[bulkDeleteChunkSize],
		},
		auditRef:      "audit",
		resourceOwner: "owner",
	}

	cli := Zms{
		AuditRef:      "audit",
		ResourceOwner: "owner",
		OutputFormat:  DefaultOutputFormat,
		Zms:           zms.NewClient("http://zms", transport),
	}

	if _, err := cli.DeletePolicies("domain1", policyNames); err != nil {
		t.Fatal(err)
	}
	transport.assertCalled()
}

func TestDeletePoliciesEmptyList(t *testing.T) {
	cli := Zms{}
	_, err := cli.DeletePolicies("domain1", []string{})
	if err == nil {
		t.Fatal("expected empty policy names error")
	}
	if err.Error() != "no policy names specified" {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestAssertionMatchTrue(t *testing.T) {

	zmsCli := zms.ZMSClient{
		URL:          "dev.zms",
		Transport:    nil,
		CredsHeaders: make(map[string]string),
		Timeout:      0,
	}

	cli := Zms{
		ZmsUrl:           "dev.zms",
		Identity:         "ntoken",
		Verbose:          false,
		Bulkmode:         false,
		Interactive:      false,
		Domain:           "domain",
		AuditRef:         "",
		UserDomain:       "user",
		ProductIdSupport: false,
		Debug:            false,
		Zms:              zmsCli,
	}

	denyEffect := zms.NewAssertionEffect("DENY")
	allowEffect := zms.NewAssertionEffect("ALLOW")

	assertion1 := zms.Assertion{Role: "role1", Resource: "resource", Action: "action", Effect: nil}
	assertion2 := zms.Assertion{Role: "role1", Resource: "resource", Action: "action", Effect: nil}

	match := cli.assertionMatch(&assertion1, &assertion2)
	if !match {
		t.Error("assertion #1 didn't match as expected")
	}

	assertion1 = zms.Assertion{Role: "role1", Resource: "resource", Action: "action", Effect: &allowEffect}
	assertion2 = zms.Assertion{Role: "role1", Resource: "resource", Action: "action", Effect: nil}
	match = cli.assertionMatch(&assertion1, &assertion2)
	if !match {
		t.Error("assertion #2 didn't match as expected")
	}

	assertion1 = zms.Assertion{Role: "role1", Resource: "resource", Action: "action", Effect: nil}
	assertion2 = zms.Assertion{Role: "role1", Resource: "resource", Action: "action", Effect: &allowEffect}
	match = cli.assertionMatch(&assertion1, &assertion2)
	if !match {
		t.Error("assertion #3 didn't match as expected")
	}

	assertion1 = zms.Assertion{Role: "role1", Resource: "resource", Action: "action", Effect: &allowEffect}
	assertion2 = zms.Assertion{Role: "role1", Resource: "resource", Action: "action", Effect: &allowEffect}
	match = cli.assertionMatch(&assertion1, &assertion2)
	if !match {
		t.Error("assertion #4 didn't match as expected")
	}

	assertion1 = zms.Assertion{Role: "role1", Resource: "resource", Action: "action", Effect: &denyEffect}
	assertion2 = zms.Assertion{Role: "role1", Resource: "resource", Action: "action", Effect: &denyEffect}
	match = cli.assertionMatch(&assertion1, &assertion2)
	if !match {
		t.Error("assertion #5 didn't match as expected")
	}
}

func TestAssertionMatchFalse(t *testing.T) {

	zmsCli := zms.ZMSClient{
		URL:          "dev.zms",
		Transport:    nil,
		CredsHeaders: make(map[string]string),
		Timeout:      0,
	}

	cli := Zms{
		ZmsUrl:           "dev.zms",
		Identity:         "ntoken",
		Verbose:          false,
		Bulkmode:         false,
		Interactive:      false,
		Domain:           "domain",
		AuditRef:         "",
		UserDomain:       "user",
		ProductIdSupport: false,
		Debug:            false,
		Zms:              zmsCli,
	}

	denyEffect := zms.NewAssertionEffect("DENY")
	allowEffect := zms.NewAssertionEffect("ALLOW")

	assertion1 := zms.Assertion{Role: "role1", Resource: "resource", Action: "action", Effect: nil}
	assertion2 := zms.Assertion{Role: "role2", Resource: "resource", Action: "action", Effect: nil}
	match := cli.assertionMatch(&assertion1, &assertion2)
	if match {
		t.Error("assertion #1 incorrectly matched")
	}

	assertion1 = zms.Assertion{Role: "role1", Resource: "resource1", Action: "action", Effect: nil}
	assertion2 = zms.Assertion{Role: "role1", Resource: "resource", Action: "action", Effect: nil}
	match = cli.assertionMatch(&assertion1, &assertion2)
	if match {
		t.Error("assertion #2 incorrectly matched")
	}

	assertion1 = zms.Assertion{Role: "role1", Resource: "resource1", Action: "action111", Effect: nil}
	assertion2 = zms.Assertion{Role: "role1", Resource: "resource1", Action: "action11", Effect: nil}
	match = cli.assertionMatch(&assertion1, &assertion2)
	if match {
		t.Error("assertion #3 incorrectly matched")
	}

	assertion1 = zms.Assertion{Role: "role1", Resource: "resource1", Action: "action", Effect: &allowEffect}
	assertion2 = zms.Assertion{Role: "role1", Resource: "resource1", Action: "action", Effect: &denyEffect}
	match = cli.assertionMatch(&assertion1, &assertion2)
	if match {
		t.Error("assertion #4 incorrectly matched")
	}

	assertion1 = zms.Assertion{Role: "role1", Resource: "resource1", Action: "action", Effect: nil}
	assertion2 = zms.Assertion{Role: "role1", Resource: "resource1", Action: "action", Effect: &denyEffect}
	match = cli.assertionMatch(&assertion1, &assertion2)
	if match {
		t.Error("assertion #5 incorrectly matched")
	}

	assertion1 = zms.Assertion{Role: "role1", Resource: "resource1", Action: "action", Effect: &denyEffect}
	assertion2 = zms.Assertion{Role: "role1", Resource: "resource1", Action: "action", Effect: nil}
	match = cli.assertionMatch(&assertion1, &assertion2)
	if match {
		t.Error("assertion #6 incorrectly matched")
	}
}
