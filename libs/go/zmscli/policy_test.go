// Copyright The Athenz Authors
// Licensed under the terms of the Apache version 2.0 license. See LICENSE file for terms.

package zmscli

import (
	"testing"

	"github.com/AthenZ/athenz/clients/go/zms"
)

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
