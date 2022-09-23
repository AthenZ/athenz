// Copyright The Athenz Authors
// Licensed under the terms of the Apache version 2.0 license. See LICENSE file for terms.

package zmscli

import (
	"bytes"
	"testing"
)

func TestLocalName(t *testing.T) {

	local := localName("coretech:role.role1", ":role.")
	if local != "role1" {
		t.Error("coretech:role.role1 didn't return role1 with prefix :role.")
	}

	local = localName("coretech:role.role1.role2", ":role.")
	if local != "role1.role2" {
		t.Error("coretech:role.role1.role2 didn't return role1.role2 with prefix :role.")
	}

	local = localName("coretech.service1", ":service.")
	if local != "coretech.service1" {
		t.Error("coretech.service1 didn't return service1 with prefix :service.")
	}
}

func TestDisplayObjectName(t *testing.T) {

	var buf bytes.Buffer
	zms := Zms{}

	zms.Verbose = false
	zms.displayObjectName(&buf, "coretech:role.role1", ":role.", "--")
	if buf.String() != "--name: role1\n" {
		t.Error("coretech:role.role1 didn't display the correct object name with Verbose off")
	}

	buf.Reset()
	zms.Verbose = true
	zms.displayObjectName(&buf, "coretech:role.role1", ":role.", "--")
	if buf.String() != "--name: coretech:role.role1\n" {
		t.Error("coretech:role.role1 didn't display the correct object name with Verbose on")
	}

	buf.Reset()
	zms.Verbose = false
	zms.displayObjectName(&buf, "coretech:role.role1", "", "--")
	if buf.String() != "--name: coretech:role.role1\n" {
		t.Error("coretech:role.role1 didn't display the correct object name with empty obj type")
	}

	buf.Reset()
	zms.Verbose = false
	zms.displayObjectName(&buf, "coretech:role.role1", ":policy.", "--")
	if buf.String() != "--name: coretech:role.role1\n" {
		t.Error("coretech:role.role1 didn't display the correct object name with no match obj type")
	}
}
