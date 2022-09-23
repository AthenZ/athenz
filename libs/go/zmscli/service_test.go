// Copyright The Athenz Authors
// Licensed under the terms of the Apache version 2.0 license. See LICENSE file for terms.

package zmscli

import (
	"testing"
)

func TestShortName(t *testing.T) {
	sn := shortname("coretech", "service1")
	if sn != "service1" {
		t.Error("shortname service1 failed")
	}
	sn = shortname("coretech", "coretech2.service2")
	if sn != "coretech2.service2" {
		t.Error("shortname service2 failed")
	}
	sn = shortname("coretech", "coretech.service3")
	if sn != "service3" {
		t.Error("shortname service3 failed")
	}
}
