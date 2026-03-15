// Copyright The Athenz Authors
// Licensed under the terms of the Apache version 2.0 license. See LICENSE file for terms.

package main

import (
	"strings"
	"testing"
)

func TestVersionStringEmpty(t *testing.T) {
	VERSION = ""
	BUILD_DATE = ""
	result := versionString()
	if result != "zts-usercert (development version)" {
		t.Errorf("expected development version string, got %s", result)
	}
}

func TestVersionStringSet(t *testing.T) {
	VERSION = "1.0.0"
	BUILD_DATE = "2025-01-01"
	result := versionString()
	expected := "zts-usercert 1.0.0 2025-01-01"
	if result != expected {
		t.Errorf("expected %s, got %s", expected, result)
	}
	VERSION = ""
	BUILD_DATE = ""
}

func TestVersionStringOnlyVersion(t *testing.T) {
	VERSION = "2.0.0"
	BUILD_DATE = ""
	result := versionString()
	if !strings.HasPrefix(result, "zts-usercert 2.0.0") {
		t.Errorf("expected version prefix, got %s", result)
	}
	VERSION = ""
}

func TestVersionStringFormat(t *testing.T) {
	VERSION = "1.12.37"
	BUILD_DATE = "2025-03-14"
	result := versionString()
	if !strings.Contains(result, "1.12.37") {
		t.Errorf("version string should contain version number, got %s", result)
	}
	if !strings.Contains(result, "2025-03-14") {
		t.Errorf("version string should contain build date, got %s", result)
	}
	VERSION = ""
	BUILD_DATE = ""
}
