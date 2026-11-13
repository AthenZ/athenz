// Copyright The Athenz Authors
// Licensed under the terms of the Apache version 2.0 license. See LICENSE file for terms.

package zmscli

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/AthenZ/athenz/clients/go/zms"
)

func TestParseBundleFileArg(t *testing.T) {
	tests := []struct {
		arg        string
		localPath  string
		bundlePath string
		valid      bool
	}{
		{"authz.rego", "authz.rego", "authz.rego", true},
		{"policy/authz.rego=authz.rego", "policy/authz.rego", "authz.rego", true},
		{"/tmp/data.json=regions/./data.json", "/tmp/data.json", "regions/data.json", true},
		{"/tmp/authz.rego", "", "", false},
		{"authz.rego=../authz.rego", "", "", false},
		{"authz.rego=..", "", "", false},
		{"=authz.rego", "", "", false},
		{"authz.rego=", "", "", false},
	}
	for _, tt := range tests {
		localPath, bundlePath, err := parseBundleFileArg(tt.arg)
		if tt.valid != (err == nil) {
			t.Errorf("arg %s: unexpected error result: %v", tt.arg, err)
			continue
		}
		if tt.valid && (localPath != tt.localPath || bundlePath != tt.bundlePath) {
			t.Errorf("arg %s: got %s/%s, expected %s/%s", tt.arg, localPath, bundlePath, tt.localPath, tt.bundlePath)
		}
	}
}

func TestReadBundleFiles(t *testing.T) {
	dir := t.TempDir()
	regoFile := filepath.Join(dir, "authz.rego")
	if err := os.WriteFile(regoFile, []byte("package sports.api\n"), 0600); err != nil {
		t.Fatal(err)
	}
	files, err := readBundleFiles([]string{regoFile + "=sports/api/authz.rego"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(files) != 1 || files[0].Path != "sports/api/authz.rego" || files[0].Content != "package sports.api\n" {
		t.Fatalf("unexpected files: %+v", files)
	}
	if _, err := readBundleFiles([]string{filepath.Join(dir, "missing.rego") + "=missing.rego"}); err == nil {
		t.Fatal("expected error for missing file")
	}
	if _, err := readBundleFiles([]string{"../authz.rego"}); err == nil {
		t.Fatal("expected error for invalid path")
	}
}

func TestSummarizePolicyBundle(t *testing.T) {
	bundle := &zms.PolicyBundle{
		Name:   "sports:bundle.api",
		Engine: "rego",
		Files: []*zms.PolicyBundleFile{
			{Path: "authz.rego", Content: "package x", Sha256: "abcd"},
		},
	}
	summary := summarizePolicyBundle(bundle)
	if summary.Name != bundle.Name || len(summary.Files) != 1 || summary.Files[0].Content != "" ||
		summary.Files[0].Sha256 != "abcd" {
		t.Fatalf("unexpected summary: %+v", summary)
	}
	if bundle.Files[0].Content != "package x" {
		t.Fatal("original bundle must not be modified")
	}
}
