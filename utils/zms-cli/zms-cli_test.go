package main

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/AthenZ/athenz/libs/go/athenzutils"
)

func TestDefaultZmsURLPrefersEnvironment(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	t.Setenv("ZMS", "https://env.athenz.io/zms/v1")

	if got := defaultZmsURL(); got != "https://env.athenz.io/zms/v1" {
		t.Fatalf("unexpected default ZMS URL: got %q", got)
	}
}

func TestDefaultZmsURLReadsDefaultConfig(t *testing.T) {
	homeDir := t.TempDir()
	t.Setenv("HOME", homeDir)
	t.Setenv("ZMS", "")

	configDir := filepath.Join(homeDir, ".athenz")
	if err := os.MkdirAll(configDir, 0755); err != nil {
		t.Fatalf("unable to create config dir: %v", err)
	}
	configFile := filepath.Join(configDir, "config")
	configData := []byte("zms: https://config.athenz.io/zms/v1\n")
	if err := os.WriteFile(configFile, configData, 0600); err != nil {
		t.Fatalf("unable to write config file: %v", err)
	}

	if got := defaultZmsURL(); got != "https://config.athenz.io/zms/v1" {
		t.Fatalf("unexpected default ZMS URL: got %q", got)
	}
}

func TestDefaultZmsURLFallback(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	t.Setenv("ZMS", "")

	if got := defaultZmsURL(); got != "https://localhost:4443/zms/v1" {
		t.Fatalf("unexpected fallback ZMS URL: got %q", got)
	}
}

func TestResolveX509CertFiles(t *testing.T) {
	defaultConfig := &athenzutils.Config{
		PrivateKey: "/default/key.pem",
		PublicCert: "/default/cert.pem",
	}

	tests := []struct {
		name     string
		keyFile  string
		certFile string
		wantKey  string
		wantCert string
	}{
		{
			name:     "uses defaults",
			wantKey:  "/default/key.pem",
			wantCert: "/default/cert.pem",
		},
		{
			name:     "keeps explicit values",
			keyFile:  "/explicit/key.pem",
			certFile: "/explicit/cert.pem",
			wantKey:  "/explicit/key.pem",
			wantCert: "/explicit/cert.pem",
		},
		{
			name:     "fills missing cert",
			keyFile:  "/explicit/key.pem",
			wantKey:  "/explicit/key.pem",
			wantCert: "/default/cert.pem",
		},
		{
			name:     "fills missing key",
			certFile: "/explicit/cert.pem",
			wantKey:  "/default/key.pem",
			wantCert: "/explicit/cert.pem",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotKey, gotCert := resolveX509CertFiles(tt.keyFile, tt.certFile, defaultConfig)
			if gotKey != tt.wantKey || gotCert != tt.wantCert {
				t.Fatalf("unexpected cert files: got key=%q cert=%q", gotKey, gotCert)
			}
		})
	}
}

func TestResolveX509CertFilesNoDefaultConfig(t *testing.T) {
	gotKey, gotCert := resolveX509CertFiles("/key.pem", "", nil)
	if gotKey != "/key.pem" || gotCert != "" {
		t.Fatalf("unexpected cert files: got key=%q cert=%q", gotKey, gotCert)
	}
}

func TestHasIncompleteX509CertCredentials(t *testing.T) {
	tests := []struct {
		name     string
		keyFile  string
		certFile string
		want     bool
	}{
		{
			name: "no cert files",
		},
		{
			name:     "complete cert files",
			keyFile:  "/key.pem",
			certFile: "/cert.pem",
		},
		{
			name:    "missing cert",
			keyFile: "/key.pem",
			want:    true,
		},
		{
			name:     "missing key",
			certFile: "/cert.pem",
			want:     true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := hasIncompleteX509CertCredentials(tt.keyFile, tt.certFile)
			if got != tt.want {
				t.Fatalf("unexpected result: got %t", got)
			}
		})
	}
}

func TestShouldLoadDefaultX509CertFiles(t *testing.T) {
	tests := []struct {
		name       string
		ntokenFile string
		debug      bool
		args       []string
		want       bool
	}{
		{
			name: "regular command",
			args: []string{"list-domain"},
			want: true,
		},
		{
			name:       "ntoken file",
			ntokenFile: "/tmp/ntoken",
			args:       []string{"list-domain"},
			want:       false,
		},
		{
			name:  "debug",
			debug: true,
			args:  []string{"list-domain"},
			want:  false,
		},
		{
			name: "get user token",
			args: []string{"get-user-token"},
			want: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := shouldLoadDefaultX509CertFiles(tt.ntokenFile, tt.debug, tt.args)
			if got != tt.want {
				t.Fatalf("unexpected result: got %t", got)
			}
		})
	}
}
