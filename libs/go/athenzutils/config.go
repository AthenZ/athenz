// Copyright The Athenz Authors
// Licensed under the terms of the Apache version 2.0 license. See LICENSE file for terms.

package athenzutils

import (
	"fmt"
	"github.com/AthenZ/athenz/libs/go/sia/util"
	"gopkg.in/yaml.v3"
	"os"
	"path/filepath"
)

type Config struct {
	PrivateKey string `yaml:"svc-key-file,omitempty"`  // principal service private key file
	PublicCert string `yaml:"svc-cert-file,omitempty"` // principal service public certificate file
	Zts        string `yaml:"zts,omitempty"`           // zts server hostname
	Zms        string `yaml:"zms,omitempty"`           // zms server hostname
}

// ReadDefaultConfig reads default configuration from the user's HOME directory
func ReadDefaultConfig() (*Config, error) {
	configFile := filepath.Join(os.Getenv("HOME"), ".athenz", "config")
	return readConfig(configFile)
}

func readConfig(configFile string) (*Config, error) {
	if !util.FileExists(configFile) {
		return nil, fmt.Errorf("file '%s' does not exist", configFile)
	}
	data, err := os.ReadFile(configFile)
	if err != nil {
		return nil, err
	}
	var conf Config
	err = yaml.Unmarshal(data, &conf)
	if err != nil {
		return nil, err
	}
	return &conf, nil
}
