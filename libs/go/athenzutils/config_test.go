// Copyright The Athenz Authors
// Licensed under the terms of the Apache version 2.0 license. See LICENSE file for terms.

package athenzutils

import "testing"

func TestReadConfig(test *testing.T) {

	tests := []struct {
		name string
		file string
		zms  string
		zts  string
		key  string
		cert string
	}{
		{"full-valid", "data/valid_config", "https://zms.athenz.io/zms/v1", "https://zts.athenz.io/zts/v1", "/athenz/key", "/athenz/cert"},
		{"partial-valid", "data/valid_config_partial", "", "https://zts.athenz.io/zts/v1", "/athenz/key", ""},
	}
	for _, tt := range tests {
		test.Run(tt.name, func(t *testing.T) {
			conf, err := readConfig(tt.file)
			if err != nil {
				test.Errorf("received an error when reading valid config file: %v", err)
			}
			if conf.Zms != tt.zms {
				test.Errorf("unexpected zms server value: %s", conf.Zms)
			}
			if conf.Zts != tt.zts {
				test.Errorf("unexpected zts server value: %s", conf.Zts)
			}
			if conf.PrivateKey != tt.key {
				test.Errorf("unexpected private key value: %s", conf.PrivateKey)
			}
			if conf.PublicCert != tt.cert {
				test.Errorf("unexpected public cert value: %s", conf.PublicCert)
			}
		})
	}
}

func TestReadConfigInvalid(test *testing.T) {
	_, err := readConfig("data/non-existent-file")
	if err == nil {
		test.Errorf("non-existent file was processed successfully")
	}
	_, err = readConfig("data/invalid_config")
	if err == nil {
		test.Errorf("invalid config file was processed successfully")
	}
}
