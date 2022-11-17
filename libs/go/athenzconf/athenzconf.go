// Copyright The Athenz Authors
// Licensed under the terms of the Apache version 2.0 license. See LICENSE file for terms.

package athenzconf

import (
	"encoding/json"
	"fmt"
	"os"

	"github.com/AthenZ/athenz/libs/go/zmssvctoken"
)

type AthenzConf struct {
	ZtsUrl        string `json:"ztsUrl"`
	ZmsUrl        string `json:"zmsUrl"`
	ZtsPublicKeys []struct {
		Id  string `json:"id"`
		Key string `json:"key"`
	} `json:"ztsPublicKeys"`
	ZmsPublicKeys []struct {
		Id  string `json:"id"`
		Key string `json:"key"`
	} `json:"zmsPublicKeys"`
}

func ReadConf(athenzConf string) (*AthenzConf, error) {
	var aConf *AthenzConf
	if !exists(athenzConf) {
		return nil, fmt.Errorf("the Athenz configuration file does not exist at path: %v", athenzConf)
	}

	data, err := os.ReadFile(athenzConf)
	if err != nil {
		return nil, fmt.Errorf("failed to read the Athenz configuration file, Error:%v", err)
	}
	err = json.Unmarshal(data, &aConf)
	if err != nil {
		return nil, fmt.Errorf("failed to parse the Athenz configuration file, Error:%v", err)
	}
	return aConf, nil
}

func (conf *AthenzConf) FetchZTSPublicKey(keyVersion string) ([]byte, error) {
	for _, publicKey := range conf.ZtsPublicKeys {
		if publicKey.Id == keyVersion {
			key, err := new(zmssvctoken.YBase64).DecodeString(publicKey.Key)
			if err != nil {
				return nil, fmt.Errorf("unable to decode ZTS public Key with id: %v, Error: %v", publicKey.Id, err)
			}
			return key, nil
		}
	}
	return nil, fmt.Errorf("ZTS Public key with %s id not found", keyVersion)
}

func (conf *AthenzConf) FetchZMSPublicKey(keyVersion string) ([]byte, error) {
	for _, publicKey := range conf.ZmsPublicKeys {
		if publicKey.Id == keyVersion {
			key, err := new(zmssvctoken.YBase64).DecodeString(publicKey.Key)
			if err != nil {
				return nil, fmt.Errorf("unable to decode ZMS public Key with id: %v, Error: %v", publicKey.Id, err)
			}
			return key, nil
		}
	}
	return nil, fmt.Errorf("ZMS Public key with %s id not found", keyVersion)
}

func exists(name string) bool {
	if _, err := os.Stat(name); os.IsNotExist(err) {
		return false
	}
	return true
}
