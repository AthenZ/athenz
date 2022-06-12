// Copyright 2017 Yahoo Holdings, Inc.
// Licensed under the terms of the Apache version 2.0 license. See LICENSE file for terms.

package zpu

import (
	"encoding/json"
	"fmt"
	"github.com/AthenZ/athenz/clients/go/zts"
	"io/ioutil"
	"log"
	"os"
	"strconv"

	siautil "github.com/AthenZ/athenz/libs/go/sia/util"
	"github.com/AthenZ/athenz/libs/go/zmssvctoken"
	"github.com/AthenZ/athenz/utils/zpe-updater/util"
)

// Default and maximal startup delay values.
const (
	DEFAULT_STARTUP_DELAY = 0
	MAX_STARTUP_DELAY     = 1440
	DEFAULT_EXPIRY_CHECK  = 2880
)

type ZpuConfiguration struct {
	Zts               string
	Zms               string
	DomainList        string
	ZpuOwner          string
	PolicyFileDir     string
	TempPolicyFileDir string
	MetricsDir        string
	ZmsKeysmap        map[string]string
	ZtsKeysmap        map[string]string
	StartUpDelay      int
	ExpiryCheck       int
	LogSize           int
	LogAge            int
	LogBackups        int
	LogCompression    bool
	PrivateKeyFile    string
	CertFile          string
	CaCertFile        string
	Proxy             bool
	CheckZMSSignature bool
	JWSPolicySupport  bool
	PolicyVersions    map[string]string
	ForceRefresh      bool
	AthenzJWKConfig   *zts.AthenzJWKConfig
	ExpiredFunc       func() bool
}

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

type ZpuConf struct {
	Domains           string            `json:"domains"`
	User              string            `json:"user"`
	PolicyDir         string            `json:"policyDir"`
	TempPolicyDir     string            `json:"tempPolicyDir"`
	MetricsDir        string            `json:"metricsDir"`
	LogMaxSize        int               `json:"logMaxsize"`
	LogMaxAge         int               `json:"logMaxage"`
	LogMaxBackups     int               `json:"logMaxbackups"`
	LogCompress       bool              `json:"logCompress"`
	PrivateKey        string            `json:"privateKeyFile"`
	CertFile          string            `json:"certFile"`
	CaCertFile        string            `json:"caCertFile"`
	Proxy             bool              `json:"proxy"`
	ExpiryCheck       int               `json:"expiryCheck"`
	CheckZMSSignature bool              `json:"checkZMSSignature"`
	JWSPolicySupport  bool              `json:"jwsPolicySupport"`
	PolicyVersions    map[string]string `json:"policyVersions"`
}

func NewZpuConfiguration(root, athensConfFile, zpuConfFile, siaDir string) (*ZpuConfiguration, error) {
	zmsKeysmap := make(map[string]string)
	ztsKeysmap := make(map[string]string)
	athenzConf, err := ReadAthenzConf(athensConfFile)
	if err != nil {
		return nil, err
	}
	zpuConf, err := ReadZpuConf(zpuConfFile)
	if err != nil {
		return nil, err
	}

	for _, publicKey := range athenzConf.ZtsPublicKeys {
		if _, exists := ztsKeysmap[publicKey.Id]; exists {
			log.Printf("Zts public Key with id: %v already existed, overwriting it with new value\n", publicKey.Id)
		}
		key, err := new(zmssvctoken.YBase64).DecodeString(publicKey.Key)
		if err != nil {
			return nil, fmt.Errorf("unable to decode Zts public Key with id: %v, Error: %v", publicKey.Id, err)
		}
		ztsKeysmap[publicKey.Id] = string(key)
	}

	for _, publicKey := range athenzConf.ZmsPublicKeys {
		if _, exists := zmsKeysmap[publicKey.Id]; exists {
			log.Printf("Zms public Key with id: %v already existed, overwriting it with new value\n", publicKey.Id)
		}
		key, err := new(zmssvctoken.YBase64).DecodeString(publicKey.Key)
		if err != nil {
			return nil, fmt.Errorf("unable to decode Zms public Key with id: %v, Error: %v", publicKey.Id, err)
		}
		zmsKeysmap[publicKey.Id] = string(key)
	}

	startupDelay := DEFAULT_STARTUP_DELAY
	startupDelayString := os.Getenv("STARTUP_DELAY")
	if startupDelayString != "" {
		startupDelay, err = strconv.Atoi(startupDelayString)
		if err != nil {
			return nil, fmt.Errorf("unable to set start up delay, Error: %v", err)
		}
	}
	if startupDelay < 0 {
		startupDelay = DEFAULT_STARTUP_DELAY
	}
	if startupDelay > MAX_STARTUP_DELAY {
		startupDelay = MAX_STARTUP_DELAY
	}
	startupDelay *= 60 // convert from min to secs

	expiryCheck := zpuConf.ExpiryCheck
	if expiryCheck == 0 {
		expiryCheck = DEFAULT_EXPIRY_CHECK
	}

	expiryCheck *= 60 // convert from min to secs

	policyDir := zpuConf.PolicyDir
	defaultPolicyDir := fmt.Sprintf("%s/var/zpe", root)
	if policyDir == "" {
		policyDir = defaultPolicyDir
	}

	tempPolicyDir := zpuConf.TempPolicyDir
	defaultTempPolicyDir := fmt.Sprintf("%s/tmp/zpe", root)
	if tempPolicyDir == "" {
		tempPolicyDir = defaultTempPolicyDir
	}

	metricDir := zpuConf.MetricsDir
	defaultMetricDir := fmt.Sprintf("%s/var/zpe_stat", root)
	if metricDir == "" {
		metricDir = defaultMetricDir
	}
	user := zpuConf.User
	if user == "" {
		user = "root"
	}

	jwkConfFile := fmt.Sprintf("%s/"+siautil.JwkConfFile, siaDir)
	jwkConf := &zts.AthenzJWKConfig{}
	err = siautil.ReadAthenzJwkConf(jwkConfFile, jwkConf)
	if err != nil {
		log.Printf(err.Error())
		jwkConf = nil
	}

	return &ZpuConfiguration{
		Zts:               athenzConf.ZtsUrl,
		Zms:               athenzConf.ZmsUrl,
		DomainList:        zpuConf.Domains,
		ZpuOwner:          user,
		PolicyFileDir:     policyDir,
		TempPolicyFileDir: tempPolicyDir,
		MetricsDir:        metricDir,
		ZtsKeysmap:        ztsKeysmap,
		ZmsKeysmap:        zmsKeysmap,
		StartUpDelay:      startupDelay,
		ExpiryCheck:       expiryCheck,
		LogAge:            zpuConf.LogMaxAge,
		LogSize:           zpuConf.LogMaxSize,
		LogBackups:        zpuConf.LogMaxBackups,
		LogCompression:    zpuConf.LogCompress,
		PrivateKeyFile:    zpuConf.PrivateKey,
		CaCertFile:        zpuConf.CaCertFile,
		CertFile:          zpuConf.CertFile,
		Proxy:             zpuConf.Proxy,
		CheckZMSSignature: zpuConf.CheckZMSSignature,
		JWSPolicySupport:  zpuConf.JWSPolicySupport,
		PolicyVersions:    zpuConf.PolicyVersions,
		AthenzJWKConfig:   jwkConf,
	}, nil
}

func ReadAthenzConf(athenzConf string) (*AthenzConf, error) {
	var aConf *AthenzConf
	if !util.Exists(athenzConf) {
		return nil, fmt.Errorf("athenz configuration file does not exist at path: %v", athenzConf)
	}

	data, err := ioutil.ReadFile(athenzConf)
	if err != nil {
		return nil, fmt.Errorf("failed to read the Athenz configuration file, Error:%v", err)
	}
	err = json.Unmarshal(data, &aConf)
	if err != nil {
		return nil, fmt.Errorf("failed to parse the Athenz configuration file, Error:%v", err)
	}
	return aConf, nil
}

func ReadZpuConf(zpuConf string) (*ZpuConf, error) {
	var zConf *ZpuConf
	if !util.Exists(zpuConf) {
		return nil, fmt.Errorf("zpu configuration file does not exist at the given path: %v", zpuConf)
	}

	data, err := ioutil.ReadFile(zpuConf)
	if err != nil {
		return nil, fmt.Errorf("failed to read the Zpu configuration file, Error:%v", err)
	}
	err = json.Unmarshal(data, &zConf)
	if err != nil {
		return nil, fmt.Errorf("failed to parse the Zpu configuration file, Error:%v", err)
	}
	return zConf, nil
}

func (config ZpuConfiguration) GetZtsPublicKey(key string) string {
	for k := range config.ZtsKeysmap {
		if k == key {
			return config.ZtsKeysmap[key]
		}
	}
	return ""
}

func (config ZpuConfiguration) PutZtsPublicKey(key, publicKey string) {
	config.ZtsKeysmap[key] = publicKey
}

func (config ZpuConfiguration) GetZmsPublicKey(key string) string {
	for k := range config.ZmsKeysmap {
		if k == key {
			return config.ZmsKeysmap[key]
		}
	}
	return ""
}

func (config ZpuConfiguration) PutZmsPublicKey(key, publicKey string) {
	config.ZmsKeysmap[key] = publicKey
}
