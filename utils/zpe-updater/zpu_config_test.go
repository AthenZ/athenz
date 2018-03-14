// Copyright 2017 Yahoo Holdings, Inc.
// Licensed under the terms of the Apache version 2.0 license. See LICENSE file for terms.

package zpu

import (
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/yahoo/athenz/libs/go/zmssvctoken"
	"github.com/yahoo/athenz/utils/zpe-updater/devel"
)

const (
	ATHENZ_CONF = "/tmp/athenz.conf"
	ZPU_CONF    = "/tmp/zpu.conf"
)

func TestReadAthenzConf(t *testing.T) {

	var athenzFile *AthenzConf
	a := assert.New(t)

	//missing keys
	err := devel.CreateFile(ATHENZ_CONF, `{"zmsUrl":"zms_url","zmsPublicKeys":[{"id":"0","key":"zmsKey"}]}`)
	a.Nil(err)
	athenzFile, err = ReadAthenzConf(ATHENZ_CONF)
	a.Nil(err)
	a.Equal(athenzFile.ZmsUrl, "zms_url")
	a.Empty(athenzFile.ZtsUrl)
	a.Equal(len(athenzFile.ZmsPublicKeys), 1)
	a.Empty(athenzFile.ZtsPublicKeys)
	a.Equal(len(athenzFile.ZtsPublicKeys), 0)
	a.Equal(athenzFile.ZmsPublicKeys[0].Id, "0")
	a.Equal(athenzFile.ZmsPublicKeys[0].Key, "zmsKey")

	//incorrect file
	err = devel.CreateFile(ATHENZ_CONF, `"zmsUrl":"zms_url","zmsPublicKeys":[{"id":"0","key":"zmsKey"}]}`)
	a.Nil(err)
	athenzFile, err = ReadAthenzConf(ATHENZ_CONF)
	a.NotNil(err)
	a.Empty(athenzFile)

	//correct file
	err = devel.CreateFile(ATHENZ_CONF, `{"zmsUrl":"zms_url","ztsUrl":"zts_url","ztsPublicKeys":[{"id":"0","key":"key0"}],"zmsPublicKeys":[{"id":"1","key":"key1"}]}`)
	a.Nil(err)
	athenzFile, err = ReadAthenzConf(ATHENZ_CONF)
	a.Nil(err)
	a.Equal(athenzFile.ZmsUrl, "zms_url")
	a.Equal(athenzFile.ZtsUrl, "zts_url")
	a.Equal(len(athenzFile.ZmsPublicKeys), 1)
	a.Equal(len(athenzFile.ZtsPublicKeys), 1)
	a.Equal(athenzFile.ZtsPublicKeys[0].Id, "0")
	a.Equal(athenzFile.ZtsPublicKeys[0].Key, "key0")
	a.Equal(athenzFile.ZmsPublicKeys[0].Id, "1")
	a.Equal(athenzFile.ZmsPublicKeys[0].Key, "key1")
}

func TestReadZpuConf(t *testing.T) {
	var zpuFile *ZpuConf
	a := assert.New(t)

	//missing keys
	err := devel.CreateFile(ZPU_CONF, `{"domains":"domain","user":"user","logMaxSize":10}`)
	a.Nil(err)
	zpuFile, err = ReadZpuConf(ZPU_CONF)
	a.Equal(zpuFile.Domains, "domain")
	a.Equal(zpuFile.User, "user")
	a.Equal(zpuFile.PolicyDir, "")
	a.Equal(zpuFile.MetricsDir, "")
	a.Equal(zpuFile.LogCompress, false)
	a.Equal(zpuFile.LogMaxSize, 10)
	a.Equal(zpuFile.LogMaxBackups, 0)
	a.Equal(zpuFile.LogMaxAge, 0)
	a.Equal(zpuFile.Proxy, false)
	a.Equal(zpuFile.PrivateKey, "")
	a.Equal(zpuFile.CaCertFile, "")
	a.Equal(zpuFile.CertFile, "")

	//incorrect file
	err = devel.CreateFile(ZPU_CONF, `{"domains":"domain""user":"user"`)
	zpuFile, err = ReadZpuConf(ZPU_CONF)
	a.NotNil(err)
	a.Empty(zpuFile)

	//correct file
	err = devel.CreateFile(ZPU_CONF, `{"domains":"domain","user":"user","policyDir":"/policy","metricsDir":"/metric","logMaxsize":10,"logMaxage":7,"logMaxbackups":2,"logCompress":true,"proxy":true,"certFile":"./certfile.pem","caCertFile":"./cacert.pem","privateKeyFile":"./privatekey"}`)
	a.Nil(err)
	zpuFile, err = ReadZpuConf(ZPU_CONF)
	a.Nil(err)
	a.Equal(zpuFile.Domains, "domain")
	a.Equal(zpuFile.User, "user")
	a.Equal(zpuFile.PolicyDir, "/policy")
	a.Equal(zpuFile.MetricsDir, "/metric")
	a.Equal(zpuFile.LogCompress, true)
	a.Equal(zpuFile.LogMaxSize, 10)
	a.Equal(zpuFile.LogMaxBackups, 2)
	a.Equal(zpuFile.LogMaxAge, 7)
	a.Equal(zpuFile.PrivateKey, "./privatekey")
	a.Equal(zpuFile.CaCertFile, "./cacert.pem")
	a.Equal(zpuFile.CertFile, "./certfile.pem")
	a.Equal(zpuFile.Proxy, true)
}

func TestNewZpuConfiguration(t *testing.T) {
	a := assert.New(t)
	os.Setenv("STARTUP_DELAY", "60")
	err := devel.CreateFile(ZPU_CONF, `{"domains":"domain","user":"user","tempPolicyDir": "/tmp/zpu_temp","policyDir":"/policy","metricsDir":"/metric","logMaxsize":10,"logMaxage":7,"logMaxbackups":2,"logCompress":true,"proxy":true,"certFile":"./certfile.pem","caCertFile":"./cacert.pem","privateKeyFile":"./privatekey"}`)
	a.Nil(err)
	a.Nil(err)
	err = devel.CreateFile(ATHENZ_CONF, `{"zmsUrl":"zms_url","ztsUrl":"zts_url","ztsPublicKeys":[{"id":"0","key":"key0"}],"zmsPublicKeys":[{"id":"1","key":"key1"}]}`)
	a.Nil(err)
	config, err := NewZpuConfiguration("", ATHENZ_CONF, ZPU_CONF)
	a.Nil(err)
	a.Equal(config.StartUpDelay, 3600)
	a.Equal(config.Zts, "zts_url")
	a.Equal(config.Zms, "zms_url")
	a.Equal(config.PolicyFileDir, "/policy")
	a.Equal(config.TempPolicyFileDir, "/tmp/zpu_temp")
	a.Equal(config.DomainList, "domain")
	a.Equal(config.ZpuOwner, "user")
	a.Equal(config.MetricsDir, "/metric")
	a.Equal(string(new(zmssvctoken.YBase64).EncodeToString([]byte(config.ZtsKeysmap["0"]))), "key0")
	a.Equal(string(new(zmssvctoken.YBase64).EncodeToString([]byte(config.ZmsKeysmap["1"]))), "key1")
	a.Equal(config.LogSize, 10)
	a.Equal(config.LogAge, 7)
	a.Equal(config.LogBackups, 2)
	a.Equal(config.LogCompression, true)
	a.Equal(config.PrivateKeyFile, "./privatekey")
	a.Equal(config.CaCertFile, "./cacert.pem")
	a.Equal(config.CertFile, "./certfile.pem")
	a.Equal(config.Proxy, true)

	//testing defaults
	os.Unsetenv("STARTUP_DELAY")
	err = devel.CreateFile(ZPU_CONF, `{"domains":"domain"}`)
	a.Nil(err)
	config, err = NewZpuConfiguration("", ATHENZ_CONF, ZPU_CONF)
	a.Nil(err)
	a.Equal(config.StartUpDelay, 0)
	a.Equal(config.Zts, "zts_url")
	a.Equal(config.Zms, "zms_url")
	a.Equal(config.PolicyFileDir, "/var/zpe")
	a.Equal(config.TempPolicyFileDir, TEMP_POLICIES_DIR)
	a.Equal(config.DomainList, "domain")
	a.Equal(config.ZpuOwner, "root")
	a.Equal(config.MetricsDir, "/var/zpe_stat")
	a.Equal(string(new(zmssvctoken.YBase64).EncodeToString([]byte(config.ZtsKeysmap["0"]))), "key0")
	a.Equal(string(new(zmssvctoken.YBase64).EncodeToString([]byte(config.ZmsKeysmap["1"]))), "key1")
	a.Equal(config.LogSize, 0)
	a.Equal(config.LogAge, 0)
	a.Equal(config.LogBackups, 0)
	a.Equal(config.LogCompression, false)
	a.Equal(config.PrivateKeyFile, "")
	a.Equal(config.CaCertFile, "")
	a.Equal(config.CertFile, "")
	a.Equal(config.Proxy, false)

	//Start up delay more than than max startup delay
	os.Setenv("STARTUP_DELAY", "2000")
	config, err = NewZpuConfiguration("", ATHENZ_CONF, ZPU_CONF)
	a.Nil(err)
	a.Equal(config.StartUpDelay, 86400)

	//Start up delay less than than min startup delay
	os.Setenv("STARTUP_DELAY", "-10")
	config, err = NewZpuConfiguration("", ATHENZ_CONF, ZPU_CONF)
	a.Nil(err)
	a.Equal(config.StartUpDelay, 0)

	//invalid environment variable
	os.Setenv("STARTUP_DELAY", "invalid")
	config, err = NewZpuConfiguration("", ATHENZ_CONF, ZPU_CONF)
	a.NotNil(err)
	a.Nil(config)

	//invalid keys
	err = devel.CreateFile(ATHENZ_CONF, `{"ztsPublicKeys":[{"id":"0","key":"key_0"}],"zmsPublicKeys":[{"id":"1","key":"key_1"}]}`)
	a.Nil(err)
	config, err = NewZpuConfiguration("", ATHENZ_CONF, ZPU_CONF)
	a.NotNil(err)
	a.Nil(config)

	//incorrect json
	err = devel.CreateFile(ZPU_CONF, `{"domains":"domain""user":"user"`)
	config, err = NewZpuConfiguration("", ATHENZ_CONF, ZPU_CONF)
	a.NotNil(err)
	a.Nil(config)

}
