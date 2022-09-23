// Copyright The Athenz Authors
// Licensed under the terms of the Apache version 2.0 license. See LICENSE file for terms.

package zpu

import (
	"os"
	"testing"

	"github.com/AthenZ/athenz/libs/go/zmssvctoken"
	"github.com/AthenZ/athenz/utils/zpe-updater/devel"
	"github.com/stretchr/testify/assert"
)

const (
	tempFolder = "/tmp"
	athenzConf = tempFolder + "/athenz.conf"
	zpuConf    = tempFolder + "/zpu.conf"
)

func TestReadAthenzConf(t *testing.T) {

	var athenzFile *AthenzConf
	a := assert.New(t)

	//missing keys
	err := devel.CreateFile(athenzConf, `{"zmsUrl":"zms_url","zmsPublicKeys":[{"id":"0","key":"zmsKey"}]}`)
	a.Nil(err)
	athenzFile, err = ReadAthenzConf(athenzConf)
	a.Nil(err)
	a.Equal(athenzFile.ZmsUrl, "zms_url")
	a.Empty(athenzFile.ZtsUrl)
	a.Equal(len(athenzFile.ZmsPublicKeys), 1)
	a.Empty(athenzFile.ZtsPublicKeys)
	a.Equal(len(athenzFile.ZtsPublicKeys), 0)
	a.Equal(athenzFile.ZmsPublicKeys[0].Id, "0")
	a.Equal(athenzFile.ZmsPublicKeys[0].Key, "zmsKey")

	//incorrect file
	err = devel.CreateFile(athenzConf, `"zmsUrl":"zms_url","zmsPublicKeys":[{"id":"0","key":"zmsKey"}]}`)
	a.Nil(err)
	athenzFile, err = ReadAthenzConf(athenzConf)
	a.NotNil(err)
	a.Empty(athenzFile)

	//correct file
	err = devel.CreateFile(athenzConf, `{"zmsUrl":"zms_url","ztsUrl":"zts_url","ztsPublicKeys":[{"id":"0","key":"key0"}],"zmsPublicKeys":[{"id":"1","key":"key1"}]}`)
	a.Nil(err)
	athenzFile, err = ReadAthenzConf(athenzConf)
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
	err := devel.CreateFile(zpuConf, `{"domains":"domain","user":"user","logMaxSize":10}`)
	a.Nil(err)
	zpuFile, err = ReadZpuConf(zpuConf)
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
	a.Equal(zpuFile.ExpiryCheck, 0)
	a.Equal(zpuFile.CheckZMSSignature, false)

	//incorrect file
	err = devel.CreateFile(zpuConf, `{"domains":"domain""user":"user"`)
	zpuFile, err = ReadZpuConf(zpuConf)
	a.NotNil(err)
	a.Empty(zpuFile)

	//correct file
	err = devel.CreateFile(zpuConf, `{"domains":"domain","user":"user","policyDir":"/policy","metricsDir":"/metric","logMaxsize":10,"logMaxage":7,"logMaxbackups":2,"logCompress":true,"proxy":true,"certFile":"./certfile.pem","caCertFile":"./cacert.pem","privateKeyFile":"./privatekey","expiryCheck":30,"checkZMSSignature":true}`)
	a.Nil(err)
	zpuFile, err = ReadZpuConf(zpuConf)
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
	a.Equal(zpuFile.ExpiryCheck, 30)
	a.Equal(zpuFile.CheckZMSSignature, true)

	//correct file with jws/policy attributes
	err = devel.CreateFile(zpuConf, `{"domains":"domain","user":"user","policyDir":"/policy","metricsDir":"/metric","logMaxsize":10,"logMaxage":7,"logMaxbackups":2,"logCompress":true,"proxy":true,"certFile":"./certfile.pem","caCertFile":"./cacert.pem","privateKeyFile":"./privatekey","expiryCheck":30,"checkZMSSignature":true,"jwsPolicySupport":true,"policyVersions":{"policy1":"0","policy2":"1"}}`)
	a.Nil(err)
	zpuFile, err = ReadZpuConf(zpuConf)
	a.Nil(err)
	a.Equal(zpuFile.Domains, "domain")
	a.Equal(zpuFile.User, "user")
	a.Equal(zpuFile.PolicyDir, "/policy")
	a.Equal(zpuFile.MetricsDir, "/metric")
	a.True(zpuFile.LogCompress)
	a.Equal(zpuFile.LogMaxSize, 10)
	a.Equal(zpuFile.LogMaxBackups, 2)
	a.Equal(zpuFile.LogMaxAge, 7)
	a.Equal(zpuFile.PrivateKey, "./privatekey")
	a.Equal(zpuFile.CaCertFile, "./cacert.pem")
	a.Equal(zpuFile.CertFile, "./certfile.pem")
	a.True(zpuFile.Proxy)
	a.Equal(zpuFile.ExpiryCheck, 30)
	a.True(zpuFile.CheckZMSSignature)
	a.True(zpuFile.JWSPolicySupport)
	a.Equal(zpuFile.PolicyVersions["policy1"], "0")
	a.Equal(zpuFile.PolicyVersions["policy2"], "1")
}

func TestNewZpuConfiguration(t *testing.T) {
	a := assert.New(t)
	_ = os.Setenv("STARTUP_DELAY", "60")
	err := devel.CreateFile(zpuConf, `{"domains":"domain","user":"user","tempPolicyDir": "/tmp/zpu_temp","policyDir":"/policy","metricsDir":"/metric","logMaxsize":10,"logMaxage":7,"logMaxbackups":2,"logCompress":true,"proxy":true,"certFile":"./certfile.pem","caCertFile":"./cacert.pem","privateKeyFile":"./privatekey","expiryCheck":50}`)
	a.Nil(err)
	a.Nil(err)
	err = devel.CreateFile(athenzConf, `{"zmsUrl":"zms_url","ztsUrl":"zts_url","ztsPublicKeys":[{"id":"0","key":"key0"}],"zmsPublicKeys":[{"id":"1","key":"key1"}]}`)
	a.Nil(err)
	config, err := NewZpuConfiguration("", athenzConf, zpuConf, tempFolder)
	a.Nil(err)
	a.Equal(config.StartUpDelay, 3600)
	a.Equal(config.Zts, "zts_url")
	a.Equal(config.Zms, "zms_url")
	a.Equal(config.PolicyFileDir, "/policy")
	a.Equal(config.TempPolicyFileDir, "/tmp/zpu_temp")
	a.Equal(config.DomainList, "domain")
	a.Equal(config.ZpuOwner, "user")
	a.Equal(config.MetricsDir, "/metric")
	a.Equal(new(zmssvctoken.YBase64).EncodeToString([]byte(config.ZtsKeysmap["0"])), "key0")
	a.Equal(new(zmssvctoken.YBase64).EncodeToString([]byte(config.ZmsKeysmap["1"])), "key1")
	a.Equal(config.LogSize, 10)
	a.Equal(config.LogAge, 7)
	a.Equal(config.LogBackups, 2)
	a.Equal(config.LogCompression, true)
	a.Equal(config.PrivateKeyFile, "./privatekey")
	a.Equal(config.CaCertFile, "./cacert.pem")
	a.Equal(config.CertFile, "./certfile.pem")
	a.Equal(config.Proxy, true)
	a.Equal(config.ExpiryCheck, 50*60)

	//testing defaults
	_ = os.Unsetenv("STARTUP_DELAY")
	err = devel.CreateFile(zpuConf, `{"domains":"domain"}`)
	a.Nil(err)
	config, err = NewZpuConfiguration("", athenzConf, zpuConf, tempFolder)
	a.Nil(err)
	a.Equal(config.StartUpDelay, 0)
	a.Equal(config.Zts, "zts_url")
	a.Equal(config.Zms, "zms_url")
	a.Equal(config.PolicyFileDir, "/var/zpe")
	a.Equal(config.TempPolicyFileDir, TempPoliciesDir)
	a.Equal(config.DomainList, "domain")
	a.Equal(config.ZpuOwner, "root")
	a.Equal(config.MetricsDir, "/var/zpe_stat")
	a.Equal(new(zmssvctoken.YBase64).EncodeToString([]byte(config.ZtsKeysmap["0"])), "key0")
	a.Equal(new(zmssvctoken.YBase64).EncodeToString([]byte(config.ZmsKeysmap["1"])), "key1")
	a.Equal(config.LogSize, 0)
	a.Equal(config.LogAge, 0)
	a.Equal(config.LogBackups, 0)
	a.Equal(config.LogCompression, false)
	a.Equal(config.PrivateKeyFile, "")
	a.Equal(config.CaCertFile, "")
	a.Equal(config.CertFile, "")
	a.Equal(config.Proxy, false)
	a.Equal(config.ExpiryCheck, 2880*60)

	//Start up delay more than max startup delay
	_ = os.Setenv("STARTUP_DELAY", "2000")
	config, err = NewZpuConfiguration("", athenzConf, zpuConf, tempFolder)
	a.Nil(err)
	a.Equal(config.StartUpDelay, 86400)

	//Start up delay less than min startup delay
	_ = os.Setenv("STARTUP_DELAY", "-10")
	config, err = NewZpuConfiguration("", athenzConf, zpuConf, tempFolder)
	a.Nil(err)
	a.Equal(config.StartUpDelay, 0)

	//invalid environment variable
	_ = os.Setenv("STARTUP_DELAY", "invalid")
	config, err = NewZpuConfiguration("", athenzConf, zpuConf, tempFolder)
	a.NotNil(err)
	a.Nil(config)

	//invalid keys
	err = devel.CreateFile(athenzConf, `{"ztsPublicKeys":[{"id":"0","key":"key_0"}],"zmsPublicKeys":[{"id":"1","key":"key_1"}]}`)
	a.Nil(err)
	config, err = NewZpuConfiguration("", athenzConf, zpuConf, tempFolder)
	a.NotNil(err)
	a.Nil(config)

	//incorrect json
	err = devel.CreateFile(zpuConf, `{"domains":"domain""user":"user"`)
	config, err = NewZpuConfiguration("", athenzConf, zpuConf, tempFolder)
	a.NotNil(err)
	a.Nil(config)

}
