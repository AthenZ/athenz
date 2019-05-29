// Copyright 2017 Yahoo Holdings, Inc.
// Licensed under the terms of the Apache version 2.0 license. See LICENSE file for terms.

// Tools is a program that runs zpu.PolicyUpdater.
package main

import (
	"flag"
	"fmt"
	"log"
	"math/rand"
	"os"
	"time"

	"github.com/yahoo/athenz/utils/zpe-updater"
	"gopkg.in/natefinch/lumberjack.v2"
)

func main() {
	root := os.Getenv("ROOT")
	if root == "" {
		root = "/home/athenz"
	}
	var athenzConf, zpuConf, logFile, ztsURL, privateKeyFile, certFile, caCertFile string
	flag.StringVar(&athenzConf, "athenzConf",
		fmt.Sprintf("%s/conf/athenz/athenz.conf", root),
		"Athenz configuration file path for ZMS/ZTS urls and public keys")
	flag.StringVar(&zpuConf, "zpuConf",
		fmt.Sprintf("%s/conf/zpu/zpu.conf", root),
		"ZPU utility configuration path")
	flag.StringVar(&logFile, "logFile",
		fmt.Sprintf("%s/logs/zpu/zpu.log", root),
		"Log file name")
	flag.StringVar(&ztsURL, "zts",
		"", "url of the ZTS Service")
	flag.StringVar(&caCertFile, "cacert",
		"", "CA certificate file")
	flag.StringVar(&privateKeyFile, "private-key",
		"", "private key file")
	flag.StringVar(&certFile, "cert-file",
		"", "certificate file")

	flag.Parse()

	logger := lumberjack.Logger{
		Compress:   true,
		Filename:   logFile,
		MaxSize:    100, // megabytes
		MaxBackups: 7,
		MaxAge:     28, //days
	}

	if logFile != "" {

		f, err := os.OpenFile(logFile, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
		if err != nil {
			log.Fatalf("The log file:%v cannot be opened, Error:%v. \n "+
				"If you do not have write access to the log file at \"%v\", use the -logFile flag to overwrite the default value. \n"+
				"Usage : zpu -athenzConf <Athenz log file> -zpuConf <zpu conf file> -logFile <log file name>. ", logFile, logFile, err)
		}
		f.Close()
		log.SetOutput(&logger)
	}

	zpuConfig, err := zpu.NewZpuConfiguration(root, athenzConf, zpuConf)
	if err != nil {
		log.Fatalf("Unable to get zpu configuration, Error: %v", err)
	}
	if !zpuConfig.LogCompression {
		logger.Compress = false
	}

	if zpuConfig.LogBackups != 0 {
		logger.MaxBackups = zpuConfig.LogBackups
	}

	if zpuConfig.LogAge != 0 {
		logger.MaxAge = zpuConfig.LogAge
	}

	if zpuConfig.LogSize != 0 {
		logger.MaxSize = zpuConfig.LogSize
	}

	if privateKeyFile != "" {
		zpuConfig.PrivateKeyFile = privateKeyFile
	}

	if caCertFile != "" {
		zpuConfig.CaCertFile = caCertFile
	}
	if certFile != "" {
		zpuConfig.CertFile = certFile
	}

	if ztsURL != "" {
		zpuConfig.Zts = ztsURL
	}

	if zpuConfig.StartUpDelay > 0 {
		rand.Seed(time.Now().Unix())
		randmonSleepInterval := rand.Intn(zpuConfig.StartUpDelay)
		log.Printf("Launching zpe_policy_updater in %v seconds", randmonSleepInterval)
		time.Sleep(time.Duration(randmonSleepInterval) * time.Second)
	} else {
		log.Println("Launching zpe_policy_updater without delay")
	}
	err = zpu.PolicyUpdater(zpuConfig)
	if err != nil {
		log.Fatalf("Policy updator failed, %v", err)
	}
	log.Println("Policy updator finished successfully")
}
