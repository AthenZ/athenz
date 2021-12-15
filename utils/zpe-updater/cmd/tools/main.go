// Copyright 2017 Yahoo Holdings, Inc.
// Licensed under the terms of the Apache version 2.0 license. See LICENSE file for terms.

// Tools is a program that runs zpu.PolicyUpdater.
package main

import (
	"flag"
	"fmt"
	"github.com/AthenZ/athenz/utils/zpe-updater/errconv"
	"github.com/AthenZ/athenz/utils/zpe-updater/metrics"
	"log"
	"math/rand"
	"os"
	"time"

	"github.com/AthenZ/athenz/utils/zpe-updater"
	"gopkg.in/natefinch/lumberjack.v2"
)

func main() {
	root := os.Getenv("ROOT")
	if root == "" {
		root = "/home/athenz"
	}
	var athenzConf, zpuConf, logFile, ztsURL, privateKeyFile, certFile, caCertFile, viewDomain string
	var forceRefresh, check bool
	flag.StringVar(&athenzConf, "athenzConf", fmt.Sprintf("%s/conf/athenz/athenz.conf", root), "Athenz configuration file path for ZMS/ZTS urls and public keys")
	flag.StringVar(&zpuConf, "zpuConf", fmt.Sprintf("%s/conf/zpu/zpu.conf", root), "ZPU utility configuration path")
	flag.StringVar(&logFile, "logFile", fmt.Sprintf("%s/logs/zpu/zpu.log", root), "Log file name")
	flag.StringVar(&ztsURL, "zts", "", "url of the ZTS Service")
	flag.StringVar(&caCertFile, "cacert", "", "CA certificate file")
	flag.StringVar(&privateKeyFile, "private-key", "", "private key file")
	flag.StringVar(&certFile, "cert-file", "", "certificate file")
	flag.BoolVar(&forceRefresh, "force-refresh", false, "Force refresh of policy files")
	flag.BoolVar(&check, "check", false, "Check zpu state")
	flag.StringVar(&viewDomain, "view-domain", "", "view policy domain")

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
				"Usage : zpu -athenzConf <Athenz conf file> -zpuConf <zpu conf file> -logFile <log file name>. ", logFile, logFile, err)
		}
		f.Close()
		log.SetOutput(&logger)
	}

	zpuConfig, err := zpu.NewZpuConfiguration(root, athenzConf, zpuConf)
	if err != nil {
		log.Fatalf("Unable to get zpu configuration, Error: %v", err)
	}
	zpuConfig.ForceRefresh = forceRefresh

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

	// first, if running check we need to verify policy files
	// validity and generate a json metrics that can be pushed to
	// a monitoring service
	if check {
		var bytes []byte
		policyStatus, errorMessages := zpu.CheckState(zpuConfig)
		policyMetrics := metrics.FormPolicyMetrics(policyStatus)
		for _, policyMetric := range policyMetrics {
			metricBytes, err := metrics.DumpMetric(policyMetric, nil)
			if err != nil {
				errorMessages = append(errorMessages, err)
			}
			bytes = append(bytes, metricBytes...)
		}
		statusBytes, ok, err := metrics.DumpStatus(errconv.Reduce(errorMessages))
		if err != nil {
			byteString := metrics.GetFailedStatus(err)
			bytes = append([]byte(byteString), bytes...)
		}
		bytes = append(statusBytes, bytes...)

		fmt.Printf("%s\n", bytes)

		if ok {
			os.Exit(0)
		}
		os.Exit(1)
	}

	// then check if we're just asked to view a local domain
	// this option is mutually exclusive with running the updater
	if viewDomain != "" {
		err = zpu.PolicyView(zpuConfig, viewDomain)
		if err != nil {
			log.Fatalf("Unable to view policy file for domain %s, %v", viewDomain, err)
		}
		os.Exit(0)
	}

	// process regular zpu update process
	if zpuConfig.StartUpDelay > 0 {
		rand.Seed(time.Now().Unix())
		randmonSleepInterval := rand.Intn(zpuConfig.StartUpDelay)
		log.Printf("Launching zpe_policy_updater in %v seconds\n", randmonSleepInterval)
		time.Sleep(time.Duration(randmonSleepInterval) * time.Second)
	} else {
		log.Println("Launching zpe_policy_updater without delay")
	}
	err = zpu.PolicyUpdater(zpuConfig)
	if err != nil {
		log.Fatalf("Policy updater failed, %v", err)
	}
	log.Println("Policy updater finished successfully")
}
