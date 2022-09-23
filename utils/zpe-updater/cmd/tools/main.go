// Copyright The Athenz Authors
// Licensed under the terms of the Apache version 2.0 license. See LICENSE file for terms.

// Tools is a program that runs zpu.PolicyUpdater.
package main

import (
	"flag"
	"fmt"
	"github.com/AthenZ/athenz/libs/go/athenz-common/log"
	"github.com/AthenZ/athenz/utils/zpe-updater/errconv"
	"github.com/AthenZ/athenz/utils/zpe-updater/metrics"
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
	var athenzConf, zpuConf, logFile, ztsURL, privateKeyFile, certFile, caCertFile, viewDomain, siaDir string
	var debug, forceRefresh, checkStatus, checkDetails bool
	flag.StringVar(&athenzConf, "athenzConf", fmt.Sprintf("%s/conf/athenz/athenz.conf", root), "Athenz configuration file path for ZMS/ZTS urls and public keys")
	flag.StringVar(&zpuConf, "zpuConf", fmt.Sprintf("%s/conf/zpu/zpu.conf", root), "ZPU utility configuration path")
	flag.StringVar(&logFile, "logFile", fmt.Sprintf("%s/logs/zpu/zpu.log", root), "Log file name")
	flag.StringVar(&ztsURL, "zts", "", "url of the ZTS Service")
	flag.StringVar(&caCertFile, "cacert", "", "CA certificate file")
	flag.StringVar(&privateKeyFile, "private-key", "", "private key file")
	flag.StringVar(&certFile, "cert-file", "", "certificate file")
	flag.BoolVar(&forceRefresh, "force-refresh", false, "Force refresh of policy files")
	flag.BoolVar(&checkStatus, "check-status", false, "Check zpu state and display status only")
	flag.BoolVar(&checkDetails, "check-details", false, "Check zpu state and display details")
	flag.StringVar(&viewDomain, "view-domain", "", "view policy domain")
	flag.StringVar(&siaDir, "sia-dir", "/var/lib/sia", "sia directory")
	flag.BoolVar(&debug, "debug", false, "Use debug logging")

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
	log.Debug = debug

	zpuConfig, err := zpu.NewZpuConfiguration(root, athenzConf, zpuConf, siaDir)
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
	if checkStatus || checkDetails {
		policyStatus, errorMessages := zpu.CheckState(zpuConfig)
		policyMetrics := metrics.FormPolicyMetrics(policyStatus)
		bytes := []byte{'['}
		for _, policyMetric := range policyMetrics {
			metricBytes, err := metrics.DumpMetric(policyMetric)
			if err != nil {
				errorMessages = append(errorMessages, err)
			} else {
				if len(bytes) != 1 {
					bytes = append(bytes, byte(','))
				}
				bytes = append(bytes, metricBytes...)
			}
		}
		bytes = append(bytes, byte(']'))
		statusBytes, exitCode, err := metrics.DumpStatus(errconv.Reduce(errorMessages))
		if err != nil {
			statusBytes = metrics.GetFailedStatus(err)
		}
		if checkStatus {
			fmt.Printf("%s\n", statusBytes)
		} else {
			fmt.Printf("%s\n", bytes)
		}
		os.Exit(exitCode)
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
		randomSleepInterval := rand.Intn(zpuConfig.StartUpDelay)
		log.Printf("Launching zpe_policy_updater in %v seconds", randomSleepInterval)
		time.Sleep(time.Duration(randomSleepInterval) * time.Second)
	} else {
		log.Printf("Launching zpe_policy_updater without delay")
	}
	err = zpu.PolicyUpdater(zpuConfig)
	if err != nil {
		log.Fatalf("Policy updater failed, %v", err)
	}
	log.Printf("Policy updater finished successfully")
}
