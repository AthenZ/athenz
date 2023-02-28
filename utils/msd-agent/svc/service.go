// Copyright The Athenz Authors
// Licensed under the terms of the Apache version 2.0 license. See LICENSE file for terms.

package svc

import (
	"net"
	"os"
	"path/filepath"

	"github.com/AthenZ/athenz/libs/go/athenz-common/log"
	siafile "github.com/AthenZ/athenz/libs/go/sia/file"
)

type MsdHost struct {
	HostDocument []byte
	SiaConfig    []byte
}

type Service struct {
	Name         string
	KeyFilename  string
	CertFilename string
	User         string
	Group        string
	Uid          int
	Gid          int
	FileMode     int
}

type ServicesData struct {
	SrvArr []Service
	Ips    []net.IP
	Domain string
}

const (
	PROFILE_CONFIG  = "/etc/sia/profile_config"
	SIA_CONFIG      = "/etc/sia/sia_config"
	SIA_DIR         = "/var/lib/sia"
	HOST_DOCUMENT   = "host_document"
	PROFILE_TAG_KEY = "profile:Tag"
)

var cloudFetcher Fetcher
var onPremFetcher Fetcher
var msdHost *MsdHost = nil

func SetCloudFetcher(fetcher Fetcher) {
	cloudFetcher = fetcher
}

func SetOnPremFetcher(fetcher Fetcher) {
	onPremFetcher = fetcher
}

// Map the service name to its service configuration
func GetServicesData(accountId string) (ServicesData, error) {
	validateMsdHost()

	// cloud host sia_config presented without host_document
	if msdHost.SiaConfig != nil && msdHost.HostDocument == nil {
		return cloudFetcher.Fetch(*msdHost, accountId)
	}

	// on-prem host
	return onPremFetcher.Fetch(*msdHost, accountId)
}

func validateMsdHost() {
	if msdHost == nil {
		docBytes, docPath := ReadHostDocument()
		siaBytes, siaPath := ReadSiaConfig()
		msdHost = &MsdHost{
			HostDocument: docBytes,
			SiaConfig:    siaBytes,
		}
		log.Debugf("HostDocument: %s", docPath)
		log.Debugf("SiaConfig: %s", siaPath)
	}
}

func GetAccountId() (string, error) {
	validateMsdHost()

	// cloud host sia_config presented without host_document
	if msdHost.SiaConfig != nil && msdHost.HostDocument == nil {
		return cloudFetcher.GetAccountId()
	}

	// on-prem host
	return onPremFetcher.GetAccountId()
}

func ReadSiaConfig() ([]byte, string) {
	if !siafile.Exists(SIA_DIR) {
		log.Print("SIA_DIR not exist")
		return nil, ""
	}
	if siafile.Exists(SIA_CONFIG) {
		bytes, err := os.ReadFile(SIA_CONFIG)
		if err != nil {
			return nil, ""
		} else if len(bytes) == 0 {
			return nil, ""
		}
		return bytes, SIA_CONFIG
	}
	return nil, ""
}

func ReadHostDocument() ([]byte, string) {
	docFile := filepath.Join(SIA_DIR, HOST_DOCUMENT)
	if siafile.Exists(docFile) {
		docBytes, err := os.ReadFile(docFile)
		if err == nil {
			return docBytes, docFile
		}
	}
	return nil, ""
}
