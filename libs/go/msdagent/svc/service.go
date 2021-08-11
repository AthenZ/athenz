package svc

import (
	"io/ioutil"
	"net"
	"path/filepath"

	"github.com/AthenZ/athenz/libs/go/msdagent/log"

	"github.com/AthenZ/athenz/libs/go/msdagent/fsutil"
	"github.com/AthenZ/athenz/provider/aws/sia-ec2/options"
)

type MsdHost struct {
	HostDocument []byte
	SiaConfig    []byte
}

type ServicesData struct {
	SrvArr []options.Service
	Ips    []net.IP
	Domain string
}

const (
	SIA_CONFIG    = "/etc/sia/sia_config"
	SIA_DIR       = "/var/lib/sia"
	HOST_DOCUMENT = "host_document"
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
	if !fsutil.Exists(SIA_DIR) {
		log.Print("SIA_DIR not exist")
		return nil, ""
	}
	if fsutil.Exists(SIA_CONFIG) {
		bytes, err := ioutil.ReadFile(SIA_CONFIG)
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
	if fsutil.Exists(docFile) {
		docBytes, err := ioutil.ReadFile(docFile)
		if err == nil {
			return docBytes, docFile
		}
	}
	return nil, ""
}
