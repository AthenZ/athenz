package otel

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"os"
	"time"

	"github.com/AthenZ/athenz/libs/go/sia/config"
	tlsconfig "github.com/AthenZ/athenz/libs/go/tls/config"
	"github.com/theparanoids/crypki/certreload"
)

// getOTelClientTLSConfig returns the tls configuration for OTel instrumentation.
func getOTelClientTLSConfig(oTelConf config.OTel) (*tls.Config, error) {
	caCertPool := x509.NewCertPool()
	caCert, err := os.ReadFile(oTelConf.CACertPath)
	if err != nil {
		return nil, fmt.Errorf(`failed to read OTel CA certificate %q, err:%v`, oTelConf.CACertPath, err)
	}
	if ok := caCertPool.AppendCertsFromPEM(caCert); !ok {
		return nil, fmt.Errorf(`failed to parse certificate %q`, oTelConf.CACertPath)
	}

	tlsConf := tlsconfig.ClientTLSConfig()
	tlsConf.ClientCAs = caCertPool

	if oTelConf.MTLS {
		reloader, err := certreload.NewCertReloader(
			certreload.CertReloadConfig{
				CertKeyGetter: func() ([]byte, []byte, error) {
					certPEMBlock, err := os.ReadFile(oTelConf.ClientCertPath)
					if err != nil {
						return nil, nil, err
					}
					keyPEMBlock, err := os.ReadFile(oTelConf.ClientKeyPath)
					if err != nil {
						return nil, nil, err
					}
					return certPEMBlock, keyPEMBlock, nil
				},
				PollInterval: 6 * time.Hour,
			})
		if err != nil {
			return nil, fmt.Errorf("unable to get client cert reloader for oTel: %s", err)
		}
		tlsConf.GetClientCertificate = reloader.GetClientCertificate
	}
	return tlsConf, nil
}
