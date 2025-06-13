package otel

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"os"
	"time"

	"github.com/AthenZ/athenz/libs/go/sia/config"
)

// GetOTelClientTLSConfig returns the tls configuration for OTel instrumentation.
func GetOTelClientTLSConfig(otelConf config.OTelConfig) (*tls.Config, error) {
	reloader, err := ytls.NewMemCertReloader(ytls.MemReloadConfig{
		CertKeyGetter: func() ([]byte, []byte, error) {
			certPEMBlock, err := os.ReadFile(otelConf.ClientCertPath)
			if err != nil {
				return nil, nil, err
			}
			keyPEMBlock, err := os.ReadFile(otelConf.ClientKeyPath)
			if err != nil {
				return nil, nil, err
			}
			return certPEMBlock, keyPEMBlock, nil
		},
		InsecureAllowPrivateKeyReuse: false,
		PollInterval:                 6 * time.Hour,
	})
	if err != nil {
		return nil, fmt.Errorf("unable to get client cert reloader: %s", err)
	}

	caCertPool := x509.NewCertPool()
	caCert, err := os.ReadFile(otelConf.OTelCACertPath)
	if err != nil {
		return nil, fmt.Errorf(`failed to read OTel CA certificate %q, err:%v`, otelConf.OTelCACertPath, err)
	}
	if ok := caCertPool.AppendCertsFromPEM(caCert); !ok {
		return nil, fmt.Errorf(`failed to parse certificate %q`, otelConf.OTelCACertPath)
	}

	clientTLSConfig := ytls.ClientTLSConfig()
	clientTLSConfig.GetClientCertificate = reloader.GetClientCertificate
	clientTLSConfig.RootCAs = caCertPool
	clientTLSConfig.InsecureSkipVerify = false
	return clientTLSConfig, nil
}
