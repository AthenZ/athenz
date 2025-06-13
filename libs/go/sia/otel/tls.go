package otel

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"os"
	"time"

	"github.com/AthenZ/athenz/libs/go/sia/config"
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

	cfg := &tls.Config{
		MinVersion:             tls.VersionTLS12,           // require TLS 1.2 or higher
		NextProtos:             []string{"h2", "http/1.1"}, // prefer HTTP/2 explicitly
		CipherSuites:           standardCipherSuites(),
		SessionTicketsDisabled: true, // Don't allow session resumption
		RootCAs:                caCertPool,
	}

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
		cfg.GetClientCertificate = reloader.GetClientCertificate
	}
	return cfg, nil
}

func standardCipherSuites() []uint16 {
	return []uint16{
		// TLS 1.3 cipher suites.
		tls.TLS_AES_128_GCM_SHA256,
		tls.TLS_AES_256_GCM_SHA384,
		tls.TLS_CHACHA20_POLY1305_SHA256,

		// TLS 1.2 cipher suites.
		tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
		tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
		tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
		// Go stdlib currently does not support AES CCM cipher suite - https://github.com/golang/go/issues/27484
		tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
		tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
		tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
	}
}
