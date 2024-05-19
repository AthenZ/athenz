package config

import (
	"crypto/tls"
	"crypto/x509"
)

func GetTLSConfigFromFiles(certFile, keyFile string) (*tls.Config, error) {
	cert, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		return nil, err
	}
	config := ClientTLSConfig()
	config.Certificates = []tls.Certificate{cert}

	return config, nil
}

func ClientTLSConfigFromPEM(keypem, certpem, cacertpem []byte) (*tls.Config, error) {
	config := &tls.Config{}
	if certpem != nil && keypem != nil {
		mycert, err := tls.X509KeyPair(certpem, keypem)
		if err != nil {
			return nil, err
		}
		config.Certificates = make([]tls.Certificate, 1)
		config.Certificates[0] = mycert
	}
	if cacertpem != nil {
		certPool := x509.NewCertPool()
		certPool.AppendCertsFromPEM(cacertpem)
		config.RootCAs = certPool
	}
	return config, nil
}

// ClientTLSConfig returns a base TLS config using standard cipher suites with additional
// attrs set, including a minimum TLS version and session tickets disabling.
func ClientTLSConfig() *tls.Config {
	var config tls.Config
	// use standard cipher suites and prefer them
	config.CipherSuites = StandardCipherSuites()
	// require TLS 1.2 or higher
	config.MinVersion = tls.VersionTLS12
	// Don't allow session resumption
	config.SessionTicketsDisabled = true
	return &config
}

// StandardCipherSuites returns a list of acceptable cipher suites in priority order of use.
func StandardCipherSuites() []uint16 {
	return []uint16{
		// TLS 1.3 cipher suites.
		tls.TLS_AES_128_GCM_SHA256,
		tls.TLS_AES_256_GCM_SHA384,
		tls.TLS_CHACHA20_POLY1305_SHA256,

		// TLS 1.2 cipher suites.
		tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
		tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
		tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305,
		// Go stdlib currently does not support AES CCM cipher suite - https://github.com/golang/go/issues/27484
		tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
		tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
		tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305,
	}
}
