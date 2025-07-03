//
// Copyright The Athenz Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//

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
