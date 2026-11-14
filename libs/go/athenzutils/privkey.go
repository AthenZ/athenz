package athenzutils

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"reflect"
	"strings"
)

// ExtractSignerInfo extracts crypto.Signer and x509.SignatureAlgorithm from the given private key (ECDSA or RSA).
// Like tls.X509KeyPair, PEM blocks before the private key (e.g. EC PARAMETERS) are skipped.
func ExtractSignerInfo(privateKeyPEM []byte) (crypto.Signer, x509.SignatureAlgorithm, error) {
	var block *pem.Block
	for rest := privateKeyPEM; ; {
		block, rest = pem.Decode(rest)
		if block == nil || block.Type == "PRIVATE KEY" || strings.HasSuffix(block.Type, " PRIVATE KEY") {
			break
		}
	}
	if block == nil {
		return nil, x509.UnknownSignatureAlgorithm, fmt.Errorf("unable to load private key")
	}

	switch block.Type {
	case "EC PRIVATE KEY":
		key, err := x509.ParseECPrivateKey(block.Bytes)
		if err != nil {
			return nil, x509.UnknownSignatureAlgorithm, err
		}
		return key, x509.ECDSAWithSHA256, nil
	case "RSA PRIVATE KEY":
		key, err := x509.ParsePKCS1PrivateKey(block.Bytes)
		if err != nil {
			return nil, x509.UnknownSignatureAlgorithm, err
		}
		return key, x509.SHA256WithRSA, nil
	case "PRIVATE KEY":
		key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
		if err != nil {
			return nil, x509.UnknownSignatureAlgorithm, err
		}
		switch k := key.(type) {
		case *ecdsa.PrivateKey:
			return k, x509.ECDSAWithSHA256, nil
		case *rsa.PrivateKey:
			return k, x509.SHA256WithRSA, nil
		default:
			// PKCS#8 format may contain multiple key types other than RSA / EC, but current ZMS / ZTS server implementation only supports RSA / EC private keys
			return nil, x509.UnknownSignatureAlgorithm, fmt.Errorf("unsupported private key type: %s", reflect.TypeOf(k).Name())
		}
	default:
		return nil, x509.UnknownSignatureAlgorithm, fmt.Errorf("unsupported private key type: %s", block.Type)
	}
}
