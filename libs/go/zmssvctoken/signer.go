// Copyright The Athenz Authors
// Licensed under the terms of the Apache version 2.0 license. See LICENSE file for terms.

package zmssvctoken

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/asn1"
	"encoding/pem"
	"fmt"
	"math/big"
	"reflect"
)

var hash = crypto.SHA256

// Signer signs a string and returns the signature.
type Signer interface {
	Sign(input string) (string, error)
}

// Verifier verifies the signature for a string.
type Verifier interface {
	Verify(input, signature string) error
}

// hashString hashes the input string using the
// standard hash algo
func hashString(input string) ([]byte, error) {
	h := hash.New()
	_, err := h.Write([]byte(input))
	if err != nil {
		return nil, err
	}

	return h.Sum(nil), nil
}

// ExtractSignerInfo extract crypto.Signer and x509.SignatureAlgorithm from the given private key (ECDSA or RSA).
func ExtractSignerInfo(privateKeyPEM []byte) (crypto.Signer, x509.SignatureAlgorithm, error) {
	block, _ := pem.Decode(privateKeyPEM)
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

// NewSigner creates an instance of Signer using the given private key (ECDSA or RSA).
func NewSigner(privateKeyPEM []byte) (Signer, error) {
	key, _, err := ExtractSignerInfo(privateKeyPEM)
	if err != nil {
		return nil, err
	}
	return &sign{key: key}, nil
}

type sign struct {
	key crypto.Signer
}

// Sign signs the given input string using the internal key.
func (s *sign) Sign(input string) (string, error) {
	hashed, err := hashString(input)
	if err != nil {
		return "", err
	}
	signed, err := s.key.Sign(rand.Reader, hashed, hash)
	if err != nil {
		return "", err
	}
	return new(YBase64).EncodeToString(signed), nil
}

type internalVerifier interface {
	Verify(hashed []byte, sig []byte) error
}

type rsaVerify struct {
	key *rsa.PublicKey
}

// Verify verifies the signature of the input using the RSA public key.
func (r *rsaVerify) Verify(hashed []byte, sig []byte) error {
	return rsa.VerifyPKCS1v15(r.key, hash, hashed, sig)
}

type ecdsaVerify struct {
	key *ecdsa.PublicKey
}

// Verify verifies the signature of the input using the ECDSA public key.
func (e *ecdsaVerify) Verify(hashed []byte, sig []byte) error {
	var s struct {
		R, S *big.Int
	}
	_, err := asn1.Unmarshal(sig, &s)
	if err != nil {
		return fmt.Errorf("Unable to unmarshal ECDSA sig, %v", err)
	}
	if ok := ecdsa.Verify(e.key, hashed, s.R, s.S); !ok {
		return fmt.Errorf("Invalid ECDSA signature")
	}
	return nil
}

// NewVerifier creates an instance of Verifier using the given public key.
func NewVerifier(publicKeyPEM []byte) (Verifier, error) {
	block, _ := pem.Decode(publicKeyPEM)
	if block == nil {
		return nil, fmt.Errorf("Unable to load public key")
	}

	xkey, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, err
	}
	switch key := xkey.(type) {
	case *rsa.PublicKey:
		return &verify{iv: &rsaVerify{key: key}}, nil
	case *ecdsa.PublicKey:
		return &verify{iv: &ecdsaVerify{key: key}}, nil
	default:
		return nil, fmt.Errorf("Unsupported key type, not RSA or ECDSA")
	}
}

type verify struct {
	iv internalVerifier
}

// Verify verifies the ybase64-encoded signature of the input.
func (v *verify) Verify(input, signature string) error {
	sigBytes, err := new(YBase64).DecodeString(signature)
	if err != nil {
		return err
	}

	hashed, err := hashString(input)
	if err != nil {
		return err
	}

	return v.iv.Verify(hashed, sigBytes)
}
