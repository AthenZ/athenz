// Copyright 2016 Yahoo Inc.
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
	"strings"
)

var hash = crypto.SHA256

// signer signs a string and returns the signature
type signer interface {
	sign(input string) (string, error)
}

// verifier verifies the signature for a string
type verifier interface {
	verify(input, signature string) error
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

func newSigner(privateKeyPEM []byte) (signer, error) {
	block, _ := pem.Decode(privateKeyPEM)
	if block == nil {
		return nil, fmt.Errorf("Unable to load private key")
	}

	switch block.Type {
	case "EC PRIVATE KEY":
		key, err := x509.ParseECPrivateKey(block.Bytes)
		if err != nil {
			return nil, err
		}
		return &sign{key: key}, nil
	case "RSA PRIVATE KEY":
		key, err := x509.ParsePKCS1PrivateKey(block.Bytes)
		if err != nil {
			return nil, err
		}
		return &sign{key: key}, nil
	default:
		return nil, fmt.Errorf("Unsupported private key type: %s", block.Type)
	}
}

type sign struct {
	key crypto.Signer
}

func (s *sign) sign(input string) (string, error) {
	hashed, err := hashString(input)
	if err != nil {
		return "", err
	}
	signed, err := s.key.Sign(rand.Reader, hashed, hash)
	if err != nil {
		return "", err
	}
	return new(yBase64).EncodeToString(signed), nil
}

type internalVerifier interface {
	verify(hashed []byte, sig []byte) error
}

type rsaVerify struct {
	key *rsa.PublicKey
}

func (r *rsaVerify) verify(hashed []byte, sig []byte) error {
	return rsa.VerifyPKCS1v15(r.key, hash, hashed, sig)
}

type ecdsaVerify struct {
	key *ecdsa.PublicKey
}

func (e *ecdsaVerify) verify(hashed []byte, sig []byte) error {
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

func newVerifier(publicKeyPEM []byte) (verifier, error) {
	block, _ := pem.Decode(publicKeyPEM)
	if block == nil {
		return nil, fmt.Errorf("Unable to load public key")
	}
	if !strings.HasSuffix(block.Type, "PUBLIC KEY") {
		return nil, fmt.Errorf("Invalid public key type: %s", block.Type)
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

func (v *verify) verify(input, signature string) error {

	sigBytes, err := new(yBase64).DecodeString(signature)
	if err != nil {
		return err
	}

	hashed, err := hashString(input)
	if err != nil {
		return err
	}

	return v.iv.verify(hashed, sigBytes)
}
