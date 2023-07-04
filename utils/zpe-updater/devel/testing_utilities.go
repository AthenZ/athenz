// Copyright The Athenz Authors
// Licensed under the terms of the Apache version 2.0 license. See LICENSE file for terms.

package devel

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"os"
	"reflect"

	"github.com/AthenZ/athenz/clients/go/zts"
	"github.com/AthenZ/athenz/libs/go/zmssvctoken"
	"github.com/AthenZ/athenz/utils/zpe-updater/util"
	"github.com/ardielle/ardielle-go/rdl"

	"gopkg.in/square/go-jose.v2"
)

func CreateFile(fileName, content string) error {
	if util.Exists(fileName) {
		err := os.Remove(fileName)
		if err != nil {
			return fmt.Errorf("unable to remove file: %v, Error:%v", fileName, err)
		}
	}
	err := os.WriteFile(fileName, []byte(content), 0755)
	if err != nil {
		return fmt.Errorf("unable to write file: %v, Error:%v", fileName, err)
	}

	return nil
}

func loadPrivateKey(privateKeyPEM []byte) (crypto.PrivateKey, error) {
	block, _ := pem.Decode(privateKeyPEM)
	if block == nil {
		return nil, fmt.Errorf("unable to load private key")
	}

	switch block.Type {
	case "EC PRIVATE KEY":
		key, err := x509.ParseECPrivateKey(block.Bytes)
		if err != nil {
			return nil, err
		}
		return key, nil
	case "RSA PRIVATE KEY":
		key, err := x509.ParsePKCS1PrivateKey(block.Bytes)
		if err != nil {
			return nil, err
		}
		return key, nil
	case "PRIVATE KEY":
		key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
		if err != nil {
			return nil, err
		}
		switch k := key.(type) {
		case *ecdsa.PrivateKey:
			return k, nil
		case *rsa.PrivateKey:
			return k, nil
		default:
			// PKCS#8 format may contain multiple key types other than RSA / EC, but current ZMS / ZTS server implementation only supports RSA / EC private keys
			return nil, fmt.Errorf("unsupported private key type: %s", reflect.TypeOf(k).Name())
		}
	default:
		return nil, fmt.Errorf("unsupported private key type: %s", block.Type)
	}
}

func SignPolicy(policyDataStr []byte, signature string, keyVersion string) (*zts.DomainSignedPolicyData, error) {
	var signedPolicyData *zts.SignedPolicyData
	err := json.Unmarshal(policyDataStr, &signedPolicyData)
	if err != nil {
		return nil, fmt.Errorf("failed to parse the signed policy data file, Error:%v", err)
	}
	domainSignedPolicyData := zts.DomainSignedPolicyData{}
	domainSignedPolicyData.SignedPolicyData = signedPolicyData
	domainSignedPolicyData.SignedPolicyData.ZmsKeyId = keyVersion
	domainSignedPolicyData.Signature = signature
	domainSignedPolicyData.KeyId = keyVersion
	return &domainSignedPolicyData, nil
}

func GenerateSignedPolicyData(filename string, privateKeyPEM []byte, keyVersion string, expiryOffset float64) (*zts.DomainSignedPolicyData, error) {
	data, err := os.ReadFile(filename)
	if err != nil {
		return nil, fmt.Errorf("failed to read the data file, Error:%v", err)
	}
	var domainSignedPolicyData *zts.DomainSignedPolicyData
	err = json.Unmarshal(data, &domainSignedPolicyData)
	if err != nil {
		return nil, fmt.Errorf("failed to parse the signed policy data file, Error:%v", err)
	}
	policyData := domainSignedPolicyData.SignedPolicyData.PolicyData
	input, err := util.ToCanonicalString(policyData)
	if err != nil {
		return nil, fmt.Errorf("failed to generate cannonical string, Error:%v", err)
	}
	signer, err := zmssvctoken.NewSigner(privateKeyPEM)
	if err != nil {
		return nil, fmt.Errorf("failed to generate new signer, Error:%v", err)
	}
	domainSignedPolicyData.SignedPolicyData.ZmsSignature, err = signer.Sign(input)
	if err != nil {
		return nil, fmt.Errorf("failed to generate signature, Error:%v", err)
	}
	if err != nil {
		return nil, fmt.Errorf("failed to generate signature, Error:%v", err)
	}
	domainSignedPolicyData.SignedPolicyData.ZmsKeyId = keyVersion
	domainSignedPolicyData.SignedPolicyData.Modified = rdl.TimestampNow()
	domainSignedPolicyData.SignedPolicyData.Expires = rdl.TimestampFromEpoch(rdl.TimestampNow().SecondsSinceEpoch() + expiryOffset)
	input, err = util.ToCanonicalString(domainSignedPolicyData.SignedPolicyData)
	if err != nil {
		return nil, fmt.Errorf("failed to generate cannonical string, Error:%v", err)
	}
	domainSignedPolicyData.Signature, err = signer.Sign(input)
	if err != nil {
		return nil, fmt.Errorf("failed to generate signature, Error:%v", err)
	}
	domainSignedPolicyData.KeyId = keyVersion
	return domainSignedPolicyData, nil
}

func GenerateJWSPolicyData(filename string, privateKeyPEM []byte, keyVersion, algorithm string, expiryOffset float64) (*zts.JWSPolicyData, error) {
	data, err := os.ReadFile(filename)
	if err != nil {
		return nil, fmt.Errorf("failed to read the data file, Error:%v", err)
	}
	var domainSignedPolicyData *zts.DomainSignedPolicyData
	err = json.Unmarshal(data, &domainSignedPolicyData)
	if err != nil {
		return nil, fmt.Errorf("failed to parse the signed policy data file, Error:%v", err)
	}
	signedPolicyData := domainSignedPolicyData.SignedPolicyData
	signedPolicyData.ZmsSignature = ""
	signedPolicyData.ZmsKeyId = ""
	signedPolicyData.Modified = rdl.TimestampNow()
	signedPolicyData.Expires = rdl.TimestampFromEpoch(rdl.TimestampNow().SecondsSinceEpoch() + expiryOffset)
	payloadData, err := json.Marshal(signedPolicyData)
	if err != nil {
		return nil, fmt.Errorf("failed to generate payload datar, Error:%v", err)
	}
	jwsPolicyData := new(zts.JWSPolicyData)
	jwsPolicyData.Header = make(map[string]string)
	jwsPolicyData.Header["kid"] = keyVersion
	encoding := base64.RawURLEncoding
	jwsPolicyData.Payload = encoding.EncodeToString(payloadData)
	protectedData := "{\"alg\":\"" + algorithm + "\",\"kid\":\"" + keyVersion + "\"}"
	jwsPolicyData.Protected = encoding.EncodeToString([]byte(protectedData))
	var signData bytes.Buffer
	signData.WriteString(jwsPolicyData.Protected)
	signData.WriteByte('.')
	signData.WriteString(jwsPolicyData.Payload)
	privateKey, err := loadPrivateKey(privateKeyPEM)
	if err != nil {
		return nil, fmt.Errorf("unable to create private key signer: %v", err)
	}
	opts := &jose.SignerOptions{
		ExtraHeaders: map[jose.HeaderKey]interface{}{
			jose.HeaderKey("kid"): keyVersion,
		},
	}
	signer, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.ES384, Key: privateKey}, opts)
	if err != nil {
		return nil, fmt.Errorf("unable to create signer: %v", err)
	}
	object, err := signer.Sign(payloadData)
	if err != nil {
		return nil, fmt.Errorf("unable to sign data: %v", err)
	}
	jwsPolicyData.Signature = encoding.EncodeToString(object.Signatures[0].Signature)
	return jwsPolicyData, nil
}
