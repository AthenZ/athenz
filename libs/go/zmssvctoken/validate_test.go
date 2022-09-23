// Copyright The Athenz Authors
// Licensed under the terms of the Apache version 2.0 license. See LICENSE file for terms.

package zmssvctoken

import (
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/ardielle/ardielle-go/rdl"
)

func makeTokenWithKey(t *testing.T, src keySource, k []byte) string {
	tb, err := NewTokenBuilder(src.domain, src.name, k, src.keyVersion)
	require.Nil(t, err)
	tok, err := tb.Token().Value()
	require.Nil(t, err)
	return tok
}

func makeToken(t *testing.T, src keySource) string {
	return makeTokenWithKey(t, src, rsaPrivateKeyPEM)
}

func makeTokenBuilder(t *testing.T, src keySource) TokenBuilder {
	tb, err := NewTokenBuilder(src.domain, src.name, rsaPrivateKeyPEM, src.keyVersion)
	require.Nil(t, err)
	return tb
}

func stdKey(src keySource) (pubKey []byte, rawResponse string, err error) {
	return rsaPublicKeyPEM, "", nil
}

func dsaKey(src keySource) (pubKey []byte, rawResponse string, err error) {
	return ecdsaPublicKeyPEM, "", nil
}

func s404(src keySource) (pubKey []byte, rawResponse string, err error) {
	return nil, "", &rdl.ResourceError{Code: 404, Message: "Not found"}
}

func hang(src keySource) (pubKey []byte, rawResponse string, err error) {
	time.Sleep(2 * time.Second)
	return nil, "", &rdl.ResourceError{Code: 500, Message: "Not implemented"}
}

func noKey(src keySource) (pubKey []byte, rawResponse string, err error) {
	return nil, `{}`, nil
}

func badBase64(src keySource) (pubKey []byte, rawResponse string, err error) {
	return nil, `{ "key": "abcdefgh!" }`, nil
}

func badJSON(src keySource) (pubKey []byte, rawResponse string, err error) {
	return nil, `{ "key": `, nil
}

func source(d, n, keyV string) keySource {
	return keySource{domain: d, name: n, keyVersion: keyV}
}

var (
	simpleSource    = source("std", "name", "v1")
	dsaSource       = source("dsa-key", "name", "v1")
	hangSource      = source("d500", "name", "v1")
	noKeySource     = source("nks", "name", "v1")
	badEncSource    = source("bes", "name", "v1")
	badJSONSource   = source("bjs", "name", "v1")
	keyRotateSource = source("rotate", "name", "v1")
	zmsSource       = source("sys.auth", "zms", "aws.prod.us-west-2.0")
	ztsSource       = source("sys.auth", "zts", "aws.prod.us-west-2.0")
)

type chandler struct {
	key1  []byte
	key2  []byte
	count int
}

func (c *chandler) getKey(src keySource) (pubKey []byte, rawResponse string, err error) {
	c.count++
	switch c.count {
	case 1:
		return c.key1, "", nil
	case 2:
		return c.key1, "", nil
	case 3:
		return c.key2, "", nil
	default:
		return nil, "", fmt.Errorf("Unexpected call")
	}
}

var ch = &chandler{key1: rsaPublicKeyPEM, key2: ecdsaPublicKeyPEM}

var handlerMap = map[keySource]handler{
	simpleSource:    stdKey,
	dsaSource:       dsaKey,
	hangSource:      hang,
	noKeySource:     noKey,
	badEncSource:    badBase64,
	badJSONSource:   badJSON,
	keyRotateSource: ch.getKey,
	zmsSource:       stdKey,
	ztsSource:       stdKey,
}

func TestCachedValidate(t *testing.T) {
	a := assert.New(t)
	h := func(src keySource) (pubKey []byte, rawResponse string, err error) {
		h2, ok := handlerMap[src]
		if ok {
			return h2(src)
		}
		return s404(src)
	}
	s, baseURL, err := newServer(h)
	t.Log(baseURL)

	require.Nil(t, err)
	go func() {
		s.run()
	}()
	defer s.close()

	config := ValidationConfig{
		ZTSBaseUrl:            baseURL,
		CacheTTL:              2 * time.Second,
		PublicKeyFetchTimeout: 1 * time.Second,
	}

	validator := NewTokenValidator(config)

	// simple successful validation
	tok, err := validator.Validate(makeToken(t, simpleSource))
	require.Nil(t, err)
	a.Equal(simpleSource.domain, tok.Domain)
	a.Equal(simpleSource.name, tok.Name)
	a.Equal(simpleSource.keyVersion, tok.KeyVersion)

	// successful validation with zms service key
	tokenBuilder := makeTokenBuilder(t, zmsSource)
	tokenBuilder.SetKeyService("zms")
	tokStr, err := tokenBuilder.Token().Value()
	require.Nil(t, err)
	tok, err = validator.Validate(tokStr)
	require.Nil(t, err)
	a.Equal(zmsSource.domain, tok.Domain)
	a.Equal(zmsSource.name, tok.Name)
	a.Equal(zmsSource.keyVersion, tok.KeyVersion)

	// successful validation with zts service key
	tokenBuilder = makeTokenBuilder(t, ztsSource)
	tokenBuilder.SetKeyService("zts")
	tokStr, err = tokenBuilder.Token().Value()
	require.Nil(t, err)
	tok, err = validator.Validate(tokStr)
	require.Nil(t, err)
	a.Equal(ztsSource.domain, tok.Domain)
	a.Equal(ztsSource.name, tok.Name)
	a.Equal(ztsSource.keyVersion, tok.KeyVersion)

	// incomplete token
	tokstr := makeToken(t, simpleSource)
	tokstr = strings.Replace(tokstr, "d=std;", "", 1)
	_, err = validator.Validate(tokstr)
	require.NotNil(t, err)
	a.Equal("Invalid token: missing domain", err.Error())

	// key mismatch
	_, err = validator.Validate(makeToken(t, dsaSource))
	require.NotNil(t, err)
	a.Equal("Invalid token signature", err.Error())

	// key not found
	nfSource := keySource{domain: "not-found", name: "not-found", keyVersion: "v1"}
	_, err = validator.Validate(makeToken(t, nfSource))
	require.NotNil(t, err)
	a.Contains(err.Error(), "404")

	// server delay in response
	_, err = validator.Validate(makeToken(t, hangSource))
	require.NotNil(t, err)
	a.Contains(err.Error(), "Timeout")

	// bad key encoding
	_, err = validator.Validate(makeToken(t, badEncSource))
	require.NotNil(t, err)
	a.Contains(err.Error(), "illegal base64 data")

	// bad JSON
	_, err = validator.Validate(makeToken(t, badJSONSource))
	require.NotNil(t, err)
	a.Contains(err.Error(), "JSON")

	// key rotation
	tok, err = validator.Validate(makeToken(t, keyRotateSource))
	require.Nil(t, err)

	// and again, immediately
	tok, err = validator.Validate(makeToken(t, keyRotateSource))
	require.Nil(t, err)

	// first iteration of expired cache, returns same key
	time.Sleep(3 * time.Second)
	tok, err = validator.Validate(makeToken(t, keyRotateSource))
	require.Nil(t, err)

	// expired cache with rotated key
	time.Sleep(3 * time.Second)
	tok, err = validator.Validate(makeToken(t, keyRotateSource))
	require.NotNil(t, err)
	a.Equal("Invalid token signature", err.Error())

	// new key should work after cache invalidation
	tok, err = validator.Validate(makeTokenWithKey(t, keyRotateSource, ecdsaPrivateKeyPEM))
	require.Nil(t, err)

}
