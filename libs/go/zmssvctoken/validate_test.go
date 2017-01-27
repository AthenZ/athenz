// Copyright 2016 Yahoo Inc.
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

func source(d string) keySource {
	return keySource{domain: d, name: "name", keyVersion: "v1"}
}

var (
	simpleSource    = source("std")
	dsaSource       = source("dsa-key")
	hangSource      = source("d500")
	noKeySource     = source("nks")
	badEncSource    = source("bes")
	badJsonSource   = source("bjs")
	keyRotateSource = source("rotate")
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
	badJsonSource:   badJSON,
	keyRotateSource: ch.getKey,
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
	s, baseUrl, err := newServer(h)
	t.Log(baseUrl)

	require.Nil(t, err)
	go func() {
		s.run()
	}()
	defer s.close()

	config := ValidationConfig{
		ZTSBaseUrl:            baseUrl,
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
	_, err = validator.Validate(makeToken(t, badJsonSource))
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
