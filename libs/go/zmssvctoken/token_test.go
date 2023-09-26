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
)

func TestTokenBuild(t *testing.T) {
	a := assert.New(t)
	tb, err := NewTokenBuilder("domain", "service", ecdsaPrivateKeyPEM, "v1")
	require.Nil(t, err)
	tok := tb.Token()
	s1, err := tok.Value()
	a.Nil(err)
	t.Log(s1)
	s2, err := tok.Value()
	a.Nil(err)
	a.Equal(s2, s1)
}

func TestTokenBuildExpiry(t *testing.T) {
	a := assert.New(t)
	tb, err := NewTokenBuilder("domain", "service", rsaPrivateKeyPEM, "v1")
	require.Nil(t, err)
	tb.SetExpiration(9 * time.Minute)
	tok := tb.Token()
	s1, err := tok.Value()
	a.Nil(err)
	t.Log(s1)
	s2, err := tok.Value()
	a.Nil(err)
	a.True(s2 != s1)
}

func TestTokenBuildNegative(t *testing.T) {
	a := assert.New(t)
	_, err := NewTokenBuilder("", "service", rsaPrivateKeyPEM, "v1")
	require.NotNil(t, err)
	a.Equal("Invalid token: missing domain", err.Error())

	_, err = NewTokenBuilder("domain", "", rsaPrivateKeyPEM, "v1")
	require.NotNil(t, err)
	a.Equal("Invalid token: missing name", err.Error())

	_, err = NewTokenBuilder("domain", "service", rsaPrivateKeyPEM, "")
	require.NotNil(t, err)
	a.Equal("Invalid token: missing key version", err.Error())
}

func TestTokenPubValidate(t *testing.T) {
	a := assert.New(t)
	tb, err := NewTokenBuilder("domain", "service", ecdsaPrivateKeyPEM, "v1")
	tb.SetHostname("host1")
	tb.SetIPAddress("127.0.0.1")
	tb.SetExpiration(2 * time.Second)

	require.Nil(t, err)
	tok := tb.Token()
	s1, err := tok.Value()
	t.Log(s1)
	a.Nil(err)

	tv, err := NewPubKeyTokenValidator(ecdsaPublicKeyPEM)
	require.Nil(t, err)
	ntoken, err := tv.Validate(s1)
	require.Nil(t, err)
	a.Equal("S1", ntoken.Version)
	a.Equal("domain", ntoken.Domain)
	a.Equal("service", ntoken.Name)
	a.Equal("v1", ntoken.KeyVersion)
	a.Equal("host1", ntoken.Hostname)
	a.Equal("127.0.0.1", ntoken.IPAddress)
	a.Equal("domain.service", ntoken.PrincipalName())
	a.False(ntoken.IsExpired())
	time.Sleep(2 * time.Second)
	a.True(ntoken.IsExpired())
}

func TestTokenPubValidateNegative(t *testing.T) {
	a := assert.New(t)

	v := "S1"
	d := "domain"
	n := "service"
	k := "v1"
	salt := "bd40daa817f98921"
	start := fmt.Sprint(time.Now().Unix())
	e := fmt.Sprint(time.Now().Add(time.Hour).Unix())

	signer, err := NewSigner(rsaPrivateKeyPEM)
	require.Nil(t, err)

	genTok := func(s string) string {
		sig, err := signer.Sign(s)
		require.Nil(t, err)
		return s + ";s=" + sig
	}

	genToken := func() string {
		base := fmt.Sprintf("v=%s;d=%s;n=%s;k=%s;a=%s;t=%s;e=%s", v, d, n, k, salt, start, e)
		return genTok(base)
	}

	tv, err := NewPubKeyTokenValidator(rsaPublicKeyPEM)
	require.Nil(t, err)

	ntok := genToken()
	_, err = tv.Validate(ntok)
	require.Nil(t, err)

	ntok = strings.Replace(ntok, "domain;", "domain2;", 1)
	_, err = tv.Validate(ntok)
	a.NotNil(err)
	a.Equal("Invalid token signature", err.Error())

	d = ""
	ntok = genToken()
	d = "domain"
	_, err = tv.Validate(ntok)
	a.NotNil(err)
	a.Equal("Invalid token: missing domain", err.Error())

	v = ""
	ntok = genToken()
	v = "S1"
	_, err = tv.Validate(ntok)
	a.NotNil(err)
	a.Equal("Invalid token: missing version", err.Error())

	n = ""
	ntok = genToken()
	n = "service"
	_, err = tv.Validate(ntok)
	a.NotNil(err)
	a.Equal("Invalid token: missing name", err.Error())

	k = ""
	ntok = genToken()
	k = "v1"
	_, err = tv.Validate(ntok)
	a.NotNil(err)
	a.Equal("Invalid token: missing key version", err.Error())

	old := start
	start = "abcd"
	ntok = genToken()
	start = old
	_, err = tv.Validate(ntok)
	a.NotNil(err)
	a.Equal("Invalid field value 'abcd' for field 't'", err.Error())

	old = e
	e = "abcd"
	ntok = genToken()
	e = old
	_, err = tv.Validate(ntok)
	a.NotNil(err)
	a.Equal("Invalid field value 'abcd' for field 'e'", err.Error())

	base := fmt.Sprintf("v=%s;d=%s;n=%s;k=%s;a=%s;e=%s", v, d, n, k, salt, e)
	ntok = genTok(base)
	_, err = tv.Validate(ntok)
	a.NotNil(err)
	a.Equal("Invalid token: missing generation time", err.Error())

	base = fmt.Sprintf("v=%s;d=%s;n=%s;k=%s;a=%s;t=%s", v, d, n, k, salt, start)
	ntok = genTok(base)
	_, err = tv.Validate(ntok)
	a.NotNil(err)
	a.Equal("Invalid token: missing expiry time", err.Error())

	base = fmt.Sprintf("v=%s;d=%s;n=%s;k=%s;a=%s;t=%s;e=%s", v, d, n, k, salt, start, e)
	_, err = tv.Validate(base)
	a.NotNil(err)
	a.Equal("Token does not have a signature", err.Error())

	// add a q field without a value
	base = fmt.Sprintf("v=%s;d=%s;n=%s;k=%s;a=%s;t=%s;e=%s;q", v, d, n, k, salt, start, e)
	ntok = genTok(base)
	_, err = tv.Validate(ntok)
	a.NotNil(err)
	a.Equal("Malformed token field q", err.Error())

	start = fmt.Sprint(time.Now().Add(-1 * time.Hour).Unix())
	e = fmt.Sprint(time.Now().Add(-30 * time.Minute).Unix())
	ntok = genToken()
	_, err = tv.Validate(ntok)
	a.NotNil(err)
	a.Equal("Token has expired", err.Error())

}

func TestBadSigner(t *testing.T) {
	_, err := NewTokenBuilder("domain", "service", []byte{1, 2, 3, 4}, "v1")
	require.NotNil(t, err)
	require.Equal(t, "Unable to create signer: unable to load private key", err.Error())
}

func TestBadVerifier(t *testing.T) {
	_, err := NewPubKeyTokenValidator([]byte{1, 2, 3, 4})
	require.NotNil(t, err)
	require.Equal(t, "Unable to create verifier: Unable to load public key", err.Error())
}

func TestMultipleTokenCallsOnBuilder(t *testing.T) {
	a := assert.New(t)
	tb, err := NewTokenBuilder("domain", "service", rsaPrivateKeyPEM, "v1")
	require.Nil(t, err)
	tok1 := tb.Token()
	tok2 := tb.Token()
	s1, err := tok1.Value()
	a.Nil(err)
	a.NotEmpty(s1)
	s2, err := tok2.Value()
	a.Nil(err)
	a.NotEmpty(s2)
}
