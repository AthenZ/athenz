// Copyright 2016 Yahoo Inc.
// Licensed under the terms of the Apache version 2.0 license. See LICENSE file for terms.

package zmssvctoken

import (
	"testing"

	"github.com/stretchr/testify/require"
)

var ecdsaPrivateKeyPEM = []byte(`-----BEGIN EC PRIVATE KEY-----
MIGkAgEBBDA27vlziu7AYNJo/aaG3mS4XPK2euiTLQDxzUoDkiMpVHRXLxSbX897
Gz7dQNFo3UWgBwYFK4EEACKhZANiAARBr6GWO6EGIV09DGInLfC/JSvPOKc26mZu
jpEdar4FkJ02OsHdtZ6AM7HgLASSBETL13Mhk8LL9qfRo+PEwLcyJnvWlDsMa3eh
Pji5iP4d9rQEOm/G9PXZ3/ZZEz5DuYs=
-----END EC PRIVATE KEY-----
`)

var ecdsaPublicKeyPEM = []byte(`-----BEGIN PUBLIC KEY-----
MHYwEAYHKoZIzj0CAQYFK4EEACIDYgAEQa+hljuhBiFdPQxiJy3wvyUrzzinNupm
bo6RHWq+BZCdNjrB3bWegDOx4CwEkgREy9dzIZPCy/an0aPjxMC3MiZ71pQ7DGt3
oT44uYj+Hfa0BDpvxvT12d/2WRM+Q7mL
-----END PUBLIC KEY-----
`)

var rsaPrivateKeyPEM = []byte(`-----BEGIN RSA PRIVATE KEY-----
MIIEpAIBAAKCAQEAxq83nCd8AqH5n40dEBMElbaJd2gFWu6bjhNzyp9562dpf454
BUSN0uF+g3i1yzcwdvADTiuExKN1u/IoGURxVCa0JTzAPJw6/JIoyOZnHZCoarcg
QQqZ56/udkSQ2NssrwGSQjOwxMrgIdH6XeLgGqVN4BoEEI+gpaQZa7rSytU5RFSG
OnZWO2Vwgs1OBxiOiYg1gzA1spJXQhxcBWw/v+YrUFtjxBKsG1UrWbnHbgciiN5U
2v51Yztjo8A1T+o9eIG90jVo3EhS2qhbzd8mLAsEhjV1sP8GItjfdfwXpXT7q2QG
99W3PM75+HdwGLvJIrkED7YRj4CpMkz6F1etawIDAQABAoIBAD67C7/N56WdJodt
soNkvcnXPEfrG+W9+Hc/RQvwljnxCKoxfUuMfYrbj2pLLnrfDfo/hYukyeKcCYwx
xN9VcMK1BaPMLpX0bdtY+m+T73KyPbqT3ycqBbXVImFM/L67VLxcrqUgVOuNcn67
IWWLQF6pWpErJaVk87/Ys/4DmpJXebLDyta8+ce6r0ppSG5+AifGo1byQT7kSJkF
lyQsyKWoVN+02s7gLsln5JXXZ672y2Xtp/S3wK0vfzy/HcGSxzn1yE0M5UJtDm/Y
qECnV1LQ0FB1l1a+/itHR8ipp5rScD4ZpzOPLKthglEvNPe4Lt5rieH9TR97siEe
SrC8uyECgYEA5Q/elOJAddpE+cO22gTFt973DcPGjM+FYwgdrora+RfEXJsMDoKW
AGSm5da7eFo8u/bJEvHSJdytc4CRQYnWNryIaUw2o/1LYXRvoEt1rEEgQ4pDkErR
PsVcVuc3UDeeGtYJwJLV6pjxO11nodFv4IgaVj64SqvCOApTTJgWXF0CgYEA3gzN
d3l376mSMuKc4Ep++TxybzA5mtF2qoXucZOon8EDJKr+vGQ9Z6X4YSdkSMNXqK1j
ILmFH7V3dyMOKRBA84YeawFacPLBJq+42t5Q1OYdcKZbaArlBT8ImGT7tQODs3JN
4w7DH+V1v/VCTl2zQaZRksb0lUsQbFiEfj+SVGcCgYAYIlDoTOJPyHyF+En2tJQE
aHiNObhcs6yxH3TJJBYoMonc2/UsPjQBvJkdFD/SUWeewkSzO0lR9etMhRpI1nX8
dGbG+WG0a4aasQLl162BRadZlmLB/DAJtg+hlGDukb2VxEFoyc/CFPUttQyrLv7j
oFNuDNOsAmbHMsdOBaQtfQKBgQCb/NRuRNebdj0tIALikZLHVc5yC6e7+b/qJPIP
uZIwv++MV89h2u1EHdTxszGA6DFxXnSPraQ2VU2aVPcCo9ds+9/sfePiCrbjjXhH
0PtpxEoUM9lsqpKeb9yC6hXk4JYpfnf2tQ0gIBrrAclVsf9WdBdEDB4Prs7Xvgs9
gT0zqwKBgQCzZubFO0oTYO9e2r8wxPPPsE3ZCjbP/y7lIoBbSzxDGUubXmbvD0GO
MC8dM80plsTym96UxpKkQMAglKKLPtG2n8xB8v5H/uIB4oIegMSEx3F7MRWWIQmR
Gea7bQ16YCzM/l2yygGhAW61bg2Z2GoVF6X5z/qhKGyo97V87qTbmg==
-----END RSA PRIVATE KEY-----
`)

var rsaPublicKeyPEM = []byte(`-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAxq83nCd8AqH5n40dEBME
lbaJd2gFWu6bjhNzyp9562dpf454BUSN0uF+g3i1yzcwdvADTiuExKN1u/IoGURx
VCa0JTzAPJw6/JIoyOZnHZCoarcgQQqZ56/udkSQ2NssrwGSQjOwxMrgIdH6XeLg
GqVN4BoEEI+gpaQZa7rSytU5RFSGOnZWO2Vwgs1OBxiOiYg1gzA1spJXQhxcBWw/
v+YrUFtjxBKsG1UrWbnHbgciiN5U2v51Yztjo8A1T+o9eIG90jVo3EhS2qhbzd8m
LAsEhjV1sP8GItjfdfwXpXT7q2QG99W3PM75+HdwGLvJIrkED7YRj4CpMkz6F1et
awIDAQAB
-----END PUBLIC KEY-----
`)

func testSV(t *testing.T, s signer, v verifier) {
	input := `
Now is the time
for all good men
to come to the aid of the party
`
	sig, err := s.sign(input)
	require.Nil(t, err)
	err = v.verify(input, sig)
	require.Nil(t, err)
	input += "X"
	err = v.verify(input, sig)
	require.NotNil(t, err)
}

func TestRSASigner(t *testing.T) {
	signer, err := newSigner(rsaPrivateKeyPEM)
	require.Nil(t, err)
	verifier, err := newVerifier(rsaPublicKeyPEM)
	testSV(t, signer, verifier)
}

func TestECDSASigner(t *testing.T) {
	signer, err := newSigner(ecdsaPrivateKeyPEM)
	require.Nil(t, err)
	verifier, err := newVerifier(ecdsaPublicKeyPEM)
	testSV(t, signer, verifier)
}
