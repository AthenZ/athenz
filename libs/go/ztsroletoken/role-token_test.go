// Copyright The Athenz Authors
// Licensed under the terms of the Apache version 2.0 license. See LICENSE file for terms.

package ztsroletoken

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/http/httputil"
	"net/url"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

var clientCert = []byte(`-----BEGIN CERTIFICATE-----
MIICEjCCAXugAwIBAgIQJ82ZFVxFJXjBIt3xA3LiWjANBgkqhkiG9w0BAQsFADAS
MRAwDgYDVQQKEwdBY21lIENvMCAXDTcwMDEwMTAwMDAwMFoYDzIwODQwMTI5MTYw
MDAwWjASMRAwDgYDVQQKEwdBY21lIENvMIGfMA0GCSqGSIb3DQEBAQUAA4GNADCB
iQKBgQC7sO6P9THICKECa63pMjsojUGCHfOI5fM/caK4hTASJZiiKkuBj7Qk0m76
B+bgEqdkTmk91JBk4FGTIO7rdLco2eigWAvZkV7yClcQgxnxL7BhaKQShG5PERQN
oipgb7Q3144I9SvZwWn+t/ya7wVg7naILCXU+VEeyCbSAtccpwIDAQABo2cwZTAO
BgNVHQ8BAf8EBAMCAqQwEwYDVR0lBAwwCgYIKwYBBQUHAwEwDwYDVR0TAQH/BAUw
AwEB/zAtBgNVHREEJjAkggpjbGllbnQuY29thwR/AAABhxAAAAAAAAAAAAAAAAAA
AAABMA0GCSqGSIb3DQEBCwUAA4GBAKWbFo78BGKQSfI5FmgGI4ApfaiioYI2+RWL
35ByJ6F+Yio9vmED5pf8mOLilZ9xRc3QvgMRufXpG0OopJ4Azto/vatDWQd0qGKL
wXEQW8kTuK1LazYL3EEgaDDFjikBahchwIMUKq4na6yyE4lvhyzMly6KL0HiP8Cn
Aazk3U+W
-----END CERTIFICATE-----`)

var clientKey = []byte(`-----BEGIN RSA PRIVATE KEY-----
MIICXAIBAAKBgQC7sO6P9THICKECa63pMjsojUGCHfOI5fM/caK4hTASJZiiKkuB
j7Qk0m76B+bgEqdkTmk91JBk4FGTIO7rdLco2eigWAvZkV7yClcQgxnxL7BhaKQS
hG5PERQNoipgb7Q3144I9SvZwWn+t/ya7wVg7naILCXU+VEeyCbSAtccpwIDAQAB
AoGAeWFoNqM8aX/jGJyooMoCZixL9CkIiT0k/Z+wuyIvP10fA6jUodpchv+sE3iu
v7Rwmrb26qygIQzM1JiUyqL1m5J1AtqvPTyyaDQntXF1YOXmn9n1o6I1DOIPA/X8
krTV6NaX/RMea/ljUK/4N+i2IYl2EsFbHVPPzLcDBZINDyECQQDq9WDcRDt8M/7s
RB89T1YTWnxxLbuRl5xDEIwxVTDOkt/IIcaPz0i8URakLOlfr/vKNk3DAORslTd6
sJOPkv53AkEAzH/ox2VbUK8ADVZVvlwvAh/GrYJ4gjWyj/50uFz1ZM88bfVcYUsm
8ymNgnGCmRzC1TxkMBoRvBy66JfE87lvUQJAOt/9w3P9i+PjjwSK52wH35We9SVG
iPb6mvt8hagZMMow9Q8xmDuSuE2BZOY0HFwWtdbhqWmB04uYeU/hyepFhQJAclIr
MpUB6Gf8cnhKNMHZ8akL62GdtsUIDqFkZNBqyrFjieD5hNZ7bsJS/pIwPSIr9QLu
y0k3kt7IylBV5R5MEQJBAJh2BB6h433bJMKRSodf3tyGB5NIj5TcTJL34TiSg9Q5
WYjCE4hWTQzn0xtwrqrT/c337wvX48p4yk31WdXtCUA=
-----END RSA PRIVATE KEY-----`)

// httptest.NewTLSServer uses a cert/key committed at net/http/internal
// Reusing the same cert here, so that we can use it as the RootCA Cert in the client connection
var LocalhostCert = []byte(`-----BEGIN CERTIFICATE-----
MIIDOTCCAiGgAwIBAgIQSRJrEpBGFc7tNb1fb5pKFzANBgkqhkiG9w0BAQsFADAS
MRAwDgYDVQQKEwdBY21lIENvMCAXDTcwMDEwMTAwMDAwMFoYDzIwODQwMTI5MTYw
MDAwWjASMRAwDgYDVQQKEwdBY21lIENvMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8A
MIIBCgKCAQEA6Gba5tHV1dAKouAaXO3/ebDUU4rvwCUg/CNaJ2PT5xLD4N1Vcb8r
bFSW2HXKq+MPfVdwIKR/1DczEoAGf/JWQTW7EgzlXrCd3rlajEX2D73faWJekD0U
aUgz5vtrTXZ90BQL7WvRICd7FlEZ6FPOcPlumiyNmzUqtwGhO+9ad1W5BqJaRI6P
YfouNkwR6Na4TzSj5BrqUfP0FwDizKSJ0XXmh8g8G9mtwxOSN3Ru1QFc61Xyeluk
POGKBV/q6RBNklTNe0gI8usUMlYyoC7ytppNMW7X2vodAelSu25jgx2anj9fDVZu
h7AXF5+4nJS4AAt0n1lNY7nGSsdZas8PbQIDAQABo4GIMIGFMA4GA1UdDwEB/wQE
AwICpDATBgNVHSUEDDAKBggrBgEFBQcDATAPBgNVHRMBAf8EBTADAQH/MB0GA1Ud
DgQWBBStsdjh3/JCXXYlQryOrL4Sh7BW5TAuBgNVHREEJzAlggtleGFtcGxlLmNv
bYcEfwAAAYcQAAAAAAAAAAAAAAAAAAAAATANBgkqhkiG9w0BAQsFAAOCAQEAxWGI
5NhpF3nwwy/4yB4i/CwwSpLrWUa70NyhvprUBC50PxiXav1TeDzwzLx/o5HyNwsv
cxv3HdkLW59i/0SlJSrNnWdfZ19oTcS+6PtLoVyISgtyN6DpkKpdG1cOkW3Cy2P2
+tK/tKHRP1Y/Ra0RiDpOAmqn0gCOFGz8+lqDIor/T7MTpibL3IxqWfPrvfVRHL3B
grw/ZQTTIVjjh4JBSW3WyWgNo/ikC1lrVxzl4iPUGptxT36Cr7Zk2Bsg0XqwbOvK
5d+NTDREkSnUbie4GeutujmX3Dsx88UiV6UY/4lHJa6I5leHUNOHahRbpbWeOfs/
WkBKOclmOV2xlTVuPw==
-----END CERTIFICATE-----`)

type tokp struct {
	sync.Mutex
	count int
}

func (t *tokp) Value() (string, error) {
	t.Lock()
	defer t.Unlock()
	t.count++
	return fmt.Sprintf("T%d", t.count), nil
}

type rtHandler struct {
	expiry time.Duration
	sync.Mutex
	count int
}

func (rt *rtHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	rt.Lock()
	rt.count++
	rt.Unlock()

	out := struct {
		Token      string `json:"token"`
		ExpiryTime int64  `json:"expiryTime"`
	}{}
	// "X-Forwarded-For" header is automatically added if the request goes through a reverse proxy
	if r.Header.Get("X-Forwarded-For") == "" {
		out.Token = fmt.Sprintf("RT%d", rt.count)
	} else {
		out.Token = fmt.Sprintf("RT%d-%s", rt.count, r.Header.Get("X-Forwarded-For"))
	}
	out.ExpiryTime = time.Now().Add(rt.expiry).Unix()
	b, _ := json.Marshal(&out)
	w.Write(b)
}

func TestRoleToken(t *testing.T) {
	s := httptest.NewServer(&rtHandler{expiry: 3 * time.Second})
	defer s.Close()

	tp := &tokp{}
	e := 3 * time.Second
	old := expirationDrift
	expirationDrift = 1 * time.Second
	defer func() {
		expirationDrift = old
	}()
	rt := NewRoleToken(tp, "my.domain", RoleTokenOptions{
		BaseZTSURL: s.URL,
		MinExpire:  e,
		MaxExpire:  e,
	})

	tok, err := rt.RoleTokenValue()
	if err != nil {
		t.Fatal("error getting role token", err)
	}
	if tok != "RT1" {
		t.Error("invalid role token", tok)
	}

	tok, err = rt.RoleTokenValue()
	if err != nil {
		t.Fatal("error getting role token", err)
	}
	if tok != "RT1" {
		t.Error("invalid role token", tok)
	}

	time.Sleep(2 * time.Second)
	tok, err = rt.RoleTokenValue()
	if err != nil {
		t.Fatal("error getting role token", err)
	}
	if tok != "RT2" {
		t.Error("invalid role token", tok)
	}
}

func TestRoleTokenPrefetching(t *testing.T) {
	e := 15 * time.Minute
	s := httptest.NewServer(&rtHandler{expiry: e})
	defer s.Close()

	tp := &tokp{}
	rt := NewRoleToken(tp, "my.domain", RoleTokenOptions{
		BaseZTSURL:       s.URL,
		MinExpire:        e,
		MaxExpire:        e,
		PrefetchInterval: 2 * time.Second,
	})

	err := rt.StartPrefetcher()
	defer rt.StopPrefetcher()
	if err != nil {
		t.Fatal("failed to start prefetcher", err)
	}
	err = rt.StartPrefetcher()
	if err == nil {
		t.Error("second execution of StartPrefetcher should return error")
	}

	tok, err := rt.RoleTokenValue()
	if err != nil {
		t.Fatal("error getting role token", err)
	}
	if tok != "RT1" {
		t.Error("invalid role token", tok)
	}

	tok, err = rt.RoleTokenValue()
	if err != nil {
		t.Fatal("error getting role token", err)
	}
	if tok != "RT1" {
		t.Error("invalid role token", tok)
	}

	time.Sleep(2100 * time.Millisecond)

	tok, err = rt.RoleTokenValue()
	if err != nil {
		t.Fatal("error getting role token", err)
	}
	if tok != "RT2" {
		t.Error("invalid role token", tok)
	}

	time.Sleep(2100 * time.Millisecond)

	tok, err = rt.RoleTokenValue()
	if err != nil {
		t.Fatal("error getting role token", err)
	}
	if tok != "RT3" {
		t.Error("invalid role token", tok)
	}

	err = rt.StopPrefetcher()
	if err != nil {
		t.Fatal("failed to stop prefetcher", err)
	}
	err = rt.StopPrefetcher()
	if err == nil {
		t.Error("second execution of StopPrefetcher should return error")
	}
}

func TestRoleTokenWithProxy(t *testing.T) {
	s := httptest.NewServer(&rtHandler{expiry: 1 * time.Minute})
	defer s.Close()

	sURL, err := url.Parse(s.URL)
	if err != nil {
		t.Fatal("failed to parse zts url", err)
	}

	p := httptest.NewServer(httputil.NewSingleHostReverseProxy(sURL))
	defer p.Close()

	tp := &tokp{}
	e := 1 * time.Minute
	rt := NewRoleToken(tp, "my.domain", RoleTokenOptions{
		BaseZTSURL: s.URL,
		ProxyURL:   p.URL,
		MinExpire:  e,
		MaxExpire:  e,
	})

	tok, err := rt.RoleTokenValue()
	if err != nil {
		t.Fatal("error getting role token", err)
	}
	if tok != "RT1-127.0.0.1" {
		t.Error("invalid role token", tok)
	}
}

func TestRoleTokenFromCert(t *testing.T) {
	s := httptest.NewTLSServer(&rtHandler{expiry: 3 * time.Second})
	defer s.Close()

	e := 3 * time.Second
	old := expirationDrift
	expirationDrift = 1 * time.Second
	defer func() {
		expirationDrift = old
	}()

	certDir := fmt.Sprintf("/tmp/certdir.%d", time.Now().Unix())
	if _, err := os.Stat(certDir); os.IsNotExist(err) {
		err := os.MkdirAll(certDir, 0755)
		require.Nil(t, err, "Should be able to create certDir")
	}

	certFile := fmt.Sprintf("%s/cert.pem", certDir)
	keyFile := fmt.Sprintf("%s/key.pem", certDir)

	err := os.WriteFile(certFile, clientCert, 0444)
	require.Nil(t, err, "Should be able to write cert to disk")

	err = os.WriteFile(keyFile, clientKey, 0400)
	require.Nil(t, err, "Should be able to write key to disk")

	rt := NewRoleTokenFromCert(certFile, keyFile, "my.domain", RoleTokenOptions{
		BaseZTSURL: s.URL,
		MinExpire:  e,
		MaxExpire:  e,
		CACert:     LocalhostCert,
	})

	tok, err := rt.RoleTokenValue()
	if err != nil {
		t.Fatal("error getting role token", err)
	}
	if tok != "RT1" {
		t.Error("invalid role token", tok)
	}

	tok, err = rt.RoleTokenValue()
	if err != nil {
		t.Fatal("error getting role token", err)
	}
	if tok != "RT1" {
		t.Error("invalid role token", tok)
	}

	time.Sleep(2 * time.Second)
	tok, err = rt.RoleTokenValue()
	if err != nil {
		t.Fatal("error getting role token", err)
	}
	if tok != "RT2" {
		t.Error("invalid role token", tok)
	}

	// Clean up
	err = os.RemoveAll(certDir)
	if err != nil {
		t.Fatalf("Unable to remove: %q, error: %v", certDir, err)
	}
}
