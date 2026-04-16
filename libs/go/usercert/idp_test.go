// Copyright The Athenz Authors
// Licensed under the terms of the Apache version 2.0 license. See LICENSE file for terms.

package usercert

import (
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"
)

// --- encode tests ---

func TestEncode(t *testing.T) {
	input := []byte("hello world")
	result := encode(input)
	decoded, err := base64.RawURLEncoding.DecodeString(result)
	if err != nil {
		t.Fatalf("failed to decode: %v", err)
	}
	if string(decoded) != string(input) {
		t.Errorf("expected %s, got %s", input, decoded)
	}
}

func TestEncodeEmpty(t *testing.T) {
	result := encode([]byte{})
	if result != "" {
		t.Errorf("expected empty string, got %s", result)
	}
}

func TestEncodeRawURLSafe(t *testing.T) {
	// bytes that would produce +/= in standard base64
	input := []byte{0xff, 0xfe, 0xfd, 0xfc, 0xfb}
	result := encode(input)
	if strings.Contains(result, "+") || strings.Contains(result, "/") || strings.Contains(result, "=") {
		t.Errorf("encoded string contains non-URL-safe characters: %s", result)
	}
}

// --- newNonce tests ---

func TestNewNonce(t *testing.T) {
	nonce, err := newCodeVerifier(24)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if nonce == "" {
		t.Fatal("expected non-empty nonce")
	}
	// 24 bytes -> base64url without padding = 32 chars
	if len(nonce) != 32 {
		t.Errorf("expected nonce length 32, got %d", len(nonce))
	}
}

func TestNewNonceUniqueness(t *testing.T) {
	seen := make(map[string]bool)
	for i := 0; i < 100; i++ {
		nonce, err := newCodeVerifier(24)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if seen[nonce] {
			t.Fatalf("duplicate nonce: %s", nonce)
		}
		seen[nonce] = true
	}
}

func TestNewNonceIsValidBase64URL(t *testing.T) {
	nonce, err := newCodeVerifier(24)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	_, err = base64.RawURLEncoding.DecodeString(nonce)
	if err != nil {
		t.Errorf("nonce is not valid base64url: %v", err)
	}
}

// --- getIdpAuthURL tests ---

func TestGetIdpAuthURL(t *testing.T) {
	authURL, err := getIdpAuthURL("https://idp.example.com/oauth2/authorize", "my-client", "openid", "test-nonce", "test-state", "9213", "")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	u, err := url.Parse(authURL)
	if err != nil {
		t.Fatalf("failed to parse auth URL: %v", err)
	}

	if u.Scheme != "https" {
		t.Errorf("expected https scheme, got %s", u.Scheme)
	}
	if u.Host != "idp.example.com" {
		t.Errorf("expected host idp.example.com, got %s", u.Host)
	}

	q := u.Query()
	if q.Get("client_id") != "my-client" {
		t.Errorf("expected client_id=my-client, got %s", q.Get("client_id"))
	}
	if q.Get("redirect_uri") != "http://localhost:9213/oauth2/callback" {
		t.Errorf("expected redirect_uri with port 9213, got %s", q.Get("redirect_uri"))
	}
	if q.Get("response_type") != "code" {
		t.Errorf("expected response_type=code, got %s", q.Get("response_type"))
	}
	if q.Get("nonce") != "test-nonce" {
		t.Errorf("expected nonce=test-nonce, got %s", q.Get("nonce"))
	}
	if q.Get("state") != "test-state" {
		t.Errorf("expected state=test-state, got %s", q.Get("state"))
	}
	if q.Get("scope") != "openid" {
		t.Errorf("expected scope=openid, got %s", q.Get("scope"))
	}
}

func TestGetIdpAuthURLDifferentPorts(t *testing.T) {
	tests := []struct {
		port        string
		expectedURI string
	}{
		{"8080", "http://localhost:8080/oauth2/callback"},
		{"3000", "http://localhost:3000/oauth2/callback"},
		{"443", "http://localhost:443/oauth2/callback"},
	}

	for _, tt := range tests {
		t.Run("port-"+tt.port, func(t *testing.T) {
			authURL, err := getIdpAuthURL("https://idp.example.com/auth", "client", "openid", "nonce", "test-state", tt.port, "")
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			u, _ := url.Parse(authURL)
			if u.Query().Get("redirect_uri") != tt.expectedURI {
				t.Errorf("expected redirect_uri=%s, got %s", tt.expectedURI, u.Query().Get("redirect_uri"))
			}
		})
	}
}

func TestGetIdpAuthURLInvalidEndpoint(t *testing.T) {
	_, err := getIdpAuthURL("://invalid", "client", "openid", "nonce", "test-state", "9213", "")
	if err == nil {
		t.Fatal("expected error for invalid endpoint")
	}
}

func TestGetIdpAuthURLPreservesExistingQueryParams(t *testing.T) {
	authURL, err := getIdpAuthURL("https://idp.example.com/auth?extra=value", "client", "openid", "nonce", "test-state", "9213", "")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	u, _ := url.Parse(authURL)
	if u.Query().Get("extra") != "value" {
		t.Error("existing query parameter 'extra' was lost")
	}
	if u.Query().Get("client_id") != "client" {
		t.Error("client_id not set")
	}
}

func TestGetIdpAuthURLCustomScope(t *testing.T) {
	authURL, err := getIdpAuthURL("https://idp.example.com/auth", "client", "openid profile email", "nonce", "test-state", "9213", "")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	u, _ := url.Parse(authURL)
	if u.Query().Get("scope") != "openid profile email" {
		t.Errorf("expected scope=openid profile email, got %s", u.Query().Get("scope"))
	}
}

// --- registerHandlers tests ---

func TestRegisterHandlersCallbackRedirect(t *testing.T) {
	mux := http.NewServeMux()
	codeChan := make(chan string, 1)
	registerHandlers(mux, codeChan)

	// Find a free port
	listener, err := net.Listen("tcp", "localhost:0")
	if err != nil {
		t.Fatalf("failed to get free port: %v", err)
	}
	port := listener.Addr().(*net.TCPAddr).Port
	listener.Close()

	server := &http.Server{
		Addr:    fmt.Sprintf("localhost:%d", port),
		Handler: mux,
	}
	go server.ListenAndServe()
	defer server.Close()

	// Wait for server to start
	time.Sleep(100 * time.Millisecond)

	client := &http.Client{
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	resp, err := client.Get(fmt.Sprintf("http://localhost:%d/oauth2/callback?code=test123&state=nonce", port))
	if err != nil {
		t.Fatalf("failed to call callback: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusSeeOther {
		t.Errorf("expected 303 redirect, got %d", resp.StatusCode)
	}

	location := resp.Header.Get("Location")
	if location != "/close" {
		t.Errorf("expected redirect to /close, got %s", location)
	}
}

func TestRegisterHandlersCallbackFollowRedirect(t *testing.T) {
	mux := http.NewServeMux()
	codeChan := make(chan string, 1)
	registerHandlers(mux, codeChan)

	listener, err := net.Listen("tcp", "localhost:0")
	if err != nil {
		t.Fatalf("failed to get free port: %v", err)
	}
	port := listener.Addr().(*net.TCPAddr).Port
	listener.Close()

	server := &http.Server{
		Addr:    fmt.Sprintf("localhost:%d", port),
		Handler: mux,
	}
	go server.ListenAndServe()
	defer server.Close()

	// Wait for server to start by polling
	for i := 0; i < 20; i++ { // poll for up to 1 second
		conn, err := net.DialTimeout("tcp", server.Addr, 50*time.Millisecond)
		if err == nil {
			conn.Close()
			break
		}
		time.Sleep(50 * time.Millisecond)
		if i == 19 {
			t.Fatalf("server did not start in time")
		}
	}

	resp, err := http.Get(fmt.Sprintf("http://localhost:%d/oauth2/callback?code=test123&state=nonce", port))
	if err != nil {
		t.Fatalf("failed to call callback: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Errorf("expected 200, got %d", resp.StatusCode)
	}
	contentType := resp.Header.Get("Content-Type")
	if !strings.Contains(contentType, "text/html") {
		t.Errorf("expected text/html content type, got %s", contentType)
	}

	select {
	case code := <-codeChan:
		if code != "code=test123&state=nonce" {
			t.Errorf("expected code=test123&state=nonce, got %s", code)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for code")
	}
}

func TestRegisterHandlersCloseEndpoint(t *testing.T) {
	mux := http.NewServeMux()
	codeChan := make(chan string, 1)
	registerHandlers(mux, codeChan)

	listener, err := net.Listen("tcp", "localhost:0")
	if err != nil {
		t.Fatalf("failed to get free port: %v", err)
	}
	port := listener.Addr().(*net.TCPAddr).Port
	listener.Close()

	server := &http.Server{
		Addr:    fmt.Sprintf("localhost:%d", port),
		Handler: mux,
	}
	go server.ListenAndServe()
	defer server.Close()

	time.Sleep(100 * time.Millisecond)

	resp, err := http.Get(fmt.Sprintf("http://localhost:%d/close", port))
	if err != nil {
		t.Fatalf("failed to call /close: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Errorf("expected 200, got %d", resp.StatusCode)
	}
	contentType := resp.Header.Get("Content-Type")
	if !strings.Contains(contentType, "text/html") {
		t.Errorf("expected text/html content type, got %s", contentType)
	}
}

// --- getAuthCodeFromCallbackHandler tests ---

func TestGetAuthCodeFromCallbackHandlerTimeout(t *testing.T) {
	// Use port 0 to let OS pick a free port - but the function takes a string port.
	// Use a high port that's likely free.
	result := getAuthCodeFromCallbackHandler("19994", 1, false)
	select {
	case r := <-result:
		if r.Error == nil {
			t.Fatal("expected timeout error")
		}
		if !strings.Contains(r.Error.Error(), "timeout") {
			t.Errorf("expected timeout error, got: %v", r.Error)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("test timed out waiting for callback handler result")
	}
}

func TestGetAuthCodeFromCallbackHandlerSuccess(t *testing.T) {
	// Find a free port first
	listener, err := net.Listen("tcp", "localhost:0")
	if err != nil {
		t.Fatalf("failed to get free port: %v", err)
	}
	port := fmt.Sprintf("%d", listener.Addr().(*net.TCPAddr).Port)
	listener.Close()

	result := getAuthCodeFromCallbackHandler(port, 10, false)

	// Wait briefly for the server to start
	time.Sleep(200 * time.Millisecond)

	// Simulate the IdP callback
	resp, err := http.Get(fmt.Sprintf("http://localhost:%s/oauth2/callback?code=auth-code-123&state=nonce", port))
	if err != nil {
		t.Fatalf("failed to call callback: %v", err)
	}
	resp.Body.Close()

	select {
	case r := <-result:
		if r.Error != nil {
			t.Fatalf("unexpected error: %v", r.Error)
		}
		if r.Code != "code=auth-code-123&state=nonce" {
			t.Errorf("expected code=auth-code-123&state=nonce, got %s", r.Code)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("test timed out waiting for auth result")
	}
}

// --- GetAuthCode tests ---

func TestGetAuthCodeSuccess(t *testing.T) {
	listener, err := net.Listen("tcp", "localhost:0")
	if err != nil {
		t.Fatalf("failed to get free port: %v", err)
	}
	port := fmt.Sprintf("%d", listener.Addr().(*net.TCPAddr).Port)
	listener.Close()

	origBrowserOpen := browserOpen
	defer func() { browserOpen = origBrowserOpen }()

	browserOpen = func(authURL string) error {
		u, err := url.Parse(authURL)
		if err != nil {
			return err
		}
		state := u.Query().Get("state")
		go func() {
			time.Sleep(200 * time.Millisecond)
			resp, err := http.Get(fmt.Sprintf("http://localhost:%s/oauth2/callback?code=test-auth-code&state=%s", port, state))
			if err == nil {
				resp.Body.Close()
			}
		}()
		return nil
	}

	code, codeVerifier, err := GetAuthCode("https://idp.example.com/oauth2/authorize", "my-client", "openid", port, 10, false, false)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	q, err := url.ParseQuery(code)
	if err != nil {
		t.Fatalf("failed to parse returned code: %v", err)
	}
	if q.Get("code") != "test-auth-code" {
		t.Errorf("expected code=test-auth-code, got %s", q.Get("code"))
	}
	if codeVerifier != "" {
		t.Errorf("expected empty code verifier when pkce is false, got %s", codeVerifier)
	}
}

func TestGetAuthCodeStateMismatch(t *testing.T) {
	listener, err := net.Listen("tcp", "localhost:0")
	if err != nil {
		t.Fatalf("failed to get free port: %v", err)
	}
	port := fmt.Sprintf("%d", listener.Addr().(*net.TCPAddr).Port)
	listener.Close()

	origBrowserOpen := browserOpen
	defer func() { browserOpen = origBrowserOpen }()

	browserOpen = func(authURL string) error {
		go func() {
			time.Sleep(200 * time.Millisecond)
			resp, err := http.Get(fmt.Sprintf("http://localhost:%s/oauth2/callback?code=test-auth-code&state=wrong-state", port))
			if err == nil {
				resp.Body.Close()
			}
		}()
		return nil
	}

	_, _, err = GetAuthCode("https://idp.example.com/oauth2/authorize", "my-client", "openid", port, 10, false, false)
	if err == nil {
		t.Fatal("expected error for state mismatch")
	}
	if !strings.Contains(err.Error(), "state mismatch") {
		t.Errorf("expected state mismatch error, got: %v", err)
	}
}

func TestGetAuthCodeMissingState(t *testing.T) {
	listener, err := net.Listen("tcp", "localhost:0")
	if err != nil {
		t.Fatalf("failed to get free port: %v", err)
	}
	port := fmt.Sprintf("%d", listener.Addr().(*net.TCPAddr).Port)
	listener.Close()

	origBrowserOpen := browserOpen
	defer func() { browserOpen = origBrowserOpen }()

	browserOpen = func(authURL string) error {
		go func() {
			time.Sleep(200 * time.Millisecond)
			resp, err := http.Get(fmt.Sprintf("http://localhost:%s/oauth2/callback?code=test-auth-code", port))
			if err == nil {
				resp.Body.Close()
			}
		}()
		return nil
	}

	_, _, err = GetAuthCode("https://idp.example.com/oauth2/authorize", "my-client", "openid", port, 10, false, false)
	if err == nil {
		t.Fatal("expected error for missing state")
	}
	if !strings.Contains(err.Error(), "state mismatch") {
		t.Errorf("expected state mismatch error, got: %v", err)
	}
}

func TestGetAuthCodeBrowserOpenFailure(t *testing.T) {
	listener, err := net.Listen("tcp", "localhost:0")
	if err != nil {
		t.Fatalf("failed to get free port: %v", err)
	}
	port := fmt.Sprintf("%d", listener.Addr().(*net.TCPAddr).Port)
	listener.Close()

	origBrowserOpen := browserOpen
	defer func() { browserOpen = origBrowserOpen }()

	browserOpen = func(authURL string) error {
		return fmt.Errorf("browser open failed")
	}

	_, _, err = GetAuthCode("https://idp.example.com/oauth2/authorize", "my-client", "openid", port, 10, false, false)
	if err == nil {
		t.Fatal("expected error when browser fails to open")
	}
	if !strings.Contains(err.Error(), "failed to open authorize URL") {
		t.Errorf("expected browser failure error, got: %v", err)
	}
}

func TestGetAuthCodeInvalidEndpoint(t *testing.T) {
	origBrowserOpen := browserOpen
	defer func() { browserOpen = origBrowserOpen }()

	browserOpen = func(authURL string) error {
		return nil
	}

	_, _, err := GetAuthCode("://invalid", "my-client", "openid", "19999", 5, false, false)
	if err == nil {
		t.Fatal("expected error for invalid endpoint")
	}
	if !strings.Contains(err.Error(), "failed to parse auth endpoint") {
		t.Errorf("expected parse error, got: %v", err)
	}
}

// --- PKCE tests ---

func TestNewCodeVerifier(t *testing.T) {
	v, err := newCodeVerifier(32)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if v == "" {
		t.Fatal("expected non-empty code verifier")
	}
	// 32 bytes -> 43 base64url chars (no padding)
	if len(v) != 43 {
		t.Errorf("expected code verifier length 43, got %d", len(v))
	}
}

func TestNewCodeVerifierUniqueness(t *testing.T) {
	seen := make(map[string]bool)
	for i := 0; i < 100; i++ {
		v, err := newCodeVerifier(32)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if seen[v] {
			t.Fatalf("duplicate code verifier: %s", v)
		}
		seen[v] = true
	}
}

func TestNewCodeVerifierIsValidBase64URL(t *testing.T) {
	v, err := newCodeVerifier(32)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	_, err = base64.RawURLEncoding.DecodeString(v)
	if err != nil {
		t.Errorf("code verifier is not valid base64url: %v", err)
	}
}

func TestNewCodeVerifierURLSafe(t *testing.T) {
	for i := 0; i < 50; i++ {
		v, err := newCodeVerifier(32)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if strings.ContainsAny(v, "+/=") {
			t.Errorf("code verifier contains non-URL-safe characters: %s", v)
		}
	}
}

func TestComputeCodeChallenge(t *testing.T) {
	verifier := "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
	challenge := computeCodeChallenge(verifier)
	// RFC 7636 Appendix B reference value
	expected := "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"
	if challenge != expected {
		t.Errorf("expected challenge %s, got %s", expected, challenge)
	}
}

func TestComputeCodeChallengeIsBase64URL(t *testing.T) {
	verifier, _ := newCodeVerifier(32)
	challenge := computeCodeChallenge(verifier)
	_, err := base64.RawURLEncoding.DecodeString(challenge)
	if err != nil {
		t.Errorf("code challenge is not valid base64url: %v", err)
	}
}

func TestComputeCodeChallengeLength(t *testing.T) {
	verifier, _ := newCodeVerifier(32)
	challenge := computeCodeChallenge(verifier)
	// SHA-256 = 32 bytes -> 43 base64url chars
	if len(challenge) != 43 {
		t.Errorf("expected code challenge length 43, got %d", len(challenge))
	}
}

func TestComputeCodeChallengeDeterministic(t *testing.T) {
	verifier := "test-verifier-value"
	c1 := computeCodeChallenge(verifier)
	c2 := computeCodeChallenge(verifier)
	if c1 != c2 {
		t.Errorf("same verifier produced different challenges: %s vs %s", c1, c2)
	}
}

func TestComputeCodeChallengeMatchesSHA256(t *testing.T) {
	verifier, _ := newCodeVerifier(32)
	challenge := computeCodeChallenge(verifier)

	h := sha256.Sum256([]byte(verifier))
	expected := base64.RawURLEncoding.EncodeToString(h[:])
	if challenge != expected {
		t.Errorf("challenge does not match manual SHA-256 computation: got %s, want %s", challenge, expected)
	}
}

func TestGetIdpAuthURLWithPKCE(t *testing.T) {
	challenge := "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"
	authURL, err := getIdpAuthURL("https://idp.example.com/oauth2/authorize", "my-client", "openid", "test-nonce", "test-state", "9213", challenge)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	u, err := url.Parse(authURL)
	if err != nil {
		t.Fatalf("failed to parse auth URL: %v", err)
	}

	q := u.Query()
	if q.Get("code_challenge") != challenge {
		t.Errorf("expected code_challenge=%s, got %s", challenge, q.Get("code_challenge"))
	}
	if q.Get("code_challenge_method") != "S256" {
		t.Errorf("expected code_challenge_method=S256, got %s", q.Get("code_challenge_method"))
	}
}

func TestGetIdpAuthURLWithoutPKCE(t *testing.T) {
	authURL, err := getIdpAuthURL("https://idp.example.com/oauth2/authorize", "my-client", "openid", "test-nonce", "test-state", "9213", "")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	u, err := url.Parse(authURL)
	if err != nil {
		t.Fatalf("failed to parse auth URL: %v", err)
	}

	q := u.Query()
	if q.Get("code_challenge") != "" {
		t.Errorf("expected no code_challenge param, got %s", q.Get("code_challenge"))
	}
	if q.Get("code_challenge_method") != "" {
		t.Errorf("expected no code_challenge_method param, got %s", q.Get("code_challenge_method"))
	}
}

func TestGetAuthCodeWithPKCESuccess(t *testing.T) {
	listener, err := net.Listen("tcp", "localhost:0")
	if err != nil {
		t.Fatalf("failed to get free port: %v", err)
	}
	port := fmt.Sprintf("%d", listener.Addr().(*net.TCPAddr).Port)
	listener.Close()

	origBrowserOpen := browserOpen
	defer func() { browserOpen = origBrowserOpen }()

	var capturedURL string
	browserOpen = func(authURL string) error {
		capturedURL = authURL
		u, err := url.Parse(authURL)
		if err != nil {
			return err
		}
		state := u.Query().Get("state")
		go func() {
			time.Sleep(200 * time.Millisecond)
			resp, err := http.Get(fmt.Sprintf("http://localhost:%s/oauth2/callback?code=pkce-code&state=%s", port, state))
			if err == nil {
				resp.Body.Close()
			}
		}()
		return nil
	}

	code, codeVerifier, err := GetAuthCode("https://idp.example.com/oauth2/authorize", "my-client", "openid", port, 10, true, false)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	q, err := url.ParseQuery(code)
	if err != nil {
		t.Fatalf("failed to parse returned code: %v", err)
	}
	if q.Get("code") != "pkce-code" {
		t.Errorf("expected code=pkce-code, got %s", q.Get("code"))
	}

	if codeVerifier == "" {
		t.Fatal("expected non-empty code verifier when pkce is true")
	}
	if len(codeVerifier) != 43 {
		t.Errorf("expected code verifier length 43, got %d", len(codeVerifier))
	}

	// Verify the auth URL contained PKCE parameters
	u, err := url.Parse(capturedURL)
	if err != nil {
		t.Fatalf("failed to parse captured auth URL: %v", err)
	}
	challenge := u.Query().Get("code_challenge")
	if challenge == "" {
		t.Fatal("expected code_challenge in auth URL")
	}
	if u.Query().Get("code_challenge_method") != "S256" {
		t.Errorf("expected code_challenge_method=S256, got %s", u.Query().Get("code_challenge_method"))
	}

	// Verify challenge matches the verifier
	expectedChallenge := computeCodeChallenge(codeVerifier)
	if challenge != expectedChallenge {
		t.Errorf("code_challenge does not match verifier: got %s, want %s", challenge, expectedChallenge)
	}
}

func TestGetAuthCodeWithPKCEDisabled(t *testing.T) {
	listener, err := net.Listen("tcp", "localhost:0")
	if err != nil {
		t.Fatalf("failed to get free port: %v", err)
	}
	port := fmt.Sprintf("%d", listener.Addr().(*net.TCPAddr).Port)
	listener.Close()

	origBrowserOpen := browserOpen
	defer func() { browserOpen = origBrowserOpen }()

	var capturedURL string
	browserOpen = func(authURL string) error {
		capturedURL = authURL
		u, err := url.Parse(authURL)
		if err != nil {
			return err
		}
		state := u.Query().Get("state")
		go func() {
			time.Sleep(200 * time.Millisecond)
			resp, err := http.Get(fmt.Sprintf("http://localhost:%s/oauth2/callback?code=no-pkce-code&state=%s", port, state))
			if err == nil {
				resp.Body.Close()
			}
		}()
		return nil
	}

	code, codeVerifier, err := GetAuthCode("https://idp.example.com/oauth2/authorize", "my-client", "openid", port, 10, false, false)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	q, err := url.ParseQuery(code)
	if err != nil {
		t.Fatalf("failed to parse returned code: %v", err)
	}
	if q.Get("code") != "no-pkce-code" {
		t.Errorf("expected code=no-pkce-code, got %s", q.Get("code"))
	}

	if codeVerifier != "" {
		t.Errorf("expected empty code verifier when pkce is false, got %s", codeVerifier)
	}

	// Verify the auth URL did NOT contain PKCE parameters
	u, err := url.Parse(capturedURL)
	if err != nil {
		t.Fatalf("failed to parse captured auth URL: %v", err)
	}
	if u.Query().Get("code_challenge") != "" {
		t.Errorf("expected no code_challenge in auth URL, got %s", u.Query().Get("code_challenge"))
	}
	if u.Query().Get("code_challenge_method") != "" {
		t.Errorf("expected no code_challenge_method in auth URL, got %s", u.Query().Get("code_challenge_method"))
	}
}

// --- closeWindowHTML tests ---

func TestCloseWindowHTMLContent(t *testing.T) {
	if !strings.Contains(closeWindowHTML, "Authentication successful") {
		t.Error("closeWindowHTML should contain success message")
	}
	if !strings.Contains(closeWindowHTML, "close this window") {
		t.Error("closeWindowHTML should contain close instruction")
	}
	if !strings.Contains(closeWindowHTML, "<!DOCTYPE html>") {
		t.Error("closeWindowHTML should be valid HTML")
	}
}
