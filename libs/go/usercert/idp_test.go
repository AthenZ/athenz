// Copyright The Athenz Authors
// Licensed under the terms of the Apache version 2.0 license. See LICENSE file for terms.

package usercert

import (
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
	nonce, err := newNonce()
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
		nonce, err := newNonce()
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
	nonce, err := newNonce()
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
	authURL, err := getIdpAuthURL("https://idp.example.com/oauth2/authorize", "my-client", "test-nonce", "3222")
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
	if q.Get("redirect_uri") != "http://localhost:3222/oauth2/callback" {
		t.Errorf("expected redirect_uri with port 3222, got %s", q.Get("redirect_uri"))
	}
	if q.Get("response_type") != "code" {
		t.Errorf("expected response_type=code, got %s", q.Get("response_type"))
	}
	if q.Get("nonce") != "test-nonce" {
		t.Errorf("expected nonce=test-nonce, got %s", q.Get("nonce"))
	}
	if q.Get("state") != "test-nonce" {
		t.Errorf("expected state=test-nonce, got %s", q.Get("state"))
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
			authURL, err := getIdpAuthURL("https://idp.example.com/auth", "client", "nonce", tt.port)
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
	_, err := getIdpAuthURL("://invalid", "client", "nonce", "3222")
	if err == nil {
		t.Fatal("expected error for invalid endpoint")
	}
}

func TestGetIdpAuthURLPreservesExistingQueryParams(t *testing.T) {
	authURL, err := getIdpAuthURL("https://idp.example.com/auth?scope=openid", "client", "nonce", "3222")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	u, _ := url.Parse(authURL)
	if u.Query().Get("scope") != "openid" {
		t.Error("existing query parameter 'scope' was lost")
	}
	if u.Query().Get("client_id") != "client" {
		t.Error("client_id not set")
	}
}

// --- registerHandlers tests ---

func TestRegisterHandlersCallback(t *testing.T) {
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
	client := &http.Client{
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	resp, err := client.Get(fmt.Sprintf("http://localhost:%s/oauth2/callback?code=auth-code-123&state=nonce", port))
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
