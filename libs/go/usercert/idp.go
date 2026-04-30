// Copyright The Athenz Authors
// Licensed under the terms of the Apache version 2.0 license. See LICENSE file for terms.

package usercert

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"os/exec"
	"runtime"
	"time"
)

type authResult struct {
	Code  string
	Error error
}

func encode(b []byte) string { return base64.RawURLEncoding.EncodeToString(b) }

// newCodeVerifier generates a random base64url-encoded string of the given size in bytes.
// It is used for PKCE code verifiers, nonces, and state values.
func newCodeVerifier(size int) (string, error) {
	b := make([]byte, size)
	_, err := io.ReadFull(rand.Reader, b)
	if err != nil {
		return "", fmt.Errorf("rand read: %w", err)
	}
	return encode(b), nil
}

// computeCodeChallenge computes the S256 code challenge per RFC 7636 Section 4.2:
// BASE64URL(SHA256(code_verifier))
func computeCodeChallenge(verifier string) string {
	h := sha256.Sum256([]byte(verifier))
	return encode(h[:])
}

func getIdpAuthURL(endPoint, clientId, scope, nonce, state string, callbackPort int, codeChallenge string) (string, error) {
	u, err := url.Parse(endPoint)
	if err != nil {
		return "", fmt.Errorf("failed to parse auth endpoint: %v", err)
	}

	redirectURL := fmt.Sprintf("http://localhost:%d/oauth2/callback", callbackPort)

	query := u.Query()
	query.Set("client_id", clientId)
	query.Set("redirect_uri", redirectURL)
	query.Set("response_type", "code")
	query.Set("scope", scope)
	query.Set("nonce", nonce)
	query.Set("state", state)
	if codeChallenge != "" {
		query.Set("code_challenge", codeChallenge)
		query.Set("code_challenge_method", "S256")
	}

	u.RawQuery = query.Encode()

	return u.String(), nil
}

var browserOpen = openBrowser

func openBrowser(url string) error {
	var cmd *exec.Cmd
	switch runtime.GOOS {
	case "darwin":
		cmd = exec.Command("/usr/bin/open", url)
	case "linux":
		cmd = exec.Command("xdg-open", url)
	default:
		return fmt.Errorf("unsupported platform: %s", runtime.GOOS)
	}
	return cmd.Run()
}

func openIdpAuthURL(endPoint, clientId, scope, nonce, state string, callbackPort int, codeChallenge string, verbose bool) error {
	authURL, err := getIdpAuthURL(endPoint, clientId, scope, nonce, state, callbackPort, codeChallenge)
	if err != nil {
		return err
	}

	if verbose {
		log.Printf("Opening IdP auth URL: %v", authURL)
	}

	err = browserOpen(authURL)
	if err != nil {
		return fmt.Errorf("failed to open authorize URL: %v", err)
	}
	return nil
}

func registerHandlers(mux *http.ServeMux, code chan<- string) {
	authCode := make(chan string, 1)

	mux.Handle("/oauth2/callback", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		authCode <- r.URL.RawQuery
		http.Redirect(w, r, "/close", http.StatusSeeOther)
	}))

	mux.Handle("/close", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		fmt.Fprint(w, closeWindowHTML)
		select {
		case c := <-authCode:
			code <- c
			close(code)
		default:
		}
	}))
}

func getAuthCodeFromCallbackHandler(port, timeoutSeconds int, verbose bool) <-chan authResult {
	result := make(chan authResult, 1)
	code := make(chan string, 1)

	mux := http.NewServeMux()
	registerHandlers(mux, code)

	if verbose {
		log.Printf("Starting callback server on port %d", port)
	}
	server := &http.Server{
		Addr:         fmt.Sprintf("localhost:%d", port),
		Handler:      mux,
		ReadTimeout:  30 * time.Second,
		WriteTimeout: 30 * time.Second,
		IdleTimeout:  120 * time.Second,
	}

	go func() {
		if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Printf("Callback server could not be started: %v", err)
			result <- authResult{Error: err}
		}
	}()

	go func() {
		defer func() {
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			if err := server.Shutdown(ctx); err != nil && verbose {
				log.Printf("Callback server shutdown error: %v", err)
			}
		}()

		select {
		case c := <-code:
			result <- authResult{Code: c}
		case <-time.After(time.Second * time.Duration(timeoutSeconds)):
			result <- authResult{Error: fmt.Errorf("timeout waiting for IdP callback")}
		}
	}()

	return result
}

// GetAuthCode initiates the IdP authentication flow. It starts a local HTTP server
// to receive the IdP callback, opens the IdP authorization URL in the browser,
// and waits for the authentication code or a timeout.
// When pkce is true, PKCE (RFC 7636) support is enabled: a code verifier/challenge
// pair is generated, the challenge is sent with the authorization request, and the
// verifier is returned so the caller can include it in the token exchange.
// Returns the raw query string containing the code and state, the PKCE code
// verifier (empty when pkce is false), or an error if the process fails.
func GetAuthCode(endPoint, clientId, scope string, callbackPort, timeoutSeconds int, pkce, verbose bool) (string, string, error) {
	result := getAuthCodeFromCallbackHandler(callbackPort, timeoutSeconds, verbose)

	nonce, err := newCodeVerifier(24)
	if err != nil {
		return "", "", err
	}

	state, err := newCodeVerifier(24)
	if err != nil {
		return "", "", err
	}

	var codeVerifier, codeChallenge string
	if pkce {
		codeVerifier, err = newCodeVerifier(32)
		if err != nil {
			return "", "", err
		}
		codeChallenge = computeCodeChallenge(codeVerifier)
	}

	err = openIdpAuthURL(endPoint, clientId, scope, nonce, state, callbackPort, codeChallenge, verbose)
	if err != nil {
		return "", "", err
	}

	authResult := <-result
	if verbose {
		log.Printf("Received auth result, error: %v", authResult.Error)
	}
	if authResult.Error != nil {
		return "", "", fmt.Errorf("error receiving auth code: %v", authResult.Error)
	}

	query, err := url.ParseQuery(authResult.Code)
	if err != nil {
		return "", "", fmt.Errorf("failed to parse auth code: %v", err)
	}
	if query.Get("state") != state {
		return "", "", fmt.Errorf("state mismatch: expected %s, got %s", state, query.Get("state"))
	}

	return authResult.Code, codeVerifier, nil
}
