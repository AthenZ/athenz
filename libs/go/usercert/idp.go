// Copyright The Athenz Authors
// Licensed under the terms of the Apache version 2.0 license. See LICENSE file for terms.

package usercert

import (
	"context"
	"crypto/rand"
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

func newNonce() (string, error) {
	n := make([]byte, 24)
	_, err := io.ReadFull(rand.Reader, n)
	if err != nil {
		return "", fmt.Errorf("rand read: %w", err)
	}
	return encode(n), nil
}

func getIdpAuthURL(endPoint, clientId, scope, nonce, callbackPort string) (string, error) {
	u, err := url.Parse(endPoint)
	if err != nil {
		return "", fmt.Errorf("failed to parse auth endpoint: %v", err)
	}

	redirectURL := fmt.Sprintf("http://localhost:%s/oauth2/callback", callbackPort)

	query := u.Query()
	query.Set("client_id", clientId)
	query.Set("redirect_uri", redirectURL)
	query.Set("response_type", "code")
	query.Set("scope", scope)
	query.Set("nonce", nonce)
	query.Set("state", nonce)

	u.RawQuery = query.Encode()

	return u.String(), nil
}

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

func openIdpAuthURL(endPoint, clientId, scope, nonce, callbackPort string, verbose bool) error {
	authURL, err := getIdpAuthURL(endPoint, clientId, scope, nonce, callbackPort)
	if err != nil {
		return err
	}

	if verbose {
		log.Printf("Opening IdP auth URL: %v", authURL)
	}

	err = openBrowser(authURL)
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

func getAuthCodeFromCallbackHandler(port string, timeoutSeconds int, verbose bool) <-chan authResult {
	result := make(chan authResult, 1)
	code := make(chan string, 1)

	mux := http.NewServeMux()
	registerHandlers(mux, code)

	if verbose {
		log.Printf("Starting callback server on port %s", port)
	}
	server := &http.Server{
		Addr:         fmt.Sprintf("localhost:%s", port),
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
// and waits for the authentication code or a timeout. Returns the raw query string
// containing the code and state, or an error if the process fails.
func GetAuthCode(endPoint, clientId, scope, callbackPort string, timeoutSeconds int, verbose bool) (string, error) {
	result := getAuthCodeFromCallbackHandler(callbackPort, timeoutSeconds, verbose)

	nonce, err := newNonce()
	if err != nil {
		return "", err
	}

	err = openIdpAuthURL(endPoint, clientId, scope, nonce, callbackPort, verbose)
	if err != nil {
		return "", err
	}

	authResult := <-result
	if verbose {
		log.Printf("Received auth result, error: %v", authResult.Error)
	}
	if authResult.Error != nil {
		return "", fmt.Errorf("error receiving auth code: %v", authResult.Error)
	}

	return authResult.Code, nil
}
