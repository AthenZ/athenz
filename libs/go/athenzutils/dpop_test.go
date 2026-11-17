// Copyright The Athenz Authors
// Licensed under the terms of the Apache version 2.0 license. See LICENSE file for terms.

package athenzutils

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/AthenZ/athenz/clients/go/zts"
	"github.com/go-jose/go-jose/v4"
)

var dpopTestAlgs = []jose.SignatureAlgorithm{jose.ES256, jose.ES384, jose.ES512, jose.RS256}

func newECSigner(t *testing.T, curve elliptic.Curve) crypto.Signer {
	t.Helper()
	key, err := ecdsa.GenerateKey(curve, rand.Reader)
	if err != nil {
		t.Fatalf("unable to generate ec key: %v", err)
	}
	return key
}

func newRSASigner(t *testing.T) crypto.Signer {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("unable to generate rsa key: %v", err)
	}
	return key
}

// parseDPoPProof verifies the proof against its embedded jwk and returns the
// signature header and decoded claims.
func parseDPoPProof(t *testing.T, proof string) (jose.Header, dpopClaims) {
	t.Helper()
	jws, err := jose.ParseSigned(proof, dpopTestAlgs)
	if err != nil {
		t.Fatalf("unable to parse proof: %v", err)
	}
	if len(jws.Signatures) != 1 {
		t.Fatalf("want 1 signature, got %d", len(jws.Signatures))
	}
	header := jws.Signatures[0].Protected
	if header.JSONWebKey == nil {
		t.Fatal("proof has no embedded jwk")
	}
	payload, err := jws.Verify(header.JSONWebKey)
	if err != nil {
		t.Fatalf("proof signature does not verify with embedded jwk: %v", err)
	}
	var claims dpopClaims
	if err := json.Unmarshal(payload, &claims); err != nil {
		t.Fatalf("unable to decode claims: %v", err)
	}
	return header, claims
}

func TestGenerateDPoPProof(t *testing.T) {
	t.Parallel()

	now := time.Unix(1700000000, 0)
	tests := []struct {
		name        string
		signer      crypto.Signer
		wantAlg     string
		accessToken string
		nonce       string
	}{
		{"ec-p256", newECSigner(t, elliptic.P256()), "ES256", "", ""},
		{"ec-p384", newECSigner(t, elliptic.P384()), "ES384", "", ""},
		{"ec-p521", newECSigner(t, elliptic.P521()), "ES512", "", ""},
		{"rsa-2048", newRSASigner(t), "RS256", "", ""},
		{"with-ath-and-nonce", newECSigner(t, elliptic.P256()), "ES256", "access-token-value", "server-nonce"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			proof, err := GenerateDPoPProof(tt.signer, "POST", "https://zts.athenz.io/zts/v1/oauth2/token", tt.accessToken, tt.nonce, now)
			if err != nil {
				t.Fatalf("GenerateDPoPProof: %v", err)
			}
			header, claims := parseDPoPProof(t, proof)

			if got := header.Algorithm; got != tt.wantAlg {
				t.Errorf("alg: got %s, want %s", got, tt.wantAlg)
			}
			if got := header.ExtraHeaders[jose.HeaderType]; got != DPoPProofType {
				t.Errorf("typ: got %v, want %s", got, DPoPProofType)
			}
			if !header.JSONWebKey.IsPublic() {
				t.Error("embedded jwk must be public only")
			}
			if header.KeyID != "" {
				t.Errorf("kid: got %q, want empty", header.KeyID)
			}
			if strings.Contains(proof, "\"d\"") {
				t.Error("proof contains private key material")
			}

			wantJkt, err := DPoPThumbprint(tt.signer.Public())
			if err != nil {
				t.Fatalf("DPoPThumbprint: %v", err)
			}
			sum, err := header.JSONWebKey.Thumbprint(crypto.SHA256)
			if err != nil {
				t.Fatalf("thumbprint of embedded jwk: %v", err)
			}
			if got := base64.RawURLEncoding.EncodeToString(sum); got != wantJkt {
				t.Errorf("embedded jwk thumbprint: got %s, want %s", got, wantJkt)
			}

			if claims.JTI == "" {
				t.Error("jti is empty")
			}
			if claims.HTM != "POST" {
				t.Errorf("htm: got %s, want POST", claims.HTM)
			}
			if claims.HTU != "https://zts.athenz.io/zts/v1/oauth2/token" {
				t.Errorf("htu: got %s", claims.HTU)
			}
			if claims.IAT != now.Unix() {
				t.Errorf("iat: got %d, want %d", claims.IAT, now.Unix())
			}
			wantAth := ""
			if tt.accessToken != "" {
				wantAth = DPoPAccessTokenHash(tt.accessToken)
			}
			if claims.ATH != wantAth {
				t.Errorf("ath: got %q, want %q", claims.ATH, wantAth)
			}
			if claims.Nonce != tt.nonce {
				t.Errorf("nonce: got %q, want %q", claims.Nonce, tt.nonce)
			}
		})
	}
}

func TestGenerateDPoPProofOmitsOptionalClaims(t *testing.T) {
	t.Parallel()

	proof, err := GenerateDPoPProof(newECSigner(t, elliptic.P256()), "POST", "https://zts/oauth2/token", "", "", time.Now())
	if err != nil {
		t.Fatalf("GenerateDPoPProof: %v", err)
	}
	jws, err := jose.ParseSigned(proof, dpopTestAlgs)
	if err != nil {
		t.Fatalf("unable to parse proof: %v", err)
	}
	var raw map[string]interface{}
	if err := json.Unmarshal(jws.UnsafePayloadWithoutVerification(), &raw); err != nil {
		t.Fatalf("unable to decode claims: %v", err)
	}
	for _, claim := range []string{"ath", "nonce"} {
		if _, ok := raw[claim]; ok {
			t.Errorf("claim %s must be omitted when empty", claim)
		}
	}
}

func TestGenerateDPoPProofUniqueJti(t *testing.T) {
	t.Parallel()

	signer := newECSigner(t, elliptic.P256())
	now := time.Now()
	seen := map[string]bool{}
	for i := 0; i < 5; i++ {
		proof, err := GenerateDPoPProof(signer, "POST", "https://zts/oauth2/token", "", "", now)
		if err != nil {
			t.Fatalf("GenerateDPoPProof: %v", err)
		}
		_, claims := parseDPoPProof(t, proof)
		if seen[claims.JTI] {
			t.Errorf("duplicate jti %s", claims.JTI)
		}
		seen[claims.JTI] = true
	}
}

func TestGenerateDPoPProofErrors(t *testing.T) {
	t.Parallel()

	_, edKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("unable to generate ed25519 key: %v", err)
	}
	tests := []struct {
		name   string
		signer crypto.Signer
		htm    string
		htu    string
	}{
		{"nil-signer", nil, "POST", "https://zts/oauth2/token"},
		{"empty-htm", newECSigner(t, elliptic.P256()), "", "https://zts/oauth2/token"},
		{"empty-htu", newECSigner(t, elliptic.P256()), "POST", ""},
		{"unsupported-curve", newECSigner(t, elliptic.P224()), "POST", "https://zts/oauth2/token"},
		{"unsupported-key-type", edKey, "POST", "https://zts/oauth2/token"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if _, err := GenerateDPoPProof(tt.signer, tt.htm, tt.htu, "", "", time.Now()); err == nil {
				t.Error("want error, got nil")
			}
		})
	}
}

func TestDPoPThumbprintRFC7638(t *testing.T) {
	t.Parallel()

	// RFC 7638 section 3.1 example RSA key
	const n = "0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMstn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqbw0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw"
	nBytes, err := base64.RawURLEncoding.DecodeString(n)
	if err != nil {
		t.Fatalf("unable to decode modulus: %v", err)
	}
	pub := &rsa.PublicKey{N: new(big.Int).SetBytes(nBytes), E: 65537}

	got, err := DPoPThumbprint(pub)
	if err != nil {
		t.Fatalf("DPoPThumbprint: %v", err)
	}
	if want := "NzbLsXh8uDCcd-6MNwXF4W_7noWXFZAfHkxZsRGC9Xs"; got != want {
		t.Errorf("got %s, want %s", got, want)
	}
}

func TestDPoPThumbprintErrors(t *testing.T) {
	t.Parallel()

	edPub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("unable to generate ed25519 key: %v", err)
	}
	tests := []struct {
		name string
		pub  crypto.PublicKey
	}{
		{"nil", nil},
		{"ed25519", edPub},
		{"p224", newECSigner(t, elliptic.P224()).Public()},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if _, err := DPoPThumbprint(tt.pub); err == nil {
				t.Error("want error, got nil")
			}
		})
	}
}

func TestDPoPAccessTokenHash(t *testing.T) {
	t.Parallel()

	// RFC 9449 section 7.1 example
	got := DPoPAccessTokenHash("Kz~8mXK1EalYznwH-LC-1fBAo.4Ljp~zsPE_NeO.gxU")
	if want := "fUHyO2r2Z3DZ53EsNrWBb0xWXoaNy59IiKCAqksmQEo"; got != want {
		t.Errorf("got %s, want %s", got, want)
	}
}

func TestVerifyDPoPTokenType(t *testing.T) {
	t.Parallel()

	tests := []struct {
		tokenType string
		wantErr   bool
	}{
		{"DPoP", false},
		{"dpop", false},
		{"Bearer", true},
		{"N_A", true},
		{"", true},
	}
	for _, tt := range tests {
		t.Run(tt.tokenType, func(t *testing.T) {
			t.Parallel()
			if err := VerifyDPoPTokenType(tt.tokenType); (err != nil) != tt.wantErr {
				t.Errorf("got err %v, wantErr %v", err, tt.wantErr)
			}
			if err := VerifyDPoPTokenType(tt.tokenType); tt.wantErr && !errors.Is(err, ErrDPoPTokenNotIssued) {
				t.Errorf("want ErrDPoPTokenNotIssued, got %v", err)
			}
		})
	}
}

type recordingTransport struct {
	requests []*http.Request
	status   int
	body     string
	err      error
}

func (r *recordingTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	r.requests = append(r.requests, req)
	if r.err != nil {
		return nil, r.err
	}
	status, body := r.status, r.body
	if status == 0 {
		status = http.StatusOK
	}
	if body == "" {
		body = `{"access_token":"token","token_type":"DPoP","expires_in":3600}`
	}
	return &http.Response{StatusCode: status, Body: io.NopCloser(strings.NewReader(body)), Request: req}, nil
}

type failingBody struct{}

func (failingBody) Read([]byte) (int, error) { return 0, errors.New("read failure") }
func (failingBody) Close() error             { return nil }

type failingBodyTransport struct{}

func (failingBodyTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	return &http.Response{StatusCode: http.StatusOK, Body: failingBody{}, Request: req}, nil
}

func TestDPoPTransportTokenTypeVerification(t *testing.T) {
	t.Parallel()

	const tokenURL = "https://zts.athenz.io/zts/v1/oauth2/token"
	tests := []struct {
		name          string
		url           string
		status        int
		body          string
		wantErr       bool
		wantNotIssued bool
	}{
		{"dpop-token", tokenURL, http.StatusOK, `{"access_token":"a","token_type":"DPoP"}`, false, false},
		{"dpop-token-lowercase", tokenURL, http.StatusOK, `{"access_token":"a","token_type":"dpop"}`, false, false},
		{"bearer-token", tokenURL, http.StatusOK, `{"access_token":"a","token_type":"Bearer"}`, true, true},
		{"missing-token-type", tokenURL, http.StatusOK, `{"access_token":"a"}`, true, true},
		{"id-jag", tokenURL, http.StatusOK, `{"access_token":"a","token_type":"N_A","issued_token_type":"urn:ietf:params:oauth:token-type:id-jag"}`, false, false},
		{"id-token-exchange", tokenURL, http.StatusOK, `{"id_token":"a","token_type":"Bearer","issued_token_type":"urn:ietf:params:oauth:token-type:id_token"}`, false, false},
		{"bearer-access-token-exchange", tokenURL, http.StatusOK, `{"access_token":"a","token_type":"Bearer","issued_token_type":"urn:ietf:params:oauth:token-type:access_token"}`, true, true},
		{"invalid-json", tokenURL, http.StatusOK, `not-json`, true, false},
		{"too-large", tokenURL, http.StatusOK, `{"token_type":"DPoP","pad":"` + strings.Repeat("a", maxTokenResponseSize) + `"}`, true, false},
		{"error-response", tokenURL, http.StatusBadRequest, `{"error":"invalid_dpop_proof"}`, false, false},
		{"other-endpoint-bearer", "https://zts.athenz.io/zts/v1/rolecert", http.StatusOK, `{"token_type":"Bearer"}`, false, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			base := &recordingTransport{status: tt.status, body: tt.body}
			transport := NewDPoPTransport(base, newECSigner(t, elliptic.P256()), "https://zts.athenz.io/zts/v1")

			req, err := http.NewRequest(http.MethodPost, tt.url, strings.NewReader("grant_type=client_credentials"))
			if err != nil {
				t.Fatalf("NewRequest: %v", err)
			}
			resp, err := transport.RoundTrip(req)
			if tt.wantErr {
				if err == nil {
					resp.Body.Close()
					t.Fatal("want error, got nil")
				}
				if got := errors.Is(err, ErrDPoPTokenNotIssued); got != tt.wantNotIssued {
					t.Errorf("errors.Is(ErrDPoPTokenNotIssued): got %v, want %v (%v)", got, tt.wantNotIssued, err)
				}
				return
			}
			if err != nil {
				t.Fatalf("RoundTrip: %v", err)
			}
			defer resp.Body.Close()
			got, err := io.ReadAll(resp.Body)
			if err != nil {
				t.Fatalf("ReadAll: %v", err)
			}
			if string(got) != tt.body {
				t.Errorf("body must be passed through unchanged: got %s, want %s", got, tt.body)
			}
		})
	}
}

func TestDPoPTransportResponseErrors(t *testing.T) {
	t.Parallel()

	const tokenURL = "https://zts.athenz.io/zts/v1/oauth2/token"
	signer := newECSigner(t, elliptic.P256())

	baseErr := errors.New("connection refused")
	transport := NewDPoPTransport(&recordingTransport{err: baseErr}, signer, "https://zts.athenz.io/zts/v1")
	req, err := http.NewRequest(http.MethodPost, tokenURL, nil)
	if err != nil {
		t.Fatalf("NewRequest: %v", err)
	}
	if _, err := transport.RoundTrip(req); !errors.Is(err, baseErr) {
		t.Errorf("want base transport error, got %v", err)
	}

	transport = NewDPoPTransport(failingBodyTransport{}, signer, "https://zts.athenz.io/zts/v1")
	req, err = http.NewRequest(http.MethodPost, tokenURL, nil)
	if err != nil {
		t.Fatalf("NewRequest: %v", err)
	}
	if _, err := transport.RoundTrip(req); err == nil || !strings.Contains(err.Error(), "unable to read token response") {
		t.Errorf("want read error, got %v", err)
	}
}

func TestZtsClientWithDPoPRejectsBearerToken(t *testing.T) {
	t.Parallel()

	client, err := ZtsClientWithDPoP("https://localhost:4443/zts/v1", "data/svc-test-key1.pem", "data/svc-test-cert1.pem", "", "", false)
	if err != nil {
		t.Fatalf("ZtsClientWithDPoP: %v", err)
	}
	transport, ok := client.Transport.(*DPoPTransport)
	if !ok {
		t.Fatalf("want *DPoPTransport, got %T", client.Transport)
	}
	transport.base = &recordingTransport{body: `{"access_token":"a","token_type":"Bearer","expires_in":3600}`}

	resp, err := client.PostAccessTokenRequest(zts.AccessTokenRequest("grant_type=client_credentials&scope=coretech%3Adomain"))
	if err == nil {
		t.Fatalf("want error for bearer token, got response %+v", resp)
	}
	if !errors.Is(err, ErrDPoPTokenNotIssued) {
		t.Errorf("want ErrDPoPTokenNotIssued, got %v", err)
	}

	transport.base = &recordingTransport{}
	resp, err = client.PostAccessTokenRequest(zts.AccessTokenRequest("grant_type=client_credentials&scope=coretech%3Adomain"))
	if err != nil {
		t.Fatalf("PostAccessTokenRequest: %v", err)
	}
	if resp.Token_type != DPoPTokenType {
		t.Errorf("token_type: got %s, want %s", resp.Token_type, DPoPTokenType)
	}
}

func TestDPoPTransportRejectsTokenEndpointRedirect(t *testing.T) {
	t.Parallel()

	// the generated client follows redirects, and the redirect target is not the
	// token endpoint, so it would get neither a proof nor response verification
	for _, status := range []int{http.StatusMovedPermanently, http.StatusFound, http.StatusSeeOther,
		http.StatusTemporaryRedirect, http.StatusPermanentRedirect} {
		t.Run(http.StatusText(status), func(t *testing.T) {
			t.Parallel()
			var redirectedCalls atomic.Int32
			mux := http.NewServeMux()
			mux.HandleFunc("/zts/v1/oauth2/token", func(w http.ResponseWriter, r *http.Request) {
				http.Redirect(w, r, "/zts/v1/token-v2", status)
			})
			mux.HandleFunc("/zts/v1/token-v2", func(w http.ResponseWriter, r *http.Request) {
				redirectedCalls.Add(1)
				w.Header().Set("Content-Type", "application/json")
				_, _ = w.Write([]byte(`{"access_token":"a","token_type":"Bearer","expires_in":3600}`))
			})
			server := httptest.NewServer(mux)
			defer server.Close()

			ztsURL := server.URL + "/zts/v1"
			client := zts.NewClient(ztsURL, NewDPoPTransport(nil, newECSigner(t, elliptic.P256()), ztsURL))
			resp, err := client.PostAccessTokenRequest(zts.AccessTokenRequest("grant_type=client_credentials&scope=coretech%3Adomain"))
			if err == nil || !strings.Contains(err.Error(), "dpop: token endpoint redirect") {
				t.Fatalf("want redirect error, got response %+v, err %v", resp, err)
			}
			if got := redirectedCalls.Load(); got != 0 {
				t.Errorf("redirect target called %d times, want 0", got)
			}
		})
	}
}

func TestDPoPTransport(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name      string
		method    string
		url       string
		wantProof bool
	}{
		{"post-token-endpoint", http.MethodPost, "https://zts.athenz.io/zts/v1/oauth2/token", true},
		{"get-token-endpoint", http.MethodGet, "https://zts.athenz.io/zts/v1/oauth2/token", false},
		{"post-other-endpoint", http.MethodPost, "https://zts.athenz.io/zts/v1/rolecert", false},
		{"post-token-prefix", http.MethodPost, "https://zts.athenz.io/zts/v1/oauth2/token/extra", false},
		{"post-introspect", http.MethodPost, "https://zts.athenz.io/zts/v1/oauth2/introspect", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			base := &recordingTransport{}
			now := time.Unix(1700000000, 0)
			transport := NewDPoPTransport(base, newECSigner(t, elliptic.P256()), "https://zts.athenz.io/zts/v1/")
			transport.now = func() time.Time { return now }

			req, err := http.NewRequest(tt.method, tt.url, strings.NewReader("grant_type=client_credentials"))
			if err != nil {
				t.Fatalf("NewRequest: %v", err)
			}
			req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			resp, err := transport.RoundTrip(req)
			if err != nil {
				t.Fatalf("RoundTrip: %v", err)
			}
			resp.Body.Close()

			if req.Header.Get(DPoPHeader) != "" {
				t.Error("original request must not be modified")
			}
			if len(base.requests) != 1 {
				t.Fatalf("want 1 forwarded request, got %d", len(base.requests))
			}
			sent := base.requests[0]
			if sent.Header.Get("Content-Type") != "application/x-www-form-urlencoded" {
				t.Error("existing headers must be preserved")
			}
			values := sent.Header.Values(DPoPHeader)
			if !tt.wantProof {
				if len(values) != 0 {
					t.Errorf("want no DPoP header, got %v", values)
				}
				return
			}
			if len(values) != 1 {
				t.Fatalf("want exactly one DPoP header, got %d", len(values))
			}
			_, claims := parseDPoPProof(t, values[0])
			if claims.HTM != http.MethodPost {
				t.Errorf("htm: got %s", claims.HTM)
			}
			if want := "https://zts.athenz.io/zts/v1/oauth2/token"; claims.HTU != want {
				t.Errorf("htu: got %s, want %s", claims.HTU, want)
			}
			if claims.IAT != now.Unix() {
				t.Errorf("iat: got %d, want %d", claims.IAT, now.Unix())
			}
		})
	}
}

func TestDPoPTransportFreshProofPerRequest(t *testing.T) {
	t.Parallel()

	base := &recordingTransport{}
	transport := NewDPoPTransport(base, newECSigner(t, elliptic.P256()), "https://zts.athenz.io/zts/v1")
	for i := 0; i < 2; i++ {
		req, err := http.NewRequest(http.MethodPost, "https://zts.athenz.io/zts/v1/oauth2/token", nil)
		if err != nil {
			t.Fatalf("NewRequest: %v", err)
		}
		if _, err := transport.RoundTrip(req); err != nil {
			t.Fatalf("RoundTrip: %v", err)
		}
	}
	_, first := parseDPoPProof(t, base.requests[0].Header.Get(DPoPHeader))
	_, second := parseDPoPProof(t, base.requests[1].Header.Get(DPoPHeader))
	if first.JTI == second.JTI {
		t.Errorf("want unique jti per request, got %s twice", first.JTI)
	}
}

func TestNewDPoPTransportDefaultBase(t *testing.T) {
	t.Parallel()

	transport := NewDPoPTransport(nil, newECSigner(t, elliptic.P256()), "https://zts.athenz.io/zts/v1")
	if transport.base != http.DefaultTransport {
		t.Error("want http.DefaultTransport as base when nil")
	}
}

type trackingBody struct {
	io.Reader
	closed bool
}

func (b *trackingBody) Close() error {
	b.closed = true
	return nil
}

func TestDPoPTransportProofError(t *testing.T) {
	t.Parallel()

	base := &recordingTransport{}
	transport := NewDPoPTransport(base, nil, "https://zts.athenz.io/zts/v1")
	body := &trackingBody{Reader: strings.NewReader("grant_type=client_credentials")}
	req, err := http.NewRequest(http.MethodPost, "https://zts.athenz.io/zts/v1/oauth2/token", body)
	if err != nil {
		t.Fatalf("NewRequest: %v", err)
	}
	if _, err := transport.RoundTrip(req); err == nil {
		t.Error("want error when proof cannot be generated")
	}
	if !body.closed {
		t.Error("request body must be closed on error")
	}
	if len(base.requests) != 0 {
		t.Error("request must not be forwarded when proof generation fails")
	}
}

func TestZtsClientWithDPoP(t *testing.T) {
	t.Parallel()

	// key file as written by openssl ecparam -genkey, which the TLS loader accepts
	keyPEM, err := os.ReadFile("data/svc-test-key1.pem")
	if err != nil {
		t.Fatalf("read key: %v", err)
	}
	keyWithParamsFile := filepath.Join(t.TempDir(), "svc-test-key1-params.pem")
	params := []byte("-----BEGIN EC PARAMETERS-----\nBggqhkjOPQMBBw==\n-----END EC PARAMETERS-----\n")
	if err := os.WriteFile(keyWithParamsFile, append(params, keyPEM...), 0600); err != nil {
		t.Fatalf("write key: %v", err)
	}

	tests := []struct {
		name        string
		keyFile     string
		certFile    string
		dpopKeyFile string
		wantErr     bool
	}{
		{"default-dpop-key", "data/svc-test-key1.pem", "data/svc-test-cert1.pem", "", false},
		{"explicit-dpop-key", "data/svc-test-key1.pem", "data/svc-test-cert1.pem", "data/svc-test-key1.pem", false},
		{"key-with-ec-parameters", keyWithParamsFile, "data/svc-test-cert1.pem", "", false},
		{"invalid-svc-key", "invalid-key-file", "data/svc-test-cert1.pem", "", true},
		{"missing-dpop-key", "data/svc-test-key1.pem", "data/svc-test-cert1.pem", "missing-dpop-key", true},
		{"invalid-dpop-key", "data/svc-test-key1.pem", "data/svc-test-cert1.pem", "data/svc-test-cert1.pem", true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			client, err := ZtsClientWithDPoP("https://localhost:4443/zts/v1", tt.keyFile, tt.certFile, "", tt.dpopKeyFile, false)
			if tt.wantErr {
				if err == nil {
					t.Error("want error, got nil")
				}
				return
			}
			if err != nil {
				t.Fatalf("ZtsClientWithDPoP: %v", err)
			}
			transport, ok := client.Transport.(*DPoPTransport)
			if !ok {
				t.Fatalf("want *DPoPTransport, got %T", client.Transport)
			}
			if want := "https://localhost:4443/zts/v1/oauth2/token"; transport.htu != want {
				t.Errorf("htu: got %s, want %s", transport.htu, want)
			}
			if _, ok := transport.base.(*http.Transport); !ok {
				t.Errorf("base: want *http.Transport, got %T", transport.base)
			}
		})
	}
}
