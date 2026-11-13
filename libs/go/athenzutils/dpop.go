// Copyright The Athenz Authors
// Licensed under the terms of the Apache version 2.0 license. See LICENSE file for terms.

package athenzutils

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/cryptosigner"
	"github.com/google/uuid"
)

const (
	// DPoPHeader is the HTTP header carrying a DPoP proof (RFC 9449).
	DPoPHeader = "DPoP"

	// DPoPTokenType is the token_type returned for DPoP-bound access tokens.
	DPoPTokenType = "DPoP"

	// DPoPProofType is the JWS typ header value for DPoP proofs.
	DPoPProofType = "dpop+jwt"

	dpopTokenEndpointPath = "/oauth2/token"

	// the ID-JAG is an assertion for another authorization server and is never DPoP bound
	idJAGTokenType = "urn:ietf:params:oauth:token-type:id-jag"

	maxTokenResponseSize = 1 << 20
)

// ErrDPoPTokenNotIssued is returned when a DPoP-bound access token was requested
// but the server issued a different token type (for example, a Bearer token from
// a server with DPoP disabled).
var ErrDPoPTokenNotIssued = errors.New("dpop: DPoP-bound token requested but not issued")

type dpopClaims struct {
	JTI   string `json:"jti"`
	HTM   string `json:"htm"`
	HTU   string `json:"htu"`
	IAT   int64  `json:"iat"`
	ATH   string `json:"ath,omitempty"`
	Nonce string `json:"nonce,omitempty"`
}

// GenerateDPoPProof returns a compact-serialized DPoP proof JWT (RFC 9449) signed
// with signer. Only the public key is embedded in the jwk header. The ath claim is
// included when accessToken is not empty, and the nonce claim when nonce is not empty.
func GenerateDPoPProof(signer crypto.Signer, htm, htu, accessToken, nonce string, now time.Time) (string, error) {
	if signer == nil {
		return "", errors.New("dpop: signer is required")
	}
	if htm == "" || htu == "" {
		return "", errors.New("dpop: htm and htu are required")
	}
	alg, err := dpopSignatureAlgorithm(signer.Public())
	if err != nil {
		return "", err
	}

	opts := (&jose.SignerOptions{EmbedJWK: true}).WithType(DPoPProofType)
	joseSigner, err := jose.NewSigner(jose.SigningKey{Algorithm: alg, Key: cryptosigner.Opaque(signer)}, opts)
	if err != nil {
		return "", fmt.Errorf("dpop: unable to create signer: %w", err)
	}

	claims := dpopClaims{
		JTI:   uuid.NewString(),
		HTM:   htm,
		HTU:   htu,
		IAT:   now.Unix(),
		Nonce: nonce,
	}
	if accessToken != "" {
		claims.ATH = DPoPAccessTokenHash(accessToken)
	}
	payload, err := json.Marshal(claims)
	if err != nil {
		return "", fmt.Errorf("dpop: unable to encode claims: %w", err)
	}

	jws, err := joseSigner.Sign(payload)
	if err != nil {
		return "", fmt.Errorf("dpop: unable to sign proof: %w", err)
	}
	return jws.CompactSerialize()
}

// DPoPAccessTokenHash returns the ath claim value for the given access token:
// base64url (no padding) of the SHA-256 hash of its ASCII encoding.
func DPoPAccessTokenHash(accessToken string) string {
	sum := sha256.Sum256([]byte(accessToken))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

// DPoPThumbprint returns the RFC 7638 SHA-256 JWK thumbprint of the public key,
// base64url encoded without padding. This is the value ZTS places in cnf.jkt.
func DPoPThumbprint(pub crypto.PublicKey) (string, error) {
	if _, err := dpopSignatureAlgorithm(pub); err != nil {
		return "", err
	}
	jwk := jose.JSONWebKey{Key: pub}
	sum, err := jwk.Thumbprint(crypto.SHA256)
	if err != nil {
		return "", fmt.Errorf("dpop: unable to compute thumbprint: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(sum), nil
}

// VerifyDPoPTokenType returns an error wrapping ErrDPoPTokenNotIssued unless
// tokenType indicates a DPoP-bound access token. Clients that request DPoP must
// not silently accept a Bearer token. DPoPTransport already applies this check
// to token endpoint responses.
func VerifyDPoPTokenType(tokenType string) error {
	if !strings.EqualFold(tokenType, DPoPTokenType) {
		return fmt.Errorf("%w: expected token_type %s, got %q", ErrDPoPTokenNotIssued, DPoPTokenType, tokenType)
	}
	return nil
}

func dpopSignatureAlgorithm(pub crypto.PublicKey) (jose.SignatureAlgorithm, error) {
	switch key := pub.(type) {
	case *ecdsa.PublicKey:
		switch key.Curve {
		case elliptic.P256():
			return jose.ES256, nil
		case elliptic.P384():
			return jose.ES384, nil
		case elliptic.P521():
			return jose.ES512, nil
		}
		return "", fmt.Errorf("dpop: unsupported ec curve: %s", key.Curve.Params().Name)
	case *rsa.PublicKey:
		return jose.RS256, nil
	}
	return "", fmt.Errorf("dpop: unsupported key type: %T", pub)
}

// DPoPTransport is an http.RoundTripper that adds a freshly generated DPoP proof
// to every POST request sent to the ZTS token endpoint and fails closed: a
// successful token endpoint response that does not carry a DPoP-bound token
// (other than an ID-JAG) is rejected with an error wrapping ErrDPoPTokenNotIssued.
// Other requests are passed through unchanged.
type DPoPTransport struct {
	base   http.RoundTripper
	signer crypto.Signer
	htu    string
	now    func() time.Time
}

// NewDPoPTransport returns a DPoPTransport that wraps base (http.DefaultTransport
// when nil) and signs proofs with signer. The proof htu is ztsURL + "/oauth2/token",
// where ztsURL is the same base URL passed to zts.NewClient.
func NewDPoPTransport(base http.RoundTripper, signer crypto.Signer, ztsURL string) *DPoPTransport {
	if base == nil {
		base = http.DefaultTransport
	}
	return &DPoPTransport{
		base:   base,
		signer: signer,
		htu:    strings.TrimRight(ztsURL, "/") + dpopTokenEndpointPath,
		now:    time.Now,
	}
}

// RoundTrip implements http.RoundTripper.
func (t *DPoPTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	if req.Method != http.MethodPost || req.URL == nil || !strings.HasSuffix(req.URL.Path, dpopTokenEndpointPath) {
		return t.base.RoundTrip(req)
	}
	proof, err := GenerateDPoPProof(t.signer, http.MethodPost, t.htu, "", "", t.now())
	if err != nil {
		if req.Body != nil {
			// the RoundTripper contract requires closing the body on error
			_ = req.Body.Close()
		}
		return nil, err
	}
	clone := req.Clone(req.Context())
	clone.Header.Set(DPoPHeader, proof)
	resp, err := t.base.RoundTrip(clone)
	if err != nil {
		return nil, err
	}
	if err := verifyDPoPTokenResponse(resp); err != nil {
		return nil, err
	}
	return resp, nil
}

// verifyDPoPTokenResponse checks the token_type of a successful token endpoint
// response and restores the body for the caller. Error responses are not checked.
func verifyDPoPTokenResponse(resp *http.Response) error {
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return nil
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxTokenResponseSize+1))
	_ = resp.Body.Close() // the body has been fully consumed and is replaced below
	if err != nil {
		return fmt.Errorf("dpop: unable to read token response: %w", err)
	}
	if len(body) > maxTokenResponseSize {
		return errors.New("dpop: token response too large")
	}
	var token struct {
		TokenType       string `json:"token_type"`
		IssuedTokenType string `json:"issued_token_type"`
	}
	if err := json.Unmarshal(body, &token); err != nil {
		return fmt.Errorf("dpop: unable to parse token response: %w", err)
	}
	if token.IssuedTokenType != idJAGTokenType {
		if err := VerifyDPoPTokenType(token.TokenType); err != nil {
			return err
		}
	}
	resp.Body = io.NopCloser(bytes.NewReader(body))
	return nil
}
