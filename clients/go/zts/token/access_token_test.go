package token

import (
	"context"
	"fmt"
	"net/url"
	"testing"
	"time"

	"github.com/AthenZ/athenz/clients/go/zts"
	"github.com/patrickmn/go-cache"
)

func TestMakeTokenRequest(t *testing.T) {
	tests := []struct {
		name     string
		domain   string
		roles    []string
		expiry   int
		proxy    string
		expected map[string]string
	}{
		{
			name:   "role is * yields domain scope",
			domain: "example.com",
			roles:  []string{"*"},
			expiry: 3600,
			proxy:  "",
			expected: map[string]string{
				"grant_type": "client_credentials",
				"expires_in": "3600",
				"scope":      "example.com:domain",
			},
		},
		{
			name:   "single role",
			domain: "example.com",
			roles:  []string{"admin"},
			expiry: 3600,
			proxy:  "",
			expected: map[string]string{
				"grant_type": "client_credentials",
				"expires_in": "3600",
				"scope":      "example.com:role.admin",
			},
		},
		{
			name:   "multiple roles",
			domain: "example.com",
			roles:  []string{"admin", "user"},
			expiry: 3600,
			proxy:  "",
			expected: map[string]string{
				"grant_type": "client_credentials",
				"expires_in": "3600",
				"scope":      "example.com:role.admin example.com:role.user",
			},
		},
		{
			name:   "with proxy",
			domain: "example.com",
			roles:  []string{"admin"},
			expiry: 3600,
			proxy:  "spiffe://proxy",
			expected: map[string]string{
				"grant_type":                  "client_credentials",
				"expires_in":                  "3600",
				"scope":                       "example.com:role.admin",
				"proxy_principal_spiffe_uris": "spiffe://proxy",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			query := makeTokenRequest(tt.domain, tt.roles, tt.expiry, tt.proxy)
			values, err := url.ParseQuery(query)
			if err != nil {
				t.Fatalf("failed to parse query: %v", err)
			}
			for key, expVal := range tt.expected {
				if got := values.Get(key); got != expVal {
					t.Errorf("for key %q, expected %q, got %q", key, expVal, got)
				}
			}
		})
	}
}

func TestNewAccessTokenClient(t *testing.T) {
	tests := []struct {
		name string
		ctx  context.Context
	}{
		{
			name: "nil context",
			ctx:  nil,
		},
		{
			name: "non-nil context",
			ctx:  context.Background(),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			client, cancel := NewAccessTokenClient(tt.ctx, "http://dummy", "dummy.pem", "dummy.key")
			defer cancel()
			if client == nil {
				t.Fatal("expected non-nil AccessTokenClient")
			}
			if cancel == nil {
				t.Error("expected non-nil cancel function")
			}
		})
	}
}

func TestNewAccessTokenClientSetCacheUpdateDuration(t *testing.T) {
	tests := []struct {
		name string
		ctx  context.Context
	}{
		{
			name: "nil context, 1 hour update duration",
			ctx:  nil,
		},
		{
			name: "non-nil context, 30 minutes update duration",
			ctx:  context.Background(),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			client, cancel := NewAccessTokenClientSetCacheUpdateDuration(tt.ctx, "http://dummy", "dummy.pem", "dummy.key", 1*time.Hour)
			defer cancel()
			if client == nil {
				t.Fatal("expected non-nil AccessTokenClient")
			}
			if client.BaseTokenClient == nil {
				t.Error("expected non-nil BaseTokenClient")
			}
			baseCli := client.BaseTokenClient.Client
			if baseCli == nil {
				t.Error("expected non-nil Client inside BaseTokenClient")
			}
			if baseCli.Cache == nil {
				t.Error("expected non-nil Cache in Client")
			}
			if baseCli.ZTS == nil {
				t.Error("expected non-nil ZTS in Client")
			}
			if baseCli.Tok != client {
				t.Error("expected Client.Tok to be equal to the created AccessTokenClient")
			}
			if client.BaseTokenClient.getTokenFunc == nil {
				t.Error("expected non-nil getTokenFunc")
			}
		})
	}
}

func TestNewAccessTokenClientWrapper(t *testing.T) {
	client, cancel := NewAccessTokenClient(context.Background(), "http://dummy", "dummy.pem", "dummy.key")
	defer cancel()
	if client == nil {
		t.Error("expected non-nil AccessTokenClient")
	}
}

func TestAccessTokenClient_Callback(t *testing.T) {
	origNewClientFunc := newClientFunc
	defer func() { newClientFunc = origNewClientFunc }()
	now := time.Now().Unix()
	tests := []struct {
		name        string
		accessToken *zts.AccessTokenResponse
		fakeErr     error
		fakeToken   string
		fakeExpiry  int64
		expectError bool
		expectToken string
	}{
		{
			name: "successful callback",
			accessToken: &zts.AccessTokenResponse{
				Access_token: "accessTokenSuccess",
				Expires_in: func() *int32 {
					exp := int32(3600)
					return &exp
				}(),
			},
			fakeErr:     nil,
			fakeExpiry:  now + 3600,
			expectError: false,
			expectToken: "accessTokenSuccess",
		},
		{
			name:        "error callback",
			accessToken: nil,
			fakeErr:     fmt.Errorf("simulated error"),
			fakeToken:   "",
			fakeExpiry:  0,
			expectError: true,
			expectToken: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fakeZTS := &fakeZTSClient{
				AccessTokenResponse: tt.accessToken,
				Error:               tt.fakeErr,
			}
			newClientFunc = func(url, pem, key string) *Client {
				return &Client{
					ZTS:   fakeZTS,
					Cache: cache.New(5*time.Minute, 10*time.Minute),
				}
			}
			atClient, cancel := NewAccessTokenClientSetCacheUpdateDuration(context.Background(), "http://dummy", "dummy.pem", "dummy.key", 1*time.Hour)
			defer cancel()

			accessToken, err := atClient.BaseTokenClient.getTokenFunc("dummyDomain", "admin", 3600)
			if tt.expectError {
				if err == nil {
					t.Error("expected error, got nil")
				}
				if accessToken != nil {
					t.Error("expected nil roleToken on error")
				}
			} else {
				if err != nil {
					t.Errorf("unexpected error: %v", err)
				}
				if accessToken == nil {
					t.Fatal("expected non-nil roleToken")
				}
				if accessToken.Token.Access_token != tt.expectToken {
					t.Errorf("expected token %q, got %q", tt.expectToken, accessToken.Token.Access_token)
				}
				if accessToken.ExpiryTime != tt.fakeExpiry {
					t.Errorf("expected expiry time %d, got %d", tt.fakeExpiry, accessToken.ExpiryTime)
				}
			}
		})
	}
}
