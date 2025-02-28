package token

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/AthenZ/athenz/clients/go/zts"
	"github.com/patrickmn/go-cache"
)

func TestNewRoleTokenClientSetCacheUpdateDuration(t *testing.T) {
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
			rtClient, cancel := NewRoleTokenClientSetCacheUpdateDuration(tt.ctx, "http://dummy", "dummy.pem", "dummy.key", 1*time.Hour)
			defer cancel()
			if rtClient == nil {
				t.Fatal("expected non-nil RoleTokenClient")
			}
			if rtClient.BaseTokenClient == nil {
				t.Error("expected non-nil BaseTokenClient")
			}
			baseCli := rtClient.BaseTokenClient.Client
			if baseCli == nil {
				t.Error("expected non-nil Client")
			}
			if baseCli.Cache == nil {
				t.Error("expected non-nil Cache in Client")
			}
			if baseCli.ZTS == nil {
				t.Error("expected non-nil ZTS in Client")
			}
			if baseCli.Tok != rtClient {
				t.Error("expected Client.Tok to equal the created RoleTokenClient")
			}
		})
	}
}

func TestNewRoleTokenClientWrapper(t *testing.T) {
	client, cancel := NewRoleTokenClient(context.Background(), "http://dummy", "dummy.pem", "dummy.key")
	defer cancel()
	if client == nil {
		t.Error("expected non-nil AccessTokenClient")
	}
}

func TestRoleTokenClient_Callback(t *testing.T) {
	origNewClientFunc := newClientFunc
	defer func() { newClientFunc = origNewClientFunc }()
	now := time.Now().Unix()
	tests := []struct {
		name        string
		roleToken   *zts.RoleToken
		fakeErr     error
		fakeToken   string
		fakeExpiry  int64
		expectError bool
		expectToken string
	}{
		{
			name: "successful callback",
			roleToken: &zts.RoleToken{
				Token:      "roleTokenSuccess",
				ExpiryTime: now + 3600,
			},
			fakeErr:     nil,
			fakeExpiry:  now + 3600,
			expectError: false,
			expectToken: "roleTokenSuccess",
		},
		{
			name:        "error callback",
			roleToken:   nil,
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
				RoleTokenResponse: tt.roleToken,
				Error:             tt.fakeErr,
			}
			newClientFunc = func(url, pem, key string) *Client {
				return &Client{
					ZTS:   fakeZTS,
					Cache: cache.New(5*time.Minute, 10*time.Minute),
				}
			}
			rtClient, cancel := NewRoleTokenClientSetCacheUpdateDuration(context.Background(), "http://dummy", "dummy.pem", "dummy.key", 1*time.Hour)
			defer cancel()

			roleToken, err := rtClient.BaseTokenClient.getTokenFunc("dummyDomain", "admin", 3600)
			if tt.expectError {
				if err == nil {
					t.Error("expected error, got nil")
				}
				if roleToken != nil {
					t.Error("expected nil roleToken on error")
				}
			} else {
				if err != nil {
					t.Errorf("unexpected error: %v", err)
				}
				if roleToken == nil {
					t.Fatal("expected non-nil roleToken")
				}
				if roleToken.Token.Token != tt.expectToken {
					t.Errorf("expected token %q, got %q", tt.expectToken, roleToken.Token)
				}
				if roleToken.ExpiryTime != tt.fakeExpiry {
					t.Errorf("expected expiry time %d, got %d", tt.fakeExpiry, roleToken.ExpiryTime)
				}
			}
		})
	}
}
