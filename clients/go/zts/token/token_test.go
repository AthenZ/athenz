package token

import (
	"testing"
	"time"

	"github.com/AthenZ/athenz/clients/go/zts"
)

func TestAccessToken_Getters(t *testing.T) {
	expectedToken := "abc123"
	expectedExpiry := time.Now().Unix() + 3600

	at := &AccessToken{
		Token: &zts.AccessTokenResponse{
			Access_token: expectedToken,
		},
		ExpiryTime: expectedExpiry,
	}

	if at.GetToken().Access_token != expectedToken {
		t.Errorf("AccessToken.GetToken: expected %q, got %q", expectedToken, at.GetToken().Access_token)
	}
	if at.GetExpiryTime() != expectedExpiry {
		t.Errorf("AccessToken.GetExpiryTime: expected %d, got %d", expectedExpiry, at.GetExpiryTime())
	}
}

func TestRoleToken_Getters(t *testing.T) {
	expectedToken := "roleTokenXYZ"
	expectedExpiry := time.Now().Unix() + 1800

	rt := &RoleToken{
		Token: &zts.RoleToken{
			Token: expectedToken,
		},
		ExpiryTime: expectedExpiry,
	}

	if rt.GetToken().Token != expectedToken {
		t.Errorf("RoleToken.GetToken: expected %q, got %q", expectedToken, rt.GetToken().Token)
	}
	if rt.GetExpiryTime() != expectedExpiry {
		t.Errorf("RoleToken.GetExpiryTime: expected %d, got %d", expectedExpiry, rt.GetExpiryTime())
	}
}
