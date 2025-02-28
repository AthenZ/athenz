package token

import (
	"time"

	"github.com/AthenZ/athenz/clients/go/zts"
)

type Token interface {
	GetExpiryTime() int64
	GetDuration() time.Duration
}

type AccessToken struct {
	Token      *zts.AccessTokenResponse
	ExpiryTime int64
	Duration   time.Duration
}

func (at *AccessToken) GetToken() *zts.AccessTokenResponse {
	return at.Token
}

func (at *AccessToken) GetExpiryTime() int64 {
	return at.ExpiryTime
}

func (at *AccessToken) GetDuration() time.Duration {
	return at.Duration
}

type RoleToken struct {
	Token      *zts.RoleToken
	ExpiryTime int64
	Duration   time.Duration
}

func (rt *RoleToken) GetToken() *zts.RoleToken {
	return rt.Token
}

func (rt *RoleToken) GetExpiryTime() int64 {
	return rt.ExpiryTime
}

func (rt *RoleToken) GetDuration() time.Duration {
	return rt.Duration
}
