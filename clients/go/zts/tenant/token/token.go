package token

import "time"

type Token interface {
	GetToken() string
	GetExpiryTime() int64
	GetDuration() time.Duration
}

type AccessToken struct {
	Token      string
	ExpiryTime int64
	Duration   time.Duration
}

func (at *AccessToken) GetToken() string {
	return at.Token
}

func (at *AccessToken) GetExpiryTime() int64 {
	return at.ExpiryTime
}

func (at *AccessToken) GetDuration() time.Duration {
	return at.Duration
}

type RoleToken struct {
	Token      string
	ExpiryTime int64
	Duration   time.Duration
}

func (rt *RoleToken) GetToken() string {
	return rt.Token
}

func (rt *RoleToken) GetExpiryTime() int64 {
	return rt.ExpiryTime
}

func (rt *RoleToken) GetDuration() time.Duration {
	return rt.Duration
}
