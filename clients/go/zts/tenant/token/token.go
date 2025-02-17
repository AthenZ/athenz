package token

type Token interface {
	GetToken() string
	GetExpiryTime() int64
}

type AccessToken struct {
	Token      string
	ExpiryTime int64
}

func (at *AccessToken) GetToken() string {
	return at.Token
}

func (at *AccessToken) GetExpiryTime() int64 {
	return at.ExpiryTime
}

type RoleToken struct {
	Token      string
	ExpiryTime int64
}

func (rt *RoleToken) GetToken() string {
	return rt.Token
}

func (rt *RoleToken) GetExpiryTime() int64 {
	return rt.ExpiryTime
}
