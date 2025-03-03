package token

import (
	"net/http"
	"time"

	"github.com/AthenZ/athenz/clients/go/zts"
)

type ZTSClientInterface interface {
	PostAccessTokenRequest(req zts.AccessTokenRequest) (*zts.AccessTokenResponse, error)
	GetRoleToken(domain zts.DomainName, roles zts.EntityList, minExpiryTime *int32, maxExpiryTime *int32, proxyForPrincipal zts.EntityName) (*zts.RoleToken, error)
	SetTransport(transport *http.Transport)
	Transport() *http.Transport
	URL() string
	SetURL(url string)
}

type ztsClientWrapper struct {
	realClient zts.ZTSClient
}

func newZTSClient(url, pem, key string) ZTSClientInterface {
	tc, _ := createTLSConfig(pem, key)
	tp := &http.Transport{
		IdleConnTimeout: 30 * time.Second,
		TLSClientConfig: tc,
	}
	real := zts.NewClient(url, tp)
	return &ztsClientWrapper{realClient: real}
}

func (z *ztsClientWrapper) PostAccessTokenRequest(req zts.AccessTokenRequest) (*zts.AccessTokenResponse, error) {
	return z.realClient.PostAccessTokenRequest(req)
}

func (z *ztsClientWrapper) GetRoleToken(domain zts.DomainName, roles zts.EntityList, minExpiryTime *int32, maxExpiryTime *int32, proxyForPrincipal zts.EntityName) (*zts.RoleToken, error) {
	return z.realClient.GetRoleToken(domain, roles, minExpiryTime, maxExpiryTime, proxyForPrincipal)
}

func (z *ztsClientWrapper) SetTransport(t *http.Transport) {
	z.realClient.Transport = t
}

func (z *ztsClientWrapper) Transport() *http.Transport {
	if t, ok := z.realClient.Transport.(*http.Transport); ok {
		return t
	}
	return nil
}

func (z *ztsClientWrapper) URL() string {
	return z.realClient.URL
}

func (z *ztsClientWrapper) SetURL(url string) {
	z.realClient.URL = url
}
