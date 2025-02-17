package clients

import (
	"context"
	"fmt"
	"net/url"
	"strings"
	"time"

	"github.com/AthenZ/athenz/clients/go/zts/tenant/token"
	"github.com/AthenZ/athenz/clients/go/zts"
)

type AccessTokenClient struct {
	*BaseTokenClient[*token.AccessToken]
}

func NewAccessTokenClient(ctx context.Context, ztsUrl, pem, key string) (*AccessTokenClient, context.CancelFunc) {
	return NewAccessTokenClientSetCacheUpdateDuration(ctx, ztsUrl, pem, key, 1*time.Hour)
}

func NewAccessTokenClientSetCacheUpdateDuration(ctx context.Context, ztsUrl, pem, key string, dur time.Duration) (*AccessTokenClient, context.CancelFunc) {
	baseCli := newClientFunc(ztsUrl, pem, key)
	accGetter := func(domain string, roles string, exp int32) (*token.AccessToken, error) {
		req := zts.AccessTokenRequest(makeTokenRequest(domain, strings.Split(roles, ","), int(exp), ""))
		res, err := baseCli.ZTS.PostAccessTokenRequest(req)
		if err != nil {
			return nil, err
		}
		expiryTime := time.Now().Unix() + int64(*res.Expires_in)
		return &token.AccessToken{
			Token:      res.Access_token,
			ExpiryTime: expiryTime,
		}, nil
	}
	btc := &BaseTokenClient[*token.AccessToken]{
		Client:       baseCli,
		getTokenFunc: accGetter,
	}
	accClient := &AccessTokenClient{BaseTokenClient: btc}
	baseCli.Tok = accClient
	cancel := baseCli.startBackgroundTasks(ctx, pem, key, dur)
	return accClient, cancel
}

func makeTokenRequest(domain string, roles []string, expiryTime int, proxyPrincipalSpiffeUris string) string {
	params := url.Values{}
	params.Add("grant_type", "client_credentials")
	params.Add("expires_in", fmt.Sprintf("%d", expiryTime))
	if proxyPrincipalSpiffeUris != "" {
		params.Add("proxy_principal_spiffe_uris", proxyPrincipalSpiffeUris)
	}
	var scope string
	if roles[0] == "*" || roles[0] == "" {
		scope = domain + ":domain"
	} else {
		for idx, role := range roles {
			if idx != 0 {
				scope += " "
			}
			scope += domain + ":role." + role
		}
	}
	params.Add("scope", scope)
	return params.Encode()
}
