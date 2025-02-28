package token

import (
	"context"
	"fmt"
	"net/url"
	"strings"
	"time"

	"github.com/AthenZ/athenz/clients/go/zts"
)

type AccessTokenClient struct {
	*BaseTokenClient[*AccessToken]
}

func NewAccessTokenClient(ctx context.Context, ztsUrl, pem, key string) (*AccessTokenClient, context.CancelFunc) {
	return NewAccessTokenClientSetCacheUpdateDuration(ctx, ztsUrl, pem, key, 10*time.Minute)
}

func NewAccessTokenClientSetCacheUpdateDuration(ctx context.Context, ztsUrl, pem, key string, cacheRefreshDuration time.Duration) (*AccessTokenClient, context.CancelFunc) {
	baseCli := newClientFunc(ztsUrl, pem, key)
	accGetter := func(domain string, roles string, exp int32) (*AccessToken, error) {
		req := zts.AccessTokenRequest(makeTokenRequest(domain, strings.Split(roles, ","), int(exp), ""))
		res, err := baseCli.ZTS.PostAccessTokenRequest(req)
		if err != nil {
			return nil, err
		}
		expiryTime := time.Now().Unix() + int64(*res.Expires_in)
		dur := time.Until(time.Unix(expiryTime, 0))
		return &AccessToken{
			Token:      res,
			ExpiryTime: expiryTime,
			Duration:   dur,
		}, nil
	}
	btc := &BaseTokenClient[*AccessToken]{
		Client:       baseCli,
		getTokenFunc: accGetter,
	}
	accClient := &AccessTokenClient{BaseTokenClient: btc}
	baseCli.Tok = accClient
	cancel := baseCli.startBackgroundTasks(ctx, pem, key, cacheRefreshDuration)
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
