package clients

import (
	"context"
	"time"

	"github.com/AthenZ/athenz/clients/go/zts"
	"github.com/AthenZ/athenz/clients/go/zts/tenant/token"
)

type RoleTokenClient struct {
	*BaseTokenClient[*token.RoleToken]
}

func NewRoleTokenClient(ctx context.Context, url, pem, key string) (*RoleTokenClient, context.CancelFunc) {
	return NewRoleTokenClientSetCacheUpdateDuration(ctx, url, pem, key, 10*time.Minute)
}

func NewRoleTokenClientSetCacheUpdateDuration(ctx context.Context, url, pem, key string, cacheRefreshDuration time.Duration) (*RoleTokenClient, context.CancelFunc) {
	baseCli := newClientFunc(url, pem, key)
	rtGetter := func(domain string, roles string, exp int32) (*token.RoleToken, error) {
		res, err := baseCli.ZTS.GetRoleToken(zts.DomainName(domain), zts.EntityList(roles), &exp, nil, "")
		if err != nil {
			return nil, err
		}

		dur := time.Until(time.Unix(res.ExpiryTime, 0))
		return &token.RoleToken{
			Token:      res.Token,
			ExpiryTime: res.ExpiryTime,
			Duration:   dur,
		}, nil
	}
	btc := &BaseTokenClient[*token.RoleToken]{
		Client:       baseCli,
		getTokenFunc: rtGetter,
	}
	rtClient := &RoleTokenClient{BaseTokenClient: btc}
	baseCli.Tok = rtClient
	cancel := baseCli.startBackgroundTasks(ctx, pem, key, cacheRefreshDuration)
	return rtClient, cancel
}
