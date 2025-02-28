package token

import (
	"context"
	"time"

	"github.com/AthenZ/athenz/clients/go/zts"
)

type RoleTokenClient struct {
	*BaseTokenClient[*RoleToken]
}

func NewRoleTokenClient(ctx context.Context, ztsUrl, pem, key string) (*RoleTokenClient, context.CancelFunc) {
	return NewRoleTokenClientSetCacheUpdateDuration(ctx, ztsUrl, pem, key, 10*time.Minute)
}

func NewRoleTokenClientSetCacheUpdateDuration(ctx context.Context, ztsUrl, pem, key string, cacheRefreshDuration time.Duration) (*RoleTokenClient, context.CancelFunc) {
	baseCli := newClientFunc(ztsUrl, pem, key)
	rtGetter := func(domain string, roles string, exp int32) (*RoleToken, error) {
		res, err := baseCli.ZTS.GetRoleToken(zts.DomainName(domain), zts.EntityList(roles), &exp, nil, "")
		if err != nil {
			return nil, err
		}

		dur := time.Until(time.Unix(res.ExpiryTime, 0))
		return &RoleToken{
			Token:      res,
			ExpiryTime: res.ExpiryTime,
			Duration:   dur,
		}, nil
	}
	btc := &BaseTokenClient[*RoleToken]{
		Client:       baseCli,
		getTokenFunc: rtGetter,
	}
	rtClient := &RoleTokenClient{BaseTokenClient: btc}
	baseCli.Tok = rtClient
	cancel := baseCli.startBackgroundTasks(ctx, pem, key, cacheRefreshDuration)
	return rtClient, cancel
}
