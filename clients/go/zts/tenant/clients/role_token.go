package clients

import (
	"context"
	"time"

	"github.com/AthenZ/athenz/clients/go/zts/tenant/token"
	"github.com/AthenZ/athenz/clients/go/zts"
)

type RoleTokenClient struct {
	*BaseTokenClient[*token.RoleToken]
}

func NewRoleTokenClient(ctx context.Context, url, pem, key string) (*RoleTokenClient, context.CancelFunc) {
	return NewRoleTokenClientSetCacheUpdateDuration(ctx, url, pem, key, 1*time.Hour)
}

func NewRoleTokenClientSetCacheUpdateDuration(ctx context.Context, url, pem, key string, dur time.Duration) (*RoleTokenClient, context.CancelFunc) {
	baseCli := newClientFunc(url, pem, key)
	rtGetter := func(domain string, roles string, exp int32) (*token.RoleToken, error) {
		res, err := baseCli.ZTS.GetRoleToken(zts.DomainName(domain), zts.EntityList(roles), &exp, nil, "")
		if err != nil {
			return nil, err
		}
		return &token.RoleToken{
			Token:      res.Token,
			ExpiryTime: res.ExpiryTime,
		}, nil
	}
	btc := &BaseTokenClient[*token.RoleToken]{
		Client:       baseCli,
		getTokenFunc: rtGetter,
	}
	rtClient := &RoleTokenClient{BaseTokenClient: btc}
	baseCli.Tok = rtClient
	cancel := baseCli.startBackgroundTasks(ctx, pem, key, dur)
	return rtClient, cancel
}
