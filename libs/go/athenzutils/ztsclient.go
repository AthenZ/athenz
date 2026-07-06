// Copyright The Athenz Authors
// Licensed under the terms of the Apache version 2.0 license. See LICENSE file for terms.

package athenzutils

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/AthenZ/athenz/clients/go/zts"
	"github.com/AthenZ/athenz/libs/go/tls/config"
	"golang.org/x/sync/singleflight"
)

// ZtsClient creates and returns a ZTS client instance.
func ZtsClient(ztsURL, keyFile, certFile, caCertFile string, proxy bool) (*zts.ZTSClient, error) {
	keypem, err := os.ReadFile(keyFile)
	if err != nil {
		return nil, err
	}
	certpem, err := os.ReadFile(certFile)
	if err != nil {
		return nil, err
	}
	var cacertpem []byte
	if caCertFile != "" {
		cacertpem, err = os.ReadFile(caCertFile)
		if err != nil {
			return nil, err
		}
	}
	config, err := config.ClientTLSConfigFromPEM(keypem, certpem, cacertpem)
	if err != nil {
		return nil, err
	}
	tr := &http.Transport{
		TLSClientConfig: config,
	}
	if proxy {
		tr.Proxy = http.ProxyFromEnvironment
	}
	client := zts.NewClient(ztsURL, tr)
	return &client, nil
}

// GenerateAccessTokenRequestString generates and urlencodes an access token string.
func GenerateAccessTokenRequestString(domain, service, roles, authzDetails, proxyPrincipalSpiffeUris, proxyForPrincipal string, expiryTime int) string {

	params := url.Values{}
	params.Add("grant_type", "client_credentials")
	// do not include the expiry param if the client is asking
	// for the server default setting (expiryTime == 0) or any
	// invalid values (expiryTime < 0)
	if expiryTime > 0 {
		params.Add("expires_in", strconv.Itoa(expiryTime))
	}

	var scope string
	if roles == "" {
		scope = domain + ":domain"
	} else {
		roleList := strings.Split(roles, ",")
		for idx, role := range roleList {
			if idx != 0 {
				scope += " "
			}
			scope += domain + ":role." + role
		}
	}
	if service != "" {
		scope += " openid " + domain + ":service." + service
	}

	params.Add("scope", scope)
	if authzDetails != "" {
		params.Add("authorization_details", authzDetails)
	}
	if proxyPrincipalSpiffeUris != "" {
		params.Add("proxy_principal_spiffe_uris", proxyPrincipalSpiffeUris)
	}
	if proxyForPrincipal != "" {
		params.Add("proxy_for_principal", proxyForPrincipal)
	}
	return params.Encode()
}

// ztsTokenFetcher is the minimal ZTS interface required by AccessTokenCache.
// The production implementation is *zts.ZTSClient; tests use a mock.
type ztsTokenFetcher interface {
	PostAccessTokenRequest(request zts.AccessTokenRequest) (*zts.AccessTokenResponse, error)
}

// accessTokenEntry is a single cached access token together with all the
// metadata needed to validate freshness and to re-fetch during background
// refresh.
type accessTokenEntry struct {
	response     *zts.AccessTokenResponse
	expiresAt    int64 // absolute unix seconds: now + expires_in at the time of fetch
	serverExpiry int64 // original expires_in returned by ZTS, used when caller passes 0
	// original request parameters, stored so the background refresh can re-issue
	// the exact same request without the caller being involved.
	domain      string
	service     string
	roles       string
	authz       string
	proxySpiffe string
	proxyFor    string
	expiryTime  int
}

// hasMinLifetime reports whether the cached token still has at least 1/4 of
// its original lifetime remaining.  This mirrors the Java
// AccessTokenResponseCacheEntry.isExpired logic:
//
//	return (expiresAt < now + expirySeconds/4)  →  invalid
//
// When expirySeconds is 0 the server-issued expiry is used as the reference.
func (e *accessTokenEntry) hasMinLifetime(expirySeconds int) bool {
	ref := int64(expirySeconds)
	if ref <= 0 {
		ref = e.serverExpiry
	}
	return (e.expiresAt - time.Now().Unix()) >= ref/4
}

// AccessTokenCache is a thread-safe, in-memory ZTS access token cache with
// automatic background refresh.  It is the primary recommended way for Go
// services to obtain access tokens; it replaces direct ad-hoc calls to
// PostAccessTokenRequest.
//
// Concurrency model:
//   - All public methods are safe for concurrent use.
//   - A read/write mutex protects the entries map; reads are lock-free on
//     the fast (cache-hit) path.
//   - A singleflight.Group collapses concurrent cache-miss fetches for the
//     same token so that exactly one network call is in-flight per unique
//     (domain, roles, …) key at any moment, preventing the thundering-herd
//     problem on cold starts or simultaneous cache expiry.
type AccessTokenCache struct {
	mu      sync.RWMutex
	entries map[string]*accessTokenEntry
	fetcher ztsTokenFetcher
	group   singleflight.Group
	cancel  context.CancelFunc
}

// NewAccessTokenCache creates an AccessTokenCache backed by a real ZTS client
// and starts a background goroutine that proactively refreshes every cached
// token on the given interval.  A typical value is 10*time.Minute.
//
// Call Stop() when the cache is no longer needed to release the background
// goroutine.
func NewAccessTokenCache(ctx context.Context, ztsURL, keyFile, certFile, caCertFile string, proxy bool, refreshInterval time.Duration) (*AccessTokenCache, error) {
	ztsClient, err := ZtsClient(ztsURL, keyFile, certFile, caCertFile, proxy)
	if err != nil {
		return nil, err
	}
	return newAccessTokenCacheWithFetcher(ctx, ztsClient, refreshInterval), nil
}

// newAccessTokenCacheWithFetcher is the internal constructor used by tests.
func newAccessTokenCacheWithFetcher(ctx context.Context, fetcher ztsTokenFetcher, refreshInterval time.Duration) *AccessTokenCache {
	if ctx == nil {
		ctx = context.Background()
	}
	ctx, cancel := context.WithCancel(ctx)
	c := &AccessTokenCache{
		entries: make(map[string]*accessTokenEntry),
		fetcher: fetcher,
		cancel:  cancel,
	}
	if refreshInterval > 0 {
		go c.refreshLoop(ctx, refreshInterval)
	}
	return c
}

// GetAccessToken returns an access token for the given parameters.
//
// On a cache hit where the token still has at least 1/4 of its lifetime
// remaining the cached token is returned without any network call.
//
// On a cache miss (or when the cached token is close to expiry) the method
// calls ZTS.  Concurrent callers for the same key are collapsed: only one
// network call is made and all callers receive the same result.
//
// If the ZTS call fails but a (possibly stale) token exists in the cache it
// is returned silently, matching the Java client's fallback behaviour.  An
// error is returned only when there is no usable token at all.
//
// The parameter list intentionally mirrors GenerateAccessTokenRequestString to
// make migration straightforward.
func (c *AccessTokenCache) GetAccessToken(domain, service, roles, authzDetails, proxyPrincipalSpiffeUris, proxyForPrincipal string, expiryTime int) (*zts.AccessTokenResponse, error) {
	key := tokenCacheKey(domain, service, roles, authzDetails, proxyPrincipalSpiffeUris, proxyForPrincipal, expiryTime)

	// Fast path: cache hit with sufficient remaining lifetime.
	c.mu.RLock()
	entry, ok := c.entries[key]
	c.mu.RUnlock()
	if ok && entry.hasMinLifetime(expiryTime) {
		return entry.response, nil
	}

	// Slow path: fetch from ZTS, deduplicated per key so that N concurrent
	// callers all waiting on the same missing/expiring token result in exactly
	// one outbound request.
	type sfResult struct {
		entry *accessTokenEntry
	}
	v, err, _ := c.group.Do(key, func() (interface{}, error) {
		request := GenerateAccessTokenRequestString(domain, service, roles, authzDetails, proxyPrincipalSpiffeUris, proxyForPrincipal, expiryTime)
		resp, fetchErr := c.fetcher.PostAccessTokenRequest(zts.AccessTokenRequest(request))
		if fetchErr != nil {
			// Fall back to a stale cached entry if one exists (Java parity).
			c.mu.RLock()
			stale, exists := c.entries[key]
			c.mu.RUnlock()
			if exists {
				return sfResult{entry: stale}, nil
			}
			return nil, fetchErr
		}
		if resp == nil || resp.Expires_in == nil {
			return nil, fmt.Errorf("athenzutils: ZTS response is nil or missing expires_in for domain %q", domain)
		}
		e := &accessTokenEntry{
			response:     resp,
			expiresAt:    time.Now().Unix() + int64(*resp.Expires_in),
			serverExpiry: int64(*resp.Expires_in),
			domain:       domain,
			service:      service,
			roles:        roles,
			authz:        authzDetails,
			proxySpiffe:  proxyPrincipalSpiffeUris,
			proxyFor:     proxyForPrincipal,
			expiryTime:   expiryTime,
		}
		c.mu.Lock()
		if current, exists := c.entries[key]; !exists || e.expiresAt > current.expiresAt {
			c.entries[key] = e
		}
		c.mu.Unlock()
		return sfResult{entry: e}, nil
	})
	if err != nil {
		return nil, err
	}
	return v.(sfResult).entry.response, nil
}

// Stop cancels the background refresh goroutine.  It is safe to call Stop
// more than once.
func (c *AccessTokenCache) Stop() {
	c.cancel()
}

// refreshLoop runs in a background goroutine and proactively refreshes every
// cached token on each tick of the interval.  Keeping cached tokens fresh
// before they reach the 1/4-lifetime threshold avoids thundering-herd on
// expiry under high concurrency.
func (c *AccessTokenCache) refreshLoop(ctx context.Context, interval time.Duration) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			c.refreshAll()
		}
	}
}

// refreshAll re-fetches every entry currently in the cache.  On ZTS failure
// the stale entry is left in place; it is never evicted by the background
// refresh (the caller's GetAccessToken will still return it as a fallback).
func (c *AccessTokenCache) refreshAll() {
	c.mu.RLock()
	snapshot := make([]*accessTokenEntry, 0, len(c.entries))
	for _, e := range c.entries {
		snapshot = append(snapshot, e)
	}
	c.mu.RUnlock()

	for _, e := range snapshot {
		request := GenerateAccessTokenRequestString(e.domain, e.service, e.roles, e.authz, e.proxySpiffe, e.proxyFor, e.expiryTime)
		resp, err := c.fetcher.PostAccessTokenRequest(zts.AccessTokenRequest(request))
		if err != nil || resp == nil || resp.Expires_in == nil {
			// Keep stale entry; do not evict on refresh failure.
			continue
		}
		updated := &accessTokenEntry{
			response:     resp,
			expiresAt:    time.Now().Unix() + int64(*resp.Expires_in),
			serverExpiry: int64(*resp.Expires_in),
			domain:       e.domain,
			service:      e.service,
			roles:        e.roles,
			authz:        e.authz,
			proxySpiffe:  e.proxySpiffe,
			proxyFor:     e.proxyFor,
			expiryTime:   e.expiryTime,
		}
		key := tokenCacheKey(e.domain, e.service, e.roles, e.authz, e.proxySpiffe, e.proxyFor, e.expiryTime)
		c.mu.Lock()
		if current, exists := c.entries[key]; !exists || updated.expiresAt > current.expiresAt {
			c.entries[key] = updated
		}
		c.mu.Unlock()
	}
}

// tokenCacheKey builds a deterministic cache key from the token request
// parameters.  Roles are sorted so that ["b","a"] and ["a","b"] map to the
// same key.  Fields are separated by the NUL byte which cannot appear in any
// of the string parameters.
func tokenCacheKey(domain, service, roles, authzDetails, proxyPrincipalSpiffeUris, proxyForPrincipal string, expiryTime int) string {
	if roles != "" {
		parts := strings.Split(roles, ",")
		sort.Strings(parts)
		roles = strings.Join(parts, ",")
	}
	return fmt.Sprintf("%s\x00%s\x00%s\x00%s\x00%s\x00%s\x00%d",
		domain, service, roles, authzDetails, proxyPrincipalSpiffeUris, proxyForPrincipal, expiryTime)
}
