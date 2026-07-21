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
	"sync/atomic"
	"time"

	"github.com/AthenZ/athenz/clients/go/zts"
	"github.com/AthenZ/athenz/libs/go/tls/config"
	"golang.org/x/sync/singleflight"
)

const (
	// Seconds to serve a stale token after a ZTS failure before retrying.
	ztsFailureBackoffSeconds = 10

	// Max parallel ZTS calls during a background refresh cycle.
	refreshConcurrency = 10

	// Evict entries not used for one token lifetime.
	entryIdleLifetimeFactor = 1
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

// ztsTokenFetcher abstracts PostAccessTokenRequest for testing.
type ztsTokenFetcher interface {
	PostAccessTokenRequest(request zts.AccessTokenRequest) (*zts.AccessTokenResponse, error)
}

// accessTokenEntry holds a cached token and the metadata needed to refresh it.
type accessTokenEntry struct {
	response     *zts.AccessTokenResponse
	expiresAt    time.Time    // when the token expires (monotonic clock)
	serverExpiry int64        // expires_in from ZTS, used as reference when caller passes 0
	retryAfter   atomic.Int64 // unix seconds: don't retry ZTS before this time after a failure
	lastUsed     atomic.Int64 // unix seconds: last successful serve to a caller
	// request params stored so the background refresh can re-issue the same call.
	domain      string
	service     string
	roles       string
	authz       string
	proxySpiffe string
	proxyFor    string
	expiryTime  int
}

// hasMinLifetime reports whether at least 1/4 of the token's lifetime remains.
// Mirrors Java's AccessTokenResponseCacheEntry. Falls back to serverExpiry when expirySeconds is 0.
func (e *accessTokenEntry) hasMinLifetime(expirySeconds int) bool {
	ref := int64(expirySeconds)
	if ref <= 0 {
		ref = e.serverExpiry
	}
	return time.Until(e.expiresAt) >= time.Duration(ref/4)*time.Second
}

// isServable returns true if the token can be served without calling ZTS:
// either it is still fresh, or we are within the failure backoff window.
func (e *accessTokenEntry) isServable(expirySeconds int) bool {
	return e.hasMinLifetime(expirySeconds) || time.Now().Unix() < e.retryAfter.Load()
}

func (e *accessTokenEntry) touch() {
	e.lastUsed.Store(time.Now().Unix())
}

func (e *accessTokenEntry) isIdle(now int64) bool {
	if e.serverExpiry <= 0 {
		return false
	}
	lastUsed := e.lastUsed.Load()
	if lastUsed <= 0 {
		return false
	}
	idleLimit := e.serverExpiry * entryIdleLifetimeFactor
	return (now - lastUsed) > idleLimit
}

// newEntryFromResponse builds an accessTokenEntry from a ZTS response.
func newEntryFromResponse(resp *zts.AccessTokenResponse, domain, service, roles, authz, proxySpiffe, proxyFor string, expiryTime int) *accessTokenEntry {
	now := time.Now()
	e := &accessTokenEntry{
		response:     resp,
		expiresAt:    now.Add(time.Duration(*resp.Expires_in) * time.Second),
		serverExpiry: int64(*resp.Expires_in),
		domain:       domain,
		service:      service,
		roles:        roles,
		authz:        authz,
		proxySpiffe:  proxySpiffe,
		proxyFor:     proxyFor,
		expiryTime:   expiryTime,
	}
	e.lastUsed.Store(now.Unix())
	return e
}

func copyResponse(resp *zts.AccessTokenResponse) *zts.AccessTokenResponse {
	if resp == nil {
		return nil
	}
	cp := *resp
	if resp.Expires_in != nil {
		val := *resp.Expires_in
		cp.Expires_in = &val
	}
	return &cp
}

// AccessTokenCache is a thread-safe in-memory ZTS access token cache with
// automatic background refresh and singleflight deduplication.
// All methods are safe for concurrent use. Call Stop() to release resources.
type AccessTokenCache struct {
	mu        sync.RWMutex
	entries   map[string]*accessTokenEntry
	fetcher   ztsTokenFetcher
	group     singleflight.Group
	cancel    context.CancelFunc
	tokenDir  string   // optional; empty means no disk fallback
	diskIndex sync.Map // diskCacheKey(domain, roles) -> absolute file path
}

// NewAccessTokenCache creates a cache backed by a real ZTS client.
// refreshInterval controls how often cached tokens are proactively refreshed (0 disables it).
// Call Stop() when done to release the background goroutine.
func NewAccessTokenCache(ctx context.Context, ztsURL, keyFile, certFile, caCertFile string, proxy bool, refreshInterval time.Duration) (*AccessTokenCache, error) {
	ztsClient, err := ZtsClient(ztsURL, keyFile, certFile, caCertFile, proxy)
	if err != nil {
		return nil, err
	}
	return newAccessTokenCacheWithFetcher(ctx, ztsClient, refreshInterval), nil
}

// newAccessTokenCacheWithFetcher is the internal constructor; tests pass a mock fetcher.
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

// GetAccessToken returns a cached token if still fresh, otherwise fetches from ZTS.
// Concurrent misses for the same key are collapsed into one ZTS call via singleflight.
// On ZTS failure, a stale token is returned if one exists (Java parity); error only when none.
// When ignoreCache is true, cache lookup and stale fallback are skipped.
// If omitted, ignoreCache defaults to false.
func (c *AccessTokenCache) GetAccessToken(domain, service, roles, authzDetails, proxyPrincipalSpiffeUris, proxyForPrincipal string, expiryTime int, ignoreCacheOpt ...bool) (*zts.AccessTokenResponse, error) {
	ignoreCache := len(ignoreCacheOpt) > 0 && ignoreCacheOpt[0]
	key := tokenCacheKey(domain, service, roles, authzDetails, proxyPrincipalSpiffeUris, proxyForPrincipal, expiryTime)

	// Fast path: token is fresh, or we are within the failure backoff window.
	if !ignoreCache {
		c.mu.RLock()
		entry, ok := c.entries[key]
		c.mu.RUnlock()
		if ok && entry.isServable(expiryTime) {
			entry.touch()
			return copyResponse(entry.response), nil
		}
	}

	// Slow path: deduplicated ZTS fetch — N concurrent misses result in one call.
	type sfResult struct {
		entry *accessTokenEntry
	}
	sfKey := key
	if ignoreCache {
		sfKey += "\x00ignoreCache"
	}
	v, err, _ := c.group.Do(sfKey, func() (interface{}, error) {
		// Check disk before calling ZTS. Disk entries are written by the SIA
		// agent and represent pre-provisioned tokens for this host identity.
		if c.tokenDir != "" {
			if diskEntry := c.readFromDisk(domain, splitRoleString(roles)); diskEntry != nil {
				// Populate request parameters so background refresh keeps
				// fetching the same token shape.
				diskEntry.service = service
				diskEntry.authz = authzDetails
				diskEntry.proxySpiffe = proxyPrincipalSpiffeUris
				diskEntry.proxyFor = proxyForPrincipal
				diskEntry.expiryTime = expiryTime
				c.mu.Lock()
				if cur, exists := c.entries[key]; !exists {
					c.entries[key] = diskEntry
				} else if cur.expiresAt.After(diskEntry.expiresAt) {
					if !ignoreCache {
						diskEntry = cur
					}
				} else {
					c.entries[key] = diskEntry
				}
				c.mu.Unlock()

				// Return immediately only if disk token satisfies caller's
				// freshness requirement. Otherwise keep it as stale fallback
				// and continue to ZTS fetch below.
				if diskEntry.hasMinLifetime(expiryTime) {
					diskEntry.touch()
					return sfResult{entry: diskEntry}, nil
				}
			}
		}

		request := GenerateAccessTokenRequestString(domain, service, roles, authzDetails, proxyPrincipalSpiffeUris, proxyForPrincipal, expiryTime)
		resp, fetchErr := c.fetcher.PostAccessTokenRequest(zts.AccessTokenRequest(request))
		if fetchErr != nil {
			// Return stale token if available and set backoff to avoid hammering ZTS.
			if !ignoreCache {
				c.mu.RLock()
				stale, exists := c.entries[key]
				c.mu.RUnlock()
				if exists {
					stale.retryAfter.Store(time.Now().Unix() + ztsFailureBackoffSeconds)
					stale.touch()
					return sfResult{entry: stale}, nil
				}
			}
			return nil, fetchErr
		}
		if resp == nil || resp.Access_token == "" || resp.Expires_in == nil || *resp.Expires_in <= 0 {
			// Invalid ZTS response is treated like a fetch failure: use stale
			// token if available, otherwise return an error.
			if !ignoreCache {
				c.mu.RLock()
				stale, exists := c.entries[key]
				c.mu.RUnlock()
				if exists {
					stale.retryAfter.Store(time.Now().Unix() + ztsFailureBackoffSeconds)
					stale.touch()
					return sfResult{entry: stale}, nil
				}
			}
			return nil, fmt.Errorf("athenzutils: ZTS returned an invalid response for domain %q", domain)
		}
		e := newEntryFromResponse(resp, domain, service, roles, authzDetails, proxyPrincipalSpiffeUris, proxyForPrincipal, expiryTime)
		c.mu.Lock()
		if current, exists := c.entries[key]; !exists {
			c.entries[key] = e
		} else if current.expiresAt.After(e.expiresAt) {
			if !ignoreCache && current.hasMinLifetime(expiryTime) {
				e = current
			}
		} else {
			c.entries[key] = e
		}
		c.mu.Unlock()
		return sfResult{entry: e}, nil
	})
	if err != nil {
		return nil, err
	}
	result := v.(sfResult).entry
	result.touch()
	return copyResponse(result.response), nil
}

// Stop cancels the background refresh goroutine. Safe to call multiple times.
func (c *AccessTokenCache) Stop() {
	c.cancel()
}

// refreshLoop ticks on interval and calls refreshAll each time.
func (c *AccessTokenCache) refreshLoop(ctx context.Context, interval time.Duration) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			c.refreshAll(ctx)
		}
	}
}

// refreshAll re-fetches all cached entries concurrently (up to refreshConcurrency at once).
// On failure, the stale entry is kept and retryAfter is set to suppress redundant ZTS calls.
func (c *AccessTokenCache) refreshAll(ctx context.Context) {
	type refreshTarget struct {
		key   string
		entry *accessTokenEntry
	}

	c.mu.RLock()
	snapshot := make([]refreshTarget, 0, len(c.entries))
	for k, e := range c.entries {
		snapshot = append(snapshot, refreshTarget{key: k, entry: e})
	}
	c.mu.RUnlock()

	var wg sync.WaitGroup
	sem := make(chan struct{}, refreshConcurrency)

	for _, t := range snapshot {
		wg.Add(1)
		go func(t refreshTarget) {
			defer wg.Done()
			select { // acquire semaphore slot or abort on cancellation
			case <-ctx.Done():
				return
			case sem <- struct{}{}:
			}
			defer func() { <-sem }()

			entry := t.entry
			if entry.isIdle(time.Now().Unix()) {
				c.mu.Lock()
				if current, exists := c.entries[t.key]; exists && current == entry {
					delete(c.entries, t.key)
				}
				c.mu.Unlock()
				return
			}
			request := GenerateAccessTokenRequestString(entry.domain, entry.service, entry.roles, entry.authz, entry.proxySpiffe, entry.proxyFor, entry.expiryTime)
			resp, err := c.fetcher.PostAccessTokenRequest(zts.AccessTokenRequest(request))
			if err != nil || resp == nil || resp.Access_token == "" || resp.Expires_in == nil || *resp.Expires_in <= 0 {
				// Keep stale entry; backoff prevents redundant ZTS calls.
				entry.retryAfter.Store(time.Now().Unix() + ztsFailureBackoffSeconds)
				return
			}
			updated := newEntryFromResponse(resp, entry.domain, entry.service, entry.roles, entry.authz, entry.proxySpiffe, entry.proxyFor, entry.expiryTime)
			updated.lastUsed.Store(entry.lastUsed.Load())
			c.mu.Lock()
			if current, exists := c.entries[t.key]; !exists || updated.expiresAt.After(current.expiresAt) {
				c.entries[t.key] = updated
			}
			c.mu.Unlock()
		}(t)
	}
	wg.Wait()
}

// tokenCacheKey returns a deterministic key for the given request params.
// Roles are sorted so ordering does not affect the key.
func tokenCacheKey(domain, service, roles, authzDetails, proxyPrincipalSpiffeUris, proxyForPrincipal string, expiryTime int) string {
	if roles != "" {
		parts := strings.Split(roles, ",")
		sort.Strings(parts)
		roles = strings.Join(parts, ",")
	}
	return fmt.Sprintf("%s\x00%s\x00%s\x00%s\x00%s\x00%s\x00%d",
		domain, service, roles, authzDetails, proxyPrincipalSpiffeUris, proxyForPrincipal, expiryTime)
}

// splitRoleString converts a comma-separated roles string (e.g. "reader,writer")
// into a slice. An empty string returns nil.
func splitRoleString(roles string) []string {
	if roles == "" {
		return nil
	}
	return strings.Split(roles, ",")
}
