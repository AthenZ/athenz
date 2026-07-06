// Copyright The Athenz Authors
// Licensed under the terms of the Apache version 2.0 license. See LICENSE file for terms.

package athenzutils

import (
	"context"
	"fmt"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/AthenZ/athenz/clients/go/zts"
)

func TestGenerateAccessTokenRequestString(test *testing.T) {

	tests := []struct {
		name              string
		domain            string
		service           string
		roles             string
		authzDetails      string
		spiffeUris        string
		proxyForPrincipal string
		expiryTime        int
		body              string
	}{
		{"domain-only", "sports", "", "", "", "", "", 1200, "expires_in=1200&grant_type=client_credentials&scope=sports%3Adomain"},
		{"roles", "sports", "", "readers,writers", "", "", "", 1400, "expires_in=1400&grant_type=client_credentials&scope=sports%3Arole.readers+sports%3Arole.writers"},
		{"domain service", "sports", "api", "readers", "", "", "", 1600, "expires_in=1600&grant_type=client_credentials&scope=sports%3Arole.readers+openid+sports%3Aservice.api"},
		{"authz-details", "sports", "", "", "[{\"type\":\"msg-access\",\"uid\":101}]", "", "", 1800, "authorization_details=%5B%7B%22type%22%3A%22msg-access%22%2C%22uid%22%3A101%7D%5D&expires_in=1800&grant_type=client_credentials&scope=sports%3Adomain"},
		{"spiffe-uri", "sports", "", "reader", "", "spiffe://athenz/sa/api", "", 2000, "expires_in=2000&grant_type=client_credentials&proxy_principal_spiffe_uris=spiffe%3A%2F%2Fathenz%2Fsa%2Fapi&scope=sports%3Arole.reader"},
		{"proxy-for-principal", "sports", "", "reader", "", "", "principal", 3000, "expires_in=3000&grant_type=client_credentials&proxy_for_principal=principal&scope=sports%3Arole.reader"},
	}
	for _, tt := range tests {
		test.Run(tt.name, func(t *testing.T) {
			body := GenerateAccessTokenRequestString(tt.domain, tt.service, tt.roles, tt.authzDetails, tt.spiffeUris, tt.proxyForPrincipal, tt.expiryTime)
			if body != tt.body {
				test.Errorf("invalid body response %s vs %s", body, tt.body)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// mockFetcher – a thread-safe fake ZTS client for unit tests.
// ---------------------------------------------------------------------------

type mockFetcher struct {
	mu        sync.Mutex
	callCount int32 // accessed atomically
	response  *zts.AccessTokenResponse
	err       error
	delay     time.Duration // optional artificial latency to widen race windows
}

func (m *mockFetcher) PostAccessTokenRequest(_ zts.AccessTokenRequest) (*zts.AccessTokenResponse, error) {
	if m.delay > 0 {
		time.Sleep(m.delay)
	}
	atomic.AddInt32(&m.callCount, 1)
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.response, m.err
}

func (m *mockFetcher) calls() int {
	return int(atomic.LoadInt32(&m.callCount))
}

func (m *mockFetcher) setResponse(resp *zts.AccessTokenResponse, err error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.response = resp
	m.err = err
}

// newTestResponse is a convenience builder for test token responses.
func newTestResponse(token string, expiresIn int32) *zts.AccessTokenResponse {
	return &zts.AccessTokenResponse{
		Access_token: token,
		Expires_in:   &expiresIn,
	}
}

// ---------------------------------------------------------------------------
// tokenCacheKey unit tests
// ---------------------------------------------------------------------------

func TestTokenCacheKey_RoleOrdering(t *testing.T) {
	k1 := tokenCacheKey("domain", "", "b,a", "", "", "", 0)
	k2 := tokenCacheKey("domain", "", "a,b", "", "", "", 0)
	if k1 != k2 {
		t.Errorf("expected same key for roles in different order, got %q vs %q", k1, k2)
	}
}

func TestTokenCacheKey_Uniqueness(t *testing.T) {
	cases := []struct {
		domain, service, roles, authz, spiffe, proxy string
		exp                                          int
	}{
		{"d1", "", "r1", "", "", "", 0},
		{"d2", "", "r1", "", "", "", 0},    // different domain
		{"d1", "svc", "r1", "", "", "", 0}, // with service
		{"d1", "", "r2", "", "", "", 0},    // different role
		{"d1", "", "r1", "az", "", "", 0},  // with authz
		{"d1", "", "r1", "", "sp", "", 0},  // with spiffe
		{"d1", "", "r1", "", "", "pp", 0},  // with proxy
		{"d1", "", "r1", "", "", "", 900},  // with expiry
	}
	seen := map[string]int{}
	for i, c := range cases {
		k := tokenCacheKey(c.domain, c.service, c.roles, c.authz, c.spiffe, c.proxy, c.exp)
		if prev, dup := seen[k]; dup {
			t.Errorf("case %d collides with case %d (key %q)", i, prev, k)
		}
		seen[k] = i
	}
}

// ---------------------------------------------------------------------------
// accessTokenEntry.hasMinLifetime unit tests
// ---------------------------------------------------------------------------

func TestHasMinLifetime_FreshToken(t *testing.T) {
	e := &accessTokenEntry{
		expiresAt:    time.Now().Unix() + 3600,
		serverExpiry: 3600,
	}
	if !e.hasMinLifetime(3600) {
		t.Error("fresh token should be considered valid")
	}
}

func TestHasMinLifetime_LessThanQuarterRemaining(t *testing.T) {
	// 3600 / 4 = 900.  With only 800 seconds remaining the token should be
	// considered stale.
	e := &accessTokenEntry{
		expiresAt:    time.Now().Unix() + 800,
		serverExpiry: 3600,
	}
	if e.hasMinLifetime(3600) {
		t.Error("token with < 1/4 lifetime should be considered stale")
	}
}

func TestHasMinLifetime_ExactlyQuarterRemaining(t *testing.T) {
	// At exactly 1/4 remaining the token should be considered valid
	// (>= not >).
	e := &accessTokenEntry{
		expiresAt:    time.Now().Unix() + 900,
		serverExpiry: 3600,
	}
	if !e.hasMinLifetime(3600) {
		t.Error("token with exactly 1/4 lifetime remaining should be valid")
	}
}

func TestHasMinLifetime_ZeroExpiryUsesServerExpiry(t *testing.T) {
	e := &accessTokenEntry{
		expiresAt:    time.Now().Unix() + 3600,
		serverExpiry: 7200,
	}
	// Caller passes 0 → use serverExpiry (7200).  7200/4 = 1800.
	// Remaining = 3600, which is >= 1800, so valid.
	if !e.hasMinLifetime(0) {
		t.Error("token should be valid when remaining >= serverExpiry/4")
	}
}

// ---------------------------------------------------------------------------
// GetAccessToken – functional tests
// ---------------------------------------------------------------------------

func TestGetAccessToken_CacheMiss_FetchesFromZTS(t *testing.T) {
	fetcher := &mockFetcher{response: newTestResponse("tok-1", 3600)}
	c := newAccessTokenCacheWithFetcher(context.Background(), fetcher, time.Hour)
	defer c.Stop()

	resp, err := c.GetAccessToken("domain", "", "role1", "", "", "", 3600)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp.Access_token != "tok-1" {
		t.Errorf("expected tok-1, got %q", resp.Access_token)
	}
	if fetcher.calls() != 1 {
		t.Errorf("expected 1 ZTS call on cache miss, got %d", fetcher.calls())
	}
}

func TestGetAccessToken_CacheHit_NoZTSCall(t *testing.T) {
	fetcher := &mockFetcher{response: newTestResponse("tok-2", 3600)}
	c := newAccessTokenCacheWithFetcher(context.Background(), fetcher, time.Hour)
	defer c.Stop()

	for i := 0; i < 10; i++ {
		resp, err := c.GetAccessToken("domain", "", "role1", "", "", "", 3600)
		if err != nil {
			t.Fatalf("call %d: unexpected error: %v", i, err)
		}
		if resp.Access_token != "tok-2" {
			t.Errorf("call %d: expected tok-2, got %q", i, resp.Access_token)
		}
	}
	if fetcher.calls() != 1 {
		t.Errorf("expected exactly 1 ZTS call for 10 repeated requests, got %d", fetcher.calls())
	}
}

func TestGetAccessToken_StaleEntry_Refetches(t *testing.T) {
	// Populate cache with an entry that has < 1/4 lifetime remaining.
	fetcher := &mockFetcher{response: newTestResponse("tok-fresh", 3600)}
	c := newAccessTokenCacheWithFetcher(context.Background(), fetcher, time.Hour)
	defer c.Stop()

	key := tokenCacheKey("domain", "", "r1", "", "", "", 3600)
	c.mu.Lock()
	c.entries[key] = &accessTokenEntry{
		response:     newTestResponse("tok-stale", 3600),
		expiresAt:    time.Now().Unix() + 100, // only 100s left out of 3600 → < 1/4
		serverExpiry: 3600,
		domain:       "domain",
		roles:        "r1",
		expiryTime:   3600,
	}
	c.mu.Unlock()

	resp, err := c.GetAccessToken("domain", "", "r1", "", "", "", 3600)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp.Access_token != "tok-fresh" {
		t.Errorf("expected fresh token, got %q", resp.Access_token)
	}
	if fetcher.calls() != 1 {
		t.Errorf("expected 1 ZTS call to refresh stale entry, got %d", fetcher.calls())
	}
}

func TestGetAccessToken_ZTSError_FallbackToStaleCache(t *testing.T) {
	fetcher := &mockFetcher{err: fmt.Errorf("ZTS unavailable")}
	c := newAccessTokenCacheWithFetcher(context.Background(), fetcher, time.Hour)
	defer c.Stop()

	// Pre-populate cache with a stale-but-existing entry.
	key := tokenCacheKey("domain", "", "r1", "", "", "", 3600)
	c.mu.Lock()
	c.entries[key] = &accessTokenEntry{
		response:     newTestResponse("tok-stale", 3600),
		expiresAt:    time.Now().Unix() + 100,
		serverExpiry: 3600,
		domain:       "domain",
		roles:        "r1",
		expiryTime:   3600,
	}
	c.mu.Unlock()

	// ZTS fails, but we have a stale entry → return it without error (Java parity).
	resp, err := c.GetAccessToken("domain", "", "r1", "", "", "", 3600)
	if err != nil {
		t.Errorf("expected nil error on stale fallback, got %v", err)
	}
	if resp == nil || resp.Access_token != "tok-stale" {
		t.Errorf("expected stale token, got %v", resp)
	}
}

func TestGetAccessToken_ZTSError_NoCacheFallback_ReturnsError(t *testing.T) {
	fetcher := &mockFetcher{err: fmt.Errorf("ZTS unavailable")}
	c := newAccessTokenCacheWithFetcher(context.Background(), fetcher, time.Hour)
	defer c.Stop()

	_, err := c.GetAccessToken("domain", "", "r1", "", "", "", 3600)
	if err == nil {
		t.Error("expected error when ZTS fails with empty cache")
	}
}

func TestGetAccessToken_NilExpiresIn_ReturnsError(t *testing.T) {
	fetcher := &mockFetcher{response: &zts.AccessTokenResponse{Access_token: "tok"}} // Expires_in is nil
	c := newAccessTokenCacheWithFetcher(context.Background(), fetcher, time.Hour)
	defer c.Stop()

	_, err := c.GetAccessToken("domain", "", "r1", "", "", "", 3600)
	if err == nil {
		t.Error("expected error for response with nil Expires_in")
	}
}

func TestGetAccessToken_NilResponse_ReturnsError(t *testing.T) {
	fetcher := &mockFetcher{response: nil, err: nil} // nil response, nil error
	c := newAccessTokenCacheWithFetcher(context.Background(), fetcher, time.Hour)
	defer c.Stop()

	_, err := c.GetAccessToken("domain", "", "r1", "", "", "", 3600)
	if err == nil {
		t.Error("expected error for nil ZTS response with nil error")
	}
}

func TestNewAccessTokenCacheWithFetcher_ZeroInterval_NoRefreshGoroutine(t *testing.T) {
	// refreshInterval <= 0 must not panic (time.NewTicker panics on <= 0).
	fetcher := &mockFetcher{response: newTestResponse("tok", 3600)}
	c := newAccessTokenCacheWithFetcher(context.Background(), fetcher, 0)
	defer c.Stop()

	resp, err := c.GetAccessToken("domain", "", "r1", "", "", "", 3600)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp.Access_token != "tok" {
		t.Errorf("expected tok, got %q", resp.Access_token)
	}
}

func TestGetAccessToken_DifferentParams_DifferentCacheEntries(t *testing.T) {
	var callCount int32
	fetcher := &mockFetcher{}
	fetcher.setResponse(newTestResponse("tok-domain1", 3600), nil)
	c := newAccessTokenCacheWithFetcher(context.Background(), fetcher, time.Hour)
	defer c.Stop()

	// Swap response for second domain.
	fetcher.mu.Lock()
	fetcher.response = newTestResponse("tok-domain2", 3600)
	fetcher.mu.Unlock()

	// Cold cache for domain1.
	atomic.StoreInt32(&callCount, 0)
	fetcher.mu.Lock()
	fetcher.response = newTestResponse("tok-d1", 3600)
	fetcher.mu.Unlock()
	resp1, _ := c.GetAccessToken("domain1", "", "r1", "", "", "", 3600)

	fetcher.mu.Lock()
	fetcher.response = newTestResponse("tok-d2", 3600)
	fetcher.mu.Unlock()
	resp2, _ := c.GetAccessToken("domain2", "", "r1", "", "", "", 3600)

	if resp1.Access_token == resp2.Access_token {
		t.Errorf("expected different tokens for different domains, both got %q", resp1.Access_token)
	}
	if fetcher.calls() != 2 {
		t.Errorf("expected 2 ZTS calls for 2 distinct domains, got %d", fetcher.calls())
	}
}

func TestGetAccessToken_Stop_CancelsRefresh(t *testing.T) {
	fetcher := &mockFetcher{response: newTestResponse("tok", 3600)}
	c := newAccessTokenCacheWithFetcher(context.Background(), fetcher, 50*time.Millisecond)

	// Populate the cache.
	_, err := c.GetAccessToken("domain", "", "r1", "", "", "", 3600)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	callsBeforeStop := fetcher.calls()

	// Stop the cache.
	c.Stop()

	// Allow time for any in-flight tick to complete.
	time.Sleep(150 * time.Millisecond)
	callsAfterStop := fetcher.calls()

	// After Stop, no further background calls should happen.
	time.Sleep(200 * time.Millisecond)
	callsLater := fetcher.calls()

	if callsLater > callsAfterStop {
		t.Errorf("background refresh continued after Stop: before=%d, afterStop=%d, later=%d",
			callsBeforeStop, callsAfterStop, callsLater)
	}
}

// ---------------------------------------------------------------------------
// Background refresh test
// ---------------------------------------------------------------------------

func TestGetAccessToken_BackgroundRefresh_UpdatesCache(t *testing.T) {
	fetcher := &mockFetcher{response: newTestResponse("tok-v1", 3600)}
	c := newAccessTokenCacheWithFetcher(context.Background(), fetcher, 50*time.Millisecond)
	defer c.Stop()

	// Prime the cache.
	resp, err := c.GetAccessToken("domain", "", "r1", "", "", "", 3600)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp.Access_token != "tok-v1" {
		t.Fatalf("expected tok-v1, got %q", resp.Access_token)
	}

	// Update the mock response to simulate ZTS issuing a new token.
	// Use a longer expiry (7200) so expiresAt is strictly later than the
	// original entry, satisfying the "only overwrite if newer" guard.
	fetcher.setResponse(newTestResponse("tok-v2", 7200), nil)

	// Wait for at least one refresh tick to fire.
	time.Sleep(200 * time.Millisecond)

	// The background refresh should have overwritten the cache entry.
	c.mu.RLock()
	key := tokenCacheKey("domain", "", "r1", "", "", "", 3600)
	entry := c.entries[key]
	c.mu.RUnlock()

	if entry == nil {
		t.Fatal("cache entry missing after refresh")
	}
	if entry.response.Access_token != "tok-v2" {
		t.Errorf("expected tok-v2 after refresh, got %q", entry.response.Access_token)
	}
}

// ---------------------------------------------------------------------------
// Concurrency – thundering herd / singleflight
// ---------------------------------------------------------------------------

func TestAccessTokenCache_Singleflight_ThunderingHerd(t *testing.T) {
	// With an artificial delay, many goroutines will all pile up on a cold
	// cache simultaneously.  The singleflight must ensure only one ZTS call
	// is made regardless.
	fetcher := &mockFetcher{
		response: newTestResponse("tok-sf", 3600),
		delay:    50 * time.Millisecond,
	}
	c := newAccessTokenCacheWithFetcher(context.Background(), fetcher, time.Hour)
	defer c.Stop()

	const goroutines = 50
	var wg sync.WaitGroup
	tokens := make([]string, goroutines)
	errs := make([]error, goroutines)

	wg.Add(goroutines)
	for i := 0; i < goroutines; i++ {
		go func(i int) {
			defer wg.Done()
			resp, err := c.GetAccessToken("domain", "", "r1", "", "", "", 3600)
			errs[i] = err
			if resp != nil {
				tokens[i] = resp.Access_token
			}
		}(i)
	}
	wg.Wait()

	// Exactly one ZTS call should have been made.
	if got := fetcher.calls(); got != 1 {
		t.Errorf("singleflight: expected 1 ZTS call for %d concurrent goroutines, got %d", goroutines, got)
	}

	// All goroutines must have received the same token without error.
	for i := 0; i < goroutines; i++ {
		if errs[i] != nil {
			t.Errorf("goroutine %d: unexpected error: %v", i, errs[i])
		}
		if tokens[i] != "tok-sf" {
			t.Errorf("goroutine %d: expected tok-sf, got %q", i, tokens[i])
		}
	}
}

// ---------------------------------------------------------------------------
// Concurrency – race detector
// ---------------------------------------------------------------------------

// TestAccessTokenCache_ConcurrentAccess exercises the cache under high
// concurrent load against multiple distinct keys.  Run with -race to verify
// there are no data races.
func TestAccessTokenCache_ConcurrentAccess(t *testing.T) {
	fetcher := &mockFetcher{response: newTestResponse("tok", 3600)}
	c := newAccessTokenCacheWithFetcher(context.Background(), fetcher, 20*time.Millisecond)
	defer c.Stop()

	const (
		goroutines      = 100
		requestsEach    = 20
		distinctDomains = 5
	)

	var wg sync.WaitGroup
	wg.Add(goroutines)
	for i := 0; i < goroutines; i++ {
		go func(i int) {
			defer wg.Done()
			domain := fmt.Sprintf("domain-%d", i%distinctDomains)
			for j := 0; j < requestsEach; j++ {
				resp, err := c.GetAccessToken(domain, "", "r1", "", "", "", 3600)
				if err != nil {
					t.Errorf("goroutine %d request %d: unexpected error: %v", i, j, err)
					return
				}
				if resp == nil {
					t.Errorf("goroutine %d request %d: nil response", i, j)
					return
				}
			}
		}(i)
	}
	wg.Wait()
}

// TestAccessTokenCache_ConcurrentReadWrite exercises concurrent reads and
// writes (cache-miss writes, background refresh writes, and reads) to verify
// there are no mutex deadlocks or data races.
func TestAccessTokenCache_ConcurrentReadWrite(t *testing.T) {
	fetcher := &mockFetcher{response: newTestResponse("tok", 3600)}
	// Short refresh interval to maximise write/read interleaving.
	c := newAccessTokenCacheWithFetcher(context.Background(), fetcher, 10*time.Millisecond)
	defer c.Stop()

	var wg sync.WaitGroup
	const goroutines = 50
	wg.Add(goroutines)
	for i := 0; i < goroutines; i++ {
		go func(i int) {
			defer wg.Done()
			domain := fmt.Sprintf("d%d", i%3)
			for j := 0; j < 30; j++ {
				_, _ = c.GetAccessToken(domain, "", "r1", "", "", "", 3600)
			}
		}(i)
	}
	wg.Wait()
}

// TestAccessTokenCache_StopDuringConcurrentRequests verifies that calling
// Stop while requests are in flight does not cause a panic or deadlock.
func TestAccessTokenCache_StopDuringConcurrentRequests(t *testing.T) {
	fetcher := &mockFetcher{
		response: newTestResponse("tok", 3600),
		delay:    5 * time.Millisecond,
	}
	c := newAccessTokenCacheWithFetcher(context.Background(), fetcher, 10*time.Millisecond)

	var wg sync.WaitGroup
	const goroutines = 20
	wg.Add(goroutines)
	for i := 0; i < goroutines; i++ {
		go func(i int) {
			defer wg.Done()
			domain := fmt.Sprintf("d%d", i%4)
			for j := 0; j < 10; j++ {
				_, _ = c.GetAccessToken(domain, "", "r1", "", "", "", 3600)
			}
		}(i)
	}

	// Stop mid-flight.
	time.Sleep(20 * time.Millisecond)
	c.Stop()

	wg.Wait() // must not deadlock
}

// ---------------------------------------------------------------------------
// NewAccessTokenCache – constructor error path
// ---------------------------------------------------------------------------

func TestNewAccessTokenCache_MissingFiles(t *testing.T) {
	_, err := NewAccessTokenCache(
		context.Background(),
		"https://zts.example.com",
		"/nonexistent/key.pem",
		"/nonexistent/cert.pem",
		"",
		false,
		10*time.Minute,
	)
	if err == nil {
		t.Error("expected error for nonexistent key/cert files")
	}
}
