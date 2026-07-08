// Copyright The Athenz Authors
// Licensed under the terms of the Apache version 2.0 license. See LICENSE file for terms.

package athenzutils

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/AthenZ/athenz/clients/go/zts"
	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
)

// ---------------------------------------------------------------------------
// JWT test helpers
// ---------------------------------------------------------------------------

var (
	testKeyOnce sync.Once
	testRSAKey  *rsa.PrivateKey
)

// sharedTestKey returns a single RSA key reused across all tests in this file
// to avoid the cost of key generation for every test case.
func sharedTestKey(t *testing.T) *rsa.PrivateKey {
	t.Helper()
	testKeyOnce.Do(func() {
		var err error
		testRSAKey, err = rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			t.Fatalf("failed to generate test RSA key: %v", err)
		}
	})
	return testRSAKey
}

// makeTestJWT creates a signed RS256 JWT with the given scope and expiry.
// The signature uses the shared test RSA key; the token is parsed without
// verification in production code so the specific key does not matter.
func makeTestJWT(t *testing.T, scope string, expireUnix int64) string {
	t.Helper()
	key := sharedTestKey(t)
	sig, err := jose.NewSigner(
		jose.SigningKey{Algorithm: jose.RS256, Key: key},
		(&jose.SignerOptions{}).WithType("JWT"),
	)
	if err != nil {
		t.Fatalf("NewSigner: %v", err)
	}

	now := time.Now()
	claims := jwt.Claims{
		IssuedAt: jwt.NewNumericDate(now),
		Expiry:   jwt.NewNumericDate(time.Unix(expireUnix, 0)),
	}
	// Mirror real Athenz JWTs: "scope" (string) + "scp" (array).
	scopeParts := strings.Fields(scope)
	scpArray := make([]interface{}, len(scopeParts))
	for i, p := range scopeParts {
		scpArray[i] = p
	}
	extra := map[string]interface{}{"scope": scope, "scp": scpArray}
	raw, err := jwt.Signed(sig).Claims(claims).Claims(extra).Serialize()
	if err != nil {
		t.Fatalf("jwt.Signed.Serialize: %v", err)
	}
	return raw
}

// writeDiskTokenFile creates <tokenDir>/<domain>/<filename> containing a
// JSON-marshalled AccessTokenResponse whose JWT has the specified scope and
// expiry.  Returns the absolute path.
func writeDiskTokenFile(t *testing.T, tokenDir, domain, filename, scope string, expiresInSec int32, expireUnix int64) string {
	t.Helper()
	dirPath := filepath.Join(tokenDir, domain)
	if err := os.MkdirAll(dirPath, 0755); err != nil {
		t.Fatalf("MkdirAll: %v", err)
	}
	jwtStr := makeTestJWT(t, scope, expireUnix)
	tokenType := "Bearer"
	resp := zts.AccessTokenResponse{
		Access_token: jwtStr,
		Token_type:   tokenType,
		Expires_in:   &expiresInSec,
	}
	data, err := json.Marshal(resp)
	if err != nil {
		t.Fatalf("json.Marshal: %v", err)
	}
	filePath := filepath.Join(dirPath, filename)
	if err := os.WriteFile(filePath, data, 0644); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	return filePath
}

// ---------------------------------------------------------------------------
// Unit tests for helper functions
// ---------------------------------------------------------------------------

func TestRolesFromScope(t *testing.T) {
	tests := []struct {
		name   string
		domain string
		scope  string
		want   []string
	}{
		// Full scoped format (domain:role.name)
		{"single role scoped", "sports", "sports:role.reader", []string{"reader"}},
		{"two roles scoped", "sports", "sports:role.reader sports:role.writer", []string{"reader", "writer"}},
		{"domain-wide scoped", "sports", "sports:domain", nil},
		{"with openid scoped", "sports", "sports:role.reader openid sports:service.api", []string{"reader"}},
		{"wrong domain prefix", "sports", "other:role.reader", nil},
		// Bare role name format (role name only, no domain prefix)
		{"single bare role", "sports", "reader", []string{"reader"}},
		{"two bare roles", "sports", "reader writer", []string{"reader", "writer"}},
		{"bare role with openid", "sports", "reader openid", []string{"reader"}},
		{"bare role with profile and email scopes", "sports", "reader profile email", []string{"reader"}},
		{"offline_access ignored", "sports", "reader offline_access", []string{"reader"}},
		{"duplicate scoped and bare role", "sports", "sports:role.reader reader sports:role.reader", []string{"reader"}},
		// Edge cases
		{"empty scope", "sports", "", nil},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := rolesFromScope(tt.domain, tt.scope)
			if len(got) != len(tt.want) {
				t.Fatalf("got %v, want %v", got, tt.want)
			}
			for i := range got {
				if got[i] != tt.want[i] {
					t.Errorf("got[%d]=%q, want %q", i, got[i], tt.want[i])
				}
			}
		})
	}
}

func TestReadFromDisk_InvalidExpiresIn_ReturnsNilAndKeepsIndex(t *testing.T) {
	dir := t.TempDir()
	expiry := time.Now().Add(2 * time.Hour).Unix()
	filePath := writeDiskTokenFile(t, dir, "sports", "token", "sports:role.reader", 3600, expiry)

	c := &AccessTokenCache{entries: make(map[string]*accessTokenEntry), tokenDir: dir}
	c.loadDiskIndex()

	// Corrupt only Expires_in after indexing.
	badResp := zts.AccessTokenResponse{
		Access_token: makeTestJWT(t, "sports:role.reader", expiry),
		Expires_in:   func() *int32 { v := int32(0); return &v }(),
	}
	data, err := json.Marshal(badResp)
	if err != nil {
		t.Fatalf("json.Marshal: %v", err)
	}
	if err := os.WriteFile(filePath, data, 0644); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	entry := c.readFromDisk("sports", []string{"reader"})
	if entry != nil {
		t.Error("expected nil for invalid expires_in")
	}
	if _, ok := c.diskIndex.Load(diskCacheKey("sports", []string{"reader"})); !ok {
		t.Error("expected disk index entry to be retained")
	}
}

func TestDiskCacheKey_Ordering(t *testing.T) {
	k1 := diskCacheKey("sports", []string{"reader", "writer"})
	k2 := diskCacheKey("sports", []string{"writer", "reader"})
	if k1 != k2 {
		t.Errorf("different orderings should produce the same key, got %q and %q", k1, k2)
	}
}

func TestDiskCacheKey_DomainIsolation(t *testing.T) {
	k1 := diskCacheKey("sports", []string{"reader"})
	k2 := diskCacheKey("finance", []string{"reader"})
	if k1 == k2 {
		t.Error("different domains should produce different keys")
	}
}

func TestScopeFromJWT_ScpStringClaim(t *testing.T) {
	key := sharedTestKey(t)
	sig, _ := jose.NewSigner(
		jose.SigningKey{Algorithm: jose.RS256, Key: key},
		(&jose.SignerOptions{}).WithType("JWT"),
	)
	claims := jwt.Claims{
		IssuedAt: jwt.NewNumericDate(time.Now()),
		Expiry:   jwt.NewNumericDate(time.Now().Add(time.Hour)),
	}
	// "scp" as a plain string (no "scope" present)
	extra := map[string]interface{}{"scp": "sports:role.admin"}
	raw, _ := jwt.Signed(sig).Claims(claims).Claims(extra).Serialize()

	scope, err := jwtScope(raw)
	if err != nil {
		t.Fatalf("jwtScope: %v", err)
	}
	if scope != "sports:role.admin" {
		t.Errorf("got %q, want %q", scope, "sports:role.admin")
	}
}

func TestScopeFromJWT_ScpArrayClaim(t *testing.T) {
	key := sharedTestKey(t)
	sig, _ := jose.NewSigner(
		jose.SigningKey{Algorithm: jose.RS256, Key: key},
		(&jose.SignerOptions{}).WithType("JWT"),
	)
	claims := jwt.Claims{
		IssuedAt: jwt.NewNumericDate(time.Now()),
		Expiry:   jwt.NewNumericDate(time.Now().Add(time.Hour)),
	}
	// "scp" as an array — this is what Athenz ZTS produces.
	extra := map[string]interface{}{"scp": []interface{}{"sports:role.reader", "sports:role.writer"}}
	raw, _ := jwt.Signed(sig).Claims(claims).Claims(extra).Serialize()

	scope, err := jwtScope(raw)
	if err != nil {
		t.Fatalf("jwtScope: %v", err)
	}
	roles := rolesFromScope("sports", scope)
	if len(roles) != 2 || roles[0] != "reader" || roles[1] != "writer" {
		t.Errorf("got roles %v, want [reader writer]", roles)
	}
}

func TestScopeFromJWT_ScopeStringPreferredOverScp(t *testing.T) {
	key := sharedTestKey(t)
	sig, _ := jose.NewSigner(
		jose.SigningKey{Algorithm: jose.RS256, Key: key},
		(&jose.SignerOptions{}).WithType("JWT"),
	)
	claims := jwt.Claims{
		IssuedAt: jwt.NewNumericDate(time.Now()),
		Expiry:   jwt.NewNumericDate(time.Now().Add(time.Hour)),
	}
	// Both "scope" (string) and "scp" (array) present — mirrors real Athenz JWTs.
	// "scope" should be preferred.
	extra := map[string]interface{}{
		"scope": "sports:role.reader sports:role.writer",
		"scp":   []interface{}{"sports:role.reader", "sports:role.writer"},
	}
	raw, _ := jwt.Signed(sig).Claims(claims).Claims(extra).Serialize()

	scope, err := jwtScope(raw)
	if err != nil {
		t.Fatalf("jwtScope: %v", err)
	}
	if scope != "sports:role.reader sports:role.writer" {
		t.Errorf("got %q, expected string form from 'scope' claim", scope)
	}
}

func TestScopeFromJWT_InvalidScopeTypeReturnsError(t *testing.T) {
	key := sharedTestKey(t)
	sig, _ := jose.NewSigner(
		jose.SigningKey{Algorithm: jose.RS256, Key: key},
		(&jose.SignerOptions{}).WithType("JWT"),
	)
	claims := jwt.Claims{
		IssuedAt: jwt.NewNumericDate(time.Now()),
		Expiry:   jwt.NewNumericDate(time.Now().Add(time.Hour)),
	}
	raw, _ := jwt.Signed(sig).Claims(claims).Claims(map[string]interface{}{"scope": 123}).Serialize()

	_, err := jwtScope(raw)
	if err == nil {
		t.Fatal("expected error for non-string scope claim")
	}
}

func TestScopeFromJWT_InvalidScpElementTypeReturnsError(t *testing.T) {
	key := sharedTestKey(t)
	sig, _ := jose.NewSigner(
		jose.SigningKey{Algorithm: jose.RS256, Key: key},
		(&jose.SignerOptions{}).WithType("JWT"),
	)
	claims := jwt.Claims{
		IssuedAt: jwt.NewNumericDate(time.Now()),
		Expiry:   jwt.NewNumericDate(time.Now().Add(time.Hour)),
	}
	raw, _ := jwt.Signed(sig).Claims(claims).Claims(map[string]interface{}{"scp": []interface{}{"sports:role.reader", 42}}).Serialize()

	_, err := jwtScope(raw)
	if err == nil {
		t.Fatal("expected error for non-string scp array element")
	}
}

func TestExpiryFromJWT(t *testing.T) {
	wantExpiry := time.Now().Add(time.Hour).Unix()
	jwtStr := makeTestJWT(t, "sports:role.reader", wantExpiry)
	got, err := jwtExpiry(jwtStr)
	if err != nil {
		t.Fatalf("jwtExpiry: %v", err)
	}
	if got != wantExpiry {
		t.Errorf("got %d, want %d", got, wantExpiry)
	}
}

func TestExtractRolesFromFile(t *testing.T) {
	dir := t.TempDir()
	scope := "sports:role.reader sports:role.writer"
	expiry := time.Now().Add(time.Hour).Unix()
	writeDiskTokenFile(t, dir, "sports", "token", scope, 3600, expiry)

	roles, err := rolesFromFile(filepath.Join(dir, "sports", "token"), "sports")
	if err != nil {
		t.Fatalf("rolesFromFile: %v", err)
	}
	got := strings.Join(roles, ",")
	// roles order from rolesFromScope preserves scope order
	if got != "reader,writer" {
		t.Errorf("got %q, want %q", got, "reader,writer")
	}
}

// ---------------------------------------------------------------------------
// loadDiskIndex tests
// ---------------------------------------------------------------------------

func TestLoadDiskIndex_PopulatesIndex(t *testing.T) {
	dir := t.TempDir()
	expiry := time.Now().Add(2 * time.Hour).Unix()
	writeDiskTokenFile(t, dir, "sports", "reader-token", "sports:role.reader", 3600, expiry)
	writeDiskTokenFile(t, dir, "sports", "writer-token", "sports:role.writer", 3600, expiry)
	writeDiskTokenFile(t, dir, "finance", "all-token", "finance:domain", 3600, expiry)

	c := &AccessTokenCache{
		entries:  make(map[string]*accessTokenEntry),
		tokenDir: dir,
	}
	c.loadDiskIndex()

	readerKey := diskCacheKey("sports", []string{"reader"})
	writerKey := diskCacheKey("sports", []string{"writer"})
	domainKey := diskCacheKey("finance", nil) // all-domain token has no roles

	if _, ok := c.diskIndex.Load(readerKey); !ok {
		t.Error("expected sports/reader to be indexed")
	}
	if _, ok := c.diskIndex.Load(writerKey); !ok {
		t.Error("expected sports/writer to be indexed")
	}
	if _, ok := c.diskIndex.Load(domainKey); !ok {
		t.Error("expected finance domain token to be indexed")
	}
}

func TestLoadDiskIndex_SkipsMissingDir(t *testing.T) {
	c := &AccessTokenCache{
		entries:  make(map[string]*accessTokenEntry),
		tokenDir: "/nonexistent/path",
	}
	// Should not panic; just logs a warning.
	c.loadDiskIndex()
}

func TestLoadDiskIndex_SkipsBadJSON(t *testing.T) {
	dir := t.TempDir()
	domainDir := filepath.Join(dir, "sports")
	_ = os.MkdirAll(domainDir, 0755)
	_ = os.WriteFile(filepath.Join(domainDir, "bad"), []byte("not json"), 0644)

	c := &AccessTokenCache{
		entries:  make(map[string]*accessTokenEntry),
		tokenDir: dir,
	}
	c.loadDiskIndex()

	// The bad file should be silently skipped; index should be empty.
	count := 0
	c.diskIndex.Range(func(_, _ interface{}) bool { count++; return true })
	if count != 0 {
		t.Errorf("expected empty index, got %d entries", count)
	}
}

func TestLoadDiskIndex_FollowsSymlinkedDomainDirectory(t *testing.T) {
	dir := t.TempDir()
	targetRoot := t.TempDir()

	expiry := time.Now().Add(2 * time.Hour).Unix()
	writeDiskTokenFile(t, targetRoot, "sports", "reader-token", "sports:role.reader", 3600, expiry)

	srcDomainDir := filepath.Join(targetRoot, "sports")
	linkDomainDir := filepath.Join(dir, "sports")
	if err := os.Symlink(srcDomainDir, linkDomainDir); err != nil {
		t.Fatalf("os.Symlink: %v", err)
	}

	c := &AccessTokenCache{
		entries:  make(map[string]*accessTokenEntry),
		tokenDir: dir,
	}
	c.loadDiskIndex()

	readerKey := diskCacheKey("sports", []string{"reader"})
	if _, ok := c.diskIndex.Load(readerKey); !ok {
		t.Fatal("expected symlinked sports domain directory to be indexed")
	}
}

// ---------------------------------------------------------------------------
// readFromDisk tests
// ---------------------------------------------------------------------------

func TestReadFromDisk_ReturnsValidEntry(t *testing.T) {
	dir := t.TempDir()
	expiry := time.Now().Add(2 * time.Hour).Unix()
	writeDiskTokenFile(t, dir, "sports", "token", "sports:role.reader", 3600, expiry)

	c := &AccessTokenCache{entries: make(map[string]*accessTokenEntry), tokenDir: dir}
	c.loadDiskIndex()

	entry := c.readFromDisk("sports", []string{"reader"})
	if entry == nil {
		t.Fatal("expected non-nil entry")
	}
	if entry.domain != "sports" {
		t.Errorf("domain = %q, want %q", entry.domain, "sports")
	}
	if entry.expiresAt.Unix() != expiry {
		t.Errorf("expiresAt = %d, want %d", entry.expiresAt.Unix(), expiry)
	}
}

func TestReadFromDisk_ExpiredToken_ReturnsNil(t *testing.T) {
	dir := t.TempDir()
	// Token expired 1 second ago.
	expiry := time.Now().Add(-time.Second).Unix()
	expiresIn := int32(3600)
	writeDiskTokenFile(t, dir, "sports", "token", "sports:role.reader", expiresIn, expiry)

	c := &AccessTokenCache{entries: make(map[string]*accessTokenEntry), tokenDir: dir}
	c.loadDiskIndex()

	entry := c.readFromDisk("sports", []string{"reader"})
	if entry != nil {
		t.Error("expected nil for expired token")
	}
	// Keep index entry so future SIA refreshes are still picked up.
	if _, ok := c.diskIndex.Load(diskCacheKey("sports", []string{"reader"})); !ok {
		t.Error("expected disk index entry to be retained")
	}
}

func TestReadFromDisk_NearExpiryToken_ReturnsEntry(t *testing.T) {
	dir := t.TempDir()
	// Less than 1/4 lifetime remaining but still unexpired.
	expiry := time.Now().Add(100 * time.Second).Unix()
	expiresIn := int32(3600)
	writeDiskTokenFile(t, dir, "sports", "token", "sports:role.reader", expiresIn, expiry)

	c := &AccessTokenCache{entries: make(map[string]*accessTokenEntry), tokenDir: dir}
	c.loadDiskIndex()

	entry := c.readFromDisk("sports", []string{"reader"})
	if entry == nil {
		t.Fatal("expected near-expiry but valid token to be returned")
	}
}

func TestReadFromDisk_NoMatchingKey_ReturnsNil(t *testing.T) {
	dir := t.TempDir()
	expiry := time.Now().Add(2 * time.Hour).Unix()
	writeDiskTokenFile(t, dir, "sports", "token", "sports:role.reader", 3600, expiry)

	c := &AccessTokenCache{entries: make(map[string]*accessTokenEntry), tokenDir: dir}
	c.loadDiskIndex()

	// Looking for "writer" but only "reader" is on disk.
	entry := c.readFromDisk("sports", []string{"writer"})
	if entry != nil {
		t.Error("expected nil when no matching disk file")
	}
}

func TestReadFromDisk_DeletedFileReturnsNil(t *testing.T) {
	dir := t.TempDir()
	expiry := time.Now().Add(2 * time.Hour).Unix()
	filePath := writeDiskTokenFile(t, dir, "sports", "token", "sports:role.reader", 3600, expiry)

	c := &AccessTokenCache{entries: make(map[string]*accessTokenEntry), tokenDir: dir}
	c.loadDiskIndex()

	// Delete the file after indexing.
	_ = os.Remove(filePath)

	entry := c.readFromDisk("sports", []string{"reader"})
	if entry != nil {
		t.Error("expected nil when file has been deleted")
	}
	// Keep index entry so a recreated file can be read later.
	if _, ok := c.diskIndex.Load(diskCacheKey("sports", []string{"reader"})); !ok {
		t.Error("expected disk index entry to be retained")
	}
}

func TestReadFromDisk_InvalidJwtExpiry_ReturnsNilAndKeepsIndex(t *testing.T) {
	dir := t.TempDir()
	expiry := time.Now().Add(2 * time.Hour).Unix()
	filePath := writeDiskTokenFile(t, dir, "sports", "token", "sports:role.reader", 3600, expiry)

	c := &AccessTokenCache{entries: make(map[string]*accessTokenEntry), tokenDir: dir}
	c.loadDiskIndex()

	// Corrupt the file after indexing: keep scope key mapping valid, but make
	// the token unreadable for jwtExpiry at read time.
	badResp := zts.AccessTokenResponse{
		Access_token: "not-a-jwt",
		Expires_in:   func() *int32 { v := int32(3600); return &v }(),
	}
	data, err := json.Marshal(badResp)
	if err != nil {
		t.Fatalf("json.Marshal: %v", err)
	}
	if err := os.WriteFile(filePath, data, 0644); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	entry := c.readFromDisk("sports", []string{"reader"})
	if entry != nil {
		t.Error("expected nil for invalid JWT expiry")
	}
	if _, ok := c.diskIndex.Load(diskCacheKey("sports", []string{"reader"})); !ok {
		t.Error("expected disk index entry to be retained")
	}
}

// ---------------------------------------------------------------------------
// GetAccessToken with disk fallback integration tests
// ---------------------------------------------------------------------------

func TestGetAccessToken_DiskHit_SkipsZTS(t *testing.T) {
	dir := t.TempDir()
	expiry := time.Now().Add(2 * time.Hour).Unix()
	writeDiskTokenFile(t, dir, "sports", "reader-token", "sports:role.reader", 3600, expiry)

	fetcher := &mockFetcher{response: newTestResponse("zts-tok", 3600), err: nil}
	c := newAccessTokenCacheWithFetcherAndDir(context.Background(), fetcher, dir, 0)
	defer c.Stop()

	resp, err := c.GetAccessToken("sports", "", "reader", "", "", "", 0)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp == nil {
		t.Fatal("expected non-nil response")
	}
	// ZTS should not have been called.
	if count := int(fetcher.callCount); count != 0 {
		t.Errorf("ZTS was called %d times, expected 0 (disk should have been used)", count)
	}
}

func TestGetAccessToken_DiskMiss_FallsBackToZTS(t *testing.T) {
	dir := t.TempDir()
	// Only writer on disk, but we request reader.
	expiry := time.Now().Add(2 * time.Hour).Unix()
	writeDiskTokenFile(t, dir, "sports", "writer-token", "sports:role.writer", 3600, expiry)

	fetcher := &mockFetcher{response: newTestResponse("zts-tok", 3600), err: nil}
	c := newAccessTokenCacheWithFetcherAndDir(context.Background(), fetcher, dir, 0)
	defer c.Stop()

	_, err := c.GetAccessToken("sports", "", "reader", "", "", "", 0)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if count := int(fetcher.callCount); count != 1 {
		t.Errorf("expected 1 ZTS call, got %d", count)
	}
}

func TestGetAccessToken_DiskHitPromotedToMemory(t *testing.T) {
	dir := t.TempDir()
	expiry := time.Now().Add(2 * time.Hour).Unix()
	writeDiskTokenFile(t, dir, "sports", "reader-token", "sports:role.reader", 3600, expiry)

	fetcher := &mockFetcher{response: newTestResponse("zts-tok", 3600), err: nil}
	c := newAccessTokenCacheWithFetcherAndDir(context.Background(), fetcher, dir, 0)
	defer c.Stop()

	// First call: hits disk.
	resp1, err := c.GetAccessToken("sports", "", "reader", "", "", "", 0)
	if err != nil {
		t.Fatalf("first call: %v", err)
	}

	// Second call: should be a memory hit (no disk/ZTS).
	resp2, err := c.GetAccessToken("sports", "", "reader", "", "", "", 0)
	if err != nil {
		t.Fatalf("second call: %v", err)
	}
	if resp1.Access_token != resp2.Access_token {
		t.Errorf("expected same cached token value, got %q and %q", resp1.Access_token, resp2.Access_token)
	}
	if count := int(fetcher.callCount); count != 0 {
		t.Errorf("expected 0 ZTS calls, got %d", count)
	}
}

func TestGetAccessToken_DiskHit_PopulatesRefreshRequestFields(t *testing.T) {
	dir := t.TempDir()
	expiry := time.Now().Add(2 * time.Hour).Unix()
	writeDiskTokenFile(t, dir, "sports", "reader-token", "sports:role.reader", 3600, expiry)

	fetcher := &mockFetcher{response: newTestResponse("zts-tok", 3600), err: nil}
	c := newAccessTokenCacheWithFetcherAndDir(context.Background(), fetcher, dir, 0)
	defer c.Stop()

	_, err := c.GetAccessToken("sports", "svc", "reader", "az", "spiffe://x", "proxy", 1800)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	key := tokenCacheKey("sports", "svc", "reader", "az", "spiffe://x", "proxy", 1800)
	c.mu.RLock()
	entry := c.entries[key]
	c.mu.RUnlock()
	if entry == nil {
		t.Fatal("expected promoted memory entry")
	}
	if entry.service != "svc" || entry.authz != "az" || entry.proxySpiffe != "spiffe://x" || entry.proxyFor != "proxy" || entry.expiryTime != 1800 {
		t.Errorf("promoted entry missing request fields: %+v", entry)
	}
}

func TestGetAccessToken_MemoryHitSkipsDisk(t *testing.T) {
	dir := t.TempDir()
	expiry := time.Now().Add(2 * time.Hour).Unix()
	writeDiskTokenFile(t, dir, "sports", "reader-token", "sports:role.reader", 3600, expiry)

	fetcher := &mockFetcher{response: newTestResponse("zts-tok", 3600), err: nil}
	c := newAccessTokenCacheWithFetcherAndDir(context.Background(), fetcher, dir, 0)
	defer c.Stop()

	// Pre-populate memory cache with a fresh token.
	key := tokenCacheKey("sports", "", "reader", "", "", "", 0)
	c.mu.Lock()
	c.entries[key] = &accessTokenEntry{
		response:     newTestResponse("cached-tok", 3600),
		expiresAt:    time.Now().Add(3600 * time.Second),
		serverExpiry: 3600,
	}
	c.entries[key].lastUsed.Store(time.Now().Unix())
	c.mu.Unlock()

	resp, err := c.GetAccessToken("sports", "", "reader", "", "", "", 0)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	// Should get the memory token, not the disk one.
	if resp.Access_token != "cached-tok" {
		t.Errorf("got token %q, expected memory token %q", resp.Access_token, "cached-tok")
	}
	if count := int(fetcher.callCount); count != 0 {
		t.Errorf("expected 0 ZTS calls, got %d", count)
	}
}

func TestGetAccessToken_DiskExpired_FallsBackToZTS(t *testing.T) {
	dir := t.TempDir()
	// Token is expired (past the 1/4-lifetime threshold).
	expiry := time.Now().Add(-time.Second).Unix()
	writeDiskTokenFile(t, dir, "sports", "reader-token", "sports:role.reader", 3600, expiry)

	fetcher := &mockFetcher{response: newTestResponse("fresh-tok", 3600), err: nil}
	c := newAccessTokenCacheWithFetcherAndDir(context.Background(), fetcher, dir, 0)
	defer c.Stop()

	resp, err := c.GetAccessToken("sports", "", "reader", "", "", "", 0)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp.Access_token != "fresh-tok" {
		t.Errorf("got %q, expected ZTS token %q", resp.Access_token, "fresh-tok")
	}
	if count := int(fetcher.callCount); count != 1 {
		t.Errorf("expected 1 ZTS call, got %d", count)
	}
}

func TestGetAccessToken_DiskTokenNotMeetingRequestedExpiry_FallsBackToZTS(t *testing.T) {
	dir := t.TempDir()
	expiry := time.Now().Add(2 * time.Hour).Unix()
	writeDiskTokenFile(t, dir, "sports", "reader-token", "sports:role.reader", 3600, expiry)

	fetcher := &mockFetcher{response: newTestResponse("fresh-tok", 3600), err: nil}
	c := newAccessTokenCacheWithFetcherAndDir(context.Background(), fetcher, dir, 0)
	defer c.Stop()

	// Request a much larger expiry so diskEntry.hasMinLifetime(expiryTime) fails.
	resp, err := c.GetAccessToken("sports", "", "reader", "", "", "", 50000)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp.Access_token != "fresh-tok" {
		t.Errorf("got %q, expected ZTS token %q", resp.Access_token, "fresh-tok")
	}
	if count := int(fetcher.callCount); count != 1 {
		t.Errorf("expected 1 ZTS call, got %d", count)
	}
}

func TestGetAccessToken_DiskNearExpiry_ZTSFailure_FallsBackToDiskStale(t *testing.T) {
	dir := t.TempDir()
	expiry := time.Now().Add(100 * time.Second).Unix()
	writeDiskTokenFile(t, dir, "sports", "reader-token", "sports:role.reader", 3600, expiry)

	fetcher := &mockFetcher{response: nil, err: fmt.Errorf("zts down")}
	c := newAccessTokenCacheWithFetcherAndDir(context.Background(), fetcher, dir, 0)
	defer c.Stop()

	resp, err := c.GetAccessToken("sports", "", "reader", "", "", "", 3600)
	if err != nil {
		t.Fatalf("expected stale disk fallback on ZTS failure, got error: %v", err)
	}
	if resp == nil || resp.Access_token == "" {
		t.Fatal("expected non-empty stale disk token")
	}
	if count := int(fetcher.callCount); count != 1 {
		t.Errorf("expected 1 ZTS call attempt, got %d", count)
	}
}

func TestGetAccessToken_DiskOlderThanCachedStale_KeepsNewerStaleOnZTSFailure(t *testing.T) {
	dir := t.TempDir()
	// Older stale disk token.
	diskExpiry := time.Now().Add(100 * time.Second).Unix()
	writeDiskTokenFile(t, dir, "sports", "reader-token", "sports:role.reader", 3600, diskExpiry)

	fetcher := &mockFetcher{response: nil, err: fmt.Errorf("zts down")}
	c := newAccessTokenCacheWithFetcherAndDir(context.Background(), fetcher, dir, 0)
	defer c.Stop()

	// Preload a newer stale in-memory token for the same key.
	key := tokenCacheKey("sports", "", "reader", "", "", "", 50000)
	c.mu.Lock()
	c.entries[key] = &accessTokenEntry{
		response:     newTestResponse("cached-newer-stale", 3600),
		expiresAt:    time.Now().Add(200 * time.Second),
		serverExpiry: 3600,
		domain:       "sports",
		roles:        "reader",
		expiryTime:   50000,
	}
	c.entries[key].lastUsed.Store(time.Now().Unix())
	c.mu.Unlock()

	resp, err := c.GetAccessToken("sports", "", "reader", "", "", "", 50000)
	if err != nil {
		t.Fatalf("expected stale fallback on ZTS failure, got error: %v", err)
	}
	if resp == nil || resp.Access_token != "cached-newer-stale" {
		t.Fatalf("expected newer cached stale token, got %+v", resp)
	}
}

func TestGetAccessToken_NoDiskDir_SkipsDiskCompletely(t *testing.T) {
	// No tokenDir configured — should call ZTS directly, same as before.
	fetcher := &mockFetcher{response: newTestResponse("zts-tok", 3600), err: nil}
	c := newAccessTokenCacheWithFetcher(context.Background(), fetcher, 0)
	defer c.Stop()

	_, err := c.GetAccessToken("sports", "", "reader", "", "", "", 0)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if count := int(fetcher.callCount); count != 1 {
		t.Errorf("expected 1 ZTS call, got %d", count)
	}
}

// ---------------------------------------------------------------------------
// Concurrency test: concurrent disk reads on a cold memory cache
// ---------------------------------------------------------------------------

func TestGetAccessToken_DiskHit_ConcurrentCallers(t *testing.T) {
	dir := t.TempDir()
	expiry := time.Now().Add(2 * time.Hour).Unix()
	writeDiskTokenFile(t, dir, "sports", "reader-token", "sports:role.reader", 3600, expiry)

	fetcher := &mockFetcher{response: newTestResponse("zts-tok", 3600), err: nil}
	c := newAccessTokenCacheWithFetcherAndDir(context.Background(), fetcher, dir, 0)
	defer c.Stop()

	const goroutines = 50
	var wg sync.WaitGroup
	wg.Add(goroutines)
	errs := make([]error, goroutines)
	for i := range goroutines {
		go func(idx int) {
			defer wg.Done()
			_, errs[idx] = c.GetAccessToken("sports", "", "reader", "", "", "", 0)
		}(i)
	}
	wg.Wait()

	for i, err := range errs {
		if err != nil {
			t.Errorf("goroutine %d: unexpected error: %v", i, err)
		}
	}
	// ZTS must never have been called — all callers should have been served
	// from disk (singleflight collapses them).
	if count := int(fetcher.callCount); count != 0 {
		t.Errorf("ZTS called %d times, expected 0 (disk should have served all)", count)
	}
}
