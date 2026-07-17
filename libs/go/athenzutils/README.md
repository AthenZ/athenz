athenzutils
===========

Go helper library for talking to ZTS. It provides:

- `ZtsClient` – a ZTS client built from a private key and certificate.
- `AccessTokenCache` – a thread-safe access token cache with automatic background refresh, request deduplication, and optional on-disk token fallback.

## Install

```bash
go get github.com/AthenZ/athenz/libs/go/athenzutils
```

## Creating a ZTS client

```go
import "github.com/AthenZ/athenz/libs/go/athenzutils"

client, err := athenzutils.ZtsClient(
    "https://zts.athenz.io:4443/zts/v1", // ZTS URL
    "/var/lib/sia/keys/service.key.pem", // private key
    "/var/lib/sia/certs/service.cert.pem", // certificate
    "/etc/ssl/certs/ca-bundle.pem",      // CA bundle ("" to use system roots)
    false,                                // use HTTP proxy from environment
)
```

## Access token cache

Most callers should use `AccessTokenCache` instead of requesting tokens directly. It caches tokens in memory, refreshes them in the background, and collapses concurrent requests for the same token into a single ZTS call.

### Create a cache

```go
ctx := context.Background()

cache, err := athenzutils.NewAccessTokenCache(
    ctx,
    "https://zts.athenz.io:4443/zts/v1",
    "/var/lib/sia/keys/service.key.pem",
    "/var/lib/sia/certs/service.cert.pem",
    "",
    false,
    10*time.Minute, // background refresh interval (0 disables refresh)
)
if err != nil {
    log.Fatal(err)
}
defer cache.Stop() // stop the background refresh goroutine
```

### Get a token

```go
resp, err := cache.GetAccessToken(
    "sports",        // domain
    "",              // service (optional)
    "reader,writer", // comma-separated roles ("" for a domain-wide token)
    "",              // authorization details (optional)
    "",              // proxy principal SPIFFE URIs (optional)
    "",              // proxy for principal (optional)
    3600,            // requested expiry in seconds (0 = ZTS default)
)
if err != nil {
    log.Fatal(err)
}

fmt.Println(resp.Access_token)
```

The first call fetches from ZTS; subsequent calls for the same parameters return the cached token until it needs refreshing. Role order does not matter — `"reader,writer"` and `"writer,reader"` share the same cache entry.

To force a fresh fetch and bypass the cache, pass `true` as the final argument:

```go
resp, err := cache.GetAccessToken("sports", "", "reader", "", "", "", 3600, true)
```

## On-disk token fallback

If a SIA agent pre-provisions tokens on disk, use `NewAccessTokenCacheFromDir`. The cache then checks memory first, then disk, and only calls ZTS if neither has a usable token. Tokens found on disk are promoted into the in-memory cache.

```go
cache, err := athenzutils.NewAccessTokenCacheFromDir(
    ctx,
    "https://zts.athenz.io:4443/zts/v1",
    "/var/lib/sia/keys/service.key.pem",
    "/var/lib/sia/certs/service.cert.pem",
    "",
    false,
    "/var/lib/sia/tokens", // SIA token directory (<tokenDir>/<domain>/<file>)
    10*time.Minute,
)
```

Token files are read-only to this library; they are written by the SIA agent. Each file is a JSON `AccessTokenResponse` laid out as `<tokenDir>/<domain>/<filename>`.

## Behavior

- **Freshness**: a cached token is reused while at least 1/4 of its lifetime remains, then refreshed.
- **Background refresh**: cached tokens are proactively refreshed on the configured interval so callers rarely wait on ZTS.
- **Stale fallback**: if ZTS is unreachable, the last cached token is returned (when available) rather than failing.
- **Deduplication**: concurrent requests for the same token trigger only one ZTS call.
- **Idle eviction**: entries that go unused for a full token lifetime are dropped during refresh.
- **Thread-safe**: all methods are safe for concurrent use. Call `Stop()` when done to release the background goroutine.

## License

Copyright The Athenz Authors

Licensed under the [Apache License, Version 2.0](http://www.apache.org/licenses/LICENSE-2.0)
