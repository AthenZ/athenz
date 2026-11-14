# DPoP-Bound Access Tokens

* [Overview](#overview)
* [How It Works](#how-it-works)
* [Security Model and Limitations](#security-model-and-limitations)
* [Server Configuration](#server-configuration)
* [DPoP Proof Requirements](#dpop-proof-requirements)
* [Issued Tokens](#issued-tokens)
* [Supported Grant Types](#supported-grant-types)
* [Errors](#errors)
* [Client Support](#client-support)
* [Resource Server Validation](#resource-server-validation)
* [Backward Compatibility](#backward-compatibility)
* [Rollout Guidance](#rollout-guidance)
* [Troubleshooting](#troubleshooting)
* [Future Work](#future-work)
* [References](#references)

## Overview

ZTS issues OAuth2 JWT access tokens from `POST /zts/v1/oauth2/token`. When a
client authenticates with an X.509 certificate, ZTS binds the issued token to
that certificate by adding the `cnf.x5t#S256` claim
([RFC 8705](https://www.rfc-editor.org/rfc/rfc8705)). A resource server that
receives the token over mTLS can then check that the caller presents the same
certificate, so a stolen token can't be replayed by a different client.

That protection disappears when TLS is terminated before the resource server,
for example at an AWS Application Load Balancer. The resource server never sees
the client certificate, so it can't verify `x5t#S256`, and the token behaves
like a plain bearer token: whoever holds it can use it.

DPoP ([RFC 9449: OAuth 2.0 Demonstrating Proof of Possession](https://www.rfc-editor.org/rfc/rfc9449))
solves this at the application layer. The client generates a key pair and
signs a short-lived *proof* JWT for each HTTP request. ZTS validates the proof
on the token request and binds the issued access token to the proof's public
key with the `cnf.jkt` claim. A resource server can then require a matching
proof, signed with the same key, on every request that uses the token. A token
that was stolen without the private key is useless.

This document describes the ZTS (authorization server) side of the feature and
the client library support. **ZTS only issues DPoP-bound tokens.** Validating
them at resource servers (auth_core `AccessToken`, ZPE, Go libraries) is a
separate effort. Until that ships, see
[Resource Server Validation](#resource-server-validation).

## How It Works

```
 Client                                   ZTS                          Resource Server
   |                                       |                                   |
   | 1. generate (or load) DPoP key pair   |                                   |
   |                                       |                                   |
   | 2. POST /zts/v1/oauth2/token          |                                   |
   |    DPoP: <proof signed with key>      |                                   |
   |    (client authenticated with mTLS    |                                   |
   |     or client_assertion)              |                                   |
   |-------------------------------------->|                                   |
   |                                       | 3. authenticate client            |
   |                                       | 4. validate DPoP proof            |
   |                                       | 5. issue token with cnf.jkt       |
   |   {"access_token": "...",             |                                   |
   |    "token_type": "DPoP", ...}         |                                   |
   |<--------------------------------------|                                   |
   |                                       |                                   |
   | 6. GET /resource                                                          |
   |    Authorization: DPoP <access token>                                     |
   |    DPoP: <new proof with ath = hash(access token)>                        |
   |-------------------------------------------------------------------------->|
   |                                       |     7. verify token signature,    |
   |                                       |        proof signature, htm/htu,  |
   |                                       |        ath and proof key == jkt   |
```

Steps 1 through 5 are implemented by this feature. Steps 6 and 7 are the
resource server's responsibility (see [Resource Server Validation](#resource-server-validation)).

In detail, for every token request ZTS:

1. Authenticates the client exactly as before (mTLS certificate, principal
   token, or `client_assertion`). The DPoP proof is only looked at after the
   client is authenticated, so unauthenticated callers can't make ZTS verify
   signatures.
2. If DPoP support is disabled, ignores the `DPoP` header entirely and issues a
   bearer token. RFC 9449 §5 allows this for servers that don't support DPoP.
3. If the request has no `DPoP` header, issues a bearer token exactly as before.
4. Otherwise validates the proof (see [DPoP Proof Requirements](#dpop-proof-requirements)).
   An invalid proof fails the request with `400`. ZTS never silently downgrades
   to a bearer token for an invalid proof.
5. Computes the [RFC 7638](https://www.rfc-editor.org/rfc/rfc7638) SHA-256 JWK
   thumbprint of the proof's public key, adds it to the token as `cnf.jkt`, and
   returns `"token_type": "DPoP"`.

## Security Model and Limitations

Read this section before relying on DPoP for protection.

**DPoP adds no protection until resource servers enforce it.** Under RFC 9449
§7.1, only a DPoP-aware resource server rejects a DPoP-bound token that is
presented with the `Bearer` scheme or without a matching proof. Current Athenz
validators (auth_core `AccessToken`, ZPE, the Go libraries, Envoy/sidecar
filters) ignore `cnf.jkt`. Against those, a stolen DPoP-bound token still works
as a bearer token. This is not a regression: a DPoP-bound token is never weaker
than the bearer token it replaces. But don't treat DPoP as a mitigation until
the resource servers that matter validate it.

**DPoP binds the token to the requester's key, not to the client identity.**
If an attacker steals a `client_assertion` (or any other client credential),
they can request a token bound to *their own* DPoP key. Short assertion
lifetimes still matter. For mTLS clients, enable
`athenz.zts.dpop_require_cert_key_match` to require that the DPoP key is the
certificate key (see [Server Configuration](#server-configuration)).

**Proof replay at the token endpoint is low impact.** To replay a captured
proof to ZTS, an attacker must also pass client authentication. Even then, the
issued token is bound to the victim's key, which the attacker doesn't hold.
Because of that, ZTS only enforces a short `iat` window and doesn't track `jti`
values. The `jti` claim is still required, so a jti cache or server nonces can
be added later without client changes.

**What is not bound:**

- The `id_token` returned when the `openid` scope is requested.
- The ID token returned by the ID-token exchange.
- The ID-JAG returned by the ID-JAG issue token exchange. It's an assertion for
  another authorization server, not an access token.

For these flows, a proof that is present is still validated, so a broken proof
fails the request.

## Server Configuration

DPoP support is controlled by system properties in `zts.properties`. Invalid
values make ZTS fail at startup rather than run with an unexpected policy.

| Property | Default | Description |
|---|---|---|
| `athenz.zts.dpop_enabled` | `false` | Master switch. When `false`, the `DPoP` header is ignored and bearer tokens are issued. |
| `athenz.zts.dpop_signing_algorithms` | `ES256,ES384,ES512,RS256,RS384,RS512,PS256,PS384,PS512` | Comma-separated allow-list of JWS algorithms for proofs. Only asymmetric RSA (`RS*`, `PS*`) and EC (`ES*`) algorithms can be configured. `none`, `HS*`, `EdDSA` or unknown names fail startup. |
| `athenz.zts.dpop_proof_max_age` | `30` | How far in the past (seconds) the proof `iat` may be. |
| `athenz.zts.dpop_proof_clock_skew` | `10` | How far in the future (seconds) the proof `iat` may be. |
| `athenz.zts.dpop_allowed_htu` | empty | Extra comma-separated token endpoint URLs to accept in the proof `htu` claim, e.g. the external load balancer URL. |
| `athenz.zts.dpop_htu_match_request_host` | `true` | Require the `htu` host to match the request `Host` header (or the issuer mapped to it). Disable only if a proxy rewrites `Host` for the token endpoint. |
| `athenz.zts.dpop_require_cert_key_match` | `false` | When the client authenticates with an X.509 certificate, require the proof to be signed with the certificate's private key. |
| `athenz.zts.dpop_max_proof_size` | `8192` | Maximum size in bytes of the `DPoP` header value. |
| `athenz.zts.dpop_min_rsa_key_size` | `2048` | Minimum RSA key size in bits for proof keys. |

Minimal configuration:

```
athenz.zts.dpop_enabled=true
```

### Allowed `htu` values and load balancers

The proof's `htu` claim is the URL the client *thinks* it's calling. ZTS
compares it against a fixed set built at startup:

- `<issuer>/oauth2/token` for every configured OAuth2 issuer. This covers
  `athenz.zts.oauth_issuer`, `athenz.zts.openid_issuer`, the OIDC port issuer,
  and every issuer in the host-to-issuer mapping file
  (`athenz.zts.host_issuer_mapping_file`).
- Every URL listed in `athenz.zts.dpop_allowed_htu`.

Issuers that aren't absolute `http`/`https` URLs are skipped, with a warning
in the server log. In particular, when `athenz.zts.oauth_issuer` isn't set,
ZTS uses the bare server hostname as the OAuth issuer, and no token endpoint
URL can be derived from it. In that case, list the token endpoint in
`athenz.zts.dpop_allowed_htu`. Changing `athenz.zts.oauth_issuer` /
`athenz.zts.openid_issuer` to full URLs also works, but it changes the `iss`
claim of issued tokens. If no valid `htu` value remains, ZTS fails to
start with DPoP enabled.

The allowed set is never built from the request URL or the `Host` header. The
request only narrows which entry of the set the proof may use. By default, the
host in the proof's `htu` must also be the host the request was sent to: the
`Host` header without the port, or the server name if the header is missing.
That way a proof created for one allowed URL isn't accepted through another
alias. The one exception is a request host that the host-to-issuer mapping
maps to an issuer (for example, requests that reach ZTS through an external
gateway). For those requests, the host of that issuer's token endpoint is
accepted too. This is the same lookup ZTS uses to choose the issuer of the
token. Scheme, port and path are still checked against the allowed set,
because ZTS can't see them as the client did when there's a load balancer in
front. If a proxy in front of the token endpoint rewrites the `Host` header to
a value that isn't mapped, set `athenz.zts.dpop_htu_match_request_host=false`
to check only the allowed set.

If clients reach ZTS through a load balancer whose external URL isn't one of
the issuers, list that URL explicitly:

```
athenz.zts.dpop_allowed_htu=https://zts.example.com/zts/v1/oauth2/token
```

The same applies when `athenz.zts.openid_issuer` uses a different hostname
than the one clients call. For example, if clients use
`https://zts.athenz.io:4443/zts/v1`, `athenz.zts.openid_issuer` is
`https://zts-oidc.athenz.io/zts/v1`, and `athenz.zts.oauth_issuer` isn't set,
only `https://zts-oidc.athenz.io/zts/v1/oauth2/token` is allowed by default.
List `https://zts.athenz.io:4443/zts/v1/oauth2/token` in
`athenz.zts.dpop_allowed_htu`. Don't change `athenz.zts.oauth_issuer` just for
DPoP, because it also changes the `iss` claim of issued access tokens. Each URL
is then accepted only on requests sent to its own host.

Both configured values and proof `htu` values are normalized before
comparison:

- The query and fragment are dropped.
- The scheme and host are lowercased.
- The default port (`443` for https, `80` for http) is removed.
- An empty path becomes `/`.

A trailing `/` is significant. URLs that aren't absolute `http`/`https` URLs, or
that contain user info, are rejected.

### Certificate key match

With `athenz.zts.dpop_require_cert_key_match=true`, a client that authenticates
with an X.509 certificate must sign its proof with the certificate's private
key. This ties the DPoP key to the attested service identity key. SIA keeps the
same private key across certificate refreshes by default, so the binding
usually survives a refresh. Clients that authenticate without a certificate
(e.g. with `client_assertion`) are not affected by this setting.

### Metadata

When DPoP is enabled, the supported algorithms are advertised as
`dpop_signing_alg_values_supported` (RFC 9449 §5.1) in both discovery documents:

- `GET /.well-known/oauth-authorization-server`
- `GET /.well-known/openid-configuration`, including host-mapped issuers.

```
{
  "issuer": "https://zts.athenz.io/zts/v1",
  "token_endpoint": "https://zts.athenz.io/zts/v1/oauth2/token",
  ...
  "dpop_signing_alg_values_supported": ["ES256","ES384","ES512","RS256","RS384","RS512","PS256","PS384","PS512"]
}
```

When DPoP is disabled, the field isn't included at all.

## DPoP Proof Requirements

A DPoP proof is a JWS in compact serialization, sent as the value of a single
`DPoP` request header.

Header:

```
{
  "typ": "dpop+jwt",
  "alg": "ES256",
  "jwk": {
    "kty": "EC",
    "crv": "P-256",
    "x": "l8tFrhx-34tV3hRICRDY9zCkDlpBhF42UQUfWVAWBFs",
    "y": "9VE4jf_Ok_o64zbTTlcuNJajHmt6v9TDVrU0CdvGRDA"
  }
}
```

Payload:

```
{
  "jti": "e1j3V_bKic8-LAEB",
  "htm": "POST",
  "htu": "https://zts.athenz.io/zts/v1/oauth2/token",
  "iat": 1762992000
}
```

ZTS validates the proof in this order (following RFC 9449 §4.3). The first
failure rejects the request:

1. **One header.** Exactly one `DPoP` header. It must be non-empty and no
   larger than `dpop_max_proof_size`.
2. **Signed JWS.** The value must parse as a signed JWS. Unsecured (`alg=none`)
   tokens and JWEs are rejected.
3. **`typ`** must be `dpop+jwt`, compared case-insensitively.
4. **`alg`** must be in the configured allow-list.
5. **`jwk`** must be present and must be a public key. Private or symmetric key
   material is rejected. `kty` must be `EC` or `RSA` and must match the `alg`
   family. For EC, the curve must match the algorithm (ES256 ↔ P-256,
   ES384 ↔ P-384, ES512 ↔ P-521). For RSA, the key must be at least
   `dpop_min_rsa_key_size` bits. `kid`, `jku`, `x5u` and `x5c` are ignored, and
   ZTS never fetches anything referenced by the proof.
6. **Signature** must verify with the embedded `jwk`. Unknown critical (`crit`)
   header parameters fail verification.
7. **Claims.** `jti` (at most 256 characters), `htm`, `htu` and `iat` are
   required. `ath` and `nonce` are accepted but ignored at the token endpoint.
8. **`htm`** must exactly match the request method (`POST`). `post` is rejected.
9. **`htu`** must match one of the allowed values after normalization and, by
   default, name the request's host or the issuer mapped to it (see
   [Allowed htu values](#allowed-htu-values-and-load-balancers)).
10. **Certificate key match**, only when `dpop_require_cert_key_match` is
    enabled and the client authenticated with a certificate.
11. **`iat` window.** `now - dpop_proof_max_age <= iat <= now + dpop_proof_clock_skew`.
    With the defaults, a proof is accepted for at most 40 seconds.

ZTS never logs the proof. Failures are logged at INFO with the reason and the
client principal. Successful validations are logged at DEBUG with the `jti` and
`jkt`.

## Issued Tokens

### Response

```
{
  "access_token": "<jwt>",
  "token_type": "DPoP",
  "expires_in": 3600,
  "scope": "demo:role.readers"
}
```

### `cnf` claim

The `cnf` claim can hold several confirmation methods, and each resource server
checks the one it can verify. When the client authenticates with mTLS **and**
sends a DPoP proof, ZTS includes both, so existing mTLS resource servers keep
working:

```
"cnf": {
  "x5t#S256": "A4DtL2JmUMhAsvJj5tKyn64SqzmuXbMrJa0n761y5v0",
  "jkt": "0ZcOCORZNYy-DWpqq30jZyJGHTN0d2HglBV3uiguA4I"
}
```

Keeping `x5t#S256` matters. auth_core's `AccessToken.confirmMTLSBoundToken`
rejects a token without it in strict mode (`setAccessTokenCertOffset(0)`) and in
the proxy-hash path.

When the client authenticates without a certificate (e.g. `client_assertion`),
only `jkt` is present:

```
"cnf": {
  "jkt": "0ZcOCORZNYy-DWpqq30jZyJGHTN0d2HglBV3uiguA4I"
}
```

If `proxy_principal_spiffe_uris` was requested, `proxy-principals#spiffe` is
added after these members as before. The JWT header type stays `at+jwt`.

### Access log

When a valid proof is present, `dpop_jkt=<thumbprint>` is added to the
additional query data in the ZTS access log, including the ID-JAG access log
entries. This lets operators correlate tokens with client keys. The thumbprint
isn't secret.

## Supported Grant Types

| Flow | Request | DPoP proof | Result |
|---|---|---|---|
| Client credentials | `grant_type=client_credentials` | validated | token bound, `token_type=DPoP` |
| Access token exchange (impersonation) | `grant_type=...:token-exchange`, `requested_token_type=...:access_token` | validated | token bound, `token_type=DPoP` |
| Access token exchange (delegation) | same as above with `actor_token` | validated | token bound, `token_type=DPoP` |
| ID-JAG exchange | `grant_type=...:jwt-bearer` | validated | token bound, `token_type=DPoP` |
| ID-JAG issue | `grant_type=...:token-exchange`, `requested_token_type=...:id-jag` | validated | not bound, `token_type=N_A` |
| ID token exchange | `grant_type=...:token-exchange`, `requested_token_type=...:id_token` | validated | not bound, `token_type=Bearer` |

The `id_token` returned with the `openid` scope in the client credentials flow
is never bound.

In a delegation request the `actor_token` authenticates the actor. If it's a
DPoP-bound token (it has a `cnf.jkt` claim), the request must include a proof
signed with that key. Otherwise ZTS returns `403` with `DPoP proof key does not
match actor token cnf.jkt`, so a stolen actor token can't be exchanged without
its key. When DPoP is disabled on the server, the `DPoP` header is ignored, so
DPoP-bound actor tokens are always rejected.

## Errors

An invalid proof returns `400 Bad Request` with the standard ZTS `ResourceError`
body. The message is prefixed with `invalid_dpop_proof:`:

```
{"code":400,"message":"invalid_dpop_proof: htu mismatch"}
```

RFC 9449 describes an `{"error":"invalid_dpop_proof"}` body. ZTS keeps the
`ResourceError` format because the existing RDL-generated clients parse it.

| Reason | Cause |
|---|---|
| `multiple DPoP headers` | More than one `DPoP` header was sent. |
| `empty proof` | The header value is empty or blank. |
| `proof too large` | The header value exceeds `dpop_max_proof_size`. |
| `malformed proof` | Not a signed JWS, or the header contains invalid or private `jwk` data. |
| `invalid typ header` | `typ` is missing or not `dpop+jwt`. |
| `unsupported alg: <alg>` | `alg` isn't in the allow-list. |
| `missing jwk header` | No `jwk` header parameter. |
| `jwk contains private key material` | The `jwk` contains private parameters. |
| `unsupported jwk key type: <kty>` | `kty` isn't `EC` or `RSA`. |
| `jwk key type does not match alg` | e.g. an EC key with `RS256`. |
| `jwk curve does not match alg` | e.g. a P-384 key with `ES256`. |
| `jwk rsa key too small` | RSA key below `dpop_min_rsa_key_size`. |
| `invalid signature` / `unable to verify signature` | The signature doesn't verify with the embedded key, or has unknown critical headers. |
| `invalid claims` | The payload isn't valid JSON or a claim has the wrong type. |
| `missing jti claim` / `jti claim too long` | `jti` is missing, empty, or longer than 256 characters. |
| `missing htm claim` / `missing htu claim` / `missing iat claim` | A required claim is missing. |
| `htm mismatch` | `htm` doesn't exactly match the request method. |
| `htu mismatch` | `htu` doesn't match any allowed token endpoint URL. |
| `htu does not match request host` | `htu` is allowed but names a different host than the one the request was sent to (and isn't the issuer mapped to that host). |
| `proof issued in the future` | `iat` is beyond the allowed clock skew. |
| `proof expired` | `iat` is older than the allowed max age. |
| `proof key does not match certificate key` | `dpop_require_cert_key_match` is on and the proof key isn't the certificate key. |

## Client Support

### Java ZTS client

`ZTSClient` installs a `DPoPRequestInterceptor` on its HTTP client. The
interceptor stays dormant until a DPoP key is configured:

```java
KeyRefresher keyRefresher = Utils.generateKeyRefresher(trustStorePath, certFile, keyFile);
keyRefresher.startup();

// the mTLS connections and the DPoP proofs use the same key refresher
ZTSClient ztsClient = new ZTSClient(ztsUrl, keyRefresher);

// recommended: sign proofs with the service identity key, following the
// key refresher when SIA refreshes the key and certificate
ztsClient.enableDPoPWithIdentityKey();

// clients created with an SSLContext can use the same provider directly
ztsClient.setDPoPKeyProvider(new KeyManagerDPoPKeyProvider(keyRefresher));

// or sign proofs with a fixed key pair
ztsClient.setDPoPKey(privateKey, publicKey);

// or supply keys from your own source
ztsClient.setDPoPKeyProvider(() -> currentKeyPair());

AccessTokenResponse response = ztsClient.getAccessToken("demo", null, 3600);
// response.getToken_type() is "DPoP"
```

`new ZTSClient(ztsUrl, keyRefresher)` (or the variant that takes a proxy URL)
builds the client's `SSLContext` from the key refresher's key and trust
manager proxies, the same way applications build it today, and remembers the
key manager. `enableDPoPWithIdentityKey()` then signs proofs with that same key
manager, so the mTLS key and the DPoP key can't come from different sources.
DPoP stays off until it's enabled. The application still starts and shuts down
the key refresher, and the existing constructors are unchanged.

`ZTSClient` never generates or rotates DPoP keys. The provider supplies them.
`KeyManagerDPoPKeyProvider` accepts a `KeyRefresher`, or any `X509KeyManager`
(with an optional key alias). On each token request it returns the key
manager's current private key and its certificate's public key. When the key
refresher reloads a refreshed key and certificate, the next token request
uses the new key, and the proof key always matches the mTLS certificate key
(as `dpop_require_cert_key_match` requires). If the key manager has no EC or
RSA client key, it throws rather than silently sending the request without a
proof. A fixed key set with `setDPoPKey` is never rotated.

Behavior once a key is configured:

- **Fresh proof per request.** Every `POST .../oauth2/token` request gets a new
  proof with a new `jti` and `iat`, including retries and background prefetch.
  The `htu` is `<ztsUrl>/oauth2/token`, so `ztsUrl` must be one of the server's
  allowed token endpoint URLs.
- **Cache separation.** The access token cache key includes the key thumbprint.
  Bearer and DPoP-bound tokens never share a cache entry, and a rotated key
  results in new tokens. Clients with bearer fallback enabled use separate
  cache entries, and a client without fallback never gets a non-DPoP token
  from the cache, even when it falls back to a cached token because the
  server request failed.
- **Key rotation.** The key provider and the fallback setting are read once
  per token request. The proof, the cache key and the token type check all
  use that one key, so rotating keys mid-request can't cache a token under
  another key's thumbprint. When the key changes, the client also drops the
  TLS sessions cached in its `SSLContext`. Otherwise new connections would
  resume a session authenticated with the old certificate, and
  `dpop_require_cert_key_match` would reject proofs signed with the new key.
- **No disk tokens.** Access tokens that SIA wrote to disk are bearer tokens, so
  they are skipped when DPoP is configured.
- **Fail closed.** If the server returns any `token_type` other than `DPoP`
  (for example, a server with DPoP disabled, or a mixed-version fleet during
  rollout), the client throws `ZTSClientException` (400) and doesn't cache the
  token. Call `setDPoPAllowBearerFallback(true)` to accept bearer tokens
  instead, which helps during gradual rollout. The ID-JAG returned by
  `getJAGToken` and the ID token returned by the ID token exchange are exempt
  from this check since they're never DPoP bound.
- **Prefetch.** Prefetched tokens use the same key provider as the client that
  scheduled them.
- **Custom clients.** If you replace the generated client with
  `setZTSRDLGeneratedClient(...)`, register the interceptor on your own
  Apache HttpClient 5 client, built with the same `SSLContext` you passed to
  `ZTSClient`. Use the client's request key accessor, not the key provider
  itself, so the proof is signed with the same key the token is cached under:

  ```java
  CloseableHttpClient httpClient = HttpClients.custom()
          .addRequestInterceptorLast(new DPoPRequestInterceptor(ztsClient.getZTSUrl(),
                  ztsClient::getRequestDPoPKeyPair))
          // connection manager, timeouts, ...
          .build();
  ztsClient.setZTSRDLGeneratedClient(new ZTSRDLGeneratedClient(ztsClient.getZTSUrl(), httpClient));
  ```

To generate proofs for resource server calls, `DPoPProof.generate(...)` in
auth_core accepts the access token and adds the `ath` claim:

```java
String proof = DPoPProof.generate(privateKey, publicKey, "GET",
        "https://api.example.com/resource", accessToken, null,
        System.currentTimeMillis() / 1000);
```

### Go

`libs/go/athenzutils` provides the Go helpers. The generated `clients/go/zts`
client is unchanged.

```go
// wrap the transport so every token request carries a fresh proof
client := zts.NewClient(ztsURL, athenzutils.NewDPoPTransport(baseTransport, signer, ztsURL))

resp, err := client.PostAccessTokenRequest(zts.AccessTokenRequest(request))
if errors.Is(err, athenzutils.ErrDPoPTokenNotIssued) {
    // the server returned a bearer token (e.g. DPoP is disabled on the server)
}
if err != nil {
    return err
}
```

- `DPoPTransport` fails closed. If a successful token endpoint response has a
  `token_type` other than `DPoP`, the request fails with an error wrapping
  `ErrDPoPTokenNotIssued`, so the bearer token never reaches the caller. ID-JAG
  responses are exempt, and error responses are passed through unchanged.
  `VerifyDPoPTokenType(tokenType)` applies the same check to a token type you
  got some other way.
- `ZtsClientWithDPoP(ztsURL, keyFile, certFile, caCertFile, dpopKeyFile, proxy)`
  builds an mTLS client that uses `DPoPTransport`. When `dpopKeyFile` is empty,
  it uses the service key.
- `GenerateDPoPProof(signer, htm, htu, accessToken, nonce, now)` creates proofs,
  including resource server proofs with `ath`.
- `DPoPThumbprint(pub)` returns the `jkt` value for a public key.

SIA (`libs/go/sia`) doesn't request DPoP-bound tokens. Tokens it writes to disk
are shared with other processes, so DPoP there needs a key-sharing design.

### zts-accesstoken utility

```
$ zts-accesstoken -domain demo -svc-key-file key.pem -svc-cert-file cert.pem \
    -zts https://zts.athenz.io/zts/v1 -dpop [-dpop-key-file dpop-key.pem]
```

The utility exits with an error if the server doesn't return a DPoP token. See
[zts-accesstoken](zts_accesstoken.md) for details.

### Other languages

Any JOSE library can build a proof. Follow the header and payload layout in
[DPoP Proof Requirements](#dpop-proof-requirements):

- Embed only the public key.
- Use a new `jti` and the current `iat` for every request.
- Set `htu` to the exact token endpoint URL the server is configured for.

## Resource Server Validation

Built-in DPoP enforcement in auth_core `AccessToken`, ZPE and the Go libraries
is planned as a separate change. Until then, a resource server that wants to
enforce the binding can use the auth_core primitives directly:

```java
// 1. validate the access token as usual
AccessToken token = new AccessToken(accessTokenValue, keyResolver);
String jkt = token.getConfirmJwkThumbprint();
if (jkt == null) {
    // not DPoP bound: handle as a bearer token (or reject if DPoP is required)
}

// 2. validate the proof for this request
DPoPProofOptions options = DPoPProofOptions.builder()
        .addAllowedHtu("https://api.example.com/resource")
        .build();
DPoPProof proof = new DPoPProof(request.getHeader("DPoP"), request.getMethod(),
        options, System.currentTimeMillis() / 1000);

// 3. the proof must be signed by the bound key and cover this token
if (!jkt.equals(proof.getJwkThumbprint())
        || !DPoPProof.computeAccessTokenHash(accessTokenValue).equals(proof.getAccessTokenHash())) {
    // reject the request
}
```

A resource server must validate at least one binding it can verify on the
channel the request arrived on:

- If the request uses the `DPoP` scheme or carries a proof, verify `jkt`.
- If it arrives over direct mTLS, verify `x5t#S256`.
- If both are available, verify both.

Resource servers should also consider tracking proof `jti` values to prevent
replay within the `iat` window.

## Backward Compatibility

| Scenario | Behavior |
|---|---|
| DPoP disabled (default) | No change. The `DPoP` header is ignored and bearer tokens are issued. |
| DPoP enabled, no `DPoP` header | No change. The token and response are identical to before. |
| DPoP enabled, valid proof | `token_type=DPoP` and `cnf.jkt` added. `x5t#S256` is kept for mTLS clients. |
| DPoP enabled, invalid proof | `400`. This only affects clients that opted in by sending the header. |
| auth_core `AccessToken` validation | Unchanged. Unknown `cnf` members are preserved and `x5t#S256` checks still pass. |
| RDL-generated Java/Go clients | No method signature changes. The `DPoP` header is read directly from the servlet request and is not declared in the RDL. |
| Discovery metadata | New optional `dpop_signing_alg_values_supported` field, only when enabled. Java and Go JSON clients ignore unknown fields. |
| Go code using positional `zts.OAuthConfig` / `zts.OpenIDConfig` struct literals | Fails to compile after upgrading because of the new field. Use keyed fields. |

## Rollout Guidance

1. Deploy the ZTS release with DPoP disabled.
2. Set `athenz.zts.dpop_allowed_htu` if clients reach ZTS through URLs other
   than the configured issuers.
3. Enable `athenz.zts.dpop_enabled` node by node. Keep the DPoP configuration
   (algorithms and allowed `htu` values) identical across the fleet.
4. Update clients. While some ZTS nodes still return bearer tokens, clients
   either fail closed (the default) or use `setDPoPAllowBearerFallback(true)`
   in Java.
5. Upgrade resource servers to enforce DPoP. Only at this step does DPoP start
   to protect against token theft.

Each DPoP request costs one extra JWS signature verification at ZTS (well under
a millisecond for ES256 or RS256). Requests without a proof have no extra cost.
The feature keeps no shared state, so nothing needs to be synchronized between
ZTS nodes.

## Troubleshooting

- **`htu mismatch`.** The client signed a URL ZTS doesn't know about. Compare the
  client's ZTS URL with the issuers and `athenz.zts.dpop_allowed_htu`. The usual
  cause is a load balancer URL. Also check the port and any trailing `/`.
- **`htu does not match request host`.** The client signed an allowed URL but
  sent the request to a different host, or a proxy rewrote the `Host` header.
  Make the client's ZTS URL match the host it connects to, map the rewritten
  host to the issuer in the host-to-issuer mapping file, or disable
  `athenz.zts.dpop_htu_match_request_host`.
- **`proof expired` / `proof issued in the future`.** Check clock
  synchronization on the client and ZTS hosts. Proofs must be generated per
  request and not reused.
- **Client receives `Bearer` instead of `DPoP`.** DPoP isn't enabled on the ZTS
  node that served the request, or the request had no `DPoP` header (for
  example, a custom HTTP client without the interceptor).
- **`proof key does not match certificate key`.** With
  `dpop_require_cert_key_match` enabled, sign the proof with the private key of
  the certificate used for mTLS.
- **Confirm the binding.** Decode the token (e.g. `zts-accesstoken -validate -claims`)
  and compare `cnf.jkt` with the thumbprint of your public key
  (`DPoPProof.computeJwkThumbprint` in Java, `athenzutils.DPoPThumbprint` in Go).

## Future Work

- Resource server validation in auth_core, ZPE and the Go libraries. This
  includes rejecting DPoP-bound tokens presented with the `Bearer` scheme, and
  `cnf`/`token_type` in introspection responses.
- Stateless server nonces (`DPoP-Nonce`, RFC 9449 §8) with client retry support.
- Per-service or per-domain enforcement so that selected clients can't obtain
  bearer tokens.
- Requiring the DPoP key to match the registered service key that verified a
  `client_assertion`.
- EdDSA proof support.
- DPoP-bound tokens written to disk by SIA.

## References

- [RFC 9449: OAuth 2.0 Demonstrating Proof of Possession (DPoP)](https://www.rfc-editor.org/rfc/rfc9449)
- [RFC 7638: JSON Web Key (JWK) Thumbprint](https://www.rfc-editor.org/rfc/rfc7638)
- [RFC 8705: OAuth 2.0 Mutual-TLS Client Authentication and Certificate-Bound Access Tokens](https://www.rfc-editor.org/rfc/rfc8705)
- [RFC 9068: JWT Profile for OAuth 2.0 Access Tokens](https://www.rfc-editor.org/rfc/rfc9068)
- [RFC 8414: OAuth 2.0 Authorization Server Metadata](https://www.rfc-editor.org/rfc/rfc8414)
- [Obtaining OAuth2 Access Tokens from ZTS](zts_access_token_guide.md)
