# User Certificate Feature — Design Document

**Date:** March 2026
**Status:** For Security Review
**Components:** `zts-usercert` CLI utility, ZTS Server (`postUserCertificateRequest`), `UserCertificateProvider`

---

## 1. Overview

The User Certificate feature allows human users to obtain X.509 TLS client certificates from the Athenz ZTS server. The user's identity is verified through an external Identity Provider (IdP) using the OAuth 2.0 Authorization Code flow. Once verified, ZTS issues a short-lived X.509 certificate that the user can use for mutual TLS authentication against Athenz-protected services.

- Allow human users to obtain X.509 certificates without pre-existing Athenz credentials.
- Delegate user authentication to an enterprise IdP (e.g., Okta, Azure AD, Google Workspace).
- Issue short-lived, client-only certificates with server-enforced maximum lifetimes.
- Prevent certificate refresh — each certificate requires a fresh IdP authentication.

---

## 2. Architecture

### 2.1 Components

| Component | Language | Location | Responsibility |
|---|---|---|---|
| `zts-usercert` | Go | `utils/zts-usercert/` | CLI tool that orchestrates the end-to-end flow |
| `usercert` library | Go | `libs/go/usercert/` | Reusable library: IdP auth, CSR generation, ZTS API call |
| ZTS Server | Java | `servers/zts/` | `postUserCertificateRequest` handler: validates request, delegates to provider, issues certificate |
| `UserCertificateProvider` | Java | `libs/java/instance_provider/` | Instance provider: exchanges OAuth2 auth code for access token, validates token identity |
| ZTS Client | Go | `clients/go/zts/` | Generated client with `PostUserCertificateRequest` method |

### 2.2 Trust Boundaries

```
┌──────────────────────────────────────────────────────────────────────┐
│                        User's Workstation                            │
│  ┌──────────────┐     ┌──────────────────────────────────────────┐   │
│  │   Browser    │     │  zts-usercert CLI                        │   │
│  │  (IdP login) │     │  • Private key (file)                    │   │
│  │              │     │  • OAuth2 callback server (localhost)    │   │
│  └──────┬───────┘     └───────────────┬──────────────────────────┘   │
│         │                             │                              │
└─────────┼─────────────────────────────┼──────────────────────────────┘
          │ HTTPS                       │ HTTPS (TLS)
          ▼                             ▼
┌──────────────────┐          ┌─────────────────────────────────────┐
│  Identity        │          │  ZTS Server                         │
│  Provider (IdP)  │◄─────────│  • postUserCertificateRequest       │
│  • /authorize    │  HTTPS   │  • UserCertificateProvider          │
│  • /token        │          │  • Certificate Signer               │
│  • /jwks         │          └─────────────────────────────────────┘
└──────────────────┘
```

---

## 3. Data Flow

### 3.1 End-to-End Sequence

```
     User              Browser          zts-usercert CLI       localhost:9213        IdP              ZTS Server
      │                   │                    │                     │                    │                   │
      │  run CLI          │                    │                     │                    │                   │
      ├──────────────────►│                    │                     │                    │                   │
      │                   │                    │                     │                    │                   │
      │                   │   1. Read private key from file          │                    │                   │
      │                   │   2. Generate CSR (CN=userName)          │                    │                   │
      │                   │   3. Generate nonce + state (24 B each)  │                    │                   │
      │                   │      Generate PKCE verifier (if enabled) │                    │                   │
      │                   │   4. Start callback HTTP server          │                    │                   │
      │                   │                    │◄────────────────────┤                    │                   │
      │                   │                    │   (listening)       │                    │                   │
      │                   │                    │                     │                    │                   │
      │                   │   5. Open browser to IdP /authorize      │                    │                   │
      │                   ├────────────────────┼─────────────────────┼───────────────────►│                   │
      │                   │                    │                     │  ?client_id=       │                   │
      │                   │                    │                     │  &redirect_uri=    │                   │
      │                   │                    │                     │  localhost:9213    │                   │
      │                   │                    │                     │  &response_type=   │                   │
      │                   │                    │                     │  code              │                   │
      │                   │                    │                     │  &scope=openid     │                   │
      │                   │                    │                     │  &nonce=...        │                   │
      │                   │                    │                     │  &state=...        │                   │
      │                   │                    │                     │  &code_challenge=..│                   │
      │                   │                    │                     │  &code_challenge_  │                   │
      │                   │                    │                     │   method=S256      │                   │
      │  6. User          │                    │                     │                    │                   │
      │  authenticates    │                    │                     │                    │                   │
      │  with IdP         │                    │                     │                    │                   │
      │  (login/MFA)      │                    │                     │                    │                   │
      │                   │                    │                     │                    │                   │
      │                   │   7. IdP redirects to callback           │                    │                   │
      │                   │◄─────────────────────────────────────────┼────────────────────┤                   │
      │                   │  302 → localhost:9213/oauth2/callback    │                    │                   │
      │                   │        ?code=AUTH_CODE&state=NONCE       │                    │                   │
      │                   │                    │                     │                    │                   │
      │                   ├────────────────────┼────────────────────►│                    │                   │
      │                   │                    │   GET /oauth2/      │                    │                   │
      │                   │                    │   callback?code=... │                    │                   │
      │                   │                    │                     │                    │                   │
      │                   │                    │◄────────────────────┤                    │                   │
      │                   │                    │  8. Extract raw     │                    │                   │
      │                   │                    │  query string       │                    │                   │
      │                   │                    │  (code=...&state=.) │                    │                   │
      │                   │                    │  Validate state     │                    │                   │
      │                   │                    │                     │                    │                   │
      │                   │   9. Redirect browser to /close page     │                    │                   │
      │                   │◄───────────────────┼─────────────────────┤                    │                   │
      │                   │  "Authentication   │  10. Shutdown       │                    │                   │
      │                   │   successful"      │  callback server    │                    │                   │
      │                   │                    │                     │                    │                   │
      │                   │   11. POST /usercert to ZTS              │                    │                   │
      │                   │                    ├─────────────────────┼────────────────────┼──────────────────►│
      │                   │                    │                     │                    │   JSON body:      │
      │                   │                    │                     │                    │   { name,         │
      │                   │                    │                     │                    │     csr,          │
      │                   │                    │                     │                    │     attestation   │
      │                   │                    │                     │                    │     Data (code +  │
      │                   │                    │                     │                    │     verifier) }   │
      │                   │                    │                     │                    │                   │
      │                   │                    │                     │                    │ 12. ZTS validates │
      │                   │                    │                     │                    │ request, calls    │
      │                   │                    │                     │                    │ provider          │
      │                   │                    │                     │                    │                   │
      │                   │                    │                     │                    │  13. Provider     │
      │                   │                    │                     │                    │◄──────────────────│
      │                   │                    │                     │                    │  exchanges code   │
      │                   │                    │                     │                    │  for access token │
      │                   │                    │                     │                    │  POST /token      │
      │                   │                    │                     │                    │──────────────────►│
      │                   │                    │                     │                    │                   │
      │                   │                    │                     │                    │  14. Validate     │
      │                   │                    │                     │                    │  JWT signature    │
      │                   │                    │                     │                    │  + subject match  │
      │                   │                    │                     │                    │  + audience match │
      │                   │                    │                     │                    │                   │
      │                   │                    │                     │                    │ 15. Sign CSR,     │
      │                   │                    │                     │                    │ return X.509 cert │
      │                   │                    │◄────────────────────┼────────────────────┼───────────────────│
      │                   │                    │                     │                    │                   │
      │                   │   16. Write cert   │                     │                    │                   │
      │                   │   to file or stdout│                     │                    │                   │
      │                   │                    │                     │                    │                   │
```

### 3.2 Server-Side Processing Flow (ZTS + Provider)

```
                    POST /usercert
                         │
                         ▼
              ┌─────────────────────┐
              │  Read-Only Mode     │──Yes──► 400 Bad Request
              │  Check              │
              └──────────┬──────────┘
                         │ No
                         ▼
              ┌─────────────────────┐
              │  userAuthority &    │──Null──► 400 Bad Request
              │  userCertProvider   │         "User authority not set"
              │  configured?        │
              └──────────┬──────────┘
                         │ Set
                         ▼
              ┌─────────────────────┐
              │  Validate request   │──Fail──► 400 Bad Request
              │  schema (RDL type)  │
              └──────────┬──────────┘
                         │ OK
                         ▼
              ┌─────────────────────┐
              │  Validate user      │
              │  principal:         │
              │  • Non-empty        │
              │  • No wildcards     │──Fail──► 400 Bad Request
              │  • Starts with      │
              │    userDomainPrefix │
              │  • USER_ACTIVE in   │
              │    userAuthority    │
              └──────────┬──────────┘
                         │ Valid
                         ▼
              ┌─────────────────────┐
              │  Parse CSR          │──Fail──► 400 Bad Request
              │  (X509UserCertReq)  │         "Unable to parse PKCS10 CSR"
              └──────────┬──────────┘
                         │ OK
                         ▼
              ┌─────────────────────┐
              │  CSR CN matches     │──No───► 400 Bad Request
              │  principal name?    │         "Certificate Request mismatch"
              └──────────┬──────────┘
                         │ Yes
                         ▼
              ┌─────────────────────┐
              │  Validate CSR:      │
              │  • No DNS SANs      │
              │  • No IP SANs       │──Fail──► 400 Bad Request
              │  • No instance ID   │         "Unable to validate cert request"
              │  • Valid O field    │
              │  • Valid SPIFFE URI │
              │    (if present)     │
              └──────────┬──────────┘
                         │ Valid
                         ▼
              ┌─────────────────────┐
              │  Get instance       │
              │  provider           │
              │  (UserCertProvider) │
              └──────────┬──────────┘
                         │
                         ▼
          ┌──────────────────────────────┐
          │  UserCertificateProvider     │
          │  .confirmInstance()          │
          │                              │
          │  ┌───────────────────────┐   │
          │  │ Extract auth code     │   │
          │  │ from attestationData  │   │
          │  └───────────┬───────────┘   │
          │              │               │
          │              ▼               │
          │  ┌────────────────────────┐  │
          │  │ POST to IdP /token     │  │    ┌─────────┐
          │  │ grant_type=            │  │    │         │
          │  │  authorization_code    │──┼───►│   IdP   │
          │  │ code=AUTH_CODE         │  │    │ /token  │
          │  │ client_id=...          │  │    │         │
          │  │ redirect_uri=...       │  │    └────┬────┘
          │  │ client_secret=... (*)  │  │         │
          │  │ code_verifier=.. (**)  │  │         │
          │  └───────────┬────────────┘  │         │
          │  (*) if configured           │         │
          │  (**) if present; required   │         │
          │       when no client_secret  │         │
          │              │◄──────────────┼─────────┘
          │              │ access_token  │
          │              ▼               │
          │  ┌───────────────────────┐   │
          │  │ Validate JWT:         │   │
          │  │ • Verify signature    │   │
          │  │   (JWKS keys)         │   │
          │  │ • Verify subject      │   │
          │  │   matches userName    │   │
          │  │ • Verify audience     │   │
          │  └───────────┬───────────┘   │
          │              │               │
          │              ▼               │
          │  Return confirmation         │
          └──────────────┬───────────────┘
                         │
                         ▼
              ┌─────────────────────┐
              │  Determine expiry:  │
              │  • Use request val  │
              │  • Cap at max       │
              │  • Default if unset │
              └──────────┬──────────┘
                         │
                         ▼
              ┌─────────────────────┐
              │  Generate X.509     │
              │  certificate via    │
              │  cert signer        │
              │  (client usage,     │
              │   high priority)    │
              └──────────┬──────────┘
                         │
                         ▼
              ┌─────────────────────┐
              │  Log certificate    │
              │  Return UserCert    │
              └─────────────────────┘
```

---

## 4. Component Details

### 4.1 Client-Side: `zts-usercert` CLI and `usercert` Library

#### 4.1.1 CLI Entry Point (`utils/zts-usercert/zts-usercert.go`)

The CLI is a thin wrapper that parses command-line flags and delegates to `usercert.Run()`.

**Required Parameters:**
- `--zts` — ZTS server URL
- `--private-key` — Path to user's private key PEM file
- `--user` — User name without domain prefix
- `--idp-endpoint` — IdP OAuth2 authorization endpoint
- `--idp-client-id` — IdP OAuth2 client ID

**Optional Parameters:**
- `--cert-file` — Output certificate file (default: stdout)
- `--subj-c`, `--subj-o`, `--subj-ou` — CSR subject fields (OU defaults to "Athenz")
- `--spiffe-trust-domain` — SPIFFE trust domain for URI SAN
- `--scope` — OIDC scope parameter (default: "openid")
- `--callback-port` — Local port for OAuth2 callback (default: 9213)
- `--callback-timeout` — Timeout in seconds for IdP auth flow (default: 45s)
- `--expiry-time` — Certificate expiry in minutes (0 = server default)
- `--cacert` — CA certificate file for ZTS TLS verification
- `--pkce` — Enable PKCE (RFC 7636) for the IdP auth flow (default: true)
- `--proxy` — Enable HTTP proxy (default: true)
- `--verbose` — Enable verbose logging
- `--version` — Show version information and exit

#### 4.1.2 Core Library (`libs/go/usercert/usercert.go`)

`RequestCertificate(opts Options)` executes the full flow:

1. **Read private key** from `opts.PrivateKeyFile`. Supports both RSA and ECDSA keys.
2. **Generate CSR** with:
   - `CN = userName` (without domain prefix)
   - Optional Subject fields: Country, Organization, OrganizationalUnit
   - Optional SPIFFE URI SAN: `spiffe://<trustDomain>/ns/default/sa/<userName>`
3. **Run IdP OAuth2 flow** via `GetAuthCode()` (see Section 4.1.3). The OIDC `scope` parameter (default: "openid") is passed to the authorization request.
4. **Build `UserCertificateRequest`** with `name`, `csr`, `attestationData`, and optional `expiryTime`. The attestation data is the raw query string from the callback; when PKCE is enabled, the code verifier is appended (e.g., `code=AUTH_CODE&state=STATE&code_verifier=VERIFIER`).
5. **POST to ZTS** `/usercert` endpoint via the generated ZTS Go client.
6. **Return** the X.509 certificate PEM string.

#### 4.1.3 IdP Authentication Flow (`libs/go/usercert/idp.go`)

`GetAuthCode()` orchestrates the local OAuth2 authorization code flow:

1. **Start a local HTTP server** on `localhost:<callbackPort>` with two routes:
   - `GET /oauth2/callback` — Receives the IdP redirect, captures `code` and `state` from the query string, redirects to `/close`.
   - `GET /close` — Renders a static HTML page ("Authentication successful. You may close this window.").
2. **Generate cryptographic nonce and state** — Two independent random values (24 bytes each, base64url-encoded) are generated for the `nonce` and `state` parameters respectively.
3. **Generate PKCE code verifier and challenge** (when PKCE is enabled) — A code verifier (32 random bytes, base64url-encoded) is generated per RFC 7636. The code challenge is computed as `BASE64URL(SHA256(code_verifier))` using the S256 method.
4. **Open the system browser** to the IdP authorization URL:
   ```
   <idpEndpoint>?client_id=<clientId>&redirect_uri=http://localhost:<port>/oauth2/callback&response_type=code&scope=<scope>&nonce=<nonce>&state=<state>&code_challenge=<challenge>&code_challenge_method=S256
   ```
   The `code_challenge` and `code_challenge_method` parameters are only included when PKCE is enabled.
5. **Wait** for either:
   - The callback to deliver the authorization code (success), or
   - A timeout (default 45 seconds).
6. **Validate state** — The `state` parameter returned in the callback is compared against the original value. A mismatch aborts the flow with an error.
7. **Shut down** the local HTTP server gracefully.
8. **Return** the raw query string (e.g., `code=AUTH_CODE&state=STATE`) and the PKCE code verifier (empty string when PKCE is disabled).

**Security properties of the local server:**
- Binds to `localhost` only (not `0.0.0.0`).
- Read/Write timeouts of 30 seconds per connection.
- Idle timeout of 120 seconds.
- Graceful shutdown with 5-second context timeout.
- Server is shut down immediately after receiving the callback or timing out.

### 4.2 Server-Side: ZTS `postUserCertificateRequest` Handler

**API Endpoint:** `POST /usercert`

**Request Schema (RDL-defined):**

| Field | Type | Required | Description |
|---|---|---|---|
| `name` | String | Yes | User principal name (e.g., `user.johndoe`) |
| `csr` | String | Yes | PEM-encoded PKCS#10 Certificate Signing Request |
| `attestationData` | String | Yes | OAuth2 callback query string containing authorization code |
| `expiryTime` | Int32 | No | Requested certificate expiry in minutes |
| `x509CertSignerKeyId` | SimpleName | No | Requested X.509 cert signer key ID |

**Response Schema:**

| Field | Type | Description |
|---|---|---|
| `x509Certificate` | String | PEM-encoded X.509 certificate |

**Handler Logic (ZTSImpl.java, lines 6538–6629):**

1. **Read-only mode check** — Reject if ZTS is in maintenance mode.
2. **Configuration check** — Verify `userAuthority` and `userCertProvider` are configured.
3. **Schema validation** — Validate request against RDL type `UserCertificateRequest`.
4. **Principal validation** (`validateUserPrincipalForCert`):
   - Name is non-empty.
   - Name contains no wildcards (`*`).
   - Name starts with the configured `userDomainPrefix` (e.g., `user.`).
   - User is active according to `userAuthority` (`USER_ACTIVE` check).
5. **CSR parsing** — Parse the PEM CSR into `X509UserCertRequest`.
6. **CN validation** — CSR Common Name must exactly match the `principalName` from the request.
7. **CSR content validation** (`X509UserCertRequest.validate`):
   - **No DNS SANs** — DNS names are forbidden in user certificates.
   - **No IP SANs** — IP addresses are forbidden in user certificates.
   - **No instance ID or URI hostname** — Must be null.
   - **URI constraint** — At most one URI SAN, which must be a valid SPIFFE URI.
   - **Subject O field** — Must be in the server's configured `validCertSubjectOrgValues`.
   - **SPIFFE URI validation** — If a SPIFFE URI is present, it must be valid for the user domain/namespace.
8. **Provider attestation** — Delegate to `UserCertificateProvider.confirmInstance()` (see Section 4.3).
9. **Expiry determination** (`determineUserCertTimeout`):
   - If no expiry requested or <= 0: use `userCertDefaultTimeout` (default: 60 minutes).
   - If requested expiry > `userCertMaxTimeout` (default: 60 minutes): cap at max.
   - Otherwise: use requested value.
10. **Certificate signing** — Submit CSR to cert signer with `client` usage, `High` priority.
11. **Logging** — Log the issued certificate.
12. **Return** — Return `UserCertificate` with the PEM certificate string.

**Configuration Properties:**

| Property | Default | Description |
|---|---|---|
| `athenz.zts.user_cert_provider` | (none) | Provider class name |
| `athenz.zts.user_cert_max_timeout` | 60 min | Maximum certificate lifetime |
| `athenz.zts.user_cert_default_timeout` | 60 min | Default certificate lifetime |

### 4.3 Server-Side: `UserCertificateProvider`

The provider implements the `InstanceProvider` interface and performs the server-side IdP verification.

#### 4.3.1 Initialization

On startup, the provider configures itself from system properties:

| Property | Required | Default                                 | Description |
|---|---|-----------------------------------------|---|
| `athenz.zts.user_cert.idp_config_endpoint` | No | —                                       | OpenID Connect discovery endpoint (auto-discovers token + JWKS endpoints) |
| `athenz.zts.user_cert.idp_token_endpoint` | Yes* | —                                       | IdP token endpoint (*auto-discovered if config endpoint is set). Must be an HTTPS URL. |
| `athenz.zts.user_cert.idp_jwks_endpoint` | Yes* | —                                       | IdP JWKS endpoint (*auto-discovered if config endpoint is set). Must be an HTTPS URL. |
| `athenz.zts.user_cert.idp_client_id` | Yes | —                                       | OAuth2 client ID |
| `athenz.zts.user_cert.idp_redirect_uri` | No | `http://localhost:9213/oauth2/callback` | OAuth2 redirect URI |
| `athenz.zts.user_cert.idp_audience` | Yes | —                                       | Expected audience claim in access token |
| `athenz.zts.user_cert.connect_timeout` | No | 10000 ms                                | Connection timeout for IdP requests |
| `athenz.zts.user_cert.read_timeout` | No | 15000 ms                                | Read timeout for IdP requests |
| `athenz.zts.user_cert.user_name_claim` | No | —                                       | Custom claim name for user identity (fallback if `sub` doesn't match) |
| `athenz.zts.user_cert.idp_client_secret_app` | No | —                                       | App name for secret store lookup |
| `athenz.zts.user_cert.idp_client_secret_keygroup` | No | —                                       | Key group for secret store lookup |
| `athenz.zts.user_cert.idp_client_secret_keyname` | No | —                                       | Key name for secret store lookup |

Both the token and JWKS endpoints are validated during initialization to ensure they use HTTPS. The provider will fail to start if either endpoint uses a non-HTTPS URL, whether configured explicitly or auto-discovered via the OpenID Connect configuration endpoint.

The JWKS signing key resolver is initialized to fetch and cache the IdP's public signing keys.

#### 4.3.2 `confirmInstance()` — Attestation Verification

1. **Extract authorization code and code verifier** from `attestationData`:
   - The attestation data is parsed as an `&`-delimited string of key=value pairs.
   - The `code=` parameter is extracted and URL-decoded. If no `code=` parameter is present, the request is rejected.
   - The `code_verifier=` parameter, if present, is extracted and URL-decoded (used for PKCE).

2. **Exchange auth code for access token** — POST to IdP token endpoint:
   ```
   POST <tokenEndpoint>
   Content-Type: application/x-www-form-urlencoded

   grant_type=authorization_code
   &client_id=<clientId>
   &redirect_uri=<redirectUri>
   &client_secret=<clientSecret>   (if configured)
   &code=<authCode>
   &code_verifier=<codeVerifier>   (if present)
   ```
   - When `client_secret` is not configured, PKCE is required: the `code_verifier` must be present in the attestation data or the request is rejected.
   - When `client_secret` is configured, `code_verifier` is optional but included when present.
   - Parse response as `AccessTokenResponse`.
   - Extract `access_token` field.

3. **Validate JWT access token**:
   - Parse and verify the JWT signature using the JWKS signing key resolver.
   - This validates the token was signed by the configured IdP.

4. **Validate token subject** (`validateTokenSubject`):
   - Check if `sub` claim equals the `userName` (without domain prefix), OR
   - Check if `sub` claim equals the full principal name (`<domain>.<userName>`), OR
   - If `userNameClaim` is configured, check if that custom claim equals `userName` or the full principal name.
   - If none match, reject with "Subject token does not match."

5. **Validate audience**:
   - The token's `aud` claim must match the configured `audience` value exactly.

#### 4.3.3 `refreshInstance()` — Explicitly Forbidden

`refreshInstance()` always throws a `FORBIDDEN` error. User certificates cannot be refreshed; a new IdP authentication is required for each certificate.

---

## 5. Security Analysis

### 5.1 Authentication Chain

```
User Identity ──► IdP Authentication ──► OAuth2 Auth Code ──► Access Token ──► X.509 Certificate
     │                    │                      │                   │                  │
     │              MFA/Password          Single-use code      JWT signed by      Short-lived,
     │              verified by IdP       bound to redirect    IdP private key    client-only cert
     │                                   URI + client_id                         max 60 min default
```

The authentication chain provides defense in depth:

1. **IdP authenticates the user** — The IdP performs the actual identity verification (password, MFA, etc.).
2. **Auth code is single-use** — The IdP authorization code can only be exchanged once for a token.
3. **Server-side code exchange** — The auth code is exchanged for a token on the ZTS server, not the client. The exchange is protected by either a client secret (when configured) or PKCE (required when no client secret is configured).
4. **JWT signature verification** — The access token's signature is verified against the IdP's JWKS keys.
5. **Subject binding** — The token's subject must match the requested user name.
6. **Certificate constraints** — The issued certificate is client-only, short-lived, and cannot be refreshed.

### 5.2 Threat Model

#### 5.2.1 Stolen Authorization Code

**Threat:** An attacker intercepts the OAuth2 authorization code from the callback.

**Mitigations:**
- The callback server binds to `localhost` only, limiting interception to local processes.
- The auth code is single-use — the legitimate code exchange by ZTS will invalidate it.
- When `client_secret` is configured, the attacker also needs the server-side secret.
- When PKCE is enabled (default), the auth code is bound to the code verifier via the S256 challenge. An attacker who intercepts the code cannot exchange it without the verifier, which never leaves the client-to-ZTS path.
- The callback server shuts down immediately after receiving the code.

#### 5.2.2 Phishing / Redirect URI Manipulation

**Threat:** An attacker substitutes a malicious redirect URI to capture the auth code.

**Mitigations:**
- The `redirect_uri` is fixed to `http://localhost:<port>/oauth2/callback` on both client and server.
- The IdP is configured with allowed redirect URIs and must validate the URI matches.
- The server-side `redirectUri` is configured independently and must match the IdP configuration.

#### 5.2.3 Token Replay

**Threat:** An attacker replays a captured access token to request a certificate for the same user.

**Mitigations:**
- The access token is exchanged server-side; the client never sees it.
- The attestation data (auth code) is single-use at the IdP.
- Token expiry limits the replay window.

#### 5.2.4 Man-in-the-Middle on IdP Communication

**Threat:** An attacker intercepts communication between ZTS and the IdP.

**Mitigations:**
- Token endpoint communication uses HTTPS — enforced at provider initialization (non-HTTPS URLs are rejected).
- JWKS keys are fetched over HTTPS — also enforced at provider initialization.
- Connection and read timeouts prevent indefinite hanging (10s connect, 15s read).

#### 5.2.5 CSR Manipulation

**Threat:** An attacker modifies the CSR to include unauthorized SANs or a different identity.

**Mitigations:**
- **CN must match** the requested `name` field exactly.
- **DNS SANs are forbidden** — `X509UserCertRequest` rejects any DNS names.
- **IP SANs are forbidden** — `X509UserCertRequest` rejects any IP addresses.
- **Instance ID must be null** — Cannot request instance-specific certificates.
- **URI SANs** — At most one URI SAN, which must be a valid SPIFFE URI matching the user's namespace.
- **Subject O field** — Must be in the server's allow-list (`validCertSubjectOrgValues`).
- **Certificate usage** — Forced to `client` only; cannot be used as a server certificate.

#### 5.2.6 Certificate Lifetime Abuse

**Threat:** A user requests an excessively long certificate lifetime.

**Mitigations:**
- Server enforces `userCertMaxTimeout` (default: 60 minutes).
- Requested expiry is capped at the maximum regardless of the client's request.
- Certificates cannot be refreshed — `refreshInstance()` always throws `FORBIDDEN`.

#### 5.2.7 Impersonation via User Name Mismatch

**Threat:** An attacker authenticates as one user but requests a certificate for a different user.

**Mitigations:**
- The `validateTokenSubject()` method verifies that the access token's subject (or configured custom claim) matches the requested user name.
- Both short name (`userName`) and full name (`domain.userName`) forms are checked.
- The `userAuthority` independently verifies the user is active.

#### 5.2.8 Local Callback Port Hijacking

**Threat:** A malicious local process binds to port 9213 before the CLI starts.

**Mitigations:**
- The timeout mechanism (default 45s) ensures the CLI doesn't hang indefinitely if the callback never arrives.
- The CLI process would receive a "port already in use" error, preventing the flow from proceeding.

### 5.3 Trust Assumptions

1. **The IdP is trusted** — The entire scheme relies on the IdP correctly authenticating users and issuing valid tokens.
2. **The user's workstation is trusted** — The private key resides on the user's machine; the localhost callback server assumes no malicious local processes.
3. **The ZTS server's `userAuthority` is authoritative** — It determines whether a user is active and eligible for certificates.
4. **TLS is correctly configured** — Communication between the CLI and ZTS is over TLS; the CLI supports custom CA certificates.
5. **The cert signer is trusted** — ZTS delegates certificate signing to a configured cert signer.

---

## 6. Configuration Summary

### 6.1 ZTS Server Configuration

```properties
# Provider class for user certificate attestation
athenz.zts.user_cert_provider=<provider-class-name>

# Certificate lifetime limits (in minutes)
athenz.zts.user_cert_max_timeout=60
athenz.zts.user_cert_default_timeout=60

# IdP Configuration (UserCertificateProvider)
athenz.zts.user_cert.idp_config_endpoint=https://idp.example.com/.well-known/openid-configuration
athenz.zts.user_cert.idp_client_id=athenz-user-cert
athenz.zts.user_cert.idp_redirect_uri=http://localhost:9213/oauth2/callback
athenz.zts.user_cert.idp_audience=athenz-user-cert

# Client secret (fetched from PrivateKeyStore)
athenz.zts.user_cert.idp_client_secret_app=athenz
athenz.zts.user_cert.idp_client_secret_keygroup=user-cert
athenz.zts.user_cert.idp_client_secret_keyname=idp-client-secret

# Timeouts
athenz.zts.user_cert.connect_timeout=10000
athenz.zts.user_cert.read_timeout=15000

# Optional: custom claim for user name mapping
athenz.zts.user_cert.user_name_claim=preferred_username
```

### 6.2 Client Configuration

```bash
zts-usercert \
  --zts https://zts.example.com/zts/v1 \
  --private-key ~/.athenz/user-key.pem \
  --user johndoe \
  --idp-endpoint https://idp.example.com/oauth2/authorize \
  --idp-client-id athenz-user-cert \
  --cert-file ~/.athenz/user-cert.pem \
  --subj-o "Example Inc." \
  --subj-ou "Athenz" \
  --spiffe-trust-domain athenz.example.com \
  --expiry-time 30
```

---

## 7. Key Design Decisions

### 7.1 Authorization Code Flow (not Implicit/Device)

The OAuth2 Authorization Code flow was chosen because:
- It allows **server-side token exchange** with a client secret, preventing token exposure to the client.
- It leverages the user's browser for IdP authentication, supporting MFA and SSO.
- The authorization code is single-use and short-lived.

### 7.2 PKCE Support (RFC 7636)

The implementation supports Proof Key for Code Exchange (PKCE) per RFC 7636 with the S256 challenge method. When PKCE is enabled on the client:

1. The CLI generates a random code verifier (32 bytes, base64url-encoded) and computes the S256 challenge.
2. The code challenge is sent with the authorization request to the IdP.
3. The code verifier is included in the attestation data sent to ZTS.
4. The provider forwards the code verifier to the IdP token endpoint during the code exchange.

PKCE is required on the server side when no client secret is configured, ensuring that the authorization code cannot be exchanged without proof of possession. This is the recommended configuration for public/native clients where a client secret cannot be securely stored.

### 7.3 Attestation Data = Raw Query String

The attestation data sent to ZTS is the raw query string from the OAuth2 callback (e.g., `code=AUTH_CODE&state=STATE`), with the PKCE code verifier appended when PKCE is enabled (e.g., `code=AUTH_CODE&state=STATE&code_verifier=VERIFIER`). The provider parses this as `&`-delimited key=value pairs to extract the `code` and optional `code_verifier`. This design:
- Keeps the client simple — it forwards the callback data with minimal transformation.
- Allows the provider to be extended to validate additional parameters if needed.
- Supports PKCE by carrying the code verifier alongside the authorization code in a single string.

### 7.4 No Certificate Refresh

User certificates explicitly cannot be refreshed. Each new certificate requires a fresh IdP authentication. This ensures:
- Revoked/disabled users cannot continue using existing certificates after their current one expires.
- The user's active status is re-verified with each certificate issuance.
- Short lifetimes (max 60 minutes default) limit exposure of compromised certificates.

### 7.5 Client-Only Certificate Usage

Certificates are issued with `client` usage only. This prevents a user certificate from being used as a server certificate, limiting its utility in case of compromise.

### 7.6 SPIFFE URI Support

The CSR can optionally include a SPIFFE URI SAN (`spiffe://<trustDomain>/ns/default/sa/<userName>`). This enables integration with SPIFFE-aware systems while being validated against the server's configured SPIFFE URI validators.

### 7.7 Audit Support

Certificate issuance is logged via `instanceCertManager.logX509Cert()`. The log includes the remote address, service name, principal name, and certificate details. This provides an audit trail for all issued user certificates.

---

## 8. Other Considerations

1. **Client secret and PKCE** — The client secret is optional. When not configured, PKCE (RFC 7636) is required: the client must include a `code_verifier` in the attestation data, and the provider will reject requests without one. When a client secret is configured, PKCE is optional but supported — the code verifier is forwarded to the IdP when present. The CLI enables PKCE by default (`--pkce=true`).

2. **Rate limiting** — The ZTS API endpoint returns `TOO_MANY_REQUESTS` (429) as a possible error code, but the rate limiting implementation is outside this feature's scope. Deployers should consider rate limiting to prevent abuse.
