# External Policy Decision Point (PDP) Integration for OAuth Token Issuance - Design Document

**Date:** November 2026
**Status:** Implemented (revision 2)
**Components:** ZTS Server (`POST /oauth2/token`), `libs/java/server_common` (`com.yahoo.athenz.common.server.pdp`)
**Supersedes:** `docs/design/external-pdp-integration.md` (revision 1, in the `athenz` repo)

---

## 1. Overview

This feature lets ZTS consult an external Policy Decision Point (PDP) when deciding which
scopes (roles) and claims go into an OAuth2 access token. The PDP is either:

- **Inline**: a Java class loaded into the ZTS JVM (`class://` scheme), following the same
  model as `InstanceProvider` class providers, or
- **Remote**: an HTTPS endpoint, which may be a sidecar in the same pod (e.g. EKS) or a
  shared remote service (`https://` scheme).

The PDP request/response **model objects** follow the **OpenID AuthZEN Authorization
API 1.0** as closely as possible: same entity names, same field names, same JSON shape.
ZTS does **not** assume the PDP itself speaks AuthZEN. PDPs fall into three levels of
compliance, and the design supports all of them (section 5.1):

| PDP | How it is integrated |
|---|---|
| Fully AuthZEN compliant (Access Evaluations batch) | Built-in `AuthZenHttpPdp`, configuration only. The model serializes directly to the wire. |
| Partially compliant (for example single Access Evaluation only, no batch) | Built-in `AuthZenHttpPdp` with capability properties. ZTS fans out single evaluations. |
| Not AuthZEN at all (custom REST, gRPC, vendor SDK, in-process engine) | A `class://` adapter implementing `ExternalPolicyDecisionPoint`. It translates the AuthZEN-shaped model to the PDP's own protocol. |

Because ZTS always works with the same AuthZEN-shaped model, the processing, decision
interpretation, logging and tests are identical regardless of the PDP behind it. A
deployment can later move from a custom adapter to a compliant PDP without any change in
ZTS semantics.

The feature is **disabled by default**. When disabled, no new code is reachable from the
token endpoint and existing token issuance is byte-for-byte unchanged.

### 1.1 Goals

- Allow a centralized, organization-wide PDP to **narrow** RBAC-granted scopes (FILTER).
- Allow deployments that do not use Athenz RBAC for scopes at all to make the PDP the
  **sole authority** for token scopes (AUTHORITATIVE).
- Allow the PDP to contribute **additional claims** to issued access tokens, behind a
  separate opt-in and strict guardrails.
- Provide a zero-impact **AUDIT** (shadow) mode to validate PDP decisions in production.
- Keep the PDP code path **physically separate** from the existing token issuance code so
  both can coexist long-term with minimal maintenance coupling.

### 1.2 Non-Goals (v1)

- PDP evaluation for role X.509 certificates and role tokens. These are Athenz-specific
  RBAC credentials that don't make sense in a PDP-governed deployment. They are
  **explicitly rejected** while the PDP is enforcing (section 6.4), not routed to the
  PDP.
- ID token exchange (`ID_TOKEN_EXCHANGE`) and the `/oauth2/auth` ID token endpoint. These
  don't carry role scopes and continue on the legacy path.
- Per-domain PDP selection or per-domain modes. The configuration is server-wide (global).
- ZMS management-API authorization.
- Decision caching and circuit breaking inside ZTS. These are PDP implementation concerns
  (section 10.3).
- PDP evaluation for any ZTS API other than `POST /oauth2/token`. AWS temporary
  credentials and the read-only role lookups (`getRoleAccess`, `getAccess`,
  `getRolesRequireRoleCert`) stay Athenz RBAC only (section 6.4).
- Non-TLS transports (plain HTTP, unix sockets).

---

## 2. Critique of Revision 1 and Summary of Changes

| # | Revision 1 | Issue | Revision 2 |
|---|---|---|---|
| 1 | Hook placed after `getAccessibleRoles` at "line 3465" and in `processAccessTokenExchangeRequest` | Line numbers are stale (`ZTSImpl.java` is now ~8.3K lines). The standard flow now supports **multi-domain scopes** (per-domain loop, `ZTSImpl.java:4386-4466`) and `proxy_for_principal` intersection (`:4437`). Token exchange is split into impersonation (`:3222`) and delegation (`:3462`), and there are two new ID-JAG flows (`:3837`, `:4023`). Two call sites no longer cover the surface. | Flow-by-flow integration semantics (section 7) and one batched PDP call per token request, covering all scope domains. |
| 2 | Hook inserted inside existing `ZTSImpl` methods; `applyExternalPDP()` helper in `ZTSImpl` | Mixes PDP logic into the most security-sensitive and most frequently changed class. The two paths are expected to coexist for years. | A separate processor class and package. `ZTSImpl` gets a field, a loader call, one dispatch `if` and a close call (section 8). AUDIT mode does not touch the legacy path at all. |
| 3 | Custom DTOs (`authorizedRoles`, `denyAll`, `errorDetail`) | Non-standard, and the model isn't usable as-is by AuthZEN PDPs. | Model objects mirror AuthZEN 1.0 Access Evaluation(s). Compliant PDPs use them as the wire format; non-compliant PDPs use them through a `class://` adapter. `denyAll` becomes a token-level evaluation; per-role decisions replace `authorizedRoles`. |
| 3a | Role certs and role tokens not addressed | In an enforcing deployment they become an RBAC-only side door around the PDP. | Explicitly rejected in FILTER and AUTHORITATIVE modes. Usage is metered in AUDIT mode (section 6.4). |
| 4 | Modes AUDIT / FILTER / REPLACE / AUGMENT | REPLACE and AUGMENT were defined as set operations without saying which other ZTS checks still apply (role-cert binding, exchange authorization, token timeouts). AUGMENT (`rbac ∪ pdp`) can be expressed entirely inside the PDP in AUTHORITATIVE mode. | DISABLED / AUDIT / FILTER / AUTHORITATIVE, with an explicit invariant table (section 6.3). AUGMENT is dropped. |
| 5 | `additionalClaims` as an open question | Left the trust expansion unspecified. | Supported, behind a separate property, with a reserved-claim denylist, optional allowlist, size and depth limits, and no override of standard or Athenz claims (section 9). |
| 6 | Timeout "inside applyExternalPDP() or delegated?" | Unresolved. Inline class PDPs can block request threads indefinitely. | ZTS enforces an overall deadline and a concurrency bulkhead for both schemes (section 10). |
| 7 | Fallback on error defaulted to RBAC | Not meaningful when RBAC is not used (AUTHORITATIVE). | Fail mode is defined per mode: AUDIT is always open, FILTER is configurable, AUTHORITATIVE is always closed (section 10.2). |
| 8 | Not covered | Shadow evaluation adds latency to every request. | AUDIT evaluations run asynchronously off the request thread and add zero latency to token issuance. |

---

## 3. Terminology

| Term | Meaning |
|---|---|
| PEP | Policy Enforcement Point, here the ZTS token endpoint. |
| PDP | Policy Decision Point, the external authorization engine. |
| Legacy path | The existing `ZTSImpl.process*Request` methods, unchanged by this feature. |
| PDP path | The new `ExternalPdpTokenProcessor` flows used in FILTER and AUTHORITATIVE modes. |
| Candidate roles | The set of roles submitted to the PDP for evaluation in a given request. |
| Token gate | A single per-request evaluation that authorizes token issuance as a whole and carries token-level response context (claims, max expiry). |

---

## 4. Architecture

```
                         POST /oauth2/token
                                 │
                       ZTSImpl.postAccessTokenRequest
          (authN, body parsing, DPoP validation — unchanged)
                                 │
            externalPdpProcessor != null && handles(requestType)?
                 ┌───────────── no ─────────────┐
                 │                              │ yes
                 ▼                              ▼
   legacy switch (unchanged)       ExternalPdpTokenProcessor   (com.yahoo.athenz.zts)
   processAccessTokenStandard…       │  mode AUDIT ─► legacy method issues token
   processAccessTokenExchange…       │               + async shadow evaluation
   processJAG…                       │  mode FILTER / AUTHORITATIVE ─► PDP-path flows
                                     ▼
                          ExternalPdpManager            (com.yahoo.athenz.zts.pdp)
                          - AuthZEN request builder
                          - deadline + bulkhead executor
                          - decision log, metrics
                          - additional-claims validator
                                     │
                    ExternalPolicyDecisionPoint (interface, server_common)
                     ┌───────────────┴────────────────┐
                     ▼                                ▼
          class://com.example.MyPdp        https://pdp.example.com:4443
          (inline adapter, in-JVM)         AuthZenHttpPdp (built-in)
          ─► embedded engine               ─► sidecar (https://localhost:8443)
          ─► non-AuthZEN PDP (any proto)   ─► remote AuthZEN PDP (full or partial)
```

---

## 5. PDP Provider Model

### 5.1 Layers: Model vs. Wire Protocol

The design separates two concerns that revision 1 combined:

| Layer | Owned by | Contract |
|---|---|---|
| **Decision model** | Athenz (`server_common`, `com.yahoo.athenz.common.server.pdp.authzen`) | AuthZEN-shaped Java objects (section 5.3). ZTS always builds requests and interprets responses in this model. This is the only contract ZTS relies on. |
| **Wire protocol** | The `ExternalPolicyDecisionPoint` implementation | Whatever the PDP speaks. The built-in `AuthZenHttpPdp` speaks AuthZEN over HTTPS. Custom adapters speak anything else. |

ZTS never sends HTTP itself and never assumes AuthZEN on the wire. That is an
implementation detail of the configured PDP class. Deployments therefore fall into one of
three integration levels:

| Integration level | Endpoint | What the operator provides |
|---|---|---|
| **A. Fully AuthZEN compliant** (Access Evaluations batch) | `https://pdp.example.com` | Configuration only. The model serializes to and from the AuthZEN JSON unchanged. |
| **B. Partially AuthZEN compliant** (for example only single `/access/v1/evaluation`, no batch, non-standard paths) | `https://pdp.example.com` | Configuration only. `AuthZenHttpPdp` capability properties (section 5.6) make ZTS fan out single evaluations and remap paths. |
| **C. Not AuthZEN** (custom REST, gRPC, vendor SDK, embedded engine such as Cedar or OPA-WASM) | `class://com.example.MyPdpAdapter` | A class that implements `ExternalPolicyDecisionPoint` and translates the model to the PDP's protocol. |

Endpoint resolution mirrors `InstanceProviderManager`:

| Endpoint | Implementation |
|---|---|
| `class://<fqcn>` | ZTS instantiates the class through its public no-arg constructor. |
| `https://host[:port][/base-path]` | ZTS instantiates the built-in `com.yahoo.athenz.common.server.pdp.impl.AuthZenHttpPdp`. |
| anything else | ZTS fails to start. |

Only one PDP is configured per ZTS server.

### 5.2 Interface (`libs/java/server_common`)

The interface, model and built-in HTTPS implementation live in `athenz-server-common`,
which plugin implementers already depend on for other Athenz extension points
(`PrivateKeyStore`, `Metric`, `RolesProvider`, and others). No new Maven module is
needed.

- **Packages:**
  - `com.yahoo.athenz.common.server.pdp`: interface, context and exception
  - `com.yahoo.athenz.common.server.pdp.authzen`: model objects
  - `com.yahoo.athenz.common.server.pdp.impl`: `AuthZenHttpPdp`
- **Dependencies:** only what `server_common` already declares (Jackson, Jersey client).
- **Java level:** the project compiles to Java 11, so model types are immutable final
  classes with builders, not records.

The interface has two levels of granularity, so adapters for simple PDPs implement only
what they need:

```java
package com.yahoo.athenz.common.server.pdp;

public interface ExternalPolicyDecisionPoint {

    /**
     * Called once at ZTS startup. Implementations read any additional
     * implementation-specific configuration from system properties.
     */
    void initialize(ExternalPdpContext context) throws ExternalPdpException;

    /**
     * Single decision (AuthZEN Access Evaluation). Implement this method for PDPs
     * that only answer one question at a time.
     */
    default EvaluationResponse evaluate(EvaluationRequest request) throws ExternalPdpException {
        throw new ExternalPdpException(ExternalPdpException.Code.UNSUPPORTED, "single evaluation not supported");
    }

    /**
     * Batch decision (AuthZEN Access Evaluations). ZTS always calls this method.
     * The default expands the batch into sequential evaluate() calls, applying the
     * AuthZEN default-value inheritance for subject/action/resource/context.
     * Implementations may call ExternalPdpSupport.expandBatch(this, request, executor)
     * with the context executor to run single calls in parallel; PDPs with native
     * batch support override it.
     * Must be thread-safe and return exactly one result per evaluation, in request order.
     */
    default EvaluationsResponse evaluations(EvaluationsRequest request) throws ExternalPdpException {
        return ExternalPdpSupport.expandBatch(this, request, null);
    }

    default void close() {
    }
}
```

An adapter must override at least one of `evaluate` or `evaluations`. ZTS checks at
startup that the class overrides at least one of them, so a misconfigured adapter fails
fast.

**Why no Resource Search.** The PDP is only consulted for token issuance, where the
candidate roles are always known before the PDP is called. They come from RBAC (FILTER),
from the explicitly requested roles, or for a domain-wide scope in AUTHORITATIVE mode from
the roles defined in the domain (section 7.4). Access Evaluation(s) is therefore the whole
contract, and adapters never need to implement AuthZEN Search.

`ExternalPdpContext` (immutable) provides:

| Field | Description |
|---|---|
| `endpoint` | The configured endpoint URI string. |
| `sslContext` | ZTS client SSL context (`ZTSUtils.getAthenzProviderClientSSLContext`), or the dedicated PDP trust store if configured (section 5.6). Adapters may use it to reach their own backends over mTLS. |
| `rolesProvider` | Read-only `RolesProvider` over the ZTS in-memory domain data (same type passed to `InstanceProvider.setRolesProvider`), so adapters can look up role definitions and tags without a network hop. |
| `privateKeyStore` | The ZTS-configured `PrivateKeyStore`. Implementations use `getSecret(appName, keygroupName, keyName)` to obtain PDP credentials other than mTLS, such as API keys, bearer tokens or client secrets. Secrets never appear in properties or logs. |
| `executor` | Bounded ZTS-owned executor for adapters that fan out calls (section 10.1). |
| `connectTimeoutMs`, `readTimeoutMs` | Transport timeouts. |

`ExternalPdpException` carries a `Code` (`UNAVAILABLE`, `TIMEOUT`, `INVALID_RESPONSE`,
`UNSUPPORTED`, `INTERNAL`) that ZTS uses for metrics and fail-mode handling.

### 5.3 Model Objects (AuthZEN-aligned)

Package `com.yahoo.athenz.common.server.pdp.authzen`. Class names, field names and JSON property names
follow AuthZEN 1.0, so level-A PDPs need no mapping. Every object keeps unknown JSON
fields received from a PDP (`@JsonAnySetter` into an `extensions` map) instead of failing,
which makes ZTS tolerant of PDPs that extend AuthZEN or of later spec revisions.

| Class | AuthZEN object | Fields (JSON names) |
|---|---|---|
| `Subject` | Subject | `type` (required), `id` (required), `properties` |
| `Resource` | Resource | `type` (required), `id` (required), `properties` |
| `Action` | Action | `name` (required), `properties` |
| `EvaluationRequest` | Access Evaluation request | `subject`, `action`, `resource`, `context` |
| `EvaluationResponse` | Access Evaluation response | `decision` (required boolean), `context` |
| `EvaluationsRequest` | Access Evaluations request | Default `subject`, `action`, `resource`, `context`; `evaluations` (list of `EvaluationRequest` with per-item overrides); `options` |
| `EvaluationsOptions` | `options` | `evaluations_semantic` (`execute_all`, `deny_on_first_deny`, `permit_on_first_permit`) |
| `EvaluationsResponse` | Access Evaluations response | `evaluations` (list of `EvaluationResponse`) |

`properties` and `context` are `Map<String, Object>`, copied defensively and exposed as
unmodifiable maps.

**Athenz conventions.** ZTS uses these fields on top of the AuthZEN model, and they are
specified in this document, not in AuthZEN:

- the resource and action vocabulary in section 7.1
- the request `context` keys in section 7.1
- the response `context` keys `claims`, `max_expires_in`, `reason_admin` and
  `reason_user` in section 7.3

They are carried in AuthZEN's free-form `properties` and `context` maps, so compliant PDPs
can consume and produce them without any protocol extension. `reason_admin` and
`reason_user` follow AuthZEN's own examples.

### 5.4 Response Validation (all PDPs)

ZTS validates every response the same way, whatever the integration level:

- `evaluations` size must equal the request's `evaluations` size. Anything else is
  `INVALID_RESPONSE`.
- A missing or non-boolean `decision` means `false` (deny) for that item. That item can't
  carry claims.
- `context.max_expires_in` must be a positive integer. Otherwise it is ignored and logged.
- `context.claims` must be a JSON object. Otherwise it is rejected per section 9.

### 5.5 Inline (class) PDP

- Loaded once at startup. An initialization failure fails ZTS startup, the same as
  `loadCertificateDataValidator`.
- Runs in-JVM, but ZTS still applies the deadline and bulkhead (section 10.1), so a slow
  or blocked plugin cannot exhaust Jetty request threads.
- Typical uses:
  - an adapter for a non-AuthZEN remote PDP
  - an embedded engine (Cedar, OPA-WASM)
  - ABAC over Athenz role tags via `rolesProvider`
  - a vendor SDK client

### 5.6 Built-in HTTPS PDP (`AuthZenHttpPdp`)

**Endpoints and capabilities.** Paths are relative to the configured base URI and can be
overridden for PDPs that mount AuthZEN elsewhere.

| Property (`athenz.zts.external_pdp.https.*`) | Default | Purpose |
|---|---|---|
| `batch_enabled` | `true` | `true`: one `POST {base}{evaluations_path}` per token request. `false`: `AuthZenHttpPdp` fans out `POST {base}{evaluation_path}` per item, in parallel on the context executor and bounded by the deadline (level-B PDPs). |
| `evaluations_path` | `/access/v1/evaluations` | AuthZEN batch endpoint. |
| `evaluation_path` | `/access/v1/evaluation` | AuthZEN single endpoint. |
| `discovery` | `false` | Read `/.well-known/authzen-configuration` once at startup and derive endpoints and batch capability from it. Discovered endpoints must have the same scheme, host and port as the configured base URI. Explicit properties override discovered values. |

**Transport and handling.**

- **TLS only.** The ZTS server enforces the `https` scheme. Hostname verification uses the
  standard HTTPS verifier against the configured host.
- **Client authentication:** mTLS with the ZTS service identity certificate, so the PDP can
  authorize its PEP. Sidecars must terminate TLS too (for example
  `https://localhost:8443` with a certificate that has a `localhost` SAN).
- **Additional authentication (optional):** for PDPs that need more than mTLS (an API key
  or a static bearer token), `AuthZenHttpPdp` sends a configured header:
  - The header name comes from `auth_header_name` (for example `Authorization` or `X-API-Key`).
  - The value comes from `PrivateKeyStore.getSecret(auth_secret_app_name,
    auth_secret_keygroup_name, auth_secret_key_name)`, prefixed with `auth_header_prefix`
    (for example `Bearer `).
  - The secret is fetched at startup and on each refresh interval
    (`auth_secret_refresh_secs`, default 3600), so rotation needs no restart.
  - Schemes that need per-request token minting, such as an OAuth client-credentials grant
    against the PDP's authorization server, are integration level C (a `class://`
    adapter using `privateKeyStore`).
- **Trust store and client certificate:** ZTS passes the same client SSL context it uses
  for HTTPS instance providers (`ZTSUtils.getAthenzProviderClientSSLContext`). Its
  existing `athenz.zts.provider.ssl_client_*` properties (`ssl_client_trust_store`,
  `ssl_client_public_cert_path`, `ssl_client_private_key_path`, ...) select the trust
  store and client certificate. A sidecar whose certificate comes from a pod-local or
  mesh CA is supported by pointing that trust store at the CA. No separate PDP trust
  store properties are introduced.
- **No retries, redirects or cookies:** a failed call is reported once and ZTS applies
  its fail mode. Request and response bodies are never logged.
- **Correlation:** each request carries an `X-Request-ID` header (as recommended by
  AuthZEN). ZTS generates a UUID per token request and logs it with the decision.
- **Status handling:** `200` responses are parsed into the model. Everything else is an
  `ExternalPdpException`. Responses larger than `max_response_bytes` (default 64 KB) are
  rejected.
- **Connection management:** pooled Apache connector (the same connector stack as
  `InstanceProviderClient`). Pool size is aligned with the bulkhead size.

Other HTTP protocols, such as a custom REST contract, are integration level C. They are
handled by a `class://` adapter, which may reuse the `AuthZenHttpClient` transport helper
from the module.
---

## 6. Operating Modes

### 6.1 Mode Definitions

| Mode | Token is issued by | PDP influence on the issued token | PDP call |
|---|---|---|---|
| `DISABLED` *(default)* | Legacy path | None | Never |
| `AUDIT` | Legacy path, unmodified | None. The diff is logged and metered. | Asynchronous, after the response is computed |
| `FILTER` | PDP path | Can remove RBAC-granted roles, deny the token, add claims, and lower expiry | Synchronous |
| `AUTHORITATIVE` | PDP path | Decides scopes (RBAC is not consulted), can deny the token, add claims, and lower expiry | Synchronous |

`athenz.zts.external_pdp.audit_target` (`FILTER` | `AUTHORITATIVE`, default `FILTER`)
selects which enforcing mode AUDIT simulates. Operators can therefore shadow-test either
rollout target before enforcing it.

### 6.2 Recommended Rollout

| Step | Configuration | Token impact |
|---|---|---|
| 1 | `mode=AUDIT`, `audit_target=FILTER` | None. Also identifies clients still using role certificates or role tokens (section 6.4) so they can migrate to access tokens. |
| 2 | `mode=FILTER` | Scopes can only shrink. Role certificates and role tokens are rejected. |
| 3 (optional, RBAC-free deployments) | `mode=AUDIT`, `audit_target=AUTHORITATIVE` | None |
| 4 (optional) | `mode=AUTHORITATIVE` | The PDP owns scopes |

Each step is a property change and a ZTS restart. No code deployment is needed.

### 6.3 Invariants per Mode

ZTS keeps a check whenever it protects **authentication binding or token integrity**.
Checks that express **authorization policy** move to the PDP only in AUTHORITATIVE mode.

| Check (existing) | Category | AUDIT / FILTER | AUTHORITATIVE |
|---|---|---|---|
| Client authentication, request parsing, DPoP proof validation | AuthN | Kept | Kept |
| Domain existence for audience and scope domains | Integrity | Kept | Kept |
| Multi-domain scope requires audience, and audience is one of the scope domains | Integrity | Kept | Kept |
| `validateProxyForPrincipalValue` (configured allow-list) | AuthN binding | Kept | Kept |
| `checkRoleTokenAuthorizedServiceRequest` | AuthN binding | Kept | Kept |
| `isPrincipalRoleCertificateAccessValid` (role-cert principals) | AuthN binding | Kept | Kept |
| `validateAuthorizationDetails` | Integrity | Kept | Kept |
| Subject/actor token validation, actor == principal, actor DPoP `cnf.jkt` match | AuthN binding | Kept | Kept |
| Exchange scope must be a subset of the subject token scope (`tokenExchangeRequestedRoles`) | Integrity | Kept | Kept |
| `disallowAuthorizedServicePrincipal` in exchange and JAG flows | AuthN binding | Kept | Kept |
| `dataStore.getAccessibleRoles` (RBAC role resolution) | Policy | Kept (sets the ceiling) | **Replaced** by PDP evaluation |
| `authorizer.access(zts.token_source_exchange / zts.token_target_exchange)` | Policy | Kept | **Replaced** by PDP evaluation |
| `authorizer.access(zts.jag_exchange)` | Policy | Kept | **Replaced** by PDP evaluation |
| Token expiry computation (`determineTokenTimeout`, `determineTokenExchangeTimeout`) | Integrity | Kept, then `min(..., pdp max_expires_in)` | Kept, then `min(..., pdp max_expires_in)` |

In AUTHORITATIVE mode:

- `athenz.zts.external_pdp.require_defined_roles` (default `true`) requires every
  PDP-permitted role to exist in the target domain's ZTS data. Undefined roles are dropped
  and logged. Setting it to `false` lets the PDP issue scopes for roles that are not
  defined in Athenz, for deployments that do not model roles in ZMS at all. Those roles
  have no role-level expiry and fall back to domain/server defaults.
- ZTS still never issues a scope for a domain that does not exist in ZTS.

### 6.4 Role Certificates and Role Tokens

Role X.509 certificates and role tokens are Athenz-specific RBAC credentials. They can't
carry PDP decisions or claims and have no meaning in a PDP-governed deployment. If they
remained available, they would also be an RBAC-only side door around the PDP. They are
therefore **explicitly disallowed** whenever the PDP is enforcing.

| Endpoint | `ZTSImpl` method | DISABLED | AUDIT | FILTER / AUTHORITATIVE |
|---|---|---|---|---|
| `GET /domain/{domainName}/token` (role token) | `getRoleToken` (`:2307`) | Legacy | Legacy, metered | **Rejected** |
| `POST /domain/{domainName}/role/{roleName}/token` (legacy role cert, returns `RoleToken`) | `postRoleCertificateRequest` (`:4687`) | Legacy | Legacy, metered | **Rejected** |
| `POST /rolecert` (role certificate) | `postRoleCertificateRequestExt` (`:5098`) | Legacy | Legacy, metered | **Rejected** |

Rejection behavior:

- **Status:** `403 Forbidden` with the message `"<api>: role credentials are not
  supported when external PDP is enabled"`. The message is the same for every principal
  and domain, so it reveals nothing about policy.
- **Timing:** the check runs right after the principal is resolved and logged, and before
  any domain lookup or RBAC evaluation, so rejected requests are cheap and still show up
  in the access log.
- **Metering:** a metric counter `zts_ext_pdp_role_credential_rejected` with the `api`
  attribute.
- **AUDIT mode:** requests are served normally, but they increment
  `zts_ext_pdp_role_credential_request` and write a decision-log entry with `flow=role_credential`.
  Operators can find every client that would break before switching to FILTER.
- **Not configurable:** there is no property to re-enable role credentials while
  enforcing. Allowing them would reintroduce the split authority this rule exists to
  prevent.

Each of the three methods gets one guarded line at its start. This is the only change in
legacy method bodies (section 8.2):

```java
if (externalPdpProcessor != null) {
    externalPdpProcessor.checkRoleCredentialRequest(ctx, caller, principalDomain);
}
```

**Unaffected by this feature** (served by the legacy path in every mode, Athenz RBAC only):

- ID token issuance (`/oauth2/auth`, `ID_TOKEN_EXCHANGE`): no role scopes.
- Read-only role lookups (`getRoleAccess`, `getAccess`, `getRolesRequireRoleCert`).
  These are expected to be revisited when ZTS itself exposes an AuthZEN-compliant PDP API
  for external PEPs (section 15, future work). At that point AuthZEN Resource Search and
  Access Evaluation may answer these lookups.
- `getAWSTemporaryCredentials`: always based on Athenz RBAC. AWS role assumption is tied to
  Athenz role membership and the AWS trust configuration, and is out of scope for the
  external PDP.

The external PDP exists only in the branched code path of `POST /oauth2/token`.

---

## 7. Decision Model Mapping (AuthZEN-aligned)

This section defines how ZTS populates the model objects in section 5.3. The JSON examples
show the model's serialized form, which is exactly what a level-A PDP receives on the wire.
Level-B PDPs receive the same objects split into single evaluations. Level-C adapters
receive the same Java objects.

### 7.1 Common Entities

**Subject**

```json
{
  "type": "service",
  "id": "sports.api",
  "properties": {
    "domain": "sports",
    "name": "api",
    "authority": "Auth-X509",
    "issuer": "...principal issuer identity (if any)...",
    "authorized_service": "...(if any)...",
    "role_identity": false,
    "mtls": true,
    "spiffe": "spiffe://athenz.io/ns/default/sa/sports.api"
  }
}
```

`type` is `user` when the principal domain equals the configured user domain, otherwise
`service`.

**Resources**

| Purpose | `type` | `id` | `properties` |
|---|---|---|---|
| Token gate | `athenz_token` | audience domain | `token_type` (`access_token`), `scope_domains` |
| Scope role | `athenz_role` | `<domain>:role.<role>` (same as `ResourceUtils.roleResourceName`) | `domain`, `role`, `defined` (bool), `rbac_granted` (FILTER only). Role tags and other role metadata are **not** sent. |
| Exchange permission (AUTHORITATIVE) | `athenz_resource` | the exact resource string the legacy `authorizer.access` call would use | none |

**Actions**

| Purpose | `name` |
|---|---|
| Token gate | `issue_token` |
| Include role in scope | `assume_role` |
| Impersonation source check | `zts.token_source_exchange` |
| Exchange per-role target check | `zts.token_target_exchange` |
| JAG exchange check | `zts.jag_exchange` |

Exchange action names match the existing `ZTSConsts.ZTS_ACTION_*` values, so policies
ported from Athenz map one-to-one.

**Request context** (top-level `context`, inherited by every evaluation)

| Key | Description |
|---|---|
| `request_id` | Same value as the `X-Request-ID` header. |
| `time` | ISO-8601 issuance time. |
| `grant_type` | Raw grant type. |
| `request_type` | `ACCESS_TOKEN`, `ACCESS_TOKEN_EXCHANGE`, `JAG_TOKEN_EXCHANGE`, `JAG_JWT_BEARER` |
| `exchange_type` | `impersonation` or `delegation` (exchange only) |
| `client_ip` | Remote address as resolved by ZTS. |
| `audience` | Audience domain. |
| `requested_scope` | Raw `scope` parameter. |
| `requested_expires_in` | `expires_in`, if supplied. |
| `proxy_for_principal`, `actor` | If supplied. |
| `client` | Authenticated client principal, when it differs from the evaluation subject (exchange and JAG flows). |
| `subject_token` | Selected claims of the validated subject token: `iss`, `sub`, `aud`, `scope`, `client_id`, `jti`, `exp`. The token itself is never sent. |
| `actor_token` | Selected claims of the validated actor token (delegation). |
| `dpop_bound` | Whether the token will be DPoP-bound. |
| `mode` | `AUDIT`, `FILTER` or `AUTHORITATIVE`, so a PDP can distinguish shadow traffic. |

### 7.2 Evaluations Request (FILTER, standard flow example)

`sports.api` asks for `scope=sports:role.readers sports:role.writers` and RBAC grants both.

```json
POST /access/v1/evaluations
{
  "subject": { "type": "service", "id": "sports.api", "properties": { ... } },
  "action":  { "name": "assume_role" },
  "context": { "request_id": "6c1e...", "request_type": "ACCESS_TOKEN", "audience": "sports", ... },
  "evaluations": [
    { "action":   { "name": "issue_token" },
      "resource": { "type": "athenz_token", "id": "sports",
                    "properties": { "token_type": "access_token", "scope_domains": ["sports"] } } },
    { "resource": { "type": "athenz_role", "id": "sports:role.readers",
                    "properties": { "domain": "sports", "role": "readers", "defined": true, "rbac_granted": true } } },
    { "resource": { "type": "athenz_role", "id": "sports:role.writers",
                    "properties": { "domain": "sports", "role": "writers", "defined": true, "rbac_granted": true } } }
  ],
  "options": { "evaluations_semantic": "execute_all" }
}
```

- The token gate is always evaluation `[0]`.
- All scope domains of a multi-domain request go into one batch, so there is one round
  trip per token request.
- `execute_all` is required so that ZTS gets per-role decisions. A PDP that returns fewer
  or more results than evaluations produces an `INVALID_RESPONSE` error.

### 7.3 Evaluations Response

```json
{
  "evaluations": [
    { "decision": true,
      "context": {
        "max_expires_in": 900,
        "claims": { "risk_tier": "low", "entitlements": ["read:scores"] }
      } },
    { "decision": true },
    { "decision": false,
      "context": { "reason_admin": { "policy": "writers-require-mfa" } } }
  ]
}
```

ZTS interprets the response as follows:

| Element | Effect |
|---|---|
| `[0].decision == false` | The request is denied with `403` and no token is issued (replaces revision 1's `denyAll`). |
| `[0].context.max_expires_in` | Optional positive integer. Token expiry becomes `min(computed, max_expires_in)`. It can only lower expiry. |
| `[0].context.claims` | Optional additional claims (section 9). Ignored unless claims are enabled. |
| `[i>0].decision == false` | The role is removed from the token scope. |
| `[i].context.reason_admin` / `reason_user` | Logged in the decision log only. Never returned to the client, so policy internals don't leak. |
| Any other context key | Ignored and reserved for future use. |

After filtering, a scope domain with no remaining roles fails the whole request with
`403`, the same all-or-nothing per-domain behavior as the legacy path.

### 7.4 Domain-wide Scope in AUTHORITATIVE Mode

When the client requests all roles in a domain (`scope=sports:domain`), RBAC can't supply
candidates in AUTHORITATIVE mode. ZTS uses the roles defined in the domain instead:

- With `require_defined_roles=true` (default), every role defined in the domain's ZTS
  data becomes a candidate. All of them are sent in the single Evaluations batch, and the
  PDP permits the ones the subject may have.
- With `require_defined_roles=false`, roles aren't modeled in Athenz, so there is nothing
  to enumerate. Domain-wide scope requests return `400 invalid_scope` and the client must
  request explicit roles.
- `athenz.zts.external_pdp.max_candidate_roles` (default 64) bounds the number of roles
  per domain sent to the PDP, for explicit and enumerated scopes alike. Larger requests
  return `400 invalid_scope` instead of issuing a partial token silently.

This keeps the contract to Access Evaluation(s) only (section 5.2).

---

## 8. Code Separation Strategy

### 8.1 Principle

> When `mode=DISABLED`, no PDP class is instantiated and the only new code executed per
> request is one null check. In `AUDIT` mode, tokens are still produced by the legacy
> methods without modification. Only `FILTER` and `AUTHORITATIVE` route requests through
> the new flow implementations.

### 8.2 Changes to Existing Files

| File | Change |
|---|---|
| `ZTSImpl.java` | (1) a field `ExternalPdpTokenProcessor externalPdpProcessor` (null by default); (2) `loadExternalPdpProcessor()` as the last step of the constructor, which passes explicit, fully initialized server objects (`DataStore`, `ZTSAuthorizer`, `IssuerResolver`, `ProviderConfigManager`, `Metric`, validator, user domain, SPIFFE manager, signing keys, `TokenIssuanceConfig`) and the legacy flow as a callback; (3) one guarded dispatch in `postAccessTokenRequest`. The request-type switch moved verbatim into `processAccessTokenRequestType`, which is also the AUDIT-mode callback. The processor holds no `ZTSImpl` reference. ZTSImpl has no shutdown hook; the PDP executors use daemon threads. |
| `ZTSImpl.java` | The token-issuance settings (role/id/JAG token timeouts, authorized proxy users, authorization-details limit and system file, unrequested-roles logging) moved into the immutable `com.yahoo.athenz.zts.token.TokenIssuanceConfig`. It is loaded once by `loadTokenIssuanceConfig()`, which replaces `loadSystemAuthorizationDetails()`, with unchanged property names, defaults and failure behavior. Both paths read this single source of truth. Server-wide state (signing keys, validator, user domain, SPIFFE manager) stays in `ZTSImpl` and is passed as references. |
| `ZTSImpl.java` | One guarded `checkRoleCredentialRequest` line at the start of `getRoleToken`, `postRoleCertificateRequest` and `postRoleCertificateRequestExt` (section 6.4). This is the only change inside legacy method bodies. It is a no-op when the processor is null (DISABLED). |
| `servers/zts/conf/zts.properties` | Commented-out property block. |
| `ZTSImpl.java` | The token-issuance helpers shared by the legacy and PDP-path flows were moved, logic only, into `com.yahoo.athenz.zts.token.TokenIssuancePolicy`. That class is stateless: server configuration and a `TokenIssuanceErrors` factory are passed in. Each `ZTSImpl` helper keeps its signature as a one-line wrapper that passes its current field values and its own `requestError`/`forbiddenError`. The moved helpers are the expiry calculations, signing key selection, proxy and authorized-service checks, role-certificate check, authorization-details validation, SPIFFE checks, token-exchange role resolution, audience validation, scope generation, token confirmation, JAG access-log data and `validate`. Legacy flow bodies, logging, metrics and existing tests are unchanged, and the state stays in `ZTSImpl`. |
| `libs/java/server_common` | New `pdp`, `pdp.authzen` and `pdp.impl` packages. These are additive, with no changes to existing classes. |

`ZTSConsts.java` is not modified. Property names live in `ExternalPdpConfig` and
`AuthZenHttpPdp`, keeping the feature self-contained.

The dispatch:

```java
if (externalPdpProcessor != null && externalPdpProcessor.handles(accessTokenRequest.getRequestType())) {
    return externalPdpProcessor.process(ctx, principal, accessTokenRequest, principalDomain, caller);
}
switch (accessTokenRequest.getRequestType()) {   // unchanged
```

No OAuth token flow method body is edited. The only edits inside legacy method bodies are
the one-line role-credential guards (section 6.4).

### 8.3 New Files

```
libs/java/server_common/src/main/java/com/yahoo/athenz/common/server/pdp/
    ExternalPolicyDecisionPoint.java
    ExternalPdpContext.java
    ExternalPdpException.java
    ExternalPdpSupport.java            — default batch → single expansion
  authzen/
    Subject.java  Resource.java  Action.java
    EvaluationRequest.java  EvaluationResponse.java
    EvaluationsRequest.java  EvaluationsOptions.java  EvaluationsResponse.java
  impl/
    AuthZenHttpPdp.java
    AuthZenHttpClient.java

servers/zts/src/main/java/com/yahoo/athenz/zts/token/
  TokenIssuancePolicy.java             — stateless token issuance rules shared by both paths
  TokenIssuanceErrors.java             — error factory supplied by the caller
  TokenIssuanceConfig.java             — immutable token issuance settings, single source of truth
servers/zts/src/main/java/com/yahoo/athenz/zts/
  ExternalPdpTokenProcessor.java       — mode routing and the PDP-path flows
                                          (same package as ZTSImpl for helper reuse)
servers/zts/src/main/java/com/yahoo/athenz/zts/pdp/
  ExternalPdpConfig.java               — immutable, parsed from system properties
  ExternalPdpMode.java                 — DISABLED, AUDIT, FILTER, AUTHORITATIVE
  ExternalPdpFlow.java                 — access_token, token_exchange, jag
  ExternalPdpManager.java              — loading, deadline/bulkhead/audit executors
  AuthZenRequestBuilder.java           — Athenz vocabulary → AuthZEN model
  ExternalPdpEvaluation.java           — builds one batch per token request
  ExternalPdpDecision.java             — interpreted result: per-role permits, gate, claims, max expiry
  AdditionalClaimsValidator.java
  ExternalPdpDecisionLog.java          — dedicated logger
```

### 8.4 Processor Behavior by Mode

- **AUDIT**:
  1. The processor calls the legacy method (for example
     `ztsImpl.processAccessTokenStandardRequest(...)`) and returns its response unmodified.
  2. On the request thread, it builds the shadow PDP request from the result. If a token
     was issued, the candidates are the roles in the issued token's scope. If the legacy
     path denied the request, they are the explicitly requested roles. Building on the
     request thread is required because the servlet request isn't valid after the
     response completes.
  3. It submits the PDP evaluation to a single-threaded, bounded audit executor, and the
     audit task logs the diff.
  4. If the legacy method throws, the request is still evaluated in shadow mode (RBAC
     denied, would the PDP have permitted?). That data is useful when planning
     AUTHORITATIVE adoption.
- **FILTER / AUTHORITATIVE**: the processor implements its own version of each in-scope
  flow (standard, impersonation, delegation, JAG issue, JAG exchange). It reuses the
  `ZTSImpl` helpers listed above, so validation, expiry and token construction stay the
  same, and inserts the PDP decision at the points defined in section 7.
- `handles()` returns `false` for `ID_TOKEN_EXCHANGE` and for any flow excluded by
  `athenz.zts.external_pdp.flows`, so those requests use the legacy path.

### 8.5 Trade-off and Drift Mitigation

Separate flow implementations mean a security fix to a legacy flow must be checked
against its PDP-path counterpart. This is accepted in exchange for zero edits to legacy
method bodies. The duplication is roughly the orchestration code of five flows, since
helpers are shared. Mitigations:

1. **Parity test harness**: every PDP-path flow has a parameterized test that runs the
   same request through the legacy method and through the processor in FILTER mode with a
   permit-all PDP. It asserts identical responses and identical decoded token claims,
   except `jti`, `iat`, `auth_time` and `exp` within skew. A change to a legacy flow that
   is not mirrored breaks this test.
2. **Invariant tests**: one negative test per row in table 6.3 for each PDP-path flow.
3. **Review checklist**: a short comment at the top of `ExternalPdpTokenProcessor` lists
   the legacy method each PDP-path flow mirrors. `CODEOWNERS` should route changes to
   either side to the same reviewers.

---

## 9. Additional Claims

Enabled only when `athenz.zts.external_pdp.claims_enabled=true` and the mode is FILTER or
AUTHORITATIVE. Claims are never applied in AUDIT mode, but they are validated and logged
by name.

Claims come from the token gate response (`evaluations[0].context.claims`) and are applied
to the issued access token through `AccessToken.setCustomClaim`. They are not applied to
ID tokens issued alongside an `openid` scope.

Guardrails, in order:

1. **Reserved names are always rejected.** This covers names `OAuth2Token.isStandardClaim`
   rejects, plus a ZTS denylist: `iss sub aud exp nbf iat jti scope scp client_id uid ver
   auth_time cnf act may_act proxy authorization_details principal_issuer spiffe
   azp nonce groups`. The list is extendable by property, not reducible.
2. **Optional allowlist** (`athenz.zts.external_pdp.claims_allowed`, comma-separated
   names or `prefix*` patterns). Recommended for production, for example `pdp_*`.
3. **Name syntax:** `[A-Za-z][A-Za-z0-9_.:-]{0,63}`.
4. **Values:** JSON string, number, boolean, array, or object. Nesting depth is at most 3.
5. **Size:** the serialized claims object is at most `claims_max_bytes` (default 2048).
6. **Violation handling:** `claims_strict=true` (default) fails the request with 403 and
   logs the reason. With `false`, ZTS drops the offending claims, logs them and issues the
   token.

ZTS never lets the PDP change a claim ZTS computes itself. Claims are additive only.

---

## 10. Reliability

### 10.1 Deadline and Bulkhead

- All PDP calls (class and HTTPS) run on a dedicated bounded executor
  (`athenz.zts.external_pdp.max_concurrency`, default 64) with a bounded queue.
- The request thread waits at most `athenz.zts.external_pdp.timeout_ms` (default 500)
  for the PDP interaction.
- Executor saturation is reported immediately as `UNAVAILABLE` instead of queuing.
- HTTPS connect and read timeouts default to the overall deadline, so threads aren't
  left behind.
- AUDIT evaluations use a separate small queue. When it is full they are dropped and
  counted, and they never block or slow token issuance.

### 10.2 Failure Handling

| Mode | PDP error, timeout, or invalid response |
|---|---|
| AUDIT | Logged and counted. No effect on the token. |
| FILTER | `athenz.zts.external_pdp.fail_open` (default `false`). `true` issues the RBAC result with no PDP claims and a reduced expiry (`fail_open_max_expires_in`, default 300s). `false` returns `503`. |
| AUTHORITATIVE | Always `503`. There is no RBAC fallback. |

A PDP *deny* is not an error: it always returns `403`, matching the existing
"no roles" response. `503` lets well-behaved clients (ZTSClient retries) distinguish
PDP outages from authorization denials.

**Startup:** if `mode != DISABLED` and the PDP cannot be loaded or initialized, ZTS fails
to start. ZTS does not silently fall back to DISABLED.

### 10.3 ZTS Responsibilities vs. PDP Implementation Responsibilities

The feature is plumbing: ZTS defines the contract and the guarantees it needs to protect
itself, and everything about *how* decisions are produced is left to the implementation.

| Concern | Owner | Reason |
|---|---|---|
| Deadline per token request | **ZTS** (`ExternalPdpManager`) | Protects ZTS request threads. A blocked implementation can't time itself out, so this must sit outside it. |
| Concurrency bulkhead | **ZTS** | Same reason. It bounds how many ZTS threads can be tied up by the PDP. |
| Fail mode (open or closed, 503) | **ZTS** | It is a property of the token issuance contract, not of the PDP. |
| Response validation (section 5.4) | **ZTS** | ZTS signs the token, so it can't trust the shape of a response. |
| Decision caching | **Implementation** | Only the PDP knows which inputs are cacheable and for how long (contextual signals such as risk score may not be). |
| Circuit breaking, retries, failover across PDP replicas | **Implementation** | These depend on the PDP's topology and SLOs. An implementation that opens a breaker throws `ExternalPdpException(UNAVAILABLE)` immediately, and ZTS applies its fail mode. The built-in `AuthZenHttpPdp` does not ship a breaker in v1. |
| Transport, connection pooling, PDP authentication | **Implementation** | `AuthZenHttpPdp` provides mTLS plus an optional header secret. Adapters do what their PDP requires. |

The deadline and bulkhead are the only resilience mechanisms ZTS implements. They are
generic wrappers around the interface call, independent of the implementation behind it,
and add no PDP-specific behavior.

---

## 11. Security Considerations

1. **Trust expansion.** In FILTER mode the PDP can only reduce access, with the exception
   of claims. In AUTHORITATIVE mode the PDP becomes a root of trust for scopes in
   ZTS-signed tokens. Operators must treat the PDP, its policy store and its
   administration with the same rigor as ZMS. The decision log records the PDP's
   decision for every issued token.
2. **Data sent to the PDP.** Principal identity, requested scopes, client IP and selected
   subject-token claims are sent. Raw tokens, DPoP proofs and certificates are never sent.
   AUDIT mode sends production data, so transport security and PDP access control apply
   from day one.
3. **Transport.** The built-in PDP is HTTPS only. `class://` adapters own their transport
   and should meet the same bar. They get the ZTS client `sslContext` for that purpose.
   The built-in PDP uses mTLS with the ZTS identity, hostname verification and
   an optional dedicated trust store. Because the configuration is global, only ZTS
   operators can change the endpoint, and domain admins cannot redirect data.
4. **Other issuance paths.** Role certificates and role tokens are rejected in FILTER and
   AUTHORITATIVE modes (section 6.4), so there is no RBAC-only route to role
   credentials. AWS temporary credentials and the read-only role lookups (`getRoleAccess`,
   `getAccess`) intentionally remain Athenz RBAC only. In AUTHORITATIVE deployments the
   lookups report Athenz role membership, which may differ from what the PDP grants in
   access tokens. Operators should document this for their users. These lookups will be
   revisited with the future ZTS AuthZEN API (section 15).
5. **Decentralized (ZPE) authorization.** Access tokens with PDP-issued scopes for roles
   that are not defined in Athenz (`require_defined_roles=false`) have no matching Athenz
   policies. ZPE-based resource servers will deny them. Such tokens are intended for
   resource servers that authorize directly on `scope` or call the PDP themselves.
6. **Staleness.** PDP context such as risk or device posture is evaluated only at
   issuance, and tokens remain valid until expiry and are cached by clients.
   `max_expires_in` lets the PDP shorten lifetimes for contextual decisions.
7. **Error leakage.** PDP reasons are logged, never returned. Clients get the same `403`
   messages as the legacy path.
8. **Shadow-traffic marking.** `context.mode=AUDIT` lets PDPs exclude shadow evaluations
   from their own enforcement analytics.

---

## 12. Observability

- **Metrics** (existing `Metric` interface):
  - `zts_ext_pdp_eval`, with attributes `mode`, `flow`, `outcome`
    (`permit`, `partial`, `deny`, `error`, `timeout`, `rejected`, `audit_dropped`)
  - `zts_ext_pdp_eval_latency` (timing)
  - `zts_ext_pdp_audit_diff` (AUDIT: `match`, `pdp_narrower`, `pdp_deny`, `pdp_permit_legacy_deny`, `match_deny`, `error`, `timeout`)
  - `zts_ext_pdp_claims_rejected`
  - `zts_ext_pdp_role_credential_request` (AUDIT) and
    `zts_ext_pdp_role_credential_rejected` (FILTER, AUTHORITATIVE), with an `api` attribute
- **Decision log**: a dedicated SLF4J logger `com.yahoo.athenz.zts.pdp.ExternalPdpDecisionLog`
  so operators can route it to an audit sink. Each request gets one structured line with:
  `request_id`, `mode`, `flow`, `principal`, `audience`, `candidate_roles`, `rbac_roles`
  (FILTER/AUDIT), `permitted_roles`, `final_roles`, `gate`, `claim_names`,
  `max_expires_in`, `latency_ms`, `error_code`, `reason_admin`. Token values and claim
  values are never logged.
- **Access log**: the PDP path appends `pdp_mode`, `pdp_request_id`, and `pdp_removed`
  (count) to the existing `ACCESS_LOG_ADDL_QUERY` data.

---

## 13. Configuration

All properties are commented out in `zts.properties`. Nothing changes until `mode` is set.

```properties
# =============================================================================
# External Policy Decision Point (PDP) - AuthZEN
# =============================================================================

# DISABLED (default) | AUDIT | FILTER | AUTHORITATIVE
#athenz.zts.external_pdp.mode=DISABLED

# Mode simulated by AUDIT: FILTER (default) | AUTHORITATIVE
#athenz.zts.external_pdp.audit_target=FILTER

# class://<fully.qualified.ClassName>  or  https://host[:port][/base-path]
#athenz.zts.external_pdp.endpoint=

# Flows routed through the PDP (default: all v1 flows)
#athenz.zts.external_pdp.flows=access_token,token_exchange,jag

# Overall deadline for the PDP interaction per token request
#athenz.zts.external_pdp.timeout_ms=500
#athenz.zts.external_pdp.max_concurrency=64
#athenz.zts.external_pdp.audit_queue_size=1000

# FILTER only: on PDP failure issue RBAC result (true) or return 503 (false)
#athenz.zts.external_pdp.fail_open=false
#athenz.zts.external_pdp.fail_open_max_expires_in=300

# AUTHORITATIVE only
#athenz.zts.external_pdp.require_defined_roles=true
#athenz.zts.external_pdp.max_candidate_roles=64

# Additional claims
#athenz.zts.external_pdp.claims_enabled=false
#athenz.zts.external_pdp.claims_allowed=
#athenz.zts.external_pdp.claims_reserved_extra=
#athenz.zts.external_pdp.claims_max_bytes=2048
#athenz.zts.external_pdp.claims_strict=true

# HTTPS PDP
#athenz.zts.external_pdp.https.batch_enabled=true
#athenz.zts.external_pdp.https.evaluations_path=/access/v1/evaluations
#athenz.zts.external_pdp.https.evaluation_path=/access/v1/evaluation
#athenz.zts.external_pdp.https.discovery=false
#athenz.zts.external_pdp.https.max_response_bytes=65536

# Optional extra authentication header (secret obtained from the PrivateKeyStore)
#athenz.zts.external_pdp.https.auth_header_name=
#athenz.zts.external_pdp.https.auth_header_prefix=
#athenz.zts.external_pdp.https.auth_secret_app_name=
#athenz.zts.external_pdp.https.auth_secret_keygroup_name=
#athenz.zts.external_pdp.https.auth_secret_key_name=
#athenz.zts.external_pdp.https.auth_secret_refresh_secs=3600
```

---

## 14. Testing

All new tests are in new classes. Existing test classes are not modified. All new code has
100% line coverage.

| Test class | Coverage |
|---|---|
| `pdp/authzen/AuthZenModelTest` (server_common) | JSON round-trip, field names, immutability, unknown-field tolerance, strict boolean decisions |
| `pdp/ExternalPdpSupportTest` (server_common) | Default inheritance, sequential/parallel expansion, short-circuit semantics, saturation, interruption |
| `pdp/impl/AuthZenHttpClientTest` (server_common) | Real TLS server with a generated certificate: hostname mismatch, untrusted server, status mapping, size limit, timeout |
| `pdp/impl/AuthZenHttpPdpTest` (server_common) | Batch and single fan-out, path overrides, discovery and same-origin checks, auth header from a fake `PrivateKeyStore`, secret rotation |
| `zts/pdp/ExternalPdpConfigTest` | Defaults, overrides, invalid values, flow mapping |
| `zts/pdp/ExternalPdpManagerTest` | Class/https loading, override check, deadline, interruption, bulkhead saturation, audit queue, result validation |
| `zts/pdp/AuthZenRequestBuilderTest`, `ExternalPdpEvaluationTest`, `AdditionalClaimsValidatorTest`, `ExternalPdpDecisionLogTest` | Mapping, decision interpretation, fail-open, claim guardrails |
| `zts/ExternalPdpTokenProcessorTest` | Against a real `ZTSImpl` and `DataStore`. Parity with the legacy path (FILTER plus permit-all) for standard (single, multi-domain, openid, proxy), impersonation, delegation, JAG issue, JAG exchange and identity-provider claims. Narrowing, gate deny, `max_expires_in`, claims (strict and lenient), fail open and closed, AUTHORITATIVE (explicit, domain enumeration, undefined roles, candidate limit, exchange permissions), AUDIT (unchanged tokens, shadow requests, legacy denials, queue overflow), role-credential rejection |

---

## 15. Resolved Decisions and Future Work

### 15.1 Resolved Decisions

| # | Question | Decision |
|---|---|---|
| 1 | PDP authentication beyond mTLS | Supported through the `PrivateKeyStore`. `ExternalPdpContext` exposes it to all implementations. `AuthZenHttpPdp` supports an optional secret-backed header (section 5.6). |
| 2 | Role tags in PDP requests | Not sent. Role resources carry only `domain`, `role`, `defined` and `rbac_granted`. |
| 3 | Other RBAC-based endpoints | The external PDP applies only to the branched `POST /oauth2/token` path. `getAWSTemporaryCredentials` is always Athenz RBAC. `getRoleAccess`, `getAccess` and `getRolesRequireRoleCert` stay on RBAC. Role certificates and role tokens are rejected while the PDP is enforcing (section 6.4). |
| 4 | Circuit breaker | Not part of ZTS. Implementations may provide one and signal it through `ExternalPdpException(UNAVAILABLE)`. ZTS implements only the deadline and bulkhead (section 10.3). |
| 5 | Decision caching | Delegated to implementations (section 10.3). |
| 6 | Per-domain enablement | Server-wide only in v1. The `handles()` seam allows per-domain selection later without touching the legacy path. |
| 7 | Interface location | `libs/java/server_common`, packages `com.yahoo.athenz.common.server.pdp[.authzen\|.impl]`. |

### 15.2 Future Work

- **ZTS as an AuthZEN PDP.** ZTS would expose AuthZEN-compliant endpoints (Access
  Evaluation, Access Evaluations, Resource Search) so external PEPs can call ZTS for
  decisions based on Athenz RBAC. The model objects in section 5.3 are intended to be
  reused for that API. When that work happens, revisit `getRoleAccess` and `getAccess`:
  Resource Search (which roles a principal has in a domain) and Access Evaluation (can a
  principal perform an action on a resource) cover the same questions in a standard form.
- **Per-domain enablement**, if multi-tenant operators need it (decision 6).

---

## 16. Related

- AuthZEN Authorization API 1.0 (OpenID Foundation AuthZEN WG): Access Evaluation,
  Access Evaluations (batch), PDP metadata discovery.
- `InstanceProviderManager` (`servers/zts/.../zts/InstanceProviderManager.java`):
  `class://` and `https://` provider model this design mirrors.
- Token endpoint: `ZTSImpl.postAccessTokenRequest` (`ZTSImpl.java:3023`) and flows:
  standard `:4300`, impersonation `:3222`, delegation `:3462`, JAG issue `:3837`,
  JAG exchange `:4023`.
- Custom claims support: `OAuth2Token.setCustomClaim` (`libs/java/auth_core`).
- [Token exchange requirements](../zts_token_exchange_requirements.md),
  [DPoP access tokens](../zts_dpop_access_tokens.md).
