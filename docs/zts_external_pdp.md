# External Policy Decision Point (PDP) for Access Tokens

* [Overview](#overview)
* [What Changes and What Doesn't](#what-changes-and-what-doesnt)
* [Operating Modes](#operating-modes)
* [Choosing How ZTS Talks to Your PDP](#choosing-how-zts-talks-to-your-pdp)
* [What Your PDP Receives and Returns](#what-your-pdp-receives-and-returns)
* [Adoption Path 1: You Use Athenz RBAC Today](#adoption-path-1-you-use-athenz-rbac-today)
* [Adoption Path 2: Starting Fresh with a PDP Only](#adoption-path-2-starting-fresh-with-a-pdp-only)
* [Writing a class:// Adapter](#writing-a-class-adapter)
* [Additional Claims](#additional-claims)
* [Failure Handling and Errors](#failure-handling-and-errors)
* [Observability](#observability)
* [Configuration Reference](#configuration-reference)
* [Security Considerations](#security-considerations)
* [Troubleshooting](#troubleshooting)

## Overview

ZTS issues OAuth2 access tokens from `POST /zts/v1/oauth2/token`. By default, the
roles that go into a token's scope are decided by Athenz role-based access control
(RBAC): role membership and policies managed in ZMS.

The external PDP feature lets ZTS consult your own policy engine for that decision.
Examples include OPA, Cedar, OpenFGA, a vendor authorization service, or a policy
service you built yourself. The PDP can:

* remove roles from the token scope,
* decide the token scope on its own, without Athenz RBAC (AUTHORITATIVE mode),
* deny the token entirely,
* shorten the token lifetime,
* add claims to the token.

ZTS still authenticates the client and validates the request, and it signs the
token. The PDP only answers authorization questions.

The request and response model follows the
[OpenID AuthZEN Authorization API 1.0](https://openid.net/specs/authorization-api-1_0.html).
A PDP that speaks AuthZEN over HTTPS needs only configuration. Any other PDP can be
connected through a small Java adapter.

The feature is **off by default**. A ZTS server without any
`athenz.zts.external_pdp.*` properties behaves exactly as before.

## What Changes and What Doesn't

**Covered by the PDP** (OAuth2 token endpoint only):

| Flow | `flows` name | Request |
|---|---|---|
| Access tokens | `access_token` | `grant_type=client_credentials` |
| Token exchange (impersonation and delegation) | `token_exchange` | `grant_type=urn:ietf:params:oauth:grant-type:token-exchange` with an access token as the subject token |
| Identity Assertion Authorization Grants (JAG) | `jag` | JAG issue (token exchange to `id-jag`) and JAG exchange (`jwt-bearer`) |

**Always enforced by ZTS, in every mode:**

* client authentication (mTLS or client assertion) and DPoP proof validation,
* request validation, including domain existence and the audience rules for multi-domain scopes,
* the authorized proxy user list and authorized-service restrictions,
* subject and actor token validation for token exchange,
* "the exchanged scope must be a subset of the subject token's scope",
* token expiry limits (the PDP can only lower them).

**Not covered by the PDP** (stay on Athenz RBAC):

* ID tokens (`/oauth2/auth` and ID token exchange),
* AWS temporary credentials,
* read-only lookups such as `getAccess` and `getRoleAccess`. These report Athenz role
  membership, which may differ from what the PDP grants.

**Disabled while the PDP is enforcing** (FILTER and AUTHORITATIVE modes):

* role certificates (`POST /rolecert` and the legacy role certificate endpoint),
* role tokens (`GET /domain/{domainName}/token`).

These are Athenz-specific RBAC credentials. If they stayed available, clients could
use them to get around the PDP. ZTS rejects them with `403` and the message
`<api>: role credentials are not supported when external PDP is enabled`. There is
no property to re-enable them while enforcing. Clients must move to access tokens.

## Operating Modes

Set the mode with `athenz.zts.external_pdp.mode`.

| Mode | Who decides the token scope | Effect on tokens | When the PDP is called |
|---|---|---|---|
| `DISABLED` (default) | Athenz RBAC | None | Never |
| `AUDIT` | Athenz RBAC | None. ZTS logs what the PDP would have done. | Asynchronously, after the response |
| `FILTER` | Athenz RBAC, then the PDP | The PDP can remove RBAC-granted roles, deny the token, lower the expiry and add claims. It can never add a role RBAC didn't grant. | Synchronously |
| `AUTHORITATIVE` | The PDP | The PDP grants roles without RBAC, and can deny the token, lower the expiry and add claims. | Synchronously |

`athenz.zts.external_pdp.audit_target` selects which enforcing mode `AUDIT`
simulates: `FILTER` (default) or `AUTHORITATIVE`. This lets you test either target
against production traffic before you switch.

## Choosing How ZTS Talks to Your PDP

Set `athenz.zts.external_pdp.endpoint` to one of:

| Your PDP | Endpoint | What you provide |
|---|---|---|
| Implements the AuthZEN Access Evaluations (batch) API over HTTPS | `https://pdp.example.com[:port][/base-path]` | Configuration only |
| Implements only the single AuthZEN Access Evaluation API, or uses non-standard paths | `https://pdp.example.com` with `athenz.zts.external_pdp.https.batch_enabled=false` and/or path overrides | Configuration only. ZTS sends one call per evaluation, in parallel. |
| Doesn't speak AuthZEN (custom REST, gRPC, vendor SDK, embedded engine) | `class://com.example.MyPdpAdapter` | A Java class that implements `ExternalPolicyDecisionPoint` (see [Writing a class:// Adapter](#writing-a-class-adapter)) |

For the built-in HTTPS PDP:

* **TLS is required.** ZTS authenticates to the PDP with mTLS using its own service
  identity certificate. It uses the same client SSL settings as HTTPS instance
  providers (`athenz.zts.provider.ssl_client_*`). Point that trust store at the CA
  that issued your PDP's server certificate.
* **Sidecars.** A sidecar in the same pod must also serve TLS, for example
  `https://localhost:8443` with a certificate that includes a `localhost` SAN.
* **Extra credentials.** If the PDP needs an API key or a bearer token in addition to
  mTLS, configure `athenz.zts.external_pdp.https.auth_header_name` and the
  `auth_secret_*` properties. ZTS reads the secret from its configured
  `PrivateKeyStore` and refreshes it every `auth_secret_refresh_secs` (default 3600
  seconds). Secrets are never put in properties or logs.
* **Discovery.** With `athenz.zts.external_pdp.https.discovery=true`, ZTS reads
  `/.well-known/authzen-configuration` once at startup. The discovered endpoints must
  have the same scheme, host and port as the configured endpoint.
* **No retries.** ZTS calls the PDP once per token request, with no retries,
  redirects or cookies. A failure is handled by the mode's fail behavior (see
  [Failure Handling and Errors](#failure-handling-and-errors)).

## What Your PDP Receives and Returns

For each token request, ZTS sends **one** AuthZEN Access Evaluations batch.

* **Evaluation `[0]`** is always the *token gate*: may this subject get a token for
  this audience at all?
* **The remaining evaluations** ask, one role at a time, whether the role may be
  included in the token scope. In AUTHORITATIVE mode, token exchange and JAG requests
  also include *permission* evaluations, which replace the Athenz exchange
  authorization checks.

### Request

Example: `sports.api` requests `scope=sports:role.readers sports:role.writers`.

```json
POST /access/v1/evaluations
X-Request-ID: 6c1e8a52-...

{
  "subject": {
    "type": "service",
    "id": "sports.api",
    "properties": { "domain": "sports", "name": "api", "authority": "Auth-X509", "mtls": true }
  },
  "action":  { "name": "assume_role" },
  "context": {
    "request_id": "6c1e8a52-...",
    "time": "2026-11-25T18:04:05Z",
    "request_type": "ACCESS_TOKEN",
    "audience": "sports",
    "requested_scope": "sports:role.readers sports:role.writers",
    "client_ip": "10.1.2.3",
    "dpop_bound": false,
    "mode": "FILTER"
  },
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

Evaluations inherit `subject`, `action` and `context` from the top level unless they
set their own. That's the standard AuthZEN behavior.

**Subject.** `type` is `user` for principals in the user domain and `service`
otherwise. For token exchange and JAG, the subject is the identity the token is
being issued for. The calling client is in `context.client`.

**Resources and actions:**

| Question | `action.name` | `resource.type` | `resource.id` |
|---|---|---|---|
| Token gate | `issue_token` | `athenz_token` | audience domain |
| Include a role in the scope | `assume_role` | `athenz_role` | `<domain>:role.<role>` |
| Impersonation from a source domain (AUTHORITATIVE only) | `zts.token_source_exchange` | `athenz_resource` | `<source-domain>:<target-domain>` |
| Token exchange per target role (AUTHORITATIVE only) | `zts.token_target_exchange` | `athenz_resource` | `<target-domain>:<source-domain>:role.<role>` |
| JAG exchange per role (AUTHORITATIVE only) | `zts.jag_exchange` | `athenz_resource` | `<domain>:role.<role>` |

The exchange actions and resources are the same ones Athenz RBAC policies use today,
so existing policies translate one-to-one. Permission evaluations use the client
principal as their subject.

Role resource properties:

* `defined`: whether the role exists in Athenz.
* `rbac_granted` (FILTER only): whether Athenz RBAC granted the role.

Role tags and other role metadata are not sent. A `class://` adapter can read them
from the `RolesProvider` in its context.

**Context keys:**

| Key | Description |
|---|---|
| `request_id` | Same value as the `X-Request-ID` header. |
| `time` | Issuance time (ISO-8601). |
| `grant_type`, `request_type` | Raw grant type, and one of `ACCESS_TOKEN`, `ACCESS_TOKEN_EXCHANGE`, `JAG_TOKEN_EXCHANGE`, `JAG_JWT_BEARER`. |
| `exchange_type` | `impersonation` or `delegation` (token exchange only). |
| `audience`, `requested_scope`, `requested_expires_in` | From the request. |
| `proxy_for_principal`, `actor` | If supplied. |
| `client` | The authenticated client principal. |
| `subject_token`, `actor_token` | Selected claims of the validated tokens (`iss`, `sub`, `aud`, `scope`, `client_id`, `jti`, `exp`). The tokens themselves are never sent. |
| `client_ip`, `dpop_bound` | Request metadata. |
| `mode` | `AUDIT`, `FILTER` or `AUTHORITATIVE`. Use it to keep shadow traffic out of your own enforcement analytics. |

### Response

Return exactly one result per evaluation, in request order.

```json
{
  "evaluations": [
    { "decision": true,
      "context": {
        "max_expires_in": 900,
        "claims": { "pdp_risk_tier": "low" }
      } },
    { "decision": true },
    { "decision": false,
      "context": { "reason_admin": { "policy": "writers-require-mfa" } } }
  ]
}
```

| Element | Effect |
|---|---|
| `[0].decision: false` | No token. ZTS returns `403`. |
| `[0].context.max_expires_in` | Optional positive integer (seconds). The token lifetime becomes the lower of this and the lifetime ZTS computed. |
| `[0].context.claims` | Optional extra token claims (see [Additional Claims](#additional-claims)). |
| `[i>0].decision: false` | That role is left out of the scope, or that permission is denied. |
| `reason_admin`, `reason_user` | Written to the ZTS decision log only. Never returned to the client. |

Rules:

* A missing or non-boolean `decision` counts as `false`.
* A wrong number of results, or a `null` result, is an invalid response (see
  [Failure Handling and Errors](#failure-handling-and-errors)).
* If a scope domain ends up with no permitted role, the whole request fails with
  `403`, as it does with RBAC today.

## Adoption Path 1: You Use Athenz RBAC Today

You already manage roles and policies in ZMS and want to add a PDP on top, for
example for contextual rules (risk score, time of day, device posture) or for
centralized policy. The safe path is to observe first, then let the PDP narrow
access, and only optionally hand it full control.

| Step | Configuration | Effect on tokens |
|---|---|---|
| 1. Shadow-test FILTER | `mode=AUDIT`, `audit_target=FILTER` | None |
| 2. Enforce FILTER | `mode=FILTER` | Scopes can only shrink. Role certs and role tokens are rejected. |
| 3. (Optional) Shadow-test AUTHORITATIVE | `mode=AUDIT`, `audit_target=AUTHORITATIVE` | None. Role certs and role tokens work again during this step. |
| 4. (Optional) Enforce AUTHORITATIVE | `mode=AUTHORITATIVE` | The PDP owns scopes |

Steps 3 and 4 are only for deployments that want to move authorization out of
Athenz RBAC entirely. Most deployments stay on FILTER.

### Step 0: Prepare

1. **Stand up the PDP and connect ZTS to it.** Choose the endpoint type (see
   [Choosing How ZTS Talks to Your PDP](#choosing-how-zts-talks-to-your-pdp)). Make
   sure the PDP trusts the ZTS service certificate and that ZTS trusts the PDP's
   server certificate.
2. **Write a permit-all policy first.** In FILTER mode, a PDP that permits every
   evaluation produces exactly the tokens RBAC produces today. Start there and add
   restrictions one at a time.
3. **Size the timeout.** ZTS waits at most `timeout_ms` (default 500 ms) for the
   whole batch. Measure your PDP's p99 latency for a batch of the size you expect.
4. **Plan the decision log.** Route the `com.yahoo.athenz.zts.pdp.ExternalPdpDecisionLog`
   logger to your audit pipeline (see [Observability](#observability)).

### Step 1: AUDIT with audit_target=FILTER

```properties
athenz.zts.external_pdp.mode=AUDIT
athenz.zts.external_pdp.audit_target=FILTER
athenz.zts.external_pdp.endpoint=https://pdp.example.com
```

ZTS issues every token exactly as before. After responding, it sends the PDP the
roles RBAC granted (or, if RBAC denied the request, the requested roles) and logs
the difference. Shadow evaluations run on a separate bounded queue and never slow
down token issuance.

Watch these:

* **`zts_ext_pdp_audit_diff`.** Its `outcome` attribute tells you what FILTER mode
  would have done:

  | Outcome | Meaning |
  |---|---|
  | `match` | Same token. |
  | `pdp_narrower` | FILTER would issue fewer roles. |
  | `pdp_deny` | FILTER would deny the request: the gate denied it, a scope domain lost all its roles, or a strict claims check failed. |
  | `pdp_permit_legacy_deny` | RBAC denied the request but the PDP would permit it. FILTER would still deny it, because FILTER never grants beyond RBAC. |
  | `match_deny` | Both deny. |
  | `error`, `timeout` | The PDP call failed. |

* **`zts_ext_pdp_role_credential_request`** (`api` attribute) and decision-log
  entries with `flow=role_credential`. These are the clients still using role
  certificates or role tokens, which **will break** when you enforce. Move them to
  access tokens before step 2.

* **`zts_ext_pdp_eval_latency`** and the `timeout` outcomes, to confirm
  `timeout_ms` fits.

Move on when every `pdp_narrower` and `pdp_deny` outcome is one you intended, and no
clients still use role credentials.

### Step 2: Enforce FILTER

```properties
athenz.zts.external_pdp.mode=FILTER
athenz.zts.external_pdp.endpoint=https://pdp.example.com
# choose one, see below
athenz.zts.external_pdp.fail_open=false
```

Decide what happens when the PDP is unavailable:

* `fail_open=false` (default): ZTS returns `503`, and no token is issued until the
  PDP recovers.
* `fail_open=true`: ZTS issues the RBAC result without PDP claims, and caps the
  lifetime at `fail_open_max_expires_in` (default 300 seconds), so the tokens get
  re-evaluated soon. Choose this only if the PDP adds restrictions you can live
  without during an outage.

From this point on, role certificates and role tokens are rejected.

### Steps 3 and 4 (optional): move to AUTHORITATIVE

In AUTHORITATIVE mode, ZTS no longer checks Athenz role membership or the Athenz
token exchange permissions. Your PDP policy must express everything those used to
enforce. Before switching:

1. Port role membership and the `zts.token_source_exchange`,
   `zts.token_target_exchange` and `zts.jag_exchange` policies to the PDP.
2. Run `mode=AUDIT` with `audit_target=AUTHORITATIVE`. ZTS runs the real
   AUTHORITATIVE flow up to the PDP call, so the shadow request has exactly the
   candidates and permission checks AUTHORITATIVE would send. New outcomes appear:

   | Outcome | Meaning |
   |---|---|
   | `pdp_broader` | AUTHORITATIVE would issue *more* roles than RBAC does today. This is common for domain-wide scopes (`scope=sports:domain`), where every role defined in the domain becomes a candidate. |
   | `pdp_mismatch` | Both added and removed roles. |
   | `target_reject` | AUTHORITATIVE would reject the request before calling the PDP. For example, a domain-wide scope with `require_defined_roles=false`, or more than `max_candidate_roles` candidates. |

   Treat every `pdp_broader` outcome as a possible privilege escalation and confirm
   it's intended.
3. Switch to `mode=AUTHORITATIVE`. There is no fail-open in this mode. If the PDP is
   unavailable, ZTS returns `503`.

Keep managing roles in ZMS if you rely on any of the RBAC-only features listed in
[What Changes and What Doesn't](#what-changes-and-what-doesnt), or on ZPE-based
resource servers.

## Adoption Path 2: Starting Fresh with a PDP Only

You're deploying Athenz for service identity and token issuance, and your
authorization policy lives in a PDP from day one. You'll run in `AUTHORITATIVE` mode
and won't need Athenz role membership or policies.

### What you still need in Athenz

* **Domains.** ZTS never issues a token for a domain that doesn't exist in ZTS.
  Create a domain for every token audience and every domain that appears in scopes.
* **Service identities.** Clients authenticate to ZTS with Athenz service identity
  certificates (or another configured authority), so register services as usual.
* **Roles.** Defining roles is a choice, controlled by
  `athenz.zts.external_pdp.require_defined_roles`:

  | | `require_defined_roles=true` (default) | `require_defined_roles=false` |
  |---|---|---|
  | Roles in Athenz | Create the roles (they can have no members). They act as a catalog of valid scope names. | Not needed. Any role name the PDP permits can be issued. |
  | Undefined roles in a request | Dropped and logged as `undefined_roles` | Sent to the PDP with `defined: false` |
  | Domain-wide scope (`scope=sports:domain`) | Every defined role is a candidate. The PDP permits the subset the subject gets. Limited by `max_candidate_roles` (default 64). | Rejected with `400 invalid_scope`. Clients must request explicit roles. |
  | Role-level token expiry settings | Applied | Not available. Domain and server defaults apply. |

  Defining roles is recommended. It keeps scope names under change control, lets
  clients use domain-wide scopes, and keeps role-level expiry settings working.

### Steps

1. **Create domains, services and (optionally) roles** in ZMS. You don't need role
   members or policies.
2. **Write the PDP policy.** It must answer every question in
   [What Your PDP Receives and Returns](#what-your-pdp-receives-and-returns):
   * the token gate (`issue_token` on `athenz_token`),
   * `assume_role` for each requested role,
   * for proxy requests (`proxy_for_principal`), a role is issued only if both the
     proxied principal and the calling client are permitted it,
   * for token exchange and JAG, the `zts.*_exchange` permissions.

   Any question the policy doesn't answer with `true` is a denial.
3. **Configure ZTS:**

   ```properties
   athenz.zts.external_pdp.mode=AUTHORITATIVE
   athenz.zts.external_pdp.endpoint=https://pdp.example.com
   athenz.zts.external_pdp.require_defined_roles=true
   ```

4. **Test in a non-production environment.** There's no RBAC baseline to compare
   against, so an AUDIT run would report every request as `pdp_permit_legacy_deny`
   or `match_deny`. That's still useful as a dry run of connectivity and request
   shape, but end-to-end tests against a test PDP are more informative.
5. **Tell your users what doesn't apply.** Role certificates and role tokens are
   rejected. AWS temporary credentials and the `getAccess`/`getRoleAccess` lookups
   still use Athenz RBAC, which has no members here, so they deny everything. Use
   access tokens.

### Resource servers

Tokens look the same as other Athenz access tokens. Resource servers that authorize
on the `scope`/`scp` claim work unchanged. ZPE-based resource servers evaluate
Athenz policies, so they deny scopes that have no matching Athenz policy. That
includes every role when `require_defined_roles=false`. In a PDP-only deployment,
resource servers should authorize on the token scope, or call the PDP themselves.

## Writing a class:// Adapter

Use an adapter when your PDP doesn't speak AuthZEN over HTTPS, or when you want to
run a policy engine inside the ZTS JVM. Implement
`com.yahoo.athenz.common.server.pdp.ExternalPolicyDecisionPoint` from
`athenz-server-common`, put the jar on the ZTS classpath, and configure:

```properties
athenz.zts.external_pdp.endpoint=class://com.example.MyPdpAdapter
```

```java
public class MyPdpAdapter implements ExternalPolicyDecisionPoint {

    private MyPolicyClient client;

    @Override
    public void initialize(ExternalPdpContext context) throws ExternalPdpException {
        // own settings come from system properties; credentials from the key store
        char[] apiKey = context.getPrivateKeyStore().getSecret("zts", "pdp", "api_key");
        client = new MyPolicyClient(context.getSslContext(), apiKey,
                context.getConnectTimeoutMs(), context.getReadTimeoutMs());
    }

    // implement evaluate() for one-at-a-time PDPs, or override evaluations() for batch PDPs
    @Override
    public EvaluationResponse evaluate(EvaluationRequest request) throws ExternalPdpException {
        try {
            boolean allowed = client.check(request.getSubject().getId(),
                    request.getAction().getName(), request.getResource().getId());
            return new EvaluationResponse(allowed, null);
        } catch (IOException ex) {
            throw new ExternalPdpException(ExternalPdpException.Code.UNAVAILABLE, "pdp call failed", ex);
        }
    }

    // run single evaluations in parallel on the ZTS-provided executor
    @Override
    public EvaluationsResponse evaluations(EvaluationsRequest request) throws ExternalPdpException {
        return ExternalPdpSupport.expandBatch(this, request, executor);
    }

    @Override
    public void close() {
        client.close();
    }
}
```

The snippet stores `context.getExecutor()` in an `executor` field during
`initialize` (not shown).

* **Methods.** Override at least one of `evaluate` or `evaluations`. ZTS checks this
  at startup. ZTS always calls `evaluations`. Its default runs `evaluate` once per
  item, in order. `ExternalPdpSupport.expandBatch` with the context executor runs the
  items in parallel, waiting for its own calls when the shared executor is full.
* **Thread safety.** The adapter must be thread-safe and return one result per
  evaluation, in request order.
* **Context.** `ExternalPdpContext` provides:
  * the ZTS client `SSLContext`,
  * a read-only `RolesProvider` over ZTS domain data (for example, for role tags),
  * the `PrivateKeyStore`,
  * the fan-out executor,
  * the connect and read timeouts.
* **Errors.** Throw `ExternalPdpException` with a code (`UNAVAILABLE`, `TIMEOUT`,
  `INVALID_RESPONSE`, `UNSUPPORTED`, `INTERNAL`). ZTS uses the code for metrics and
  for the mode's fail behavior.
* **What ZTS handles.** ZTS applies its deadline and concurrency limit around the
  adapter, so a slow adapter can't exhaust ZTS request threads. Caching, circuit
  breaking and failover are up to the adapter. An adapter whose circuit breaker is
  open should throw `UNAVAILABLE` right away.
* **Startup.** If `initialize` fails, ZTS doesn't start.

## Additional Claims

With `athenz.zts.external_pdp.claims_enabled=true`, in FILTER or AUTHORITATIVE mode,
ZTS adds the claims returned in `evaluations[0].context.claims` to the access token.
They are not added to ID tokens. They are also not added in AUDIT mode, but they are
validated and logged by name.

ZTS checks them as follows:

* **Reserved names** are always rejected: `iss sub aud exp nbf iat jti scope scp
  client_id uid ver auth_time cnf act may_act proxy authorization_details
  principal_issuer spiffe azp nonce groups resource typ`. Add more with
  `claims_reserved_extra`.
* **Allowlist.** `claims_allowed` is an optional comma-separated list of names or
  `prefix*` patterns. It's recommended in production, for example `pdp_*`.
* **Names** must match `[A-Za-z][A-Za-z0-9_.:-]{0,63}`.
* **Values** must be strings, numbers, booleans, arrays or objects, nested at most 3
  levels.
* **Size.** The serialized claims are limited to `claims_max_bytes` (default 2048).
* **Violations.** With `claims_strict=true` (default), a violation fails the request
  with `403`. With `false`, ZTS drops the offending claims and issues the token.

The PDP can't override a claim ZTS sets itself.

## Failure Handling and Errors

| Situation | AUDIT | FILTER | AUTHORITATIVE |
|---|---|---|---|
| PDP denies (gate, all roles of a domain, a permission, strict claims) | No effect | `403` | `403` |
| PDP error, timeout, invalid response, or ZTS concurrency limit reached | Logged and counted | `503`, or with `fail_open=true` the RBAC result with a capped lifetime | `503` |
| Role certificate or role token request | Served, and counted | `403` | `403` |
| Domain-wide scope with `require_defined_roles=false`, or too many candidate roles | No effect | n/a | `400 invalid_scope` |

`403` responses use the same messages as the RBAC path, so policy details don't leak
to clients. `503` lets clients tell a PDP outage apart from a denial.

**Startup.** If the mode isn't `DISABLED` and the PDP can't be loaded or
initialized, ZTS fails to start. It never falls back to `DISABLED` silently. When
the mode is `DISABLED`, ZTS ignores all other `external_pdp` properties.

## Observability

**Metrics:**

| Metric | Attributes | Description |
|---|---|---|
| `zts_ext_pdp_eval` | `mode`, `flow`, `outcome` (`permit`, `partial`, `deny`, `error`, `timeout`, `rejected`, `audit_dropped`) | One per PDP-path token request. `audit_dropped` counts shadow evaluations dropped because the audit queue was full. |
| `zts_ext_pdp_eval_latency` | | PDP evaluation time |
| `zts_ext_pdp_audit_diff` | `flow`, `outcome` | AUDIT comparison (outcomes listed under [Adoption Path 1](#adoption-path-1-you-use-athenz-rbac-today)) |
| `zts_ext_pdp_claims_rejected` | `flow` | Requests with rejected claims |
| `zts_ext_pdp_role_credential_request` | `api` | AUDIT: role credential requests that FILTER or AUTHORITATIVE would reject |
| `zts_ext_pdp_role_credential_rejected` | `api` | FILTER and AUTHORITATIVE: rejected role credential requests |

**Decision log.** The logger `com.yahoo.athenz.zts.pdp.ExternalPdpDecisionLog`
writes one INFO line per decision: `pdp_decision {json}`. Fields include
`request_id`, `mode`, `flow`, `outcome`, `principal`, `audience`,
`candidate_roles`, `permitted_roles`, `final_roles`, `gate`, `max_expires_in`,
`claim_names`, `claims_rejected`, `undefined_roles`, `reasons`, `error_code` and
`latency_ms`. AUDIT entries also include `audit_target`, `legacy_status`,
`legacy_roles` and `simulated_roles`.

Token values and claim values are never logged. Route this logger to a separate
appender if you keep an authorization audit trail.

**Access log.** PDP-path requests append `pdp_mode`, `pdp_request_id` and
`pdp_removed` (the number of candidate roles the PDP removed). `pdp_request_id`
matches the `X-Request-ID` header sent to the PDP, so you can correlate ZTS and PDP
logs.

## Configuration Reference

All properties go in `zts.properties` (or system properties). The commented-out
block in the shipped `zts.properties` lists all of them.

| Property (`athenz.zts.external_pdp.*`) | Default | Description |
|---|---|---|
| `mode` | `DISABLED` | `DISABLED`, `AUDIT`, `FILTER`, `AUTHORITATIVE` |
| `audit_target` | `FILTER` | Mode simulated by `AUDIT`: `FILTER` or `AUTHORITATIVE` |
| `endpoint` | | `https://host[:port][/base-path]` or `class://fully.qualified.ClassName`. Required unless `DISABLED`. |
| `flows` | `access_token,token_exchange,jag` | Flows routed through the PDP. Other flows stay on RBAC. |
| `timeout_ms` | `500` | Deadline for the PDP interaction per token request. Also used as the HTTPS connect and read timeout. |
| `max_concurrency` | `64` | Maximum concurrent PDP calls, which is also the HTTPS connection pool size |
| `audit_queue_size` | `1000` | Pending AUDIT evaluations before new ones are dropped |
| `fail_open` | `false` | FILTER only: issue the RBAC result when the PDP fails |
| `fail_open_max_expires_in` | `300` | Token lifetime cap (seconds) for fail-open tokens |
| `require_defined_roles` | `true` | AUTHORITATIVE: only issue roles defined in Athenz |
| `max_candidate_roles` | `64` | AUTHORITATIVE: maximum roles per domain sent to the PDP |
| `claims_enabled` | `false` | Apply PDP-returned claims |
| `claims_allowed` | | Allowed claim names or `prefix*` patterns |
| `claims_reserved_extra` | | Additional reserved claim names |
| `claims_max_bytes` | `2048` | Maximum serialized claims size |
| `claims_strict` | `true` | Fail the request on a claims violation |
| `https.batch_enabled` | `true` | Use the AuthZEN batch endpoint. `false` sends single evaluations in parallel. |
| `https.evaluations_path` | `/access/v1/evaluations` | Batch endpoint path |
| `https.evaluation_path` | `/access/v1/evaluation` | Single endpoint path |
| `https.discovery` | `false` | Read `/.well-known/authzen-configuration` at startup |
| `https.max_response_bytes` | `65536` | Maximum PDP response size |
| `https.auth_header_name` | | Extra authentication header, for example `Authorization` |
| `https.auth_header_prefix` | | Header value prefix, for example `Bearer ` |
| `https.auth_secret_app_name`, `https.auth_secret_keygroup_name`, `https.auth_secret_key_name` | | `PrivateKeyStore.getSecret` arguments for the header value |
| `https.auth_secret_refresh_secs` | `3600` | Secret refresh interval |

## Security Considerations

* **The PDP becomes part of your trust base.** In FILTER mode it can only reduce
  access (except for claims). In AUTHORITATIVE mode it decides what ZTS-signed
  tokens grant. Protect the PDP, its policy store and its administration as
  carefully as ZMS.
* **Data sent to the PDP.** This includes principal names, requested scopes, the
  client IP and selected subject-token claims. Raw tokens, DPoP proofs and
  certificates are never sent. AUDIT mode sends production data from day one, so
  secure the transport and PDP access before enabling it.
* **Configuration is server-wide.** Only ZTS operators can change the endpoint.
  Domain administrators can't redirect data to another PDP.
* **Contextual decisions only apply at issuance.** A token stays valid until it
  expires. Use `max_expires_in` to shorten lifetimes for decisions based on
  short-lived signals such as risk scores.

## Troubleshooting

| Symptom | Check |
|---|---|
| ZTS fails to start after enabling | The ZTS log names the failing property or the PDP initialization error. Common causes are a missing `endpoint`, a `class://` class not on the classpath, an adapter that overrides neither `evaluate` nor `evaluations`, an unreachable discovery endpoint, or a missing auth secret. |
| Every request returns `503` | Decision-log `error_code`. `TIMEOUT` means raise `timeout_ms` or speed up the PDP. `UNAVAILABLE` means the PDP can't be reached or `max_concurrency` was reached. `INVALID_RESPONSE` means the PDP returned the wrong number of results, a `null` result, or a non-200 status. |
| Role certificate clients get `403` | Expected in FILTER and AUTHORITATIVE. Move them to access tokens. Use AUDIT and `zts_ext_pdp_role_credential_request` to find them in advance. |
| A role is missing from the token | Decision-log `permitted_roles` and `reasons`. In AUTHORITATIVE, also check `undefined_roles` (the role isn't defined and `require_defined_roles=true`). |
| `400 invalid_scope` in AUTHORITATIVE | The request used a domain-wide scope with `require_defined_roles=false`, or exceeded `max_candidate_roles`. |
| Claims missing from the token | `claims_enabled`, decision-log `claims_rejected`, `claims_allowed` and the reserved-name list. |
| AUDIT shows `audit_dropped` | The PDP is slower than the request rate. Raise `audit_queue_size` or speed up the PDP. Token issuance is unaffected. |

For the design rationale and internals, see
[External PDP Integration design](design/external-pdp-integration.md).
