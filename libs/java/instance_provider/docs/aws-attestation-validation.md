# AWS Instance Attestation Validation

Reference for the pluggable AWS instance-attestation validation in
`InstanceAWSProvider`, which supports both the traditional AWS STS temporary
credentials mechanism and AWS's OIDC **web identity token** (outbound identity
federation).

## 1. Overview

When an AWS workload requests an X.509 identity from ZTS, the `InstanceAWSProvider`
must prove the caller really is the IAM role it claims to be, in the expected AWS
account. Historically this proof was done by placing **STS temporary credentials**
(access key / secret / session token) in the attestation data; ZTS then called
`sts:GetCallerIdentity` and matched the returned ARN.

AWS now also supports issuing a signed OIDC **JWT web identity token** that
external systems can verify against AWS's published JWKS. This module can accept
that token as attestation data and validate it **locally** (signature + claims),
avoiding the need to ship live credentials to ZTS and aligning AWS with the other
JWT/OIDC-based providers (GitHub Actions, Harness, BuildKite, Spacelift, EKS).

The identity-verification step lives behind a **swappable interface**, so Athenz
adopters can choose the STS mechanism, the JWT mechanism, both (the default), or a
completely custom implementation. **The change is fully backward compatible**: with
no configuration change, existing credentials-based clients keep working exactly as
before.

## 2. The two attestation mechanisms

| | STS temporary credentials (traditional) | AWS web identity token (new) |
|---|---|---|
| Attestation data | `access` / `secret` / `token` | `identityToken` (a signed JWT) |
| How ZTS verifies | Calls `sts:GetCallerIdentity`, matches ARN | Verifies JWT signature via the per-account issuer JWKS, then validates the audience, `aws_account`, `org_id`, and (optionally) the `sub`/`principal_tags` |
| Network call at verify time | Yes (to AWS STS) | No (JWKS is fetched + cached per issuer) |
| Live credentials sent to ZTS | Yes | No |

Selection is **per request**: the default `CompositeAWSAttestationValidator` routes
to the JWT validator when `identityToken` is present in the attestation data, and
falls back to the STS validator otherwise.

## 3. Architecture

The design mirrors the existing `KubernetesDistributionValidator` /
`KubernetesDistributionValidatorFactory` pattern in this module.

```
InstanceAWSProvider
   │  initialize(): reads factory class property, creates validator
   │  confirmInstance()/refreshInstance(): delegates identity check
   ▼
AWSAttestationValidator (interface)
   ├── AWSStsCredentialsAttestationValidator      (STS GetCallerIdentity)
   ├── AWSWebIdentityTokenAttestationValidator     (AWS OIDC JWT)
   └── CompositeAWSAttestationValidator            (routes by identityToken; DEFAULT)

AWSAttestationValidatorFactory (interface)
   └── DefaultAWSAttestationValidatorFactory       (builds + initializes the composite)
```

### Class reference

| Class / interface | Path |
|---|---|
| `AWSAttestationValidator` | `src/main/java/com/yahoo/athenz/instance/provider/AWSAttestationValidator.java` |
| `AWSAttestationValidatorFactory` | `src/main/java/com/yahoo/athenz/instance/provider/AWSAttestationValidatorFactory.java` |
| `AWSStsCredentialsAttestationValidator` | `src/main/java/com/yahoo/athenz/instance/provider/impl/AWSStsCredentialsAttestationValidator.java` |
| `AWSWebIdentityTokenAttestationValidator` | `src/main/java/com/yahoo/athenz/instance/provider/impl/AWSWebIdentityTokenAttestationValidator.java` |
| `CompositeAWSAttestationValidator` | `src/main/java/com/yahoo/athenz/instance/provider/impl/CompositeAWSAttestationValidator.java` |
| `DefaultAWSAttestationValidatorFactory` | `src/main/java/com/yahoo/athenz/instance/provider/impl/DefaultAWSAttestationValidatorFactory.java` |
| `InstanceAWSProvider` (wiring) | `src/main/java/com/yahoo/athenz/instance/provider/impl/InstanceAWSProvider.java` |
| `AWSAttestationData` (`identityToken` field) | `src/main/java/com/yahoo/athenz/instance/provider/impl/AWSAttestationData.java` |

### Interface contract

```java
public interface AWSAttestationValidator {
    void initialize(SSLContext sslContext, Authorizer authorizer, Principal providerPrincipal);
    boolean validateIdentity(InstanceConfirmation confirmation, AWSAttestationData info,
            String awsAccount, StringBuilder errMsg);
}

public interface AWSAttestationValidatorFactory {
    AWSAttestationValidator create(SSLContext sslContext, Authorizer authorizer, Principal providerPrincipal);
}
```

`validateIdentity` returns `true` when the attestation proves the instance identity
for the requested `confirmation` in `awsAccount`; on failure it returns `false` and
appends a human-readable reason to `errMsg`. The `Authorizer` (supplied at init) is
used for the launch checks; the STS validator ignores it. The `providerPrincipal`
identifies the provider service (e.g. `sys.auth.aws`) carrying out the system level
launch check.

`awsAccount` may be **empty** — the domain need not have an associated AWS account.
Only `AWSWebIdentityTokenAttestationValidator.validateAwsAccount()` tolerates that
(the request is then authorized purely through the launch policies below); every
other consumer rejects an empty account as early as possible:
`InstanceAWSProvider.validateAWSAccount()` (the instance document path) and
`AWSStsCredentialsAttestationValidator.validateIdentity()`.

## 4. Request flow

Both `confirmInstance()` and `refreshInstance()` perform the same identity step:

1. Parse `AWSAttestationData` from the confirmation's attestation data.
2. Validate AWS account id, service/role name, SAN DNS entries, the instance
   identity document (if present), and IP addresses — **unchanged** existing logic.
3. Verify identity via the configured validator:

   ```java
   StringBuilder identityErrMsg = new StringBuilder(256);
   if (!attestationValidator.validateIdentity(confirmation, info, awsAccount, identityErrMsg)) {
       throw error("Unable to verify instance identity credentials: " + identityErrMsg);
   }
   ```

Inside `CompositeAWSAttestationValidator`:

```
identityToken present?  ── yes ──▶ AWSWebIdentityTokenAttestationValidator
        │
        └── no ──▶ AWSStsCredentialsAttestationValidator
```

- **STS validator** — builds an `StsClient` from the temporary credentials, calls
  `GetCallerIdentity`, and checks `response.arn()` starts with
  `arn:aws:sts::<awsAccount>:assumed-role/<role>/`.
- **Web identity validator** — validates a real AWS STS token whose issuer is unique
  per account (e.g. `https://<uuid>.tokens.sts.global.api.aws`) and whose identity
  attributes live in a nested claim keyed `https://sts.amazonaws.com/`. Steps:
  1. Extract the issuer from the token and confirm it matches the configured issuer
     regex.
  2. Resolve (and cache per issuer) the issuer JWKS via its
     `/.well-known/openid-configuration`, then verify the token signature + expiry.
  3. `aud` must equal the configured audience.
  4. The nested `aws_account` must equal one of the domain's AWS accounts (the domain
     may have none). Otherwise a **tenant** `launch` authorization is required —
     `authorizer.access("launch", "<domain>:<service>:<tokenAwsAccount>",
     <domain>.<service>)` (mirrors EKS). That policy is granted inside the tenant
     domain itself, so when `athenz.zts.aws_web_identity_cross_authz_domain` is
     configured a **system** `launch` authorization is evaluated first —
     `authorizer.access("launch",
     "<crossAuthzDomain>:<tokenAwsAccount>:<domain>:<service>", <providerPrincipal>)` —
     letting the system administrators gate which account/service combinations may use
     the cross-account path at all. Both checks must pass; when the property is unset
     only the tenant check applies.
  5. `org_id` must be present and in the configured allowlist (mandatory).
  6. **Principal role binding (default).** The IAM role name in the token `sub`
     (`arn:aws:iam::<acct>:role/[path/]<name>` — the IAM path, if any, is stripped)
     must equal the requested service: `<domain>.<service>` or `<service>`. This mirrors
     the STS validator's ARN check and prevents one role in the account from obtaining a
     certificate for a different service identity (e.g. a `sys.auth.cron` role requesting
     `sys.auth.zts`). Since AWS only mints a token for the role a workload actually is,
     the `sub` cannot be forged to another service.
  7. If an adopter `AttrValidator` is configured, the `sub` and `principal_tags` are
     placed on the confirmation attributes and `attrValidator.confirm(...)` is called.
     When configured it has the **final say** on the principal and is the escape hatch
     for adopters whose IAM role names diverge from the service — it is consulted even
     when the default binding in step 6 does not match. When **not** configured, the
     step 6 binding is strictly enforced (a mismatch is rejected).

## 5. Reused building blocks

The JWT validator does **not** re-implement JWT handling; it reuses `auth_core` and
existing provider extension points:

- `com.yahoo.athenz.auth.token.jwts.JwtsHelper` — `parseJWTWithoutSignature` (issuer
  extraction before verification) and `extractJwksUri` (derives the JWKS URI from the
  issuer's `/.well-known/openid-configuration`).
- `com.yahoo.athenz.auth.token.jwts.JwtsSigningKeyResolver` — fetches and caches the
  issuer JWKS (7-day cache, outage tolerant); one resolver is cached per issuer in a
  `ConcurrentHashMap`, mirroring `CommonKubernetesDistributionValidator`.
- `com.yahoo.athenz.auth.token.IdToken` / `OAuth2Token` — verifies the signature +
  expiry and exposes `getAudience`, `getSubject`, `getClaim(name)` (used to read the
  nested `https://sts.amazonaws.com/` claim).
- `com.yahoo.athenz.instance.provider.AttrValidator` / `AttrValidatorFactory` — the
  existing extension point reused for **additional** adopter-specific `sub` /
  `principal_tags` validation on top of the mandatory role-name binding (same mechanism
  the K8S provider uses for subject validation).
- `com.yahoo.athenz.common.server.util.config.dynamic.DynamicConfigCsv` — the
  dynamically-reloadable `org_id` allowlist.

## 6. Configuration

All properties are optional **except** the `org_id` allowlist (required for the JWT
path). With none set, behavior is identical to the previous STS-only implementation
(the JWT path only engages when a token is presented).

| Property | Purpose | Default |
|---|---|---|
| `athenz.zts.aws_attestation_validator_factory_class` | Fully-qualified `AWSAttestationValidatorFactory` to load | `com.yahoo.athenz.instance.provider.impl.DefaultAWSAttestationValidatorFactory` |
| `athenz.zts.aws_web_identity_audience` | Expected JWT audience (`aud`) — set to the ZTS URL | *(unset → every token rejected)* |
| `athenz.zts.aws_web_identity_issuer_regex` | Allowed issuer (`iss`) host pattern | `https://[a-z0-9-]+\.tokens\.sts\.global\.api\.aws` |
| `athenz.zts.aws_web_identity_allowed_org_ids` | **Mandatory** `org_id` allowlist (CSV, dynamically reloadable) | *(empty → every token rejected)* |
| `athenz.zts.aws_web_identity_cross_authz_domain` | Optional system level authorization domain for the cross-account case. When set, the provider service must additionally be granted `launch` on `<domain>:<tokenAwsAccount>:<tenantDomain>:<tenantService>` | *(unset → only the tenant launch policy is evaluated)* |
| `athenz.zts.aws_web_identity_principal_validator_factory_class` | Optional adopter `AttrValidatorFactory` for `sub`/`principal_tags`. When set it has the final say on the principal (and overrides the default role-name binding); when unset the default binding is strictly enforced | *(unset → default binding enforced)* |
| `athenz.zts.aws_web_identity_sts_claim_name` | Nested identity claim key | `https://sts.amazonaws.com/` |
| `athenz.zts.aws_web_identity_discovery_proxy` | Optional HTTP proxy for issuer OIDC discovery + JWKS fetch | *(none)* |
| `athenz.zts.aws_region_name` | AWS region for the STS client (reused, pre-existing) | *(none)* |

### Attestation data schema

`AWSAttestationData` gained one optional field; the JSON is otherwise unchanged:

```json
{
  "role": "athenz.api",
  "access": "…", "secret": "…", "token": "…",   // STS path
  "identityToken": "<signed-JWT>"                 // web identity path (new, optional)
}
```

### Example decoded web identity token

```json
{
  "aud": "https://dev-zts.example.com/zts/v1",
  "iss": "https://a235ce0e-ece5-7bh3-b26c-62f78631444b.tokens.sts.global.api.aws",
  "sub": "arn:aws:iam::123456789012:role/athenz.api",
  "exp": 1777042075, "iat": 1777041775,
  "https://sts.amazonaws.com/": {
    "aws_account": "123456789012",
    "org_id": "o-qwsedrftg3",
    "principal_id": "arn:aws:iam::123456789012:role/athenz.api",
    "principal_tags": { "key1": "val1", "key2": "val2", "key3": "val3" }
  }
}
```

## 7. Backward compatibility

- The default factory produces the **composite** validator.
- Existing clients send no `identityToken`, so the composite routes to the STS
  validator — identical to the prior behavior.
- Subclasses `InstanceAWSECSProvider` and `InstanceAWSLambdaProvider` are unaffected;
  they don't participate in identity verification beyond the shared delegation.

## 8. Extensibility

An adopter can plug in custom behavior at two levels without modifying this module:

**Whole validator** — supply an `AWSAttestationValidatorFactory`:

1. Implement `AWSAttestationValidator` (and optionally reuse
   `AWSStsCredentialsAttestationValidator` / `AWSWebIdentityTokenAttestationValidator`).
2. Implement `AWSAttestationValidatorFactory.create(...)` to build + `initialize` it.
3. Set `-Dathenz.zts.aws_attestation_validator_factory_class=<your.Factory>`.

**Principal (sub/tags) validation** — the default role-name binding (role in `sub` must
equal the requested service) is enforced whenever no adopter validator is configured.
Adopters whose IAM role names diverge from the service, or who need extra `principal_tags`
policy, supply an `AttrValidatorFactory` via
`-Dathenz.zts.aws_web_identity_principal_validator_factory_class=<your.Factory>`; when set it has
the final say on the principal and is consulted even if the default binding does not match.
The validator receives the `InstanceConfirmation` with the token `sub` in the
`attestationDataSubject` attribute and each principal tag under the
`awsPrincipalTag:<TagName>` attribute prefix
(`InstanceProvider.ZTS_INSTANCE_ATTESTATION_DATA_SUBJECT` /
`ZTS_INSTANCE_AWS_PRINCIPAL_TAG_PREFIX`). Adopters who need to reject certain requests
outright can also replace the whole validator (above).

## 9. Testing

Unit tests (TestNG + Mockito; module enforces 100% line coverage) under
`src/test/java/com/yahoo/athenz/instance/provider/impl/`:

| Test | Covers |
|---|---|
| `AWSStsCredentialsAttestationValidatorTest` | STS client creation, `GetCallerIdentity`, ARN match/mismatch, empty aws account, null/exception paths |
| `AWSWebIdentityTokenAttestationValidator[Test]` | Issuer extraction + regex, per-issuer JWKS resolution & cache, signature/expiry, audience, nested `sts` claim, aws_account match, empty domain account (allowed only here), tenant cross-account launch authorization (allow/deny/no-authorizer), system cross-account launch authorization (unconfigured/allow/deny, tenant check skipped on deny), mandatory org_id allowlist, default role-name binding (match / mismatch / IAM path / service-only / malformed / missing sub) and its `AttrValidator` override (mismatch allowed/denied), `AttrValidator` principal allow/deny/skip |
| `CompositeAWSAttestationValidatorTest` | Routing (token → JWT, no token → STS), init delegation |
| `DefaultAWSAttestationValidatorFactoryTest` | Factory returns an initialized composite |
| `InstanceAWSProviderTest` | Factory selection (default/custom/invalid class), `setAuthorizer`, provider principal creation, empty aws account (rejected with an instance document, allowed without one), confirm/refresh delegation via `MockAWSAttestationValidator` |
| `AWSAttestationDataTest` | `identityToken` getter/setter |

`MockAWSAttestationValidator` is a shared test helper whose result can be toggled so
provider tests can force identity success/failure without calling AWS. The principal
`AttrValidator` plug-in is exercised with the existing `MockAttrValidatorFactory` /
`MockFailingAttrValidatorFactory`.

## 10. Open items / follow-ups

- **SIA client side is not yet implemented.** The `sia-ec2` / `sia-eks` /
  `sia-fargate` agents do not yet obtain and populate `identityToken`, so the JWT
  path is dormant until that client work lands. The ZTS-side validation is ready.
- **AWS token spec defaults to the observed format.** The issuer regex, the nested
  `https://sts.amazonaws.com/` claim key, and the audience are configurable; adjust
  the defaults in `AWSWebIdentityTokenAttestationValidator` if AWS changes the format.
