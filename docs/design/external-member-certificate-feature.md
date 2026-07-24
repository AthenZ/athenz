# External Member Certificate Feature - Design Document

**Date:** July 2026
**Status:** For Security Review
**Components:** ZTS Server (`postExternalMemberCertificateRequest`), `ExternalMemberCertificateProvider`, `X509ExternalMemberCertRequest`

---

## 1. Overview

The External Member Certificate feature allows an external member principal to obtain a short-lived X.509 TLS client certificate from ZTS through a dedicated `/extmembercert` endpoint. The requested identity is validated through an external Identity Provider (IdP) using the OAuth 2.0 Authorization Code flow before ZTS signs the submitted CSR.

This feature is intentionally separate from the User Certificate feature:

- It uses `POST /extmembercert`, not `POST /usercert`.
- It uses `ExternalMemberCertificateRequest` and `ExternalMemberCertificate` API types, not `UserCertificateRequest` or `UserCertificate`.
- It uses `ExternalMemberCert.rdli`, not `UserCert.rdli`.
- It uses `ExternalMemberCertificateProvider`, not `UserCertificateProvider`.
- It uses `athenz.zts.external_member_cert_provider`, not `athenz.zts.user_cert_provider`.
- It uses separate timeout and signer-key allow-list properties.
- It does not consult `userAuthority` or user-domain role tags.

---

## 2. API Contract

**API Endpoint:** `POST /extmembercert`

**Request Schema:**

| Field | Type | Required | Description |
|---|---|---|---|
| `name` | `ExternalMemberName` | Yes | External member principal name. The RDL pattern is `{DomainName}:ext\\..+`. |
| `csr` | String | Yes | PEM-encoded PKCS#10 Certificate Signing Request |
| `attestationData` | String | Yes | OAuth2 callback query string containing the authorization code |
| `expiryTime` | Int32 | No | Requested certificate expiry in minutes |
| `x509CertSignerKeyId` | SimpleName | No | Requested X.509 cert signer key ID |

**Response Schema:**

| Field | Type | Description |
|---|---|---|
| `x509Certificate` | String | PEM-encoded X.509 certificate |

---

## 3. Server-Side Handling

The ZTS handler is `postExternalMemberCertificateRequest`.

1. **Read-only mode check** - Reject if ZTS is in maintenance mode.
2. **Configuration check** - Verify `externalMemberCertProvider` is configured. The handler does not fall back to `userCertProvider`.
3. **Schema validation** - Validate the request against `ExternalMemberCertificateRequest`.
4. **External member name validation**:
   - The name must be non-empty.
   - The name must not contain wildcards.
   - The name must satisfy the `ExternalMemberName` RDL type.
   - The domain before `:` must be listed in `athenz.zts.external_member_cert_allowed_domains`.
5. **CSR parsing** - Parse the CSR as `X509ExternalMemberCertRequest`.
6. **CN validation** - The CSR Common Name must exactly match the requested external member name.
7. **CSR content validation**:
   - DNS SANs are forbidden.
   - IP SANs are forbidden.
   - Instance ID and URI hostname must be absent.
   - URI SANs are forbidden.
   - Subject `O` must be in the configured certificate subject organization allow-list.
8. **Provider attestation** - Delegate to the configured external member certificate provider.
9. **Signer key selection** - Accept `x509CertSignerKeyId` only when it is listed in `athenz.zts.external_member_cert_signer_key_id_list`.
10. **Expiry determination** - Use `athenz.zts.external_member_cert_default_timeout`, honor shorter valid request values, and cap the result with `athenz.zts.external_member_cert_max_timeout`.
11. **Certificate signing** - Submit the CSR to the cert signer with client certificate usage.
12. **Logging and response** - Log the issued certificate and return `ExternalMemberCertificate`.

---

## 4. Provider

`ExternalMemberCertificateProvider` implements `InstanceProvider` and performs IdP attestation for external member certificate requests.

### 4.1 Initialization

| Property | Required | Default | Description |
|---|---|---|---|
| `athenz.zts.external_member_cert.idp_config_endpoint` | No | - | OpenID Connect discovery endpoint. When set, token and JWKS endpoints are discovered from it. |
| `athenz.zts.external_member_cert.idp_token_endpoint` | Yes* | - | IdP token endpoint. Required when discovery is not used. Must be HTTPS. |
| `athenz.zts.external_member_cert.idp_jwks_endpoint` | Yes* | - | IdP JWKS endpoint. Required when discovery is not used. Must be HTTPS. |
| `athenz.zts.external_member_cert.idp_client_id` | Yes | - | OAuth2 client ID |
| `athenz.zts.external_member_cert.idp_redirect_uri` | No | `http://127.0.0.1:9213/oauth2/callback` | OAuth2 redirect URI |
| `athenz.zts.external_member_cert.idp_audience` | Yes | - | Expected access token audience |
| `athenz.zts.external_member_cert.connect_timeout` | No | `10000` ms | Connection timeout for IdP requests |
| `athenz.zts.external_member_cert.read_timeout` | No | `15000` ms | Read timeout for IdP requests |
| `athenz.zts.external_member_cert.member_name_claim` | No | - | Optional custom claim that can contain the external member name |
| `athenz.zts.external_member_cert.idp_client_secret_app` | No | - | App name for secret store lookup |
| `athenz.zts.external_member_cert.idp_client_secret_keygroup` | No | - | Key group for secret store lookup |
| `athenz.zts.external_member_cert.idp_client_secret_keyname` | No | - | Key name for secret store lookup |

The token endpoint and JWKS endpoint are validated during initialization and must use HTTPS.

### 4.2 `confirmInstance()` Attestation Verification

1. Extract `code` and optional `code_verifier` from `attestationData`.
2. Exchange the authorization code for an access token at the configured IdP token endpoint.
3. Require PKCE (`code_verifier`) when no client secret is configured.
4. Validate the returned JWT access token signature using the configured JWKS endpoint.
5. Validate that the token subject equals the requested external member name, or that the configured `member_name_claim` equals the requested external member name.
6. Validate that the token audience equals `athenz.zts.external_member_cert.idp_audience`.

### 4.3 `refreshInstance()`

`refreshInstance()` always rejects the request. External member X.509 certificates cannot be refreshed.

---

## 5. ZTS Configuration Summary

```properties
# Provider class for external member certificate attestation
athenz.zts.external_member_cert_provider=<external-member-provider-class-name>

# External member domains allowed for POST /extmembercert, for example: email
athenz.zts.external_member_cert_allowed_domains=email

# Certificate lifetime limits, in minutes
athenz.zts.external_member_cert_max_timeout=60
athenz.zts.external_member_cert_default_timeout=60

# Optional signer key allow list for external member certificate requests
athenz.zts.external_member_cert_signer_key_id_list=<signer-key-id-1>,<signer-key-id-2>

# IdP configuration
athenz.zts.external_member_cert.idp_config_endpoint=https://idp.example.com/.well-known/openid-configuration
athenz.zts.external_member_cert.idp_client_id=athenz-external-member-cert
athenz.zts.external_member_cert.idp_redirect_uri=http://127.0.0.1:9213/oauth2/callback
athenz.zts.external_member_cert.idp_audience=athenz-external-member-cert

# Client secret, fetched from PrivateKeyStore when configured
athenz.zts.external_member_cert.idp_client_secret_app=athenz
athenz.zts.external_member_cert.idp_client_secret_keygroup=external-member-cert
athenz.zts.external_member_cert.idp_client_secret_keyname=idp-client-secret

# Timeouts
athenz.zts.external_member_cert.connect_timeout=10000
athenz.zts.external_member_cert.read_timeout=15000

# Optional custom claim for external member name mapping
athenz.zts.external_member_cert.member_name_claim=preferred_username
```

---

## 6. Security Properties

- External member certificate requests are denied unless `athenz.zts.external_member_cert_provider` is configured.
- External member domains are denied by default unless explicitly listed in `athenz.zts.external_member_cert_allowed_domains`.
- The request name is validated as `ExternalMemberName` and the CSR Common Name must match it exactly.
- CSR DNS SANs, IP SANs, URI SANs, instance IDs, and URI hostnames are rejected.
- IdP token and JWKS endpoints must use HTTPS.
- The access token must be signed by the configured IdP and must match the configured audience.
- The token subject or configured member-name claim must match the requested external member name.
- Certificates are client-only, short-lived, and cannot be refreshed.
