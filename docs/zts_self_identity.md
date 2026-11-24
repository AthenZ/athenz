# ZTS Self Identity

ZTS can issue and refresh a client certificate for its own identity
(`sys.auth.zts`) with its configured certificate signer. ZTS can then use
that certificate to prove its identity to external services, without
provisioning a certificate outside of ZTS (e.g. with SIA or another PKI):

- mTLS connections to instance providers (`athenz.client@` endpoints)
- IAM Roles Anywhere when obtaining AWS temporary credentials

The feature is disabled unless a self identity store is configured.

## How It Works

1. During startup, after the domain data has been loaded, ZTS generates a key
   pair and a CSR for `sys.auth.zts` and signs it with its cert signer.
2. The key and certificate are passed to the configured `SelfIdentityStore`.
   The default store writes them as PEM files into a directory.
3. This happens before the instance provider manager is created, so the
   provider client SSL context can load the files. If the initial certificate
   cannot be issued or stored, ZTS fails to start.
4. A new key pair and certificate are issued at the configured refresh
   interval. If a refresh fails, the current certificate keeps being used and
   the refresh is retried every 5 minutes.

## Issuance Rules

The certificate is issued with the same rules as service identity
certificates:

- The `sys.auth.zts` service must be registered in ZMS, unless
  `athenz.zts.validate_service_identity` is disabled.
- The CSR is validated the same way as service certificate requests
  (common name, dns names, Subject O/OU fields and SPIFFE URI).
- The expiry time and signer key id are determined the same way as for
  service identity certificates. The requested expiry time cannot exceed the
  service cert expiry configured for the `sys.auth` domain. If no expiry time
  is requested, the domain value or `athenz.zts.service_cert_default_expiry_mins`
  is used, and otherwise the cert signer default applies.
- The certificate is requested for client usage. The cert signer decides the
  final extended key usage: the crypki based signers (e.g. `HttpCertSignerFactory`
  and the `JavaCrypkiCertSignerFactory` signers) issue a clientAuth only
  certificate, while `KeyStoreCertSignerFactory` and `SelfCertSignerFactory`
  ignore the requested usage and include both clientAuth and serverAuth.
- Every issued certificate is logged in the cert record store log with the
  loopback address and the ZTS hostname as the instance id.

## Configuration

| Property | Description |
|---|---|
| `athenz.zts.self_identity_store_factory_class` | `SelfIdentityStoreFactory` implementation. Set to `com.yahoo.athenz.common.server.identity.impl.FileSelfIdentityStoreFactory` to use the default file store. |
| `athenz.zts.self_identity.dir` | Directory where the default file store writes the files (required for the file store). |
| `athenz.zts.self_identity.cert_expiry_mins` | Requested expiry time in minutes, capped as described above. |
| `athenz.zts.self_identity.refresh_interval_mins` | Refresh interval in minutes (default `1440`). The value is used as is, so it must be shorter than the certificate expiry time. A warning is logged if the certificate expires before the next refresh. |
| `athenz.zts.self_identity.key_algorithm` | `RSA` (2048 bits, default) or `EC` (prime256v1). |
| `athenz.zts.self_identity.spiffe_uri_format` | `trust_domain` (default): `spiffe://<athenz.zts.spiffe_trust_domain>/ns/default/sa/sys.auth.zts`, `basic`: `spiffe://sys.auth/sa/zts`, or `none` to not include a SPIFFE URI. The format must be accepted by `athenz.zts.spiffe_uri_validator_classes` (both validators are enabled by default). |

## Default File Store

The default store writes the following files into `athenz.zts.self_identity.dir`.
The directory is created if necessary and restricted to the owner (mode 0700).
Each file is replaced atomically.

| File | Content |
|---|---|
| `zts.key.pem` | Unencrypted PKCS#8 private key (mode 0600) |
| `zts.cert.pem` | Certificate as returned by the cert signer: the leaf certificate, followed by its intermediate certificates if the signer includes them |
| `ca.cert.pem` | CA certificate bundle of the cert signer (only if available), same as the `ca.cert.pem` file written by SIA |

The private key is written unencrypted, so using a memory backed file system
(e.g. tmpfs) is recommended. The files do not need to persist across restarts
since ZTS issues a new identity during every startup.

## Using the Identity

Point the existing settings of other components to the files.

### Instance Provider mTLS

```properties
athenz.zts.provider.ssl_client_public_cert_path=<dir>/zts.cert.pem
athenz.zts.provider.ssl_client_private_key_path=<dir>/zts.key.pem
```

All the certificates in the cert file, including the intermediate certificates
returned by the cert signer, are sent during the TLS handshake. The files are
reloaded periodically (hourly by default), so the certificate expiry time must
leave enough time to load a refreshed certificate.

### IAM Roles Anywhere

```properties
athenz.zts.rolesanywhere.cert_path=<dir>/zts.cert.pem
athenz.zts.rolesanywhere.key_path=<dir>/zts.key.pem
```

- `athenz.zts.rolesanywhere.key_algorithm` must match
  `athenz.zts.self_identity.key_algorithm` since the private key is parsed with
  the configured algorithm.
- Only the first certificate in `zts.cert.pem` (the leaf certificate) is used.
  No intermediate-only chain file is provided for
  `athenz.zts.rolesanywhere.chain_path` (`ca.cert.pem` is the CA bundle and may
  include root certificates), so the trust anchor must be the CA that issues
  the certificate.
- When the Athenz CA is the trust anchor, the role trust policy must restrict
  the certificate subject, e.g. with the condition
  `aws:PrincipalTag/x509Subject/CN = sys.auth.zts`, since otherwise any service
  certificate issued by the same CA can assume the role.

## Custom Stores

To keep the identity somewhere other than files (e.g. in memory or in an
external secret store), implement `com.yahoo.athenz.common.server.identity.SelfIdentityStore`
and `SelfIdentityStoreFactory`. ZTS calls `storeIdentity` with the private key,
the certificate chain returned by the cert signer and the CA certificate bundle
during startup and after every refresh. If the method throws an exception during
startup, ZTS fails to start; otherwise the refresh is retried.

## Limitations

- The identity cannot be used by ZTS to fetch domain data from ZMS
  (e.g. `athenz.common.server.clog.zts_server_cert_path`), since the
  certificate is issued based on the domain data. Use the default private key
  based authentication or an externally provisioned certificate for ZMS.
- The certificate is a full `sys.auth.zts` identity. Protect the files and keep
  the expiry time short.
- Refresh failures are only reported in the server log.
