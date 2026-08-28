# athenz-crypki

Generic Athenz X.509 signing library. ZTS builds a sign request and calls
`CrypkiSigner`. Backends plug in without changing the ZTS cert-signer contract.

This is a **library**, not a standalone signing service. The historical
[Go Crypki](https://github.com/theparanoids/crypki) project is a separate
process that talks to an HSM over PKCS#11 and exposes REST/gRPC. This module
gives ZTS the same X.509 minting path either by calling that Go service over
HTTP, or by signing in-process with KMS / HSM.

See also the ZTS-facing page: [Certificate Signer](../../../docs/cert_signer.md).

## How the library works

ZTS already has a `CertSigner` SPI (`athenz.zts.cert_signer_factory_class`).
This module sits under that SPI:

1. `CrypkiRequestFactory` turns ZTS arguments (CSR PEM, provider, key usage,
   expiry minutes, priority, signer key id) into a generic `X509SignRequest`.
   Key-id resolution matches the historical HTTP client: explicit `signerKeyId`,
   else a per-provider map, else `x509-key`.
2. `CrypkiSigner.sign(X509SignRequest)` returns a PEM leaf certificate.
   `getCACertificate(keyId)` returns the CA PEM that ZTS ships back to the client.
3. `CrypkiCertSigner` is the `CertSigner` adapter used by the KMS/HSM factories.
4. Cloud SDKs stay out of this jar. `KmsClient` and `HsmClient` are interfaces
   here; AWS and GCP implement them in `athenz-server-aws-common` and
   `athenz-server-gcp-common`.

There is one CA for all identities this signer mints. Caller identity is
in the leaf (CN, SAN, SPIFFE), not a per-tenant CA.

```
SIA / instance provider
  → ZTS (validates CSR, Copper Argos)
      → CertSigner
          → CrypkiRequestFactory
          → CrypkiSigner.sign()
               → HttpCrypkiSigner     (remote Go Crypki)
               → KmsCrypkiSigner      (AWS KMS / GCP KMS)
               → HsmCrypkiSigner      (CloudHSM / PKCS#11)
```

## Deployments

Existing deployments keep the remote Go Crypki path. The HTTP client that used
to live only in ZTS is now in this module. ZTS
`com.yahoo.athenz.zts.cert.impl.crypki.HttpCertSigner` is a thin subclass that
only supplies ZTS TLS settings.

```
athenz.zts.cert_signer_factory_class=com.yahoo.athenz.zts.cert.impl.crypki.HttpCertSignerFactory
athenz.zts.certsign_base_uri=https://crypki.example.com:4443
```

HTTP property names are unchanged (`athenz.zts.certsign_*`). A deployment that
already talks to Go Crypki does not need a new factory class.

Optional in-process backends (same ZTS property, different factory):

| Backend | Factory | Library |
|---|---|---|
| Remote Go Crypki (HTTP) | `com.yahoo.athenz.crypki.http.HttpCrypkiSignerFactory` | this jar |
| AWS KMS | `io.athenz.server.aws.common.cert.impl.AwsKmsCrypkiSignerFactory` | athenz-server-aws-common |
| AWS CloudHSM | `io.athenz.server.aws.common.cert.impl.AwsCloudHsmCrypkiSignerFactory` | athenz-server-aws-common |
| GCP KMS | `io.athenz.server.gcp.common.cert.impl.GcpKmsCrypkiSignerFactory` | athenz-server-gcp-common |

Environment-specific wiring (account, key alias, CA PEM path) belongs in the
deploying repo, not this module.

## Workflow

1. A service (SIA) sends a CSR to ZTS.
2. ZTS authenticates the instance and checks the CSR (domain, SAN, SPIFFE).
3. ZTS calls `CertSigner.generateX509Certificate(...)`.
4. `CrypkiRequestFactory` picks the key id, caps validity, and maps key usage
   to Crypki EKU integers (`client` → 2, `codeSigning` → 3, `timestamping` → 8).
5. The selected `CrypkiSigner` mints the leaf:
   - **HTTP:** POST `/sig/x509-cert/keys/{keyId}` on Go Crypki; GET for the CA.
   - **KMS:** `X509CertificateMinter` builds the TBS certificate; `KmsClient.sign`
     produces the signature. The CA cert is loaded from
     `athenz.crypki.kms.ca_cert_path`.
   - **HSM:** same minter, but `HsmClient.getSigningKey(keyId)` supplies a
     `SigningKey` whose private key never leaves the module.
6. ZTS returns the leaf PEM plus the CA PEM to the client.

## What changed from the Go library

Go Crypki (`theparanoids/crypki`) is a **signing service**. This module is a
**signer library** that ZTS embeds.

| | Go Crypki | Java `athenz-crypki` |
|---|---|---|
| Form | Standalone daemon (REST + gRPC v3) | In-process jar used by ZTS |
| Callers | ZTS, SSHCA, and other HTTP/gRPC clients | ZTS `CertSigner` only |
| Certificates | X.509 and SSH | X.509 only |
| Key custody | PKCS#11 / HSM inside the Go process | Pluggable: remote Go Crypki, KMS, or HSM |
| HTTP API | Owns `/sig/x509-cert/keys/...` | Optional client of that API (`HttpCrypkiSigner`) |
| Cloud KMS | Not in-tree | AWS/GCP clients in the existing cloud common modules |
| ZTS config | `HttpCertSignerFactory` + `athenz.zts.certsign_base_uri` | Same factory still works; KMS/HSM use new factories |

Compatibility kept on purpose:

- Existing `HttpCertSignerFactory` class name and `athenz.zts.certsign_*`
  properties still work.
- Request shape (key meta, CSR, EKU ints, validity seconds, priority) matches
  the Go `/sig/x509-cert` contract.
- Soft-fail HTTP behavior is unchanged: `sign()` may return `null` instead of
  throwing, same as the old ZTS client.

Intentionally not ported:

- SSH certificate minting
- A Java clone of the Go HTTP/gRPC server (no v3 facade unless a non-ZTS
  caller appears)
- Per-tenant CAs
- Cloud SDK types inside `athenz-crypki` itself

## Configuration

HTTP (Go Crypki) — same properties as before:

- `athenz.zts.certsign_base_uri`
- `athenz.zts.certsign_connect_timeout`
- `athenz.zts.certsign_request_timeout`
- `athenz.zts.certsign_retry_count`
- `athenz.zts.certsign_max_expiry_time`
- `athenz.zts.certsign_provider_keys_fname`

KMS / HSM:

- `athenz.crypki.kms.key_id`
- `athenz.crypki.kms.ca_cert_path`
- `athenz.crypki.kms.signing_algorithm` (default `SHA256withRSA`)
- `athenz.crypki.hsm.module_path` (CloudHSM default `/opt/cloudhsm/lib/libcloudhsm_pkcs11.so`)
- `athenz.crypki.hsm.slot`
- `athenz.crypki.hsm.key_label` (default `athenz-crypki-ca`)
- `athenz.crypki.hsm.pin_path` (CloudHSM PIN file: `username:password`)
- `athenz.crypki.hsm.ca_cert_path`

AWS CloudHSM signing keys are label-only (no PKCS#11 certificate object).
Put `cloudhsm-jce-*.jar` on the ZTS classpath so
`AwsCloudHsmCrypkiSignerFactory` can load the key by label. SunPKCS11
alone will not see those keys.
