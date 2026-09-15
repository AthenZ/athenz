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

The default KMS/HSM settings mint under one CA. Per-tenant CAs use ZTS
domain/service `x509CertSignerKeyId` (a CompoundName such as `tenant-a-ca`,
not `alias/...`) plus `athenz.crypki.kms.ca_cert_map_path` or
`athenz.crypki.hsm.ca_cert_map_path`. AWS KMS treats a SimpleName as
`alias/<id>` unless the map entry sets an explicit `keyId`. CloudHSM
uses the Athenz id as the PKCS#11 label unless `keyId` is set. GCP KMS
entries must set `keyId` to a CryptoKeyVersion resource
(`.../cryptoKeys/{key}/cryptoKeyVersions/{version}`); a path-only map
value leaves the Athenz id unchanged and GCP rejects it. Each tenant
must have its own KMS key or HSM label; sharing one signing key across
CA PEMs does not isolate tenants.

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

Existing ZTS `HttpCertSigner` / `HttpCertSignerFactory` code is unchanged.
In-process Java Crypki is opt-in by selecting its factory:

```
athenz.zts.cert_signer_factory_class=com.yahoo.athenz.zts.cert.impl.crypki.JavaCrypkiCertSignerFactory
athenz.zts.java_crypki_factory_class=io.athenz.server.aws.common.cert.impl.AwsKmsCrypkiSignerFactory
```

Without that factory class, ZTS keeps using the original HTTP Crypki client.

Optional in-process backends:

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
     `athenz.crypki.kms.ca_cert_path`, or from the per-key map when
     `x509CertSignerKeyId` is set.
   - **HSM:** same minter, but `HsmClient.getSigningKey(keyId)` supplies a
     `SigningKey` whose private key never leaves the module. The CA comes
     from `athenz.crypki.hsm.ca_cert_path`, or from the per-key map when
     `x509CertSignerKeyId` is set.
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
| ZTS config | `HttpCertSignerFactory` + `athenz.zts.certsign_base_uri` | Unchanged unless `cert_signer_factory_class` is `JavaCrypkiCertSignerFactory` |

Compatibility kept on purpose:

- Existing ZTS `HttpCertSigner` / `HttpCertSignerFactory` stay as they are.
  In-process backends require `JavaCrypkiCertSignerFactory`.
- Request shape (key meta, CSR, EKU ints, validity seconds, priority) matches
  the Go `/sig/x509-cert` contract.
- Soft-fail HTTP behavior is unchanged: `sign()` may return `null` instead of
  throwing, same as the old ZTS client.

Intentionally not ported:

- SSH certificate minting
- A Java clone of the Go HTTP/gRPC server (no v3 facade unless a non-ZTS
  caller appears)
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
- `athenz.crypki.kms.ca_cert_path` (default CA when the key id is not in the map)
- `athenz.crypki.kms.ca_cert_map_path` (optional JSON: Athenz signer key id → CA PEM path, or `{ "keyId": "<cloud key>", "caCertPath": "<pem>" }`. GCP requires the object form with a CryptoKeyVersion `keyId`.)
- `athenz.crypki.kms.signing_algorithm` (default `SHA256withRSA`)
- `athenz.crypki.hsm.module_path` (CloudHSM default `/opt/cloudhsm/lib/libcloudhsm_pkcs11.so`)
- `athenz.crypki.hsm.slot`
- `athenz.crypki.hsm.key_label` (default `athenz-crypki-ca`)
- `athenz.crypki.hsm.pin_path` (CloudHSM PIN file: `username:password`)
- `athenz.crypki.hsm.ca_cert_path` (default CA when the key id is not in the map)
- `athenz.crypki.hsm.ca_cert_map_path` (optional JSON: Athenz signer key id → CA PEM path, or `{ "keyId": "<hsm-label>", "caCertPath": "<pem>" }`)

AWS CloudHSM signing keys are label-only (no PKCS#11 certificate object).
Put `cloudhsm-jce-*.jar` on the ZTS classpath so
`AwsCloudHsmCrypkiSignerFactory` can load the key by label. SunPKCS11
alone will not see those keys.
