# KeyStoreCertSigner
Load the CA certificate and its corresponding private key from keystore, and sign service certificate using them.

## sample configuration
```properties
athenz.zts.keystore_signer.keystore=/opt/athenz/zts/var/keys/zts_cert_signer_keystore.pkcs12
#athenz.zts.keystore_signer.keystore.password=athenz
athenz.zts.keystore_signer.keystore.ca_alias=zts_cert_signer_ca
#athenz.zts.keystore_signer.keystore.max_cert_expire_time=43200
```
