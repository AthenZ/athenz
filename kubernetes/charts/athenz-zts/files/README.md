# Suggested file structures

```bash
── conf
│   ├── athenz.properties
│   ├── athenz_conf.json
│   ├── authorized_client_ids.txt
│   ├── logback.xml
│   └── zts.properties
└── secrets
    ├── signer
    │   ├── zts_signer_cert.pem
    │   └── zts_signer_key.pem
    ├── tls
    │   ├── CAs
    │   │   ├── athenz_ca.pem
    │   │   ├── service_ca.pem
    │   │   └── user_ca.pem
    │   ├── zts_cert.pem
    │   └── zts_key.pem
    ├── zms-client
    │   ├── zms_client_cert_bundle.pem
    │   └── zms_client_key.pem
    └── zts_private.pem
```
