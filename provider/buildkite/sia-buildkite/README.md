# SIA for BuildKite

The SIA utility must be installed in the BuildKite runtime to allow the BuildKite
to authenticate with Athenz and obtain the service identity x.509 certificate.

```
/usr/local/bin/sia -zts <zts-server-url> -domain <athenz-domain> -service <athenz-service> -dns-domain <dns-domain> -key-file <key-file> -cert-file <cert-file>
```

The utility will generate a unique RSA private key and obtain a service identity x.509 certificate
from Athenz and store the key and certificate in the specified files.

As part of its output, the agent shows the action and resource values that the domain administrator
must use to configure the Athenz services to allow the BuildKite runner to authorize:

```
2024/02/15 17:05:43 Action:                    build-kite.build
2024/02/15 17:05:43 Resource for main service: athens.builder:organization:my-org:pipeline:my-pipeline:ref:refs/heads/main:*
2024/02/15 17:05:43 Resource for PR service:   athens.builder:organization:my-org:pipeline:my-pipeline:*
```