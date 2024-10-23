# SIA for Harness

The SIA utility must be installed on the Harness runner image to allow the
Harness pipelines to authenticate with Athenz and obtain the service identity
x.509 certificate.

```
/usr/local/bin/siad -zts <zts-server-url> -harness <harness-oidc-token-url> -domain <athenz-domain> -service <athenz-service> -dns-domain <dns-domain> -key-file <key-file> -cert-file <cert-file>
```

The utility will generate a unique RSA private key and obtain a service identity x.509 certificate
from Athenz and store the key and certificate in the specified files.

As part of its output, the agent shows the action and resource values that the domain administrator
must use to configure the Athenz service to allow the Harness pipeline to authorize:

```
2024/10/15 17:05:43 Action: harness.manual
2024/10/15 17:05:43 Resource: athenz.harness:account/athenzaccount:org/centraltech:project/cicd
```
