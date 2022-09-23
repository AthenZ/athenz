zts-svccert
===========

ZTS Service Certificate Client application in Go to generate service tokens based on given private key and service details, then generate a CSR using the same private key and then request a X509 Certificate for that service token from ZTS Server. Once ZTS validates the NToken and CSR, it will issue a new 30-day X509 Certificate for the service.

```shell
$ zts-svccert -domain <domain> -service <service> -private-key <key-file> -key-version <version> -zts <zts-server-url> -dns-domain <dns-domain> [-cert-file <output-cert-file>]
```

## License

Copyright The Athenz Authors

Licensed under the [Apache License, Version 2.0](http://www.apache.org/licenses/LICENSE-2.0)

