zts-svccert
===========

ZTS Service Certificate Client application in Go to generate service tokens based on given private key and service details, then generate a CSR using the same private key and then request a X509 Certificate for that service token from ZTS Server. Once ZTS validates the NToken and CSR, it will issue a new 30-day X509 Certificate for the service.

```shell
$ zts-svccert -domain <domain> -service <service> -private-key <key-file> -key-version <version> -zts <zts-server-url> -dns-domain <dns-domain> [-cert-file <output-cert-file>]
```

If the CSR has already been generated, it can be passed with the `-request-csr` option. In this case
the utility does not generate the CSR, so the `-private-key` and `-dns-domain` options are not required
unless the private key is needed to authenticate the request (e.g. to generate the service token):

```shell
$ zts-svccert -domain <domain> -service <service> -request-csr <csr-file> -provider <provider> -instance <instance-id> -attestation-data <attestation-data-file> -svc-key-file <key-file> -svc-cert-file <cert-file> -zts <zts-server-url> [-cert-file <output-cert-file>]
```

## License

Copyright The Athenz Authors

Licensed under the [Apache License, Version 2.0](http://www.apache.org/licenses/LICENSE-2.0)

