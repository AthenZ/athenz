zts-rolecert
============

ZTS Role Certificate Client application in Go to use Athenz Service
Identity certificate to request a X509 Certificate for the requested
role from ZTS Server. Once ZTS validates the service identity certificate,
it will issue a new 30-day X509 Certificate for the role.

```shell
$ zts-rolecert -svc-key-file <key-file> -svc-cert-file <cert-file> -zts <zts-server-url> -role-domain <domain> -role-name <name> -dns-domain <dns-domain> [-role-cert-file <output-cert-file>]
```

## License

Copyright The Athenz Authors
Licensed under the [Apache License, Version 2.0](http://www.apache.org/licenses/LICENSE-2.0)
