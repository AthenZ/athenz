zts-roletoken
=============

ZTS Role Token Client application in Go to request a role token from
ZTS Server for the given identity to access a role in a provider domain:

There are three possible ways to use the utility:

1) using your athenz service identity certificate

```shell
$ zts-roletoken -domain <domain> [-role <role>] -svc-key-file <private-key-file> -svc-cert-file <service-cert-file> -zts <ZTS url> [-expire-time <expire-time-in-mins>]
```

2) using ntoken from a file

```shell
$ zts-roletoken -domain <domain> [-role <role>] -ntoken-file <ntoken-file> -zts <ZTS url> [-expire-time <expire-time-in-mins>]
```

3) using ntoken as command-line (not recommended since others running ps might see your ntoken).

```shell
$ zts-roletoken -domain <domain> [-role <role>] -ntoken <ntoken> -zts <ZTS url> [-expire-time <expire-time-in-mins>]
```

The service identity ntoken can be obtained by using the zms-svctoken
utility. The optional expire-time argument specifies how long the role
token should be valid for. The value must be specified in minutes. The
defualt if no value is specified is 120 minutes.

## License

Copyright The Athenz Authors

Licensed under the [Apache License, Version 2.0](http://www.apache.org/licenses/LICENSE-2.0)
