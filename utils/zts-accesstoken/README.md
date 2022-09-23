zts-accesstoken
===============

ZTS OAuth2 Access Token Client application in Go to request an access token from
ZTS Server for the given identity to access a role in a provider domain:

There are two possible ways to use the utility:

1) using your athenz service identity certificate

```shell
$ zts-accesstoken -domain <domain> [-roles <roles>] [-service <service>] -svc-key-file <private-key-file> -svc-cert-file <service-cert-file> -zts <ZTS url> [-expire-time <expire-time-in-mins>]
```

2) using ntoken from a file

```shell
$ zts-accesstoken -domain <domain> [-roles <roles>] [-service <service>] -ntoken-file <ntoken-file> -hdr Athenz-Principal-Auth -zts <ZTS url> [-expire-time <expire-time-in-mins>]
```

The service identity ntoken can be obtained by using the zms-svctoken
utility. The optional expire-time argument specifies how long the access
token should be valid for. The value must be specified in minutes. The
defualt if no value is specified is 120 minutes.

## License

Copyright The Athenz Authors

Licensed under the [Apache License, Version 2.0](http://www.apache.org/licenses/LICENSE-2.0)
