zts-idtoken
===========

ZTS OIDC ID Token Client application in Go to request an id token from
ZTS Server for the given identity:

Using your athenz service identity certificate

```shell
$ zts-idtoken -svc-key-file <private-key-file> -svc-cert-file <service-cert-file> -zts <ZTS url> -scope <scope> -redirect-uri <redirect-uri> -nonce <nonce> -client-id <client-id> -state <state>
```

## License

Copyright The Athenz Authors

Licensed under the [Apache License, Version 2.0](http://www.apache.org/licenses/LICENSE-2.0)
