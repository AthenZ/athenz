zts-roletoken
=============

ZTS Role Token Client application in go to request a role token from
ZTS Server for the given identity to access a role in a provider domain:

```shell
$ zts-roletoken -domain <domain> -role <role> -ntoken <ntoken> -zts <ZTS url>
```

The service identity ntoken can be obtained by using the zms-svctoken
utility.

## License

Copyright 2016 Yahoo Inc.

Licensed under the [Apache License, Version 2.0](http://www.apache.org/licenses/LICENSE-2.0)

