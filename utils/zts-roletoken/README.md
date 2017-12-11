zts-roletoken
=============

ZTS Role Token Client application in Go to request a role token from
ZTS Server for the given identity to access a role in a provider domain:

```shell
$ zts-roletoken -domain <domain> [-role <role>] -ntoken <ntoken> -zts <ZTS url> [-expire-time <expire-time-in-mins>] // using ntoken string on the command line
$ zts-roletoken -domain <domain> [-role <role>] -ntoken-file <ntoken-file> -zts <ZTS url> [-expire-time <expire-time-in-mins>] // using ntoken string from the given file
```

The service identity ntoken can be obtained by using the zms-svctoken
utility. The optional expire-time argument specifies how long the role
token should be valid for. The value must be specified in minutes. The
defualt if no value is specified is 120 minutes.

## License

Copyright 2016 Yahoo Inc.

Licensed under the [Apache License, Version 2.0](http://www.apache.org/licenses/LICENSE-2.0)

