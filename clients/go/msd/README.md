# msd-go-client

A Go client library to talk to Athenz MSD.

The model.go and client.go files are generated from msd_core, and checked in so users of this library need not know that.

Additionally, an implementation of rdl.Authorizer and rdl.Authenticator are provided that use this library to delegate that functionality to Athenz MSD.

## License

Copyright The Athenz Authors

Licensed under the [Apache License, Version 2.0](http://www.apache.org/licenses/LICENSE-2.0)
