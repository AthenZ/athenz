ZTS Server
=======================

ZTS (AuthZ Token System)

ZTS, the authentication token service, is only needed to support decentralized or data plane functionality. In many ways, ZTS is like a local replica of ZMS’s data to check a principal’s authentication and confirm membership in roles within a domain. The authentication is in the form of a signed ZToken that can be presented to any decentralized service that wants to authorize access efficiently. If needed, multiple ZTS instances will be distributed to different data centers as needed to scale for issuing tokens.

## License

Copyright The Athenz Authors

Licensed under the [Apache License, Version 2.0](http://www.apache.org/licenses/LICENSE-2.0)
