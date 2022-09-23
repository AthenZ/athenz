ZMS Server
=======================

ZMS is where domains, roles, and policies are defined. This is Athenz’s centralized authorization system and is likely part of a larger management system. In addition to allowing CRUD operations on the basic entities, ZMS provides an API to replicate the entities, per domain, to ZTS. It also can directly support the access check, both for internal management system checks, as well as a simple centralized deployment.

ZMS is the source of truth for domains, roles, and policies for centralized authorization. ZMS supports a centralized call to check if a principal has access to a resource. Because ZMS supports service identities, ZMS can authenticate services.

For centralized authorization, ZMS may be the only Athenz subsystem that you need to interact with.

## License

Copyright The Athenz Authors

Licensed under the [Apache License, Version 2.0](http://www.apache.org/licenses/LICENSE-2.0)
