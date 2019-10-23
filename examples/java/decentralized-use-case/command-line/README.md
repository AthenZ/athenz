Athenz Java Decentralized Authorization Example
===============================================

This example demonstrates the use of ZPE Java client to implement
Athenz decentralized authorization support in an application. Decentralized
authorization support requires the installation of the ZPE Policy Updater (ZPU)
utility on the host. This utility will download the policy files from the
ZTS Server that are used by ZPE client for authorization checks.

```
java -cp target/athenz-data.jar com.yahoo.athenz.example.authz.ZpeCheck -p <policy-dir>
     -c <athenz.conf path>> -a <action>> -r <resource> -t <access or role token>
```

## License

Copyright 2019 Oath Holdings, Inc.

Licensed under the [Apache License, Version 2.0](http://www.apache.org/licenses/LICENSE-2.0)
