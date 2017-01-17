zms-java-client
===============

A Java client library to access the ZMS server.
The client library encapsulates the stub generated from the ZMS RDL. 
It includes zms-core and all other dependencies.

--- Connection Timeouts ---

Default read and connect timeout values for ZMS Client connections
are 30000ms (30sec). The application can change these values by using
the following system properties:

 * athenz.zms.client.read_timeout
 * athenz.zms.client.connect_timeout

The values specified for timeouts must be in milliseconds.

## License

Copyright 2016 Yahoo Inc.

Licensed under the [Apache License, Version 2.0](http://www.apache.org/licenses/LICENSE-2.0)
