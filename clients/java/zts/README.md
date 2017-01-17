zts-java-client
===============

A Java client library to access ZTS. This client library is generated
from the RDL, and includes zts-core and all other dependencies.

--- Connection Timeouts ---

Default read and connect timeout values for ZTS Client connections
are 30000ms (30sec). The application can change these values by using
the following system properties:

 * athenz.zts.client.read_timeout
 * athenz.zts.client.connect_timeout

The values specified for timeouts must be in milliseconds.

--- Prefetch Settings ---

 * athenz.zts.client.prefetch_auto_enable : true or false, default is false

## License

Copyright 2016 Yahoo Inc.

Licensed under the [Apache License, Version 2.0](http://www.apache.org/licenses/LICENSE-2.0)

