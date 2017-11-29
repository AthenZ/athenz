# Athenz ZTS TLS Client Example

An example showing the use of ZTS Client with Athenz CA issued client certificates.

A prerequisite for this utility is that the user has already obtained
the client X.509 certificate for their service. The private key is
stored in the current directory in `key.pem` file while the corresponding
certificate in the `cert.pem` file.

The example retrieves the public key for a given service from Athenz ZTS
Service. The utility supports the following command line options:

```
usage: zts-tls-client
 -k,--key <arg>                  private key path
 -c,--cert <arg>                 certficate path
 -t,--trustStorePath <arg>       CA TrustStore path
 -p,--trustStorePassword <arg>   CA TrustStore password
 -d,--domain <arg>               domain name
 -s,--service <arg>              service name
 -i,--keyid <arg>                key id
 -z,--ztsurl <arg>               ZTS Server url
```

First build the example by executing `mvn clean package` and then run
from the current directory by replacing `<cwd>` with your current working
directory path and `<java-home>` with your java home directory path.

```
java -cp <cwd>/target/example-zts-tls-java-client-1.0.jar:<cwd>/target/dependency/* com.yahoo.athenz.example.zts.tls.client.ZTSTLSClient -d sys.auth -s zms -i 0 -k <cwd>/key.pem -c <cwd>/cert.pem -t <java-home>/jre/lib/security/cacerts -p changeit -z https://<athenz-zts-server-host>:4443/zts/v1
```

Copyright 2017 Yahoo Holdings, Inc.

Licensed under the [Apache License, Version 2.0](http://www.apache.org/licenses/LICENSE-2.0)
