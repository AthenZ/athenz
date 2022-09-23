# Athenz ZMS TLS Client Example

An example showing the use of ZMS Client with Athenz CA issued client certificates.

A prerequisite for this utility is that the user has already obtained
the client X.509 certificate for their service. The private key is
stored in the current directory in `key.pem` file while the corresponding
certificate in the `cert.pem` file.

The example carries out a centralized authorization check by contacting
Athenz ZMS Service to see if a given principal has been authorized to
execute a given action against a configured resource. The utility supports
the following command line options:

```
usage: zms-tls-client
 -k,--key <arg>                  private key path
 -c,--cert <arg>                 certficate path
 -t,--trustStorePath <arg>       CA TrustStore path
 -p,--trustStorePassword <arg>   CA TrustStore password
 -d,--domain <arg>               domain name
 -a,--action <arg>               action value
 -r,--resource <arg>             resource value
 -u,--principal <arg>            principal to authorize
 -ro,--role <arg>                role name
 -m,--method <arg>               ZMS API method name to call
```

First build the example by executing `mvn clean package` and then run
from the current directory by replacing `<cwd>` with your current working
directory path and `<java-home>` with your java home directory path.

```
java -cp <cwd>/target/example-zms-tls-java-client-1.0.jar:<cwd>/target/dependency/* com.yahoo.athenz.example.zms.tls.client.ZMSTLSClient -k <cwd>/key.pem -c <cwd>/cert.pem -t <java-home>/jre/lib/security/cacerts -p changeit -a "read" -u "user.john" -r "sports.api:hockey" -z https://<athenz-zms-server-host>:4443/zms/v1
```

Copyright The Athenz Authors

Licensed under the [Apache License, Version 2.0](http://www.apache.org/licenses/LICENSE-2.0)
