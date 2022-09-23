# Athenz HTTP TLS Client Example

An example showing the use of HTTPSUrlConnection Client with Athenz CA issued client certificates.

A prerequisite for this utility is that the user has already obtained
the client X.509 certificate for their service. The private key is
stored in the current directory in `key.pem` file while the corresponding
certificate in the `cert.pem` file.

The example carries out a simple HTTP GET operation by contacting
the configured url. The utility supports the following command line options:

```
usage: http-tls-client
 -k,--key <arg>                  private key path
 -c,--cert <arg>                 certficate path
 -t,--trustStorePath <arg>       CA TrustStore path
 -p,--trustStorePassword <arg>   CA TrustStore password
 -u,--url <arg>                  HTTP Server GET url
```

First build the example by executing `mvn clean package` and then run
from the current directory by replacing `<cwd>` with your current working
directory path and `<java-home>` with your java home directory path.

```
java -cp <cwd>/target/example-http-tls-java-client-1.0.jar:<cwd>/target/dependency/* com.yahoo.athenz.example.http.tls.client.HttpTLSClient -k <cwd>/key.pem -c <cwd>/cert.pem -t <java-home>/jre/lib/security/cacerts -p changeit -u <url>
```

Copyright The Athenz Authors

Licensed under the [Apache License, Version 2.0](http://www.apache.org/licenses/LICENSE-2.0)
