# Athenz GCP SIA Credentials Examples

This repo contains examples showing the use of fetching GCP SIA Credentials

The utility supports the following command line options:

```
usage: gcp-workload-credentials
 -d,--domain <arg>      domain name
 -n,--dnsdomain <arg>   san dns domain
 -r,--region <arg>      gcp region
 -s,--service <arg>     service name
 -z,--ztsurl <arg>      ZTS Server url
```

First build the example by executing `mvn clean package` and then run
from the current directory by replacing `<cwd>` with your current working
directory path and `<java-home>` with your java home directory path.

```
java -cp <cwd>/target/example-gcp-workload-credentials-1.0.jar:<cwd>/target/dependency/* com.yahoo.athenz.example.zts.gcp.GCPWorkloadCredentials -d {domain-name} -s {service-name} -z {zts-url} -r {gcp-region} -n {san-dns-domain}
```

Copyright The Athenz Authors

Licensed under the [Apache License, Version 2.0](http://www.apache.org/licenses/LICENSE-2.0)
