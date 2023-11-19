# Athenz GCP ZTS Credentials Examples

This repo contains examples showing the use of fetching GCP Credentials with ZTS ID Tokens

A prerequisite for this utility is that the user has already obtained
the client X.509 certificate for their service. The private key is
stored in the current directory in `key.pem` file while the corresponding
certificate in the `cert.pem` file.

Example 1:

The example lists the objects from the specified GCP storage bucket.
The utility supports the following command line options:

```
usage: zts-gcp-creds-client
 -b,--bucket <arg>                 bucket name
 -c,--cert <arg>                   certificate path
 -d,--domain <arg>                 domain name
 -f,--redirectUriSuffix <arg>      redirect uri prefix
 -i,--clientid <arg>               client id
 -j,--projectId <arg>              project id
 -k,--key <arg>                    private key path
 -m,--workLoadProviderName <arg>   workload identity provider name
 -n,--projectNumber <arg>          project id
 -p,--trustStorePassword <arg>     CA TrustStore password
 -r,--role <arg>                   role name
 -s,--serviceAccount <arg>         service account name
 -t,--trustStorePath <arg>         CA TrustStore path
 -w,--workLoadPoolName <arg>       workload identity pool name
 -z,--ztsurl <arg>                 ZTS Server url
```

First build the example by executing `mvn clean package` and then run
from the current directory by replacing `<cwd>` with your current working
directory path and `<java-home>` with your java home directory path.

```
java -cp <cwd>/target/example-zts-gcp-creds-1.0.jar:<cwd>/target/dependency/* com.yahoo.athenz.example.zts.gcp.ZTSGCPCredsStorageClient -d athenz.project1 -k <cwd>/key.pem -c <cwd>/cert.pem -p changeit -z https://<athenz-zts-server-host>/zts/v1 -t <java-home>/jre/lib/security/cacerts -r gcp.fed.admin.user -i athenz.project1.gcp -b gcp-bucket-name -j athenz-project1 -n 12345678 -w athenz -m athenz -f gcp.athenz.io -s gcp-service-name
```

Example 2:

The example lists the all the DNS Zones from the specified GCP Project.
It then proceeds to display any TXT records if configured.
The utility supports the following command line options:

```
usage: zts-gcp-creds-client
 -c,--cert <arg>                   certificate path
 -d,--domain <arg>                 domain name
 -f,--redirectUriSuffix <arg>      redirect uri prefix
 -i,--clientid <arg>               client id
 -j,--projectId <arg>              project id
 -k,--key <arg>                    private key path
 -m,--workLoadProviderName <arg>   workload identity provider name
 -n,--projectNumber <arg>          project id
 -p,--trustStorePassword <arg>     CA TrustStore password
 -r,--role <arg>                   role name
 -s,--serviceAccount <arg>         service account name
 -t,--trustStorePath <arg>         CA TrustStore path
 -w,--workLoadPoolName <arg>       workload identity pool name
 -z,--ztsurl <arg>                 ZTS Server url
```

First build the example by executing `mvn clean package` and then run
from the current directory by replacing `<cwd>` with your current working
directory path and `<java-home>` with your java home directory path.

```
java -cp <cwd>/target/example-zts-gcp-creds-1.0.jar:<cwd>/target/dependency/* com.yahoo.athenz.example.zts.gcp.ZTSGCPCredsDNSClient -d athenz.project1 -k <cwd>/key.pem -c <cwd>/cert.pem -p changeit -z https://<athenz-zts-server-host>/zts/v1 -t <java-home>/jre/lib/security/cacerts -r gcp.fed.admin.user -i athenz.project1.gcp -j athenz-project1 -n 12345678 -w athenz -m athenz -f gcp.athenz.io -s gcp-service-name
```

Copyright The Athenz Authors

Licensed under the [Apache License, Version 2.0](http://www.apache.org/licenses/LICENSE-2.0)
