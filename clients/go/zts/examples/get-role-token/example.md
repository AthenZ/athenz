# Fetch RoleTokens

## Scenario

Use the service cert present locally on the box to talk to ZTS and fetch a role token

## Input

  - cert: TLS cert to use
  - key: key for the TLS cert
  - ztsUrl: ZTS endpoint
  - domain: domain the principal is from
  - role: optional role for which the roletoken needs to be fetched

## Output

  - Role Token

## Notes
  - Use the ZTS client
  - provide a http.Transport option with TLSClientConfig object set with TLS cert read from the x509 cert.

## How to Run
  - Use a domain/service that you wish to use. For trial run, you can use your personal domain, home.{userid} and create a service and obtain the TLS certificate in Athenz UI

![Get Service TLS Cert](images/tls.png)

  - Sample commands for generating key pairs
    - openssl genrsa -out service_private.key 2048
    - openssl rsa -in service_private.key -pubout > service_public.key
  - Sample Command for fetching CSR
    - zts-svccert -csr -domain home.palakas -service helloworld -private-key ./service_private.key -key-version 0 -dns-domain yourdomain.cloud

  - go build
  - ./get-role-token -domain home.palakas -cert ./service_cert.pem -key ./service_private.key -zts https://zts-endpoint.com

```sh
./get-role-token -domain home.palakas -cert ./service_cert.pem -key ./service_private.key
2017/11/14 23:23:01 RoleToken: "v=Z1;d=home.palakas;r=ums.tprofile2;c=1;p=home.palakas.helloworld;h=ip-10-0-5-212.us-west-2.compute.internal;a=537af2983c4092f2;t=1510730580;e=1510737780;k=aws.prod.us-west-2.0;i=209.131.62.126;s=NN9miwROtizzT..."
```

## License

Copyright The Athenz Authors
Licensed under the [Apache License, Version 2.0](http://www.apache.org/licenses/LICENSE-2.0)
