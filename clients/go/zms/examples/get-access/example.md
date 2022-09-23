# Fetch Access status

## Scenario

Use the service cert present locally on the box to talk to ZMS, find out if the current principal has "Access" to a specified resource, in a given domain.

Principal Domain: home.userid
Principal identity: home.userid.helloworld

Target Domain: home.userid.movies
Target Role: home.userid.movies:role.editors
Target Resource: home.userid:rec.movie

## Input

  - cert: TLS cert to use
  - key: key for the TLS cert
  - zms: ZMS endpoint
  - domain: domain the principal is from (example: home.userid)
  - action: action to be checked for
  - resource: fully qualified resource name (example: home.userid.movies:role.editors)
  - zms: optional role for which the roletoken needs to be fetched

## Output

  - Granted status for get-access call

## Notes
  - Use the ZMS Go client
  - provide a http.Transport option with TLSClientConfig object set with TLS cert read from the x509 cert.

## How to Run
  - Use a domain/service that you wish to use. For trial run, you can use your personal domain, home.{userid}
and create a service and obtain the TLS certificate in Athenz UI

  - Sample commands for generating key pairs
    - openssl genrsa -out service_private.key 2048
    - openssl rsa -in service_private.key -pubout > service_public.key
  - Sample Command for fetching CSR
    - zts-svccert -csr -domain home.palakas -service helloworld -private-key ./service_private.key -key-version 0 -dns-domain zts.oath.cloud


  - Setup role/policy in target domain
    - zms-cli -d home.userid.movies add-regular-role editors home.userid.helloworld
    - zms-cli -d home.userid.movies add-policy editors_policy grant read to editors on rec.movie

  - go build
  - ./get-access -zms https://<zms-endpoint-domain>:<port>/zms/v1 -cert /path/to/cert -key /path/to/key -domain home.userid -resource "home.userid:rec.movie" -action read


## License

Copyright The Athenz Authors
Licensed under the [Apache License, Version 2.0](http://www.apache.org/licenses/LICENSE-2.0)
