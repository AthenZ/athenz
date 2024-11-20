zms-domainattrs
===============

The utility looks at the domains specified in a given file (one domain per line) and
for each domain, it retrieves and displays the requested attributes associated with
the domain.

The utility supports the following list of attributes:

- businessService
- productId
- account
- gcpProject
- gcpProjectNumber
- azureSubscription
- azureTenant
- azureClient
- org
- slackChannel
- environment

For businessService and productId attributes, if the given domain does not have the
attribute set, the utility will look at the parent domain to see if the attribute
is set there. If the attribute is set in the parent domain, the utility will display
the value from the parent domain. It will continue to look at the parent domains until
it finds the attribute set, or it reaches the top level domain.

## Usage

```
zms-domainattrs -svc-key-file ./key.pem -svc-cert-file ./cert.pem -zms https://athenz.io:4443/zms/v1 -domain-file ./domain.txt -attrs businessService,account
```

where domain.txt might contain:

```
weather
sports.prod
sports.nhl
sys.auth
```

And the output might look like ('weather' domain does not have a businessService attribute and
'sports.prod' domain does not have an account attribute):

```
Domain,businessService,account
weather,,123456
sports.prod,sports-service,
sports.nhl,sports-service,123456
sys.auth,athenz,456789
```

## License

Copyright The Athenz Authors

Licensed under the [Apache License, Version 2.0](http://www.apache.org/licenses/LICENSE-2.0)
