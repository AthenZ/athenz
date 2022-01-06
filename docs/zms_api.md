# ZMS API

## Introduction

The Authorization Management Service (ZMS) API

This API has the following attributes:

| Attribute | Value                |
| --- |----------------------|
| namespace | com.yahoo.athenz.zms |
| version | 1                    |

## Authentication

### X.509 Certificate Support

All ZMS API commands require that the client use a TLS certificate issued by Athenz.
Services can use their Athenz Issued Service Identity certificates when communicating
with ZMS.

## Authorization

Every write request against ZMS server is authorized against the configured
policy data to verify that the principal has been given the rights to make
the requested change. Each request description below gives the authorization command
that includes the action and resource that the ZMS Server will run the authorization
check against. For example, the create subdomain command has the following authorize statement:

``` sourceCode
authorize ("create", "{parent}:domain");
```

This indicates that the principal requesting to create subdomain called athens.ci
must have grant rights to action "create" for resource called "domain" in domain "athens".

## API Documentation

Please refer to the [ZMS OpenAPI documentation](https://athenz.github.io/athenz/api/index.html?server=zms)
