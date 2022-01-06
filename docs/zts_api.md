# ZTS API

## Introduction

The Authorization Token Service (ZTS) API

This API has the following attributes:

| Attribute | Value                  |
| --- |------------------------|
| namespace | com.yahoo.athenz.zts   |
| version | 1                      |

## Authentication

### X.509 Certificate Support

All ZTS API commands require that the client use a TLS certificate issued by Athenz.
Services can use their Athenz Issued Service Identity certificates when communicating
with ZTS.

## Authorization

Limited number of ZTS API endpoints are authorized against the configured
policy data to verify that the principal has been given the rights to make
the requested change. Each request description below gives the authorization command
that includes the action and resource that the ZTS Server will run the authorization
check against. For example, to delete an instance from the local database we have
the following authorize statement:

``` sourceCode
authorize("delete", "{domain}:instance.{instanceId}");
```

This indicates that the principal requesting to delete instance id host001 from
athenz.ci domain must have grant rights to action "delete" for resource called
"instance.host001" in domain "athenz.ci".

## API Documentation

Please refer to the [ZTS OpenAPI documentation](https://athenz.github.io/athenz/api/index.html?server=zts)
