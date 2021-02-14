* [Overview](#overview)
* [Getting Software](#getting-software)
* [Prerequisites](#prerequisites)
* [Usage](#usage)

## Overview
----------

ZTS OAuth2 Access Token Client application in Go to request an access token from
ZTS Server for the given identity to access a role in a provider domain.

## Getting Software
-------------------

Download latest ZTS OAuth2 Access Token Client package from
[Maven Central](https://search.maven.org/artifact/com.yahoo.athenz/athenz-utils):
click on the `Browse` button, choose the latest version directory and then
download the `athenz-utils-<latest-version>-bin.tar.gz`.

```shell
$ tar xvfz athenz-utils-X.Y-bin.tar.gz
```

## Prerequisites
----------------

Before you can use the ZTS AccessToken utility, you need to have
asked the Athenz administrators to create your top level domain.

## Usage
--------

An access token from ZTS service can be fetched using Service Identity x.509 certificates.

The optional `expire-time` argument specifies how long the access
token should be valid for. The value must be specified in minutes. The
default if no value is specified is 120 minutes.

The optional `roles` argument requests an access token for the given roles
only (comma separated) as opposed to all the roles the service identity has
access to in the requested domain.

The optional `service` argument requests an id token for the given service.
The full `domain.service` value will be set as the audience for the id token.

### Using Athenz Identity X.509 Certificates

```
$ zts-accesstoken -domain <domain> [-roles <roles>] [-service <service>] -svc-key-file <private-key-file> -svc-cert-file <service-cert-file> -zts <ZTS url> [-expire-time <expire-time-in-mins>]
```