* [Overview](#overview)
* [Getting Software](#getting-software)
* [Prerequisites](#prerequisites)
* [Usage](#usage)

## Overview
----------

ZTS Role Certificate Client utility uses Athenz Service
Identity certificate to request a X509 Certificate for the requested
role from ZTS Server. Once ZTS validates the service identity certificate,
it will issue a new 30-day X509 Certificate for the role. Unlike access tokens,
role certificates are issued for a given role only.

## Getting Software
-------------------

Download latest ZTS Role Certificate Client utility binary release from
[Maven Central](https://search.maven.org/artifact/com.yahoo.athenz/athenz-utils):
click on the `Browse` button, choose the latest version directory and then 
download the `athenz-utils-<latest-version>-bin.tar.gz`.

```shell
$ tar xvfz athenz-utils-X.Y-bin.tar.gz
```

## Prerequisites
----------------

Before you can use the ZTS RoleCertificate utility, you need to have
asked the Athenz administrators to create your top level domain.


## Usage
--------

Role X.509 certificates can only be requested using Athenz x.509 Identity
certificates. Typically you configure your service identity agent (SIA) to automatically fetch and refresh the role certificates.

### Requesting Role Certificates

```
$ zts-rolecert -svc-key-file <key-file> -svc-cert-file <cert-file> -zts https://zts-server.athenzcompany.com:4443/zts/v1 -role-domain <domain> -role-name <name> -dns-domain <dns-domain> [-role-cert-file <output-cert-file>]
```
