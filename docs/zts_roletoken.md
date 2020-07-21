* [Overview](#overview)
* [Getting Software](#getting-software)
* [Prerequisites](#prerequisites)
* [Usage](#usage)

## Overview
----------

ZTS Role Token Client utility requests a role token from
ZTS Server for the given identity to process a request against a provider domain.

## Getting Software
-------------------

Download latest ZTS Role Token Client utility binary release from Bintray - click
on the `Files` tab, choose the latest version directory and then
download the `athenz-utils-<latest-version>-bin.tar.gz` file::

[ ![Download](https://api.bintray.com/packages/yahoo/maven/athenz-utils/images/download.svg) ](https://bintray.com/yahoo/maven/athenz-utils/_latestVersion)

```shell
$ tar xvfz athenz-utils-X.Y-bin.tar.gz
```

## Prerequisites
----------------

Before you can use the ZTS RoleToken utility, you need to have
asked the Athenz administrators to create your top level domain.

## Usage
--------

A role token from ZTS service can be fetched using either Service Identity x.509 certificates
or service ntokens.

The optional `expire-time` argument specifies how long the role
token should be valid for. The value must be specified in minutes. The
default if no value is specified is 120 minutes.

The optional `role` argument requests a role token for the given role
only as opposed to all the roles the service identity has access to
in the requested domain.

The role token returned must be cached and re-used by the client before
it expires.

### Using Athenz Identity X.509 Certificates

```
$ zts-roletoken -domain <domain> [-role <role>] -svc-key-file <private-key-file> -svc-cert-file <service-cert-file> -zts https://zts-server.athenzcompany.com:4443/zts/v1 [-expire-time <expire-time-in-mins>]
```

### Using NToken from command line

```
$ zts-roletoken -domain <domain> [-role <role>] -ntoken <ntoken> -hdr Athenz-Principal-Auth -zts https://zts-server.athenzcompany.com:4443/zts/v1 [-expire-time <expire-time-in-mins>]
```

The service identity ntoken can be obtained by using the [zms-svctoken](zms_svctoken.md) utility.

### Using NToken from a given file

```
$ zts-roletoken -domain <domain> [-role <role>] -ntoken-file <ntoken-file> -hdr Athenz-Principal-Auth -zts https://zts-server.athenzcompany.com:4443/zts/v1 [-expire-time <expire-time-in-mins>]
```