* [Overview](#overview)
* [Getting Software](#getting-software)
* [Prerequisites](#prerequisites)
* [Usage](#usage)

## Overview
----------

ZTS TLS Certificate utility provides a service identity x.509 certificate
based on registered service's ntoken.

## Getting Software
-------------------

Download latest ZTS TLS Certificate utility binary release from Bintray - click
on the `Files` tab, choose the latest version directory and then
download the `athenz-utils-<latest-version>-bin.tar.gz` file::

[ ![Download](https://api.bintray.com/packages/yahoo/maven/athenz-utils/images/download.svg) ](https://bintray.com/yahoo/maven/athenz-utils/_latestVersion)

```shell
$ tar xvfz athenz-utils-X.Y-bin.tar.gz
```

## Prerequisites
----------------

Before you can use the ZTS ServiceCertificate utility, you need to have
asked the Athenz administrators to create your top level domain.

## Usage
-------

```
$ zts-svccert -domain <domain> -service <service> -private-key <key-file> -key-version <version> -zts https://zts-server.athenzcompany.com:4443/zts/v1 -dns-domain <dns-domain> -hdr Athenz-Principal-Auth [-cert-file <output-cert-file>]
```

It is expected that you have already generated a public/private key pair and
registered the public key for the service in your Athenz domain. When registering
the public key, you also specified a unique key-version for that key pair.

If you have not completed these steps follow
[Athenz Service Identity With Public/Private Key Pairs](reg_service_guide.md)
section in our user guide for instructions.

Assuming your domain is `sports` and you have registered a service called `api`
with a key-version value of `0` and the private key is stored in `./sports_private.pem` file,
then the zms-svccert utility with following arguments will return the x.509 certificate for
your `sports.api` service:

```
$ zts-svccert -domain sports -service api -private-key `./sports_private.pem` -key-version 0 -zts https://zts-server.athenzcompany.com:4443/zts/v1 -dns-domain <dns-domain> -hdr Athenz-Principal-Auth
```

The certificate cannot be refreshed and the user must request a new certificate
for the service before the current one expires.
