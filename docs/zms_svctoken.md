* [Overview](#overview)
* [Getting Software](#getting-software)
* [Prerequisites](#prerequisites)
* [Usage](#usage)


## Overview
----------

ZMS Service Token Client utility generates service tokens
based on given private key and service details.

## Getting Software
-------------------

Download latest ZMS Service Token Client utility binary release from Bintray - click
on the `Files` tab, choose the latest version directory and then
download the `athenz-utils-<latest-version>-bin.tar.gz` file::

[ ![Download](https://api.bintray.com/packages/yahoo/maven/athenz-utils/images/download.svg) ](https://bintray.com/yahoo/maven/athenz-utils/_latestVersion)

```shell
$ tar xvfz athenz-utils-X.Y-bin.tar.gz
```

## Prerequisites
----------------

Before you can use the ZMS Service Token utility, you need to have
asked the Athenz administrators to create your top level domain.


## Usage
--------

```
$ zms-svctoken -domain <domain> -service <service> -private-key <key-file> -key-version <key-id>
```

It is expected that you have already generated a public/private key pair and
registered the public key for the service in your Athenz domain. When registering
the public key, you also specified a unique key-version for that key pair.

If you have not completed these steps follow
[Athenz Service Identity With Public/Private Key Pairs](reg_service_guide.md)
section in our user guide for instructions.

Assuming your domain is `sports` and you have registered a service called `api`
with a key-version value of `0` and the private key is stored in `./sports_private.pem` file,
then the zms-svctoken utility with following arguments will return the ntoken for
your `sports.api` service:

    $ zms-svctoken -domain sports -service api -private-key ./sports_private.pem -key-version 0

zms-svctoken does not make any requests to Athenz services. The service identity ntoken
is generated on your local host based on the private key. You then would use that ntoken
as the value for `Athenz-Principal-Auth` header when making requests to Athenz services.
The identity ntoken must not be sent to any other service as you'll be exposing your
service identity to others. It is strongly recommended to utilize Athenz Service Identity
x.509 certificates instead of ntokens.
