# Setup ZMS (AuthoriZation Management System)
---------------------------------------------

* [Requirements](#requirements)
    * [JDK 8](#jdk-8)
* [Getting Software](#getting-software)
* [Configuration](#configuration)
    * [Private/Public Key Pair](#privatepublic-key-pair)
    * [Self Signed X509 Certificate](#self-signed-x509-certificate)
* [Start ZMS Server](#start-zms-server)

## Requirements
---------------

The following tools are required to be installed on hosts
configured to run ZMS server.

### JDK 8
---------

ZMS Server is written in Java and using embedded Jetty.

[Oracle Java Platform JDK 8](http://www.oracle.com/technetwork/java/javase/downloads/jdk8-downloads-2133151.html)

While ZMS has been developed and tested with Oracle Java Platform JDK 8
it should run successfully with OpenJDK 8 as well.

## Getting Software
-------------------

Download latest ZMS binary release from

```
https://github.com/yahoo/athenz/releases/latest
```

```shell
$ tar xvfz athenz-zms-X.Y-bin.tar.gz
$ cd athenz-zms-X.Y
```

## Configuration
----------------

To run ZMS Server, the system administrator must generate the keys
and make necessary changes to the configuration settings.

### Private/Public Key Pair
---------------------------

Generate a unique private/public key pair that ZMS Server will use
to sign any NTokens it issues. From the `athenz-zms-X.Y` directory
execute the following commands:

```shell
$ cd var/zms_server/keys
$ openssl genrsa -out zms_private.pem 2048
$ openssl rsa -in zms_private.pem -pubout > zms_public.pem
```

### Self Signed X509 Certificate
--------------------------------

Generate a self-signed X509 certificate for ZMS Server HTTPS
support. After we generate the X509 certificate, we need to add
that certificate along with its private key to a keystore for Jetty 
use. From the `athenz-zms-X.Y` directory execute the following
commands:

```shell
$ cd var/zms_server/certs
$ openssl req -x509 -newkey rsa:2048 -keyout zms_key.pem -out zms_cert.pem -days 365
```

Generate a keystore in PKCS#12 format:

```shell
$ openssl pkcs12 -export -out zms_keystore.pkcs12 -in zms_cert.pem -inkey zms_key.pem
```

## Start ZMS Server
-------------------

Set the required Athenz ROOT environment variable to the `athenz-zms-X.Y`
directory and from there start the ZMS Server by executing:

```shell
$ export ROOT=<full-path-to-athenz-zms-X.Y>
$ bin/zms_start.sh
```

Based on the sample configuration file provided, ZMS Server will be listening
on port 4443.
