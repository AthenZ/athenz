# Setup ZTS (authoriZation Token System) for Production
-------------------------------------------------------

* [Requirements](#requirements)
    * [JDK 8](#jdk-8)
* [Getting Software](#getting-software)
* [Configuration](#configuration)
    * [Private/Public Key Pair](#privatepublic-key-pair)
    * [Server X509 Certificate](#server-x509-certificate)
    * [Register ZTS Service](#register-zts-service)
    * [Generate Athenz Configuration File](#generate-athenz-configuration-file)
* [Start ZTS Server](#start-zts-server)

## Requirements
---------------

The following tools are required to be installed on hosts
configured to run ZTS server.

### JDK 8
---------

ZTS Server is written in Java and using embedded Jetty.

[Oracle Java Platform JDK 8](http://www.oracle.com/technetwork/java/javase/downloads/jdk8-downloads-2133151.html)

While ZTS has been developed and tested with Oracle Java Platform JDK 8
it should run successfully with OpenJDK 8 as well.

## Getting Software
-------------------

Download latest ZTS binary release from

```
https://github.com/yahoo/athenz/releases/latest
```

```shell
$ tar xvfz athenz-zts-X.Y-bin.tar.gz
$ cd athenz-zts-X.Y
```

## Configuration
----------------

To run ZTS Server, the system administrator must generate the keys
and make necessary changes to the configuration settings.

### Private/Public Key Pair
---------------------------

Generate a unique private/public key pair that ZTS Server will use
to sign any ZTokens it issues. From the `athenz-zts-X.Y` directory
execute the following commands:

```shell
$ cd var/zts_server/keys
$ openssl genrsa -out zts_private.pem 2048
$ openssl rsa -in zts_private.pem -pubout > zts_public.pem
```

### Server X509 Certificate
---------------------------

While it is still possible to generate and use a self-signed X509 
certificate for ZTS Servers, it is recommended to purchase one for
your production server from a well known certificate authority.
Having such a certificate installed on your ZTS Servers will no
longer require to distribute the server's public certificate to
other hosts (e.g. Hosts running ZPU).

Follow the instructions provided by the Certificate Authority to
generate your private key and then the Certificate Request (CSR).
Once you have received your X509 certificate, we just need to add
that certificate along with its private key to a keystore for Jetty 
use. From the `athenz-zts-X.Y` directory execute the following
command:

```shell
$ openssl pkcs12 -export -out zts_keystore.pkcs12 -in zts_cert.pem -inkey zts_key.pem
```

### Register ZTS Service
------------------------

In order for ZTS to access ZMS domain data, it must identify itself
as a registered service in ZMS. Using the `zms-cli` utility, we will
register a new service in `sys.auth` domain. Since ZMS Servers should
be running with a X509 certificate from a well know certificate 
authority (not a self-signed one) we don't need to reference the CA
cert like we did for the local/development environment setup.

```shell
$ cd athenz-zts-X.Y
$ bin/<platform>/zms-cli -z https://<zms-server>:4443/zms/v1 -d sys.auth add-service zts 0 var/zts_server/keys zts_public.pem
```

### Generate Athenz Configuration File
--------------------------------------

Generate an Athenz configuration file `athenz.conf` in `athenz-zts-X.Y/conf/zts_server`
directory to include the ZMS Server URL and the registered public keys that the
athenz client libraries and utilities will use to establish connection and validate any
data signed by the ZMS Server:

```shell
$ cd athenz-zts-X.Y
$ bin/<platform>/athenz-conf -o conf/zts_server/athenz.conf -z https://<zms-server>:4443/ -t https://<zts-server>:8443/
```

## Start ZTS Server
-------------------

Set the required Athenz ROOT environment variable to the `athenz-zts-X.Y`
directory and from there start the ZTS Server by executing:

```shell
$ export ROOT=<full-path-to-athenz-zts-X.Y>
$ bin/zts_start.sh
```

Based on the sample configuration file provided, ZTS Server will be listening
on port 8443.
