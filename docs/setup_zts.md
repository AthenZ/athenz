# Setup ZTS (authoriZation Token System)
----------------------------------------

* [Requirements](#requirements)
    * [JDK 8](#jdk-8)
* [Getting Software](#getting-software)
* [Configuration](#configuration)
    * [Private/Public Key Pair](#privatepublic-key-pair)
    * [Self Signed X509 Certificate](#self-signed-x509-certificate)
    * [ZMS Certificate TrustStore](#zms-certificate-truststore)
    * [Register ZTS Service](#register-zts-service)
    * [Update Athenz Configuration File](#update-athenz-configuration-file)
* [Start ZMS Server](#start-zms-server)

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
https://github.com/yahoo/AtheNZ/releases/latest
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

```
cd var/zts_server/keys
openssl genrsa -out zts_private.pem 2048
openssl rsa -in zts_private.pem -pubout > zts_public.pem
```

### Self Signed X509 Certificate
--------------------------------

Generate a self-signed X509 certificate for ZTS Server HTTPS
support. After we generate the X509 certificate, we need to add
that certificate along its private key to a keystore for Jetty 
use. From the `athenz-zts-X.Y` directory execute the following
commands:

```
cd var/zts_server/certs
openssl req -x509 -newkey rsa:2048 -keyout zts_key.pem -out zts_cert.pem -days 365
```

Generate a keystore in PKCS#12 format:

```
openssl pkcs12 -export -out zts_keystore.pkcs12 -in zts_cert.pem -inkey zts_key.pem
```

### ZMS Certificate TrustStore
------------------------------

ZTS Server needs to access ZMS Server to download all domain details
in order to issue RoleTokens. Since ZMS Server is running with a
self-signed certificate, we need to generate a truststore for the
java http client to use when communicating with the ZMS Server.
From your ZMS Server installation, copy the `zms_cert.pem` file
from the `athenz-zms-X.Y/var/zms_server/certs` directory to the
`athenz-zts-X.Y/var/zts_server/certs` directory and execute the following
command:

```
keytool -importcert -noprompt -alias zms -keystore zts_truststore.jks -file zms_cert.pem -storepass athenz
```

### Register ZTS Service
------------------------

In order for ZTS to access ZMS domain data, it must identify itself
as a registered service in ZMS. Using the `zms-cli` utility, we will
register a new service in `sys.auth` domain:

```
cd athenz-zts-X.Y
bin/zms-cli -k -z https://<zms-server>:4443/zms/v1 -d sys.auth add-service zts 0 var/zts_server/keys zts_public.pem
```

### Update Athenz Configuration File
------------------------------------

Update the Athenz configuration file `athenz.conf` in `athenz-zts-X.Y/conf/zts_server`
directory to include the correct ZMS Server URL and the registered public keys.

## Start ZTS Server
-------------------

Set the required Athenz ROOT environment variable to the `athenz-zts-X.Y`
directory and from there start the ZTS Server by executing:

```
export ROOT=<full-path-to-athenz-zts-X.Y>
sudo -E bin/zts_start.sh
```

Based on the sample configuration file provided, ZTS Server will be listening
on port 8443.
