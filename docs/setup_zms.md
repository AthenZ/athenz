# Setup ZMS (AuthoriZation Management System)
---------------------------------------------

* [Requirements](#requirements)
    * [JDK 8](#jdk-8)
* [Getting Software](#getting-software)
* [Configuration](#configuration)
    * [Private Key](#private-key)
    * [Self Signed X509 Certificate](#self-signed-x509-certificate)
    * [User Authentication](#user-authentication)
    * [System Administrators](#system-administrators)
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

Download latest ZMS binary release from Bintray - click on the `Files` tab,
choose the latest version directory and then download the
`athenz-zms-<latest-version>-bin.tar.gz` file:

[ ![Download](https://api.bintray.com/packages/yahoo/maven/athenz-zms/images/download.svg) ](https://bintray.com/yahoo/maven/athenz-zms/_latestVersion)


```shell
$ tar xvfz athenz-zms-X.Y-bin.tar.gz
$ cd athenz-zms-X.Y
```

## Configuration
----------------

To run ZMS Server, the system administrator must generate the keys
and make necessary changes to the configuration settings.

### Private Key
---------------------------

Generate a unique private key that ZMS Server will use
to sign any NTokens it issues. From the `athenz-zms-X.Y` directory
execute the following commands:

```shell
$ cd var/zms_server/keys
$ openssl genrsa -out zms_private.pem 2048
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

### User Authentication
-----------------------

For a user to authenticate himself/herself in ZMS, the server must have
the appropriate authentication authority implementation configured. By
default, ZMS enables the following two authorities:

* Unix User Authority - using pam login profile to authenticate users
* Principal Authority - validating Principal Tokens that are issued
  when users authenticate using their unix login password.

The server also provides other authorities - e.g. Kerberos, TLS Certificate
that are not enabled by default. Since the default setup includes Unix
Authority, the user that the ZMS process runs as must have read access
to the /etc/shadow file. There are two options available:

* Run the process as root using sudo. This is only recommended for a local
  development installation.
* Create a special Unix group that has read access to the /etc/shadow file
  and set the user that the ZMS process will be running as a member of that
  group.

Checkout the [Principal Authentication](principal_authentication.md) section
for full details on authorities.

### System Administrators
-------------------------

When running the server very first time, ZMS Server automatically creates
the required domains and sets the running user as the system administrator.
The system administrators are the only ones authorized to create top
level domains in Athenz. Before running the server very first time, you
can configure the set of system administrators by following these steps:

```shell
$ cd athenz-zms-X.Y
$ vi conf/zms_server/container_settings
```

Modify the `CONTAINER_ADMINUSER="user.${USER}"` line and include comma
separated list of unix user ids that should be set as Athenz system
administrators. e.g. `CONTAINER_ADMINUSER="user.joe,user.john`

## Start ZMS Server
-------------------

Set the required Athenz ROOT environment variable to the `athenz-zms-X.Y`
directory and from there start the ZMS Server by executing:

```shell
$ export ROOT=<full-path-to-athenz-zms-X.Y>
$ sudo -E bin/zms_start.sh
```

See the `User Authentication` section above regarding an alternative
solution of starting ZMS Server without using sudo.

Based on the sample configuration file provided, ZMS Server will be listening
on port 4443.
