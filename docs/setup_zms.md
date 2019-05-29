# Setup ZMS (AuthoriZation Management System)
---------------------------------------------

* [Requirements](#requirements)
    * [JDK 8](#jdk-8)
* [Getting Software](#getting-software)
* [Configuration](#configuration)
    * [User Authentication](#user-authentication)
    * [System Administrators](#system-administrators)
* [Start/Stop ZMS Server](#startstop-zms-server)

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
```

## Configuration
----------------

To run ZMS Server, the system administrator must generate the keys
and make necessary changes to the configuration settings.

```shell
$ cd athenz-zms-X.Y
$ bin/setup_dev_zms.sh
```

Running this setup script completes the following two tasks:

* Generate a unique private key that ZMS Server will use to sign any NTokens it issues
* Generate a self-signed X509 certificate for ZMS Server HTTPS support

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
$ vi conf/zms_server/zms.properties
```

Modify the `athenz.zms.domain_admin=user.admin` line and include comma
separated list of unix user ids that should be set as Athenz system
administrators. e.g. `athenz.zms.domain_admin=user.joe,user.john`

## Start/Stop ZMS Server
------------------------

Start the ZMS Server by executing:

```shell
$ cd athenz-zms-X.Y
$ sudo -E bin/zms start
```

See the `User Authentication` section above regarding an alternative
solution of starting ZMS Server without using sudo.

Based on the sample configuration file provided, ZMS Server will be listening
on port 4443.

Stop the ZMS Server by executing:

```shell
$ cd athenz-zms-X.Y
$ sudo -E bin/zms stop
```
