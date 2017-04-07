# Setup ZTS (authoriZation Token System)
----------------------------------------

* [Requirements](#requirements)
    * [JDK 8](#jdk-8)
* [Getting Software](#getting-software)
* [Configuration](#configuration)
* [Start/Stop ZTS Server](#startstop-zts-server)

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

Download latest ZTS binary release from Bintray - click on the `Files` tab,
choose the latest version directory and then download the
`athenz-zts-<latest-version>-bin.tar.gz` file::

[ ![Download](https://api.bintray.com/packages/yahoo/maven/athenz-zts/images/download.svg) ](https://bintray.com/yahoo/maven/athenz-zts/_latestVersion)

```shell
$ tar xvfz athenz-zts-X.Y-bin.tar.gz
$ cd athenz-zts-X.Y
```

## Configuration
----------------

To run ZTS Server, the system administrator must generate the keys,
certificates and make necessary changes to the configuration settings.
Since ZMS Server is running with a self-signed certificate, we need to
generate a truststore for the java http client to use when communicating
with the ZMS Server. For our configuration script we need the ZMS server
hostname and a copy of the server certificate file. From your ZMS Server
installation, copy the `zms_cert.pem` file from the
`athenz-zms-X.Y/var/zms_server/certs` directory to a local directory on the
host that will be running the ZTS Server. For the `zms-public-cert-path`
argument below pass the full path of the zms_cert.pem.

```shell
$ cd athenz-zms-X.Y
$ bin/setup_dev_zts.sh <zms-hostname> <zms-public-cert-path>
```

Running this setup script completes the following tasks:

* Generate a unique private key that ZTS Server will use to sign any ZTokens it issues
* Generate a self-signed X509 certificate for ZTS Server HTTPS support
* Generate a truststore for secure communication with the ZMS Server
* Registers the zts service in Athenz sys.auth domain
* Generates an Athenz configuration file

## Start/Stop ZTS Server
------------------------

Start the ZTS Server by executing:

```shell
$ cd athenz-zts-X.Y
$ bin/zts start
```

Based on the sample configuration file provided, ZTS Server will be listening
on port 8443.

Stop the ZTS Server by executing:

```shell
$ cd athenz-zts-X.Y
$ bin/zts stop
```

