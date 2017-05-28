# Setup Athenz UI
-----------------

* [Requirements](#requirements)
    * [Node.JS](#nodejs)
* [Getting Software](#getting-software)
* [Configuration](#configuration)
* [Start/Stop UI Server](#startstop-ui-server)

## Requirements
---------------

The following tools are required to be installed on hosts
configured to run UI server.

### Node.js
-----------

UI Server is a Node.js application.

[Node.js JavaScript Runtime](https://nodejs.org/en/)

Verify that you have the required minimum version of `node` and
`nodemon` binaries installed on your system and are included
in your runtime path:

```shell
$ node --version
v6.9.4
$ nodemon --version
1.11.0
```

## Getting Software
-------------------

Download latest Athenz UI release from Bintray - click on the `Files` tab,
choose the latest version directory and then download the
`athenz-ui-<latest-version>-bin.tar.gz` file:

[ ![Download](https://api.bintray.com/packages/yahoo/maven/athenz-ui/images/download.svg) ](https://bintray.com/yahoo/maven/athenz-ui/_latestVersion)

```shell
$ tar xvfz athenz-ui-X.Y-bin.tar.gz
$ cd athenz-ui-X.Y
```

## Configuration
----------------

To run UI Server, the system administrator must generate the keys,
certificates and make necessary changes to the configuration settings.
For our configuration script we need the ZMS server hostname and a
copy of the server certificate file since ZMS Server is
running with a self-signed certificate. From your ZMS Server
installation, copy the `zms_cert.pem` file from the
`athenz-zms-X.Y/var/zms_server/certs` directory to a local directory on the
host that will be running the UI Server. For the `zms-public-cert-path`
argument below pass the full path of the zms_cert.pem.

```shell
$ cd athenz-ui-X.Y
$ bin/setup_dev_ui.sh <zms-hostname> <zms-public-cert-path>
```

Running this setup script completes the following tasks:

* Generate a unique public/private key pair that UI Server will use
  to sign user's authorized service tokens. The UI has already been
  authorized to be allowed to carry out the users' requested
  operations.
* Generate a self-signed X509 certificate for UI Server HTTPS support
* Create a new domain called athenz and register the ui service in that domain

## Start/Stop UI Server
-----------------------

Set the following environment variable before starting the UI Server:

```shell
$ export UI_SERVER=<ui-server-host-name> ZMS_SERVER=<zms-server-host-name>
$ cd athenz-ui-X.Y
$ bin/athenz_ui start
```

Based on the sample configuration file provided, Athenz UI Server will be listening
on port 9443.

To stop the UI server, execute the following commands:

```shell
$ export UI_SERVER=<ui-server-host-name> ZMS_SERVER=<zms-server-host-name>
$ cd athenz-ui-X.Y
$ bin/athenz_ui stop
```

## Befor accessing to UI
-----------------------

Install self-signed X509 certificates into your own web browser in order to have HTTPS support for ZMS Server and UI Server:

To access UI we need the self-signed certificates for ZMS Server and UI Server.
From your ZMS Server installation, copy the `zms_cert.pem` file from the `athenz-zms-X.Y/var/zms_server/certs` directory to a local directory on the host that will be running web browser.
From your UI Server installation, copy the `ui_cert.pem` file from the `athenz-ui-X.Y/keys` directory to a local directory on the host that will be running web browser.
