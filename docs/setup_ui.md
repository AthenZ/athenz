# Setup Athenz UI
-----------------

* [Requirements](#requirements)
    * [Node.JS](#nodejs)
* [Getting Software](#getting-software)
* [Configuration](#configuration)
* [Start/Stop UI Server](#startstop-ui-server)
* [UI Access](ui-access)

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
v12.14.0
$ npm install -g nodemon
$ nodemon --version
2.0.3
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
$ bin/setup_dev_ui.sh <zms-hostname> <zms-public-cert-path> <admin-username> <admin-fullname>
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
$ cd athenz-ui-X.Y
$ export UI_SERVER=<ui-server-host-name> ZMS_SERVER=<zms-server-host-name>
$ sudo -E bin/athenz_ui start
```

Based on the sample configuration file provided, Athenz UI Server will be listening
on port 443.

To stop the UI server, execute the following commands:

```shell
$ cd athenz-ui-X.Y
$ export UI_SERVER=<ui-server-host-name> ZMS_SERVER=<zms-server-host-name>
$ sudo -E bin/athenz_ui stop
```

## UI Access
------------

To access Athenz UI in your browser, visit:

```
https://<ui-server-host-name>
```

Since the development setup is using self-signed X509 certificates for
Athenz ZMS and UI servers, the administrator must add exceptions when
accessing Athenz UI or install the self-signed certificates for those two
servers into his/her own web browser.

The administrator must first access the ZMS Server endpoint in the browser to
accept the exception since the Athenz UI contacts ZMS Server to get an authorized
token for the user when logging in. The administrator must access:

```
https://<zms-server-host-name>:4443/zms/v1/schema
```

first and accept the certificate exception before accessing Athenz UI.

Alternatively, the administrator may decide to install the self-signed
certificates for the ZMS and UI servers in their browser. For ZMS Server,
the self-signed certificate is called `zms_cert.pem` and this file
is located in the `athenz-zms-X.Y/var/zms_server/certs` directory.
For UI Server, the self-signed certificate is called `ui_cert.pem` and this file
is located in the `athenz-ui-X.Y/keys` directory.

