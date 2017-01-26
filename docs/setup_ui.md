# Setup Athenz UI
-----------------

* [Requirements](#requirements)
    * [Node.JS](#nodejs)
* [Getting Software](#getting-software)
* [Configuration](#configuration)
    * [Private/Public Key Pair](#privatepublic-key-pair)
    * [Self Signed X509 Certificate](#self-signed-x509-certificate)
    * [ZMS Certificate](#zms-certificate)
    * [Register UI Service](#register-ui-service)
* [Start UI Server](#start-ui-server)

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

To run UI Server, the system administrator must generate the keys
and make necessary changes to the configuration settings.

### Private/Public Key Pair
---------------------------

Generate a unique private/public key pair that UI Server will use
to sign user's authorized service tokens. The UI has already been
authorized to be allowed to carry out the users' requested
operations. From the `athenz-ui-X.Y` directory execute the following
commands:

```shell
$ cd keys
$ openssl genrsa -out athenz.ui.pem 2048
$ openssl rsa -in athenz.ui.pem -pubout > athenz.ui_pub.pem
```

### Self Signed X509 Certificate
--------------------------------

Unlike ZMS/ZTS Servers, for UI server it is strongly recommended
to purchase a certificate for HTTPS access from a well known
certificate authority. When using a self-signed certificate,
the user's browser will not able to recognize the UI Server's
certificate and the user must add an exception to allow
communication with the UI server.

If necessary, the following steps can be followed to generate
a self-signed X509 certificate for UI Server HTTPS support.
From the `athenz-ui-X.Y` directory execute the following
commands. When prompted for a PEM passpharse, enter `athenz`:

```shell
$ cd keys
$ openssl req -x509 -newkey rsa:2048 -keyout ui_key.pem -out ui_cert.pem -days 365
```

### ZMS Certificate
-------------------

UI Server needs to access ZMS Server to executed the user's requested
operations. Since ZMS Server is running with a self-signed certificate,
we need to configure the UI server with a copy of the ZMS Server's
public certificate. From your ZMS Server installation, copy the
`zms_cert.pem` file from the `athenz-zms-X.Y/var/zms_server/certs` directory
to the `athenz-ui-X.Y/keys` directory.

### Register UI Service
------------------------

In order for UI to access ZMS domain data, it must identify itself
as a registered service in ZMS. Using the `zms-cli` utility, we will
register a new service in `athenz` domain. For this step, we also
need to reference the zms_cert.pem certificate file in order to
successfully validate ZMS Server's certificate.

```shell
$ cd athenz-ui-X.Y
$ bin/<platform>/zms-cli -c keys/zms_cert.pem -z https://<zms-server>:4443/zms/v1 add-domain athenz
$ bin/<platform>/zms-cli -c keys/zms_cert.pem -z https://<zms-server>:4443/zms/v1 -d athenz add-service ui 0 keys/athenz.ui_pub.pem
```

## Start UI Server
------------------

Set the following environment variables before starting the UI Server:

```shell
$ export ZMS_SERVER=<zms-server-name>
$ export ZMS_SERVER_URL=https://<zms-server-name>:4443/zms/v1/
$ bin/ui_start.sh
```

Based on the sample configuration file provided, Athenz UI Server will be listening
on port 9443.
