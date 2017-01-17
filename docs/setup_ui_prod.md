# Setup Athenz UI for Production
--------------------------------

* [Requirements](#requirements)
    * [Node.JS](#nodejs)
* [Getting Software](#getting-software)
* [Configuration](#configuration)
    * [Private/Public Key Pair](#privatepublic-key-pair)
    * [X509 Certificate](#x509-certificate)
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

Download latest Athenz UI release from

```
https://github.com/yahoo/athenz/releases/latest
```

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

### X509 Certificate
--------------------

For Athenz UI production server it is strongly recommended
to purchase a certificate for HTTPS access from a well known
certificate authority.

Follow the instructions provided by the Certificate Authority to
generate your private key and then the Certificate Request (CSR).
Once you have received your X509 certificate name your UI
server private key as `ui_key.pem` and the X509 certificate
as `ui_cert.pem` and copy those files into the keys subdirectory.

### Register UI Service
------------------------

In order for UI to access ZMS domain data, it must identify itself
as a registered service in ZMS. Using the `zms-cli` utility, we will
register a new service in `athenz` domain:

```shell
$ cd athenz-ui-X.Y
$ bin/<platform>/zms-cli -z https://<zms-server>:4443/zms/v1 add-domain athenz
$ bin/<platform>/zms-cli -z https://<zms-server>:4443/zms/v1 -d athenz add-service ui 0 keys/athenz.ui_pub.pem
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
