# Setup Athenz UI

* [Requirements](#requirements)
    * [Node.JS](#nodejs)
* [Getting Software](#getting-software)
* [Server Configuration Setup](#server-configuration-setup)
  * [Development Environment](#development-environment)
  * [Production Environment](#production-environment)
* [Start/Stop UI Server](#startstop-ui-server)
* [UI Access](#ui-access)

## Requirements

The following tools are required to be installed on hosts
configured to run UI server.

### Node.js

UI Server is a Node.js 18.x application.

[Node.js JavaScript Runtime](https://nodejs.org/en/)

Verify that you have the following or newer versions of `node` and
`nodemon` binaries installed on your system and are included
in your runtime path:

```shell
$ node --version
v18.19.0
$ npm -v
10.3.0
$ npm install -g nodemon
$ nodemon --version
3.0.3
```
 
## Getting Software

Build the latest UI binary release by following the
[development instructions](dev_environment.md). The binary release
packages  will be created automatically in the `assembly` subdirectory.
Copy the `athenz-ui-X.Y-bin.tar.gz` to your desired setup directory.

```shell
$ tar xvfz athenz-ui-X.Y-bin.tar.gz
$ cd athenz-ui-X.Y
```

## Server Configuration Setup

### Development Environment

To run UI Server, the system administrator must generate the keys,
certificates and make necessary changes to the configuration settings.
For our configuration script we need the ZMS server hostname and a
copy of the server certificate file since ZMS Server is
running with a self-signed certificate. From your ZMS Server
installation, copy the `zms_cert.pem` file from the
`athenz-zms-X.Y/var/zms_server/certs` directory to a local directory on the
host that will be running the UI Server. For the `zms-public-cert-path`
argument below pass the full path of the zms_cert.pem. For the `admin-username`
argument below pass the system admin that the zms server configured with:
e.g. `user.john` and the `admin-fullname` is the full name for the administrator:
e.g. `John Smith`.

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

### Production Environment

#### Private/Public Key Pair

Generate a unique private/public key pair that UI Server will use
to sign user's authorized service tokens. The UI has already been
authorized to be allowed to carry out the users' requested
operations. From the `athenz-ui-X.Y` directory execute the following
commands:

```shell
$ cd keys
$ openssl genrsa -out athenz.ui-server.pem 2048
$ openssl rsa -in athenz.ui-server.pem -pubout > athenz.ui-server_pub.pem
```

#### Server X509 Certificate

For Athenz UI production server it is strongly recommended
purchasing a certificate for HTTPS access from a well known
certificate authority.

Follow the instructions provided by the Certificate Authority to
generate your private key and then the Certificate Request (CSR).
Once you have received your X509 certificate name your UI
server private key as `ui_key.pem` and the X509 certificate
as `ui_cert.pem` and copy those files into the `keys` subdirectory.

#### Register UI Service

In order for UI to access ZMS domain data, it must identify itself
as a registered service in ZMS. Using the `zms-cli` utility, we will
register a new service in `athenz` domain:

```shell
$ cd athenz-ui-X.Y
$ bin/<platform>/zms-cli -z https://<zms-server>:4443/zms/v1 add-domain athenz
$ bin/<platform>/zms-cli -z https://<zms-server>:4443/zms/v1 -d athenz add-service ui-server 0 keys/athenz.ui-server_pub.pem
```

#### Generate Athenz Configuration File

Generate an Athenz configuration file `athenz.conf` in `athenz-ui-X.Y/config`
directory to include the ZMS Server URL and the registered public keys that the
athenz client libraries and utilities will use to establish connection and validate any
data signed by the ZMS Server:

```shell
$ cd athenz-ui-X.Y
$ bin/<platform>/athenz-conf -o config/athenz.conf -z https://<zms-server>:4443/
```

## Start/Stop UI Server

Set the following environment variable before starting the UI Server:

### Development Environment

```shell
$ cd athenz-ui-X.Y
$ export UI_SERVER=<ui-server-host-name> ZMS_SERVER=<zms-server-host-name> NODE_TLS_REJECT_UNAUTHORIZED=0
$ sudo -E bin/athenz_ui start
```

We're setting the `NODE_TLS_REJECT_UNAUTHORIZED` environment variable to `0` to disable the certificate
verification since we're running with self-signed certificates in our development environment.

### Production Environment

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

To access Athenz UI in your browser, visit:

```
https://<ui-server-host-name>
```

### Development Environment Restrictions

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
