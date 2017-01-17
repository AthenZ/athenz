# Setup Athenz UI
-----------------

* [Requirements](#requirements)
    * [Node.JS](#nodejs)
* [Getting Software](#getting-software)
* [Configuration](#configuration)
    * [Private/Public Key Pair](#privatepublic-key-pair)
* [Start UI Server](#start-ui-server)

## Requirements
---------------

The following tools are required to be installed on hosts
configured to run UI server.

### Node.js
-----------

UI Server is a Node.js application.

[Node.js JavaScript Runtime](https://nodejs.org/en/)

## Getting Software
-------------------

Download latest ZMS binary release from

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
to authenticate itself against ZMS Server and execute the requested
operation. From the `athenz-ui-X.Y` directory execute the following
commands:

```shell
$ cd var/athenz_ui/keys
$ openssl genrsa -out ui_private.pem 2048
$ openssl rsa -in ui_private.pem -pubout > ui_public.pem
```

## Start UI Server
------------------


Based on the sample configuration file provided, Athenz UI Server will be listening
on port 443.
