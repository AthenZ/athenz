# Setup ZPU (ZPE Policy Updater)
--------------------------------

ZPU is only needed to support decentralized authorization.
The policy updater is the utility that retrieves from ZTS
the policy files for provisioned domains on a host, which ZPE uses to
evaluate access requests.

* [Requirements](#requirements)
    * [JDK 8](#jdk-8)
* [Getting Software](#getting-software)
* [Configuration](#configuration)
    * [Domain Setting](#domain-setting)
    * [Generate Athenz Configuration File](#generate-athenz-configuration-file)
    * [ZTS Certificate TrustStore](#zts-certificate-truststore)
    * [ZPE Policy Directory](#zpe-policy-directory)
* [Run ZPU Utility](#run-zpu-utility)
    * [Periodic Update](#periodic-update)

## Requirements
---------------

The following tools are required to be installed on hosts
configured to run ZPE Policy Updater.

### JDK 8
---------

ZPU Utility is a java application.

[Oracle Java Platform JDK 8](http://www.oracle.com/technetwork/java/javase/downloads/jdk8-downloads-2133151.html)

While ZPU has been developed and tested with Oracle Java Platform JDK 8
it should run successfully with OpenJDK 8 as well.

## Getting Software
-------------------

Download latest ZPU binary release from Bintray - click on the `Files` tab,
choose the latest version directory and then download the
`athenz-zpu-<latest-version>-bin.tar.gz` file::

[ ![Download](https://api.bintray.com/packages/yahoo/maven/athenz-zpu/images/download.svg) ](https://bintray.com/yahoo/maven/athenz-zpu/_latestVersion)

```shell
$ tar xvfz athenz-zpu-X.Y-bin.tar.gz
$ cd athenz-zpu-X.Y
```

## Configuration
----------------

To successfully run ZPU, the domain administrator must
update a couple of settings files and generate a java
truststore the utility.

### Domain Setting
------------------

Before running ZPU utility, the system administrator must
configure what domains are provisioned on the host so the
utility can retrieve the policy files for those domains
only.

```shell
$ cd athenz-zpu-X.Y
$ vi conf/zpe_policy_updater/zpu.conf
```

In the json file, edit the value for the "domains" field
and specify a comma separated list of domain names.

### ZTS Certificate TrustStore
------------------------------

ZPU needs to access ZTS Server to download all domain policies
in order to execute authorization checks. Since ZTS Server is
running with a self-signed certificate, we need to generate a
truststore for the java http client to use when communicating
with the ZTS Server. From your ZTS Server installation, copy
the `zts_cert.pem` file from the `athenz-zts-X.Y/var/zts_server/certs`
directory to the `athenz-zpu-X.Y/var/zpe_policy_updater/certs`
directory and execute the following command:

```shell
$ cd athenz-zpu-X.Y/var/zpe_policy_updater/certs
$ keytool -importcert -noprompt -alias zts -keystore zpu_truststore.jks -file zts_cert.pem -storepass athenz
```

### Generate Athenz Configuration File
--------------------------------------

Generate an Athenz configuration file `athenz.conf` in
`athenz-zpu-X.Y/conf/zpe_policy_updater` directory to include
the ZTS Server URL and the registered public keys that the
athenz client libraries and utilities will use to establish
connection and validate any data signed by the ZMS and ZTS
Servers. To communicate with ZMS over SSL, the utility needs
to have access to the ZMS Server's public certificate so you
need to copy the `zms_cert.pem` file from the
`athenz-zms-X.Y/var/zms_server/certs` directory to the
`athenz-zpu-X.Y/var/zpe_policy_updater/certs` directory

```shell
$ cd athenz-zpu-X.Y
$ bin/<platform>/athenz-conf -o conf/zpe_policy_updater/athenz.conf -c var/zpe_policy_updater/certs/zms_cert.pem -z https://<zms-server>:4443/ -t https://<zts-server>:8443/
```

### ZPE Policy Directory
------------------------

By default ZPU will save any downloaded policy files in the
`${ROOT}/var/zpe` directory. You need to make sure this is the
directory where ZPE is configured to look for policy files.
To change this directory, please update the UTILITY_POLICY_FILE_DIR
setting in the `conf/zpe_policy_updater/utility_settings` file.

## Run ZPU Utility
------------------

Set the required Athenz ROOT environment variable to the `athenz-zpu-X.Y`
directory and from there start the ZPU utility by executing:

```shell
$ export ROOT=<full-path-to-athenz-zpu-X.Y>
$ bin/zpu_run.sh
```

### Periodic Update
-------------------

The ZPU utility needs to run periodically so it can automatically
download any modified policy files for the configured list of
domains. The system aministrator should setup this utility to be
automatically executed by cron utility at least once every couple
of hours.
