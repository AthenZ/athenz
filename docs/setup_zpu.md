# Setup ZPU (ZPE Policy Updater)
--------------------------------

ZPU is only needed to support decentralized authorization.
The policy updater is the utility that retrieves from ZTS
the policy files for provisioned domains on a host, which ZPE uses to
evaluate access requests.

* [Getting Software](#getting-software)
* [Configuration](#configuration)
    * [Domain Setting](#domain-setting)
    * [Generate Athenz Configuration File](#generate-athenz-configuration-file)
    * [ZTS Certificate TrustStore](#zts-certificate-truststore)
    * [ZPE Policy Directory](#zpe-policy-directory)
* [Run ZPU Utility](#run-zpu-utility)
    * [Periodic Update](#periodic-update)
* [Policy File Details](#policy-file-details)

## Requirements
---------------

The following tools are required to be installed on hosts
configured to run ZPE Policy Updater.

## Getting Software
-------------------

Download latest ZPU binary release from from
[Maven Central](https://search.maven.org/artifact/com.yahoo.athenz/athenz-utils):
click on the `Browse` button, choose the latest version directory and then 
download the `athenz-utils-<latest-version>-bin.tar.gz`.

```shell
$ tar xvfz athenz-utils-X.Y-bin.tar.gz
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
only. Create a configuration settings file with the
following content:

```json
{
  "domains": "<domain1>,<domain2>",
  "caCertFile": "<path to caCert file>"
}
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
directory to another directory that is configured as the value
of the `caCertFile` setting in the zpu configuration file.

### Generate Athenz Configuration File
--------------------------------------

Generate an Athenz configuration file `athenz.conf` in a directory to
include the ZTS Server URL and the registered public keys that the
athenz client libraries and utilities will use to establish
connection and validate any data signed by the ZMS and ZTS
Servers. To communicate with ZMS over SSL, the utility needs
to have access to the ZMS Server's public certificate, so you
need to copy the `zms_cert.pem` file from the
`athenz-zms-X.Y/var/zms_server/certs` directory to a local directory
and execute the following cmmmand:

```shell
$ bin/<platform>/athenz-conf -o <path-to-athenz.conf> -c <path-to-zms_cert.pem> -z https://<zms-server>:4443/ -t https://<zts-server>:8443/
```

### ZPE Policy Directory
------------------------

By default ZPU will save any downloaded policy files in the
`${ROOT}/var/zpe` directory. You need to make sure this is the
directory where ZPE is configured to look for policy files.

## Run ZPU Utility
------------------

Set the required Athenz ROOT environment variable to the required
directory and from there start the ZPU utility by executing:

```shell
$ export ROOT=<full-path-to-required-root-directory>
$ zpu -athenzConf <Athenz conf file> -zpuConf <zpu conf file> 
```

### Periodic Update
-------------------

The ZPU utility needs to run periodically so it can automatically
download any modified policy files for the configured list of
domains. The system administrator should setup this utility to be
automatically executed by cron utility at least once every couple
of hours.

## Policy File Details
------------------------

Checkout the [ZPU Policy File](zpu_policy_file.md) for details
how to manually validate the signatures in the policy file. This
would be necessary if you'll be writing your own authorization
policy engine library instead of using the Athenz provided one.

