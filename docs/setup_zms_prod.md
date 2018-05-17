# Setup ZMS (AuthoriZation Management System) For Production
------------------------------------------------------------

The primary requirement for running ZMS in a Production environment is
using JDBC (MySQL Server) to store the domain data as opposed to
file based json documents.

* [Requirements](#requirements)
    * [JDK 8](#jdk-8)
    * [MySQL Server](#mysql-server)
        * [ZMS Server Schema Setup](#zms-server-schema-setup)
        * [MySQL User and Permissions](#mysql-user-and-permissions)
* [Getting Software](#getting-software)
* [Configuration](#configuration)
    * [DB Access](#db-access)
    * [Private Key](#private-key)
    * [Server X509 Certificate](#server-x509-certificate)
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

### MySQL Server
----------------

On a separate host, download and install the latest version
of [MySQL Server](https://dev.mysql.com/downloads/mysql/)

#### ZMS Server Schema Setup
----------------------------

Copy the `zms_server.sql` file from the Athenz Git repository (from the
servers/zms/schema directory) onto this host and create the database:

```shell 
$ mysql -u root < zms_server.sql
```

#### MySQL User and Permissions
-------------------------------

Follow MySQL documentation to create a user and grant this user full
privileges over the zms_server database created. For example, let's assume
our ZMS Server will be running on zms1.athenz.com host and we want to
create a user called zms_admin with password "Athenz":

```
$ mysql -u root
mysql> CREATE USER 'zms_admin'@'zms1.athenz.com' IDENTIFIED BY 'Athenz';
mysql> GRANT ALL PRIVILEGES ON zms_server.* TO 'zms_admin'@'zms1.athenz.com';
mysql> FLUSH PRIVILEGES;
```

We recommend to have a strong admin password for better security.

## Getting Software
-------------------

Download latest ZMS binary release from

```
https://github.com/yahoo/athenz/releases/latest
```

```shell
$ tar xvfz athenz-zms-X.Y-bin.tar.gz
$ cd athenz-zms-X.Y
```

## Configuration
----------------

To run ZMS Server, the system administrator must generate the keys
and make necessary changes to the configuration settings.

### DB Access
-------------

In the "MySQL Server" section above we installed and configured the
schema required for ZMS Server. We also created a zms admin user and
granted full access over those tables. Now, we need to configure the
ZMS with those access details:

```shell
$ cd conf/zms_server
$ vi zms.properties
```

Make the following changes:

1. Uncomment the `#athenz.zms.jdbcstore=` line and set it to point to your
   MySQL Server instance. For example if your DB Server is running on
   a host called db1.athenz.com, then your line would be:
   
   athenz.zms.jdbc_store=jdbc:mysql://db1.athenz.com:3306/zms_server

2. Uncomment the `#athenz.zms.jdbc_user=` line and set it to the user
   configured to have full access over zms server database:
   
   athenz.zms.jdbc_user=zms_admin

3. Uncomment the `#athenz.zms.jdbc_password=` line and set it to the
   configured password the for the jdbc user with full access:
   
   athenz.zms.jdbc_password=Athenz
   
Storing the password in property file is not secure. The more robust approach 
is to use Key Management Store like HashiCorp Vault to store your passwords.
ZMS Servers expect the private key store factory class name in its
`athenz.zms.private_key_store_factory_class` system property and uses that 
PrivateKeyStoreFactory to get access to its secrets. 

Refer [private key store](private_key_store) for 
full details how to implement your private key store.

Store the jdbc password in your key management store with Keyname 
like `athenz.zms.jdbc_password` and set its value to the configured
password for the jdbc user with full access in your key management store. 
The password is retrieved using the `getApplicationSecret()` of your private 
key store class that takes keyName (`athenz.zms.jdbc_password` in this case) 
as input and returns key value that is your configured password .

### Private Key
---------------

Generate a unique private key that ZMS Server will use
to sign any NTokens it issues. From the `athenz-zms-X.Y` directory
execute the following commands:

```shell
$ cd var/zms_server/keys
$ openssl genrsa -out zms_private.pem 2048
```

### Server X509 Certificate
---------------------------

While it is still possible to generate and use a self-signed X509 
certificate for ZMS Servers, it is recommended to purchase one for
your production server from a well known certificate authority.
Having such a certificate installed on your ZMS Servers will no
longer require to distribute the server's public certificate to
other hosts (e.g. ZTS Servers, Hosts running ZPU).

Follow the instructions provided by the Certificate Authority to
generate your private key and then the Certificate Request (CSR).
Once you have received your X509 certificate, we just need to add
that certificate along with its private key to a keystore for Jetty 
use. From the `athenz-zms-X.Y` directory execute the following
command:

```shell
$ openssl pkcs12 -export -out zms_keystore.pkcs12 -in zms_cert.pem -inkey zms_key.pem
```

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

* Create a special Unix group that has read access to the /etc/shadow file
  and set the user that the ZMS process will be running as a member of that
  group.
* Run the process as root using sudo. This is not recommended for a
  production installation.
  
To add your own authentication authority modify the `athenz.zms.authority_classes=com.yahoo.athenz.auth.impl.PrincipalAuthority,com.yahoo.athenz.auth.impl.UserAuthority` line and include comma
separated list of authority implementation classes to support.

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

Modify the `athenz.zms.domain_admin=user.${USER}` line and include comma
separated list of unix user ids that should be set as Athenz system
administrators. e.g. `athenz.zms.domain_admin=user.joe,user.john`

## Start/Stop ZMS Server
------------------------

Start the ZMS Server by executing:

```shell
$ cd athenz-zms-X.Y
$ bin/zms start
```

Make sure the user that the ZMS Server process is running as has read
access to the /etc/shadow file. For full details, please check out
the `User Authentication` section above.

Based on the sample configuration file provided, ZMS Server will be listening
on port 4443.

Stop the ZMS Server by executing:

```shell
$ cd athenz-zms-X.Y
$ bin/zms stop
```
