# Setup ZMS (AuthoriZation Management System)

* [Requirements](#requirements)
    * [JDK 11](#jdk-11)
    * [MySQL Server](#mysql-server)
        * [ZMS Server Schema Setup](#zms-server-schema-setup)
        * [MySQL User and Permissions](#mysql-user-and-permissions)
* [Getting Software](#getting-software)
* [Configuration](#configuration)
    * [DB Access](#db-access)
    * [Private Key and Server X509 Certificate Setup](#private-key-and-server-x509-certificate-setup)
      * [Development Environment](#development-environment)
      * [Production Environment](#production-environment)
    * [User Authentication](#user-authentication)
    * [System Administrators](#system-administrators)
* [Start/Stop ZMS Server](#startstop-zms-server)

## Requirements

The following tools are required to be installed on hosts
configured to run ZMS server.

### JDK 11

ZMS Server is written in Java and using embedded Jetty. It requires JDK 11.

### MySQL Server

On a separate host, download and install the latest version
of [MySQL Server 8.x](https://dev.mysql.com/downloads/mysql/)

#### ZMS Server Schema Setup

Copy the `zms_server.sql` file from the Athenz Git repository (from the
servers/zms/schema directory) onto this host and create the database:

```shell 
$ mysql -u root < zms_server.sql
```

#### MySQL User and Permissions

Follow MySQL documentation to create a user and grant this user full
privileges over the zms_server database created. For example, let's assume
our ZMS Server will be running on zms1.athenz.com host, and we want to
create a user called zms_admin with password "rdvXC7wgvm3g":

```
$ mysql -u root
mysql> CREATE USER 'zms_admin'@'zms1.athenz.com' IDENTIFIED BY 'rdvXC7wgvm3g';
mysql> GRANT ALL PRIVILEGES ON zms_server.* TO 'zms_admin'@'zms1.athenz.com';
mysql> FLUSH PRIVILEGES;
```

We recommend having a strong admin password for better security.

## Getting Software

Build the latest ZMS binary release by following the
[development instructions](dev_environment.md). The binary release
packages  will be created automatically in the `assembly` subdirectory.
Copy the `athenz-zms-X.Y-bin.tar.gz` to your desired setup directory.

```shell
$ tar xvfz athenz-zms-X.Y-bin.tar.gz
```

## Configuration

### DB Access

In the "MySQL Server" section above we installed and configured the
schema required for ZMS Server. We also created a zms admin user and
granted full access over those tables. Now, we need to configure the
ZMS with those access details:

```shell
$ cd athenz-zms-X.Y
$ vi conf/zms_server/zms.properties
```

Make the following changes:

1. Configure the ZMS Server to use JDBC object store implementation.
   Uncomment the `#athenz.zms.object_store_factory_class=` line and set
   it to point to the JDBC Factory class name. It should be set to:

   athenz.zms.object_store_factory_class=com.yahoo.athenz.zms.store.impl.JDBCObjectStoreFactory

2. Uncomment the `#athenz.zms.jdbcstore=` line and set it to point to your
   MySQL Server instance. For example if your DB Server is running on
   a host called db1.athenz.com, then your line would be:

   athenz.zms.jdbc_store=jdbc:mysql://db1.athenz.com:3306/zms_server

3. Uncomment the `#athenz.zms.jdbc_user=` line and set it to the user
   configured to have full access over zms server database:

   athenz.zms.jdbc_user=zms_admin

4. Uncomment the `#athenz.zms.jdbc_password=` line and set it to the
   configured password the for the jdbc user with full access:

   athenz.zms.jdbc_password=rdvXC7wgvm3g

Storing the password in property file is not secure. The more secure approach
is to use a Key Management Store like HashiCorp Vault to store your passwords.
Athenz provides a PrivateKeyStoreFactory interface for accessing secrets from
your key management store. The recommended approach would to write your own
implementation of this interface and configure ZMS server to use that factory
to fetch the password for your database access. ZMS Server expect the private
key store factory implementation class name in its
`athenz.zms.private_key_store_factory_class` system property.

Refer to [Private Key Store](private_key_store.md) section for
full details how to implement your private key store.

When storing the jdbc user password for your database access in your key management
store with a given keyname like `athenz.admin_db_password` and using your own
implementation of the PrivateKeyStoreFactory, then the value of the
`athenz.zms.jdbc_password` property would be the key name. For example:

    athenz.zms.jdbc_password=athenz.admin_db_password

The password is retrieved using the `getApplicationSecret()` of your private
key store class that takes keyName (`athenz.admin_db_password` in this case)
as input and returns key value that is your configured password.

### Private Key and Server X509 Certificate Setup

#### Development Environment

To run ZMS Server, the system administrator must generate the keys
and make necessary changes to the configuration settings.

```shell
$ cd athenz-zms-X.Y
$ bin/setup_dev_zms.sh
```

Running this setup script completes the following two tasks:

* Generate a unique private key that ZMS Server will use to sign any NTokens it issues
* Generate a self-signed X509 certificate for ZMS Server HTTPS support

#### Production Environment

##### Private Key

Generate a unique private key that ZMS Server will use
to sign any NTokens it issues. From the `athenz-zms-X.Y` directory
execute the following commands:

```shell
$ cd var/zms_server/keys
$ openssl genrsa -out zms_private.pem 2048
```

If you have multiple ZMS servers in your environment, your private key
must be stored in your key management store and securely installed
on all hosts where ZMS servers will be running in the specified
directory.

##### Server X509 Certificate

While it is still possible to generate and use a self-signed X509
certificate for ZMS Servers, it is recommended to purchase one for
your production server from a well known certificate authority.
Having such a certificate installed on your ZMS Servers will no
longer require to distribute the server's CA certificate to
other hosts (e.g. ZTS Servers, Hosts running ZPU).

Follow the instructions provided by the Certificate Authority that
you're going to purchase your certificate from to
generate your private key and then the Certificate Request (CSR).
Once you have received your X509 certificate, we just need to add
that certificate along with its private key to a keystore for Jetty
use. From the `athenz-zms-X.Y` directory execute the following
command:

```shell
$ openssl pkcs12 -export -out zms_keystore.pkcs12 -in zms_cert.pem -inkey zms_key.pem
```

### User Authentication

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

* Run the process as root using sudo. This is only recommended for a local
  development installation.
* Create a special Unix group that has read access to the /etc/shadow file
  and set the user that the ZMS process will be running as a member of that
  group.

Checkout the [Principal Authentication](principal_authentication.md) section
for full details on authorities.

To add your own authentication authority, modify the
`athenz.zms.authority_classes=com.yahoo.athenz.auth.impl.PrincipalAuthority,com.yahoo.athenz.auth.impl.UserAuthority`
line and include comma separated list of authority implementation classes to support.

### System Administrators

When running the server very first time, ZMS Server automatically creates
the required domains and sets the running user as the system administrator.
The system administrators are the only ones authorized to create top
level domains in Athenz. Before running the server very first time, you
can configure the set of system administrators by following these steps:

```shell
$ cd athenz-zms-X.Y
$ vi conf/zms_server/zms.properties
```

Modify the `athenz.zms.domain_admin=user.admin` line and include comma
separated list of unix user ids that should be set as Athenz system
administrators. e.g. `athenz.zms.domain_admin=user.joe,user.john`

## Start/Stop ZMS Server

Start the ZMS Server by executing:

```shell
$ cd athenz-zms-X.Y
$ sudo -E bin/zms start
```

See the `User Authentication` section above regarding an alternative
solution of starting ZMS Server without using sudo. If using the Unix Authority
to authenticate users against their unix password, make sure the user that the
ZMS Server process is running as has read access to the /etc/shadow file.

Based on the sample configuration file provided, ZMS Server will be listening
on port 4443.

Stop the ZMS Server by executing:

```shell
$ cd athenz-zms-X.Y
$ sudo -E bin/zms stop
```
