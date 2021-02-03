# Private Key Store
-------------------

* [Private Key Store Interfaces](#private-key-store-interfaces)
* [Configuration](#configuration)
* [Provided Implementation](#provided-implementation)
    * [File Based Private Key Store](#file-based-private-key-store)


Athenz servers (both ZMS and ZTS) require a unique private key
to sign their respective tokens. There are 2 distinct operations
that require the use of signatures:

* X509 Certificates / Access Token signatures
* Policy Document signatures

The private key could be unique per host (if you have multiple
ZMS and/or ZTS servers in your production environment) or per
data center location. By default the server ships with a file
based private key store which expects to find the private key
in PEM format in the configured file. The system administrator
may decide to configure and use this implementation or otherwise
implement a completely new one to satisfy their requirements
(e.g. the private keys are to be stored in some external system
rather than a file).

## Private Key Store Interfaces
-------------------------------

To provide ZMS/ZTS servers with private keys, the following two
interfaces must be implemented:

* [PrivateKeyStoreFactory](https://github.com/AthenZ/athenz/blob/master/libs/java/auth_core/src/main/java/com/yahoo/athenz/auth/PrivateKeyStoreFactory.java)

The job of the PrivateKeyStoreFactory class is to implement a single
`create()` method which returns an instance of `PrivateKeyStore` class
implementation.

* [PrivateKeyStore](https://github.com/AthenZ/athenz/blob/master/libs/java/auth_core/src/main/java/com/yahoo/athenz/auth/PrivateKeyStore.java)

The job of the PrivateKeyStore class is to return a private key
for a given host in a PEM format. The hostname is passed as the first
argument to the `getPrivateKey()` method. Each private key in Athenz
is identified by a unique key identifier. This allows each service to
have multiple active private/public key pairs to support per host
keys with key rotation capability. The `getPrivateKey()` method is
passed a `StringBuilder` object that the implementation must update
and return the corresponding key identifier for the public key
returned from this method.

During server startup, Athenz servers will load the configured
private key store factory class and invoke the create method.
Then it will use the PrivateKeyStore object returned to retrieve
the private key for the host.

If the private key store does not return a PrivateKey (returns null),
then the server will continue to run. This is necessary since it's
possible that an environment may choose to run only ZMS Servers
for centralized authorization thus no need to sign and distribute
policy documents and only supports TLS certificates for principal
authentication.

## Configuration
----------------

Both ZMS and ZTS Servers expect to find the configured private key
store factory class names in their respective system properties:

* ZMS: athenz.zms.private_key_store_factory_class
* ZTS: athenz.zts.private_key_store_factory_class

For example,

```
-Dathenz.zms.private_key_store_factory_class=com.yahoo.athenz.zms.pkey.file.FilePrivateKeyStoreFactory
```

If you're installing and running Athenz services using the binary
packages provided, you can configure the private key store factory
class in the conf/zms_server/zms.properties or conf/zts_server/zts.properties
files for ZMS and ZTS servers respectively:

```
athenz.zms.private_key_store_factory_class=com.yahoo.athenz.auth.impl.FilePrivateKeyStoreFactory

athenz.zts.private_key_store_factory_class=com.yahoo.athenz.auth.impl.FilePrivateKeyStoreFactory
```

## Provided Implementation
--------------------------

Here is the list of Athenz provided private key store implementations with
brief description of each one.

### File Based Private Key Store
--------------------------------

Class: com.yahoo.athenz.auth.impl.FilePrivateKeyStoreFactory

This factory class creates and returns a single private key
regardless of the hostname passed to the `getPrivateKey()` method.
The private key file and its corresponding id can be configured by
using the following system properties:

* Key File: athenz.auth.private_key_store.private_key
* Key-Id: athenz.auth.private_key_store.private_key_id

The key file must be a PEM encoded either RSA or EC
private key.
