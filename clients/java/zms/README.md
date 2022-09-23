zms-java-client
===============

A Java client library to access the ZMS server.
The client library encapsulates the stub generated from the ZMS RDL.
It includes zms-core and all other dependencies.

## System Properties

- `athenz.zms.client.read_timeout`: The read timeout in milliseconds. Default: `30000` (30sec)
- `athenz.zms.client.connect_timeout`:  The connection timeout in milliseconds. Default: `30000` (30sec)

- `athenz.zms.client.cert_alias`: Used for specifying client certificate based on the alias name if you have more than one private key/cert pairs in the keystore. Default: Use all certs.
- `athenz.zms.client.keystore_path`: Path to keystore file. 
- `athenz.zms.client.keystore_type`: Key store types.  Default: `pkcs12`
- `athenz.zms.client.keystore_password`: Key Store password.
- `athenz.zms.client.keystore_pwd_app_name`: Key Store password application name. Default: none
- `athenz.zms.client.keymanager_password`: Key Manager password.
- `athenz.zms.client.keymanager_pwd_app_name`: Key Manager password application name. Default: none

- `athenz.zms.client.truststore_path`: Path to truststore file. 
- `athenz.zms.client.truststore_type`: Trust store types.  Default is `pkcs12`
- `athenz.zms.client.truststore_password`: Trust Store password.
- `athenz.zms.client.truststore_pwd_app_name`: Trust Store password application name. Default: none
- `athenz.zms.client.private_keystore_factory_class`: Private key store factory class implements [com.yahoo.athenz.auth.PrivateKeyStoreFactory](https://github.com/AthenZ/athenz/blob/master/libs/java/auth_core/src/main/java/com/yahoo/athenz/auth/PrivateKeyStoreFactory.java) 
which will be used for retrieving passwords. Default: `com.yahoo.athenz.auth.impl.FilePrivateKeyStoreFactory`.

- `athenz.zms.client.client_ssl_protocol`: Client TLS protocol. Default: `TLSv1.2`

## Examples

### TLS Support

Using X.509 Certificates when communicating with ZMS Server:

[ZMS Client with TLS Support](https://github.com/AthenZ/athenz/tree/master/clients/java/zms/examples/tls-support)

## License

Copyright The Athenz Authors

Licensed under the [Apache License, Version 2.0](http://www.apache.org/licenses/LICENSE-2.0)
