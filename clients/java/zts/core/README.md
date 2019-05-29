zts-java-client
===============

A Java client library to access ZTS. This client library is generated
from the RDL, and includes zts-core and all other dependencies.

## System Properties

- `athenz.zts.client.read_timeout`: The read timeout in milliseconds. Default: `30000` (30sec)
- `athenz.zts.client.connect_timeout`:  The connection timeout in milliseconds. Default: `30000` (30sec)
- `athenz.zts.client.prefetch_auto_enable`:  true or false. Default: `false`

- `athenz.zts.client.cert_alias`: Used for specifying client certificate based on the alias name if you have more than one private key/cert pairs in the keystore. Default: Use all certs.
- `athenz.zts.client.keystore_path`: Path to keystore file. 
- `athenz.zts.client.keystore_type`: Key store types.  Default: `pkcs12`
- `athenz.zts.client.keystore_password`: Key Store password.
- `athenz.zts.client.keystore_pwd_app_name`: Key Store password application name. Default: none
- `athenz.zts.client.keymanager_password`: Key Manager password.
- `athenz.zts.client.keymanager_pwd_app_name`: Key Manager password application name. Default: none

- `athenz.zts.client.truststore_path`: Path to truststore file. 
- `athenz.zts.client.truststore_type`: Trust store types.  Default is `pkcs12`
- `athenz.zts.client.truststore_password`: Trust Store password.
- `athenz.zts.client.truststore_pwd_app_name`: Trust Store password application name. Default: none
- `athenz.zts.client.private_keystore_factory_class`: Private key store factory class implements [com.yahoo.athenz.auth.PrivateKeyStoreFactory](https://github.com/yahoo/athenz/blob/master/libs/java/auth_core/src/main/java/com/yahoo/athenz/auth/PrivateKeyStoreFactory.java) 
which will be used for retrieving passwords. Default: `com.yahoo.athenz.auth.impl.FilePrivateKeyStoreFactory`.

- `athenz.zts.client.client_ssl_protocol`: Client TLS protocol. Default: `TLSv1.2`

## Examples

### TLS Support

Using X.509 Certificates when communicating with ZTS Server:

[ZTS Client with TLS Support](https://github.com/yahoo/athenz/tree/master/clients/java/zts/core/examples/tls-support)

## License

Copyright 2016 Yahoo Inc.

Licensed under the [Apache License, Version 2.0](http://www.apache.org/licenses/LICENSE-2.0)

