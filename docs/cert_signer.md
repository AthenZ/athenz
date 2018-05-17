# Cert Signer
-------------------

* [Cert Signer Interfaces](#private-key-store-interfaces)
* [Configuration](#configuration)
* [Provided Implementation](#provided-implementation)
    * [Self Cert Signer](#self cert signer)
    * [HTTP Cert Signer](#http cert signer)


Athenz supports service authentication with  X.509 certificates which is 
preferred approach over ntokens. 
The services receive X509 certificates from ZTS.
For this there needs to be a cert signer implementation which
allows ZTS to issue X509 certificates. 

## Cert Signer Interfaces
-------------------------------

For ZTS servers to issue X509 certificates, the following two
interfaces must be implemented:

* [CertSignerFactory](https://github.com/yahoo/athenz/blob/master/libs/java/server_common/src/main/java/com/yahoo/athenz/common/server/cert/CertSignerFactory.java).
 The job of the PrivateKeyStoreFactory class is to implement a single
`create()` method which returns an instance of CertSigner class implementation.

* [CertSigner](https://github.com/yahoo/athenz/blob/master/libs/java/server_common/src/main/java/com/yahoo/athenz/common/server/cert/CertSigner.java). 
  This class implements six methods listed below:
  
    * generateX509Certificate(): This method generates a signed X509 Certificate
      based on the given request. It takes three parameters `csr (Certificate request)`,
      requested key usage `keyUsage` (null for both server and client,
      otherwise specified usage type: server or client) and `expiryTime` 
      which specifies requested certificate expiration time in minutes.
      and returnsX509 Certificate in PEM format
      
    * getCACertificate(): This method is to retrieve the CA certificate in PEM format that will be
     returned along with the x509 certificate back to the client.
     
    * generateSSHCertificate(): This method is to generate an SSH Certificate based on the given request.
    
    * getSSHCertificate(): This method is to retrieve the SSH Signer certificate for the given type.
    
    * getMaxCertExpiryTimeMins(): This method is to retrieve the certificate max expiry time supported
      by the given signer.
      
    * close(): This method is for Closing  the certSigner signer object and release all
      allocated resources

During server startup, ZTS servers will load the configured
cert signer factory factory class and invoke the create method.
Then it will use the CertSigner object returned to issue X509 certificates to 
requesting services.


## Configuration
----------------

ZTS Servers expect the configured cert signer factory class names in its `athenz.zts.private_key_store_factory_class` 
system property.

For example,

```
-Dathenz.zts.cert_signer_factory_class=com.yahoo.athenz.zts.cert.impl.HttpCertSignerFactory
```

If you're installing and running Athenz services using the binary
packages provided, you can configure the cert signer factory class
in the conf/zts_server/zts.properties file for  ZTS server

```
athenz.zts.cert_signer_factory_class=com.yahoo.athenz.zts.cert.impl.HttpCertSignerFactory
```

## Provided Implementation
--------------------------

Here is the list of Athenz provided cert signer implementations with
brief description of each one.

### Self Cert Signer 
--------------------

Class: com.yahoo.athenz.zts.cert.impl.SelfCertSignerFactory

This factory class creates and returns a object of SelfCertSigner class
[com.yahoo.athenz.zts.cert.impl.SelfCertSignerFactory](https://github.com/yahoo/athenz/blob/master/servers/zts/src/main/java/com/yahoo/athenz/zts/cert/impl/SelfCertSigner.java) 
The private key file name, private key password and the domanin name for self signer can be configured by
using the following system properties:

* Key File: athenz.zts.self_signer_private_key_fname
* Key password: athenz.zts.self_signer_private_key_password
* Domanin name: athenz.zts.self_signer_cert_dn

The key file must be a PEM encoded either RSA or EC
private key.

### Http Cert Signer
--------------------

Class: com.yahoo.athenz.zts.cert.impl.HttpCertSignerFactory

This factory class creates and returns a object of SelfCertSigner class
[com.yahoo.athenz.zts.cert.impl.SelfCertSignerFactory](https://github.com/yahoo/athenz/blob/master/servers/zts/src/main/java/com/yahoo/athenz/zts/cert/impl/HttpCertSigner.java) 
The base uri of signer service and other settings can be configured by
using the following system properties:

* Base Uri of Cert Signer Service: athenz.zts.certsign_base_uri
* Connect Timeout: athenz.zts.certsign_connect_timeout
  This setting specifies in seconds the connect timeout. We are setting it to 10.
* Request Timeout: athenz.zts.certsign_request_timeout
  This setting specifies in seconds the request timeout. We are setting it to 5.
* Retry count: athenz.zts.certsign_retry_count
  This setting specifies the number of times the request
  should be retried if it's not completed with the requested 
  timeout value. We are setting it to 3.

