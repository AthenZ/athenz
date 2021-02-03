# Certificate Signer
--------------------

* [Cert Signer Interfaces](#cert-signer-interfaces)
* [Configuration](#configuration)
* [Provided Implementations](#provided-implementations)
    * [Self Cert Signer](#self-cert-signer)
    * [HTTP Cert Signer](#http-cert-signer)


Athenz supports service authentication with X.509 certificates. 
The services receive X509 certificates from ZTS which requires a cert 
signer implementation to sign and issue X509 certificates for Athenz Services.
This feature, commonly referred as Copper Argos, is described in the 
following [section](copper_argos.md).

## Cert Signer Interfaces
-------------------------

For ZTS servers to issue X509 certificates, the following two
interfaces must be implemented:

* [CertSignerFactory](https://github.com/AthenZ/athenz/blob/master/libs/java/server_common/src/main/java/com/yahoo/athenz/common/server/cert/CertSignerFactory.java).

The job of the CertSignerFactory class is to implement a single
`create()` method which returns an instance of CertSigner class
implementation.

* [CertSigner](https://github.com/AthenZ/athenz/blob/master/libs/java/server_common/src/main/java/com/yahoo/athenz/common/server/cert/CertSigner.java). 

This class implements six methods listed below:
  
  * generateX509Certificate():
      This method generates a signed X509 Certificate
      based on the given request. It takes three parameters `csr (Certificate request)`,
      requested key usage `keyUsage` (null for both server and client,
      otherwise specified usage type: server or client) and `expiryTime` 
      which specifies requested certificate expiration time in minutes
      and returns a X509 Certificate in PEM format
  * getCACertificate(): This method is to retrieve the CA certificate in PEM format that will be
      returned along with the x509 certificate back to the client.
  * generateSSHCertificate(): This method is to generate a SSH Certificate based on the given request.
  * getSSHCertificate(): This method is to retrieve the SSH Signer certificate for the given type.
  * getMaxCertExpiryTimeMins(): This method is to retrieve the certificate max expiry time supported
      by the given signer.
  * close(): This method is for closing  the certSigner signer object and release all
      allocated resources

During server startup, ZTS servers will load the configured cert signer factory
class and invoke the create method. Then it will use the CertSigner object returned
to issue X509 certificates to requesting services.

## Configuration
----------------

ZTS Servers expect the configured cert signer factory class name in its
`athenz.zts.cert_signer_factory_class` system property.

For example,

```
-Dathenz.zts.cert_signer_factory_class=com.yahoo.athenz.zts.cert.impl.HttpCertSignerFactory
```

If you're installing and running Athenz services using the binary
packages provided, you can configure the cert signer factory class
in the conf/zts_server/zts.properties file for ZTS server:

```
athenz.zts.cert_signer_factory_class=com.yahoo.athenz.zts.cert.impl.HttpCertSignerFactory
```

## Provided Implementations
---------------------------

Here is the list of Athenz provided certificate signer implementations with a
brief description of each one.

### Self Cert Signer
--------------------

Class: com.yahoo.athenz.zts.cert.impl.SelfCertSignerFactory

This factory class creates and returns an object of SelfCertSigner class
[com.yahoo.athenz.zts.cert.impl.SelfCertSignerFactory](https://github.com/AthenZ/athenz/blob/master/servers/zts/src/main/java/com/yahoo/athenz/zts/cert/impl/SelfCertSigner.java) 
The private key file name, private key password and the DN for self signer can be configured by
using the following system properties:

* Key File: athenz.zts.self_signer_private_key_fname
* Key password: athenz.zts.self_signer_private_key_password
* DN: athenz.zts.self_signer_cert_dn

The key file must be a PEM encoded either RSA or EC private key.

### Http Cert Signer
--------------------

Class: com.yahoo.athenz.zts.cert.impl.HttpCertSignerFactory

This factory class creates and returns a object of HttpCertSigner class
[com.yahoo.athenz.zts.cert.impl.SelfCertSignerFactory](https://github.com/AthenZ/athenz/blob/master/servers/zts/src/main/java/com/yahoo/athenz/zts/cert/impl/HttpCertSigner.java)
This signer assumes you have a certificate singing daemon that
implements POST/GET REST /x509 and /ssh endpoints to sign and
return x.509 certificates.

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
