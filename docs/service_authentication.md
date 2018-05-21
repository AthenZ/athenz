# Athenz Service Authentication
-------------------------------

* [Copper Argos](#copper-argos)
* [Using zts-svcvert Utility](#using-zts-svcvert-utility)


Athenz Service Identity x.509 certificates are used to establish standard 
mutual TLS communication with other Athenz Enabled Services.

![Service Authentication](images/service authentication.png)

The services running on the instance can obtain X.509 certificates from zts
using two approaches discussed below:

## Copper Argos(Prefered)
------------------------
 
Refer [Copper Argos](copper_argos.md) for full details.
            
## Using zts-svccert utility (Not recommended)
----------------------------

1. Create a public/private key pair for your service and register
   the public key in Athenz. Refer [Service Registration](reg_service_guide.md) for complete 
   details on registering services in Athenz.
   Store your private key securely. You can store that in a file on the host. 
   The recommended approach is to use Key Management Store like HashiCorp.
   ZMS and ZTS Server use PrivateKeyStoreFactory interface to get access to its secrets. 
   
   Refer [Private Key Store](private_key_store.md) for
   full details how to implement your private key store.
     
2. Use the private key to obtain X.509 certificate from ZTS using zts-svccert 
   utility as below:

   Download latest ZTS SVCCERT utility binary release from Bintray - click
   on the `Files` tab, choose the latest version directory and then
   download the `athenz-utils-<latest-version>-bin.tar.gz` file:
  
   [ ![Download](https://api.bintray.com/packages/yahoo/maven/athenz-utils/images/download.svg) ](https://bintray.com/yahoo/maven/athenz-utils/_latestVersion)

   ```shell
   $ tar xvfz athenz-utils-X.Y-bin.tar.gz
   ```
   You need to make sure to pass the correct `key-version` argument that matches to the key identifier
   that was used to register the public key for the service in Athenz.

   ```
   zts-svccert -domain <domain> -service <service> -private-key <private key file> -key-version <version> -zts <zts_url> -dns-domain <dns-name>  -cert-file <output certificate file>
   ```
   The certificates and keys should be carefully rotated and service should repeatedly refresh them.
