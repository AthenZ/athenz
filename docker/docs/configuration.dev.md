# Deploy Athenz with docker (development environment)

<a id="markdown-index" name="index"></a>
## Index
<!-- TOC depthFrom:2 updateOnSave:true -->

- [Deploy Athenz with docker (development environment)](#Deploy-Athenz-with-docker-development-environment)
    - [Index](#Index)
    - [Component dependency](#Component-dependency)
    - [Prepare ZMS configuration](#Prepare-ZMS-configuration)
        - [details](#details)
    - [Prepare ZTS configuration based on ZMS configuration](#Prepare-ZTS-configuration-based-on-ZMS-configuration)
        - [details](#details-1)
    - [UI](#UI)
        - [prepare UI configuration](#prepare-UI-configuration)

<!-- /TOC -->

<a id="markdown-component-dependency" name="component-dependency"></a>
## Component dependency
![Athenz-components](./images/Athenz-components.png)

<a id="markdown-prepare-zms-configuration" name="prepare-zms-configuration"></a>
## Prepare ZMS configuration

<a id="markdown-details" name="details"></a>
### details
1. ZMS database configuration
  
    1. [zms-db.cnf](../db/zms/zms-db.cnf)
1. ZMS service key pair
    1. [zms_private.pem](../zms/var/keys/zms_private.pem)
    1. [zms_public.pem](../zms/var/keys/zms_public.pem)
1. ZMS server X.509 certificate
    1. [zms_key.pem](../zms/var/certs/zms_key.pem)
    1. [dev_x509_cert.cnf](../zms/var/certs/dev_x509_cert.cnf)
    1. [zms_cert.pem](../zms/var/certs/zms_cert.pem)
    1. [zms_keystore.pkcs12](../zms/var/certs/zms_keystore.pkcs12)
    
1. ZMS trust store with ZTS and UI CA certificate

    1. [zms_truststore.jks](../zms/var/certs/zms_truststore.jks)

1. `zms.properties`
    1. [database access](../zms/conf/zms.properties#L126-L169)
      
        ```properties
        athenz.zms.object_store_factory_class=com.yahoo.athenz.zms.store.impl.JDBCObjectStoreFactory
        athenz.zms.jdbc_store=jdbc:mysql://localhost:3306/zms_server
        athenz.zms.jdbc_user=root
        #athenz.zms.jdbc_password=mariadb
        ```
    1. [user authentication](../zms/conf/zms.properties#L10-L12)
        ```properties
        athenz.zms.authority_classes=com.yahoo.athenz.auth.impl.PrincipalAuthority,com.yahoo.athenz.auth.impl.UserAuthority
        ```
    1. [domain admin](../zms/conf/zms.properties#L37-L41)
        ```properties
        athenz.zms.domain_admin=user.admin
        ```
    1. [ZMS service key](../zms/conf/zms.properties#L43-L52)
        ```properties
        athenz.auth.private_key_store.private_key=/opt/athenz/zms/var/keys/zms_private.pem
        athenz.auth.private_key_store.private_key_id=0
        ```
1. `athenz.properties`
    1. [trust store and key store settings](../zms/conf/athenz.properties#L28-L47)
        ```properties
        athenz.ssl_key_store=/opt/athenz/zms/var/certs/zms_keystore.pkcs12
        athenz.ssl_key_store_type=PKCS12
        #athenz.ssl_key_store_password=athenz
        athenz.ssl_trust_store=/opt/athenz/zms/var/certs/zms_truststore.jks
        athenz.ssl_trust_store_type=JKS
        #athenz.ssl_trust_store_password=athenz
        ```

<a id="markdown-prepare-zts-configuration-based-on-zms-configuration" name="prepare-zts-configuration-based-on-zms-configuration"></a>
## Prepare ZTS configuration based on ZMS configuration

<a id="markdown-details-1" name="details-1"></a>
### details
1. ZTS database configuration
  
    1. [zts-db.cnf](../db/zts/zts-db.cnf)
    
1. ZTS service key pair
  
    1. [zts_private.pem](../zts/var/keys/zts_private.pem)
    1. [zts_public.pem](../zts/var/keys/zts_public.pem)
    
1. ZTS server X.509 certificate
    1. [zts_key.pem](../zts/var/certs/zts_key.pem)
    1. [dev_x509_cert.cnf](../zts/var/certs/dev_x509_cert.cnf)
    1. [zts_cert.pem](../zts/var/certs/zts_cert.pem)
    1. [zts_keystore.pkcs12](../zts/var/certs/zts_keystore.pkcs12)
    
1. ZTS trust store with ZMS CA certificate
  
    1. [zts_truststore.jks](../zts/var/certs/zts_truststore.jks)
    
1. ZTS cert signer

    1. [zts_cert_signer_ca.cnf](../zts/var/certs/zts_cert_signer_ca.cnf)
    1. [zts_cert_signer_key.pem](../zts/var/certs/zts_cert_signer_key.pem)
    1. [zts_cert_signer_cert.pem](../zts/var/certs/zts_cert_signer_cert.pem)

1. `zts.properties`
    1. [database access](../zts/conf/zts.properties#L188-L220)
        ```properties
        athenz.zts.cert_record_store_factory_class=com.yahoo.athenz.zts.cert.impl.JDBCCertRecordStoreFactory
        athenz.zts.cert_jdbc_store=jdbc:mysql://localhost:3307/zts_store
        athenz.zts.cert_jdbc_user=root
        #athenz.zts.cert_jdbc_password=mariadb
        ```
    1. [user authentication](../zts/conf/zts.properties#L10-L12)
      
        ```properties
        athenz.zts.authority_classes=com.yahoo.athenz.auth.impl.PrincipalAuthority,com.yahoo.athenz.auth.impl.CertificateAuthority
        ```
    1. [ZTS service key](../zts/conf/zts.properties#L14-L23)
      
        ```properties
        athenz.auth.private_key_store.private_key=/opt/athenz/zts/var/keys/zts_private.pem
        athenz.auth.private_key_store.private_key_id=0
        ```
    1. [ZTS service certificate signing class and its config](../zts/conf/zts.properties#L123-L129)
      
        ```properties
        athenz.zts.self_signer_private_key_fname=/opt/athenz/zts/var/keys/zts_private.pem
        #athenz.zts.self_signer_private_key_password=athenz
        athenz.zts.self_signer_cert_dn=cn=Sample Self Signed Athenz CA,o=Athenz,c=US
        ```
    1. [ZTS client TLS config](../zts/conf/zts.properties#L28-L51)
      
        ```properties
        athenz.zts.ssl_key_store=/opt/athenz/zts/var/certs/zts_keystore.pkcs12
        athenz.zts.ssl_key_store_type=PKCS12
        #athenz.zts.ssl_key_store_password=athenz
    
        athenz.zts.ssl_trust_store=/opt/athenz/zts/var/certs/zts_truststore.jks
        javax.net.ssl.trustStore=/opt/athenz/zts/var/certs/zts_truststore.jks
        athenz.zts.ssl_trust_store_type=JKS
        javax.net.ssl.trustStoreType=JKS
        #athenz.zts.ssl_trust_store_password=athenz
        #javax.net.ssl.trustStorePassword=athenz
        ```
1. `athenz.properties`
  
    1. [trust store and key store settings](../zts/conf/athenz.properties#L28-L47)
        ```properties
        athenz.ssl_key_store=/opt/athenz/zts/var/certs/zts_keystore.pkcs12
        athenz.ssl_key_store_type=PKCS12
        #athenz.ssl_key_store_password=athenz
    
        athenz.ssl_trust_store=/opt/athenz/zts/var/certs/zts_truststore.jks
        athenz.ssl_trust_store_type=JKS
        #athenz.ssl_trust_store_password=athenz
        ```
    
1. `athenz.conf`
    1. [ZMS URL](../zts/conf/athenz.conf#L2)
    1. [ZMS public keys](../zts/conf/athenz.conf#L4-L9)

<a id="markdown-ui" name="ui"></a>
## UI

<a id="markdown-prepare-ui-configuration" name="prepare-ui-configuration"></a>
### prepare UI configuration
1. UI service key pair
    1. [athenz.ui-server.pem](../ui/keys/athenz.ui-server.pem)
    1. [athenz.ui-server_pub.pem](../ui/keys/athenz.ui-server_pub.pem)
1. UI server X.509 certificate
    1. [ui_key.pem](../ui/keys/ui_key.pem)
    1. [dev_ui_x509_cert.cnf](../ui/keys/dev_ui_x509_cert.cnf)
    1. [ui_cert.pem](../ui/keys/ui_cert.pem)
1. `athenz.conf`
    1. same as ZTS configuration
