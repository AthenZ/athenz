# Athenz configuration with docker (development environment)

<a id="markdown-index" name="index"></a>
## Index
<!-- TOC depthFrom:2 updateOnSave:true -->

- [Athenz configuration with docker (development environment)](#Athenz-configuration-with-docker-development-environment)
    - [Index](#Index)
    - [Component dependency](#Component-dependency)
    - [ZMS](#ZMS)
        - [ZMS database configuration](#ZMS-database-configuration)
        - [ZMS server configuration](#ZMS-server-configuration)
    - [ZTS](#ZTS)
        - [ZTS database configuration](#ZTS-database-configuration)
        - [ZTS server configuration](#ZTS-server-configuration)
    - [UI](#UI)
        - [UI server configuration](#UI-server-configuration)

<!-- /TOC -->

<a id="markdown-zms" name="zms"></a>
## ZMS

<a id="markdown-zms-database-configuration" name="zms-database-configuration"></a>
### ZMS database configuration

- file structure
    ```bash
    $ tree docker/db/zms
    docker/db/zms
    └── zms-db.cnf
    ```
- configuration
  
    1. [zms-db.cnf](../db/zms/zms-db.cnf)

<a id="markdown-zms-server-configuration" name="zms-server-configuration"></a>
### ZMS server configuration

- file structure
    ```bash
    $ tree docker/zms
    docker/zms
    ├── conf
    │   ├── athenz.properties
    │   ├── authorized_services.json
    │   ├── logback.xml
    │   ├── solution_templates.json
    │   └── zms.properties
    └── var
        ├── certs
        │   ├── dev_x509_cert.cnf
        │   ├── zms_cert.pem
        │   ├── zms_key.pem
        │   ├── zms_keystore.pkcs12
        │   └── zms_truststore.jks
        └── keys
            ├── zms_private.pem
            └── zms_public.pem
    ```
- configuration
    - keys and certificates
        1. ZMS service key pair (generation script: [2.create-service-keypair.sh](../setup-scripts/2.create-service-keypair.sh))
            1. zms_private.pem
            1. zms_public.pem
        1. ZMS server X.509 certificate
            1. [dev_x509_cert.cnf](../zms/var/certs/dev_x509_cert.cnf)
                - Note
                    - make sure CN, SAN, IP SAN are valid
            1. zms_key.pem (generation script: [1.create-private-key.sh](../setup-scripts/1.create-private-key.sh))
            1. zms_cert.pem (generation script: [3.generate-self-signed-certificate.sh](../setup-scripts/3.generate-self-signed-certificate.sh))
            1. zms_keystore.pkcs12 (generation script: [4.create-keystore.sh](../setup-scripts/4.create-keystore.sh))
        1. ZMS trust store with CA certificate of ZTS and UI
            1. zms_truststore.jks (generation script: [5.create-truststore.sh](../setup-scripts/5.create-truststore.sh))
    - `zms.properties`
        1. [database access](../zms/conf/zms.properties#L126-L169)
            ```properties
            athenz.zms.object_store_factory_class=com.yahoo.athenz.zms.store.impl.JDBCObjectStoreFactory
            athenz.zms.jdbc_store=jdbc:mysql://athenz-zms-db:3306/zms_server
            athenz.zms.jdbc_user=root
            #athenz.zms.jdbc_password=mariadb
            ```
        1. [user/service authentication](../zms/conf/zms.properties#L10-L12)
            ```properties
            athenz.zms.authority_classes=com.yahoo.athenz.auth.impl.PrincipalAuthority,com.yahoo.athenz.auth.impl.UserAuthority
            ```
            - Note
                - Please do **NOT** use `com.yahoo.athenz.auth.impl.UserAuthority` in production.
                - deployment script: [1.2.config-zms-domain-admin.dev.sh](../deploy-scripts/1.2.config-zms-domain-admin.dev.sh)
        1. [domain admin](../zms/conf/zms.properties#L37-L41)
            ```properties
            athenz.zms.domain_admin=user.admin
            ```
        1. [ZMS service key](../zms/conf/zms.properties#L43-L52)
            ```properties athenz.auth.private_key_store.private_key=/opt/athenz/zms/var/keys/zms_private.pem
            athenz.auth.private_key_store.private_key=/opt/athenz/zms/var/keys/zms_private.pem
            athenz.auth.private_key_store.private_key_id=0
            ```
    - `athenz.properties`
        1. [trust store and key store settings](../zms/conf/athenz.properties#L28-L47)
            ```properties
            athenz.ssl_key_store=/opt/athenz/zms/var/certs/zms_keystore.pkcs12
            athenz.ssl_key_store_type=PKCS12
            #athenz.ssl_key_store_password=athenz
            athenz.ssl_trust_store=/opt/athenz/zms/var/certs/zms_truststore.jks
            athenz.ssl_trust_store_type=JKS
            #athenz.ssl_trust_store_password=athenz
            ```

<a id="markdown-zts" name="zts"></a>
## ZTS

<a id="markdown-zts-database-configuration" name="zts-database-configuration"></a>
### ZTS database configuration

- file structure
    ```bash
    $ tree docker/db/zts
    docker/db/zts
    └── zts-db.cnf
    ```
- configuration
  
    1. [zts-db.cnf](../db/zts/zts-db.cnf)

<a id="markdown-zts-server-configuration" name="zts-server-configuration"></a>
### ZTS server configuration

- file structure
    ```bash
    $ tree docker/zts
    docker/zts
    ├── conf
    │   ├── athenz.conf
    │   ├── athenz.properties
    │   ├── logback.xml
    │   └── zts.properties
    └── var
        ├── certs
        │   ├── dev_x509_cert.cnf
        │   ├── zts_cert.pem
        │   ├── zts_key.pem
        │   ├── zts_keystore.pkcs12
        │   └── zts_truststore.jks
        ├── keys
        │   ├── zts_cert_signer_ca.cnf
        │   ├── zts_cert_signer_cert.pem
        │   ├── zts_cert_signer_key.pem
        │   ├── zts_private.pem
        │   └── zts_public.pem
    ```
- configuration
    - keys and certificates
        1. ZTS service key pair (generation script: [2.create-service-keypair.sh](../setup-scripts/2.create-service-keypair.sh))
            1. zts_private.pem
            1. zts_public.pem
        1. ZTS server X.509 certificate
            1. [dev_x509_cert.cnf](../zts/var/certs/dev_x509_cert.cnf)
                - Note
                    - make sure CN, SAN, IP SAN are valid
            1. zts_key.pem (generation script: [1.create-private-key.sh](../setup-scripts/1.create-private-key.sh))
            1. zts_cert.pem (generation script: [3.generate-self-signed-certificate.sh](../setup-scripts/3.generate-self-signed-certificate.sh))
            1. zts_keystore.pkcs12 (generation script: [4.create-keystore.sh](../setup-scripts/4.create-keystore.sh))
        1. ZTS trust store with ZMS CA certificate
            1. zts_truststore.jks (generation script: [5.create-truststore.sh](../setup-scripts/5.create-truststore.sh))
    - ZTS certificate signer (generation script: [6.1.create-zts-cert-signer-pair.sh](../setup-scripts/6.1.create-zts-cert-signer-pair.sh))
        1. [zts_cert_signer_ca.cnf](../zts/var/keys/zts_cert_signer_ca.cnf)
        1. zts_cert_signer_key.pem
        1. zts_cert_signer_cert.pem
    - `zts.properties`
        1. [database access](../zts/conf/zts.properties#L188-L220)
            ```properties
            athenz.zts.cert_record_store_factory_class=com.yahoo.athenz.zts.cert.impl.JDBCCertRecordStoreFactory
            athenz.zts.cert_jdbc_store=jdbc:mysql://athenz-zts-db:3307/zts_store
            athenz.zts.cert_jdbc_user=root
            #athenz.zts.cert_jdbc_password=mariadb
            ```
        1. [user/service authentication](../zts/conf/zts.properties#L10-L12)
            ```properties
            athenz.zts.authority_classes=com.yahoo.athenz.auth.impl.PrincipalAuthority,com.yahoo.athenz.auth.impl.CertificateAuthority
            ```
        1. [ZTS service key](../zts/conf/zts.properties#L14-L23)
            ```properties
            athenz.auth.private_key_store.private_key=/opt/athenz/zts/var/keys/zts_private.pem
            athenz.auth.private_key_store.private_key_id=0
            ```
        1. [ZTS service certificate signing class](../zts/conf/zts.properties#L123-L129) and [its config](../zts/conf/zts.properties#L61-L77)
            ```properties
            athenz.zts.cert_signer_factory_class=com.yahoo.athenz.zts.cert.impl.SelfCertSignerFactory

            athenz.zts.self_signer_private_key_fname=/opt/athenz/zts/var/keys/zts_private.pem
            #athenz.zts.self_signer_private_key_password=
            athenz.zts.self_signer_cert_dn=cn=Sample Self Signed Athenz CA,o=Athenz,c=US
            ```
            - Note
                - Please do **NOT** use `com.yahoo.athenz.zts.cert.impl.SelfCertSignerFactory` in production.
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
    - `athenz.properties`
        1. [trust store and key store settings](../zts/conf/athenz.properties#L28-L47)
            ```properties
            athenz.ssl_key_store=/opt/athenz/zts/var/certs/zts_keystore.pkcs12
            athenz.ssl_key_store_type=PKCS12
            #athenz.ssl_key_store_password=athenz

            athenz.ssl_trust_store=/opt/athenz/zts/var/certs/zts_truststore.jks
            athenz.ssl_trust_store_type=JKS
            #athenz.ssl_trust_store_password=athenz
            ```
    - `athenz.conf` (deployment script: [2.2.create-athenz-conf.sh](../deploy-scripts/2.2.create-athenz-conf.sh))

<a id="markdown-ui" name="ui"></a>
## UI

<a id="markdown-ui-server-configuration" name="ui-server-configuration"></a>
### UI server configuration

- file structure
    ```bash
    $ tree docker/ui
    docker/ui
    └── var
        ├── certs
        │   ├── dev_x509_cert.cnf
        │   ├── ui_cert.pem
        │   └── ui_key.pem
        └── keys
            ├── athenz.ui-server.pem
            └── athenz.ui-server_pub.pem
    ```
- configuration
    - keys and certificates
        1. UI service key pair (generation script: [2.create-service-keypair.sh](../setup-scripts/2.create-service-keypair.sh))
            1. athenz.ui-server.pem
            1. athenz.ui-server_pub.pem
        1. UI server X.509 certificate
            1. [dev_x509_cert.cnf](../ui/var/certs/dev_x509_cert.cnf)
                - Note
                    - make sure CN, SAN, IP SAN are valid
            1. ui_key.pem (generation script: [1.create-private-key.sh](../setup-scripts/1.create-private-key.sh))
            1. ui_cert.pem (generation script: [3.generate-self-signed-certificate.sh](../setup-scripts/3.generate-self-signed-certificate.sh))
    - `athenz.conf` (same as ZTS configuration)
