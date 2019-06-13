# Deploy Athenz with docker (development environment)

<a id="markdown-index" name="index"></a>
## Index
<!-- TOC depthFrom:2 updateOnSave:true -->

- [Deploy Athenz with docker (development environment)](#deploy-athenz-with-docker-development-environment)
    - [Index](#index)
    - [Component dependency](#component-dependency)
    - [Build docker images](#build-docker-images)
    - [Deploy ZMS & ZTS with docker stack](#deploy-zms--zts-with-docker-stack)
    - [Prepare ZMS configuration](#prepare-zms-configuration)
        - [details](#details)
    - [Prepare ZTS configuration based on ZMS configuration](#prepare-zts-configuration-based-on-zms-configuration)
        - [details](#details-1)
        - [setup ZMS for ZTS](#setup-zms-for-zts)
    - [UI](#ui)
        - [prepare UI configuration](#prepare-ui-configuration)
        - [setup ZMS for UI](#setup-zms-for-ui)
        - [deploy UI](#deploy-ui)

<!-- /TOC -->

<a id="markdown-component-dependency" name="component-dependency"></a>
## Component dependency
![Athenz-components](./images/Athenz-components.png)


<a id="markdown-build-docker-images" name="build-docker-images"></a>
## Build docker images

```bash
cd ${PROJECT_ROOT}

make build-docker
```

<a id="markdown-deploy-zms--zts-with-docker-stack" name="deploy-zms--zts-with-docker-stack"></a>
## Deploy ZMS & ZTS with docker stack

1. prepare passwords
    ```bash
    cd ${PROJECT_ROOT}

    # prepare passwords (values in *.properties files will overwrite these settings)
    ### DB password
    export ZMS_JDBC_PASSWORD=${ZMS_JDBC_PASSWORD:-mariadb}
    export ZTS_CERT_JDBC_PASSWORD=${ZTS_CERT_JDBC_PASSWORD:-mariadb}
    ### SSL private key password
    export ZMS_PK_PASS=${ZMS_PK_PASS:-athenz}
    export ZTS_PK_PASS=${ZTS_PK_PASS:-athenz}
    export UI_PK_PASS=${UI_PK_PASS:-athenz}
    ### keystore password
    export ZMS_SSL_KEYSTORE_PASS=${ZMS_SSL_KEYSTORE_PASS:-athenz}
    export ZTS_SSL_KEYSTORE_PASS=${ZTS_SSL_KEYSTORE_PASS:-athenz}
    export ZTS_ZTS_SSL_KEYSTORE_PASS=${ZTS_SSL_KEYSTORE_PASS}
    ### truststore password
    export ZMS_SSL_TRUSTSTORE_PASS=${ZMS_SSL_TRUSTSTORE_PASS:-athenz}
    export ZTS_SSL_TRUSTSTORE_PASS=${ZTS_SSL_TRUSTSTORE_PASS:-athenz}
    export ZTS_ZTS_SSL_TRUSTSTORE_PASS=${ZTS_SSL_TRUSTSTORE_PASS}
    ### ZTS self cert signer private key password
    export ZTS_CERT_SIGNER_PK_PASS=${ZTS_CERT_SIGNER_PK_PASS:-athenz}
    ```
1. prepare keys, certificates, keystores and truststores
  
    ```bash
    # build execution env.
    docker build -t openssl-alpine -f ./docker/setup-scripts/openssl/Dockerfile ./docker/setup-scripts
    docker build -t keytool-alpine -f ./docker/setup-scripts/keytool/Dockerfile ./docker/setup-scripts
    
    # test docker image
    docker run --rm openssl-alpine
    docker run --rm keytool-alpine
    
    # run setup scripts (1)
    docker run --rm --entrypoint /usr/bin/run.sh \
      -e ZMS_PK_PASS=${ZMS_PK_PASS:-athenz} \
      -e ZTS_PK_PASS=${ZTS_PK_PASS:-athenz} \
      -e UI_PK_PASS=${UI_PK_PASS:-athenz} \
      -v `pwd`/docker:/usr/bin/docker \
      -v `pwd`/docker/setup-scripts/1.create-private-key.sh:/usr/bin/run.sh \
      openssl-alpine
    
    # run setup scripts (2)
    docker run --rm --entrypoint /usr/bin/run.sh \
      -v `pwd`/docker:/usr/bin/docker \
      -v `pwd`/docker/setup-scripts/2.create-service-keypair.sh:/usr/bin/run.sh \
      openssl-alpine
    
    # run setup scripts (3)
    docker run --rm --entrypoint /usr/bin/run.sh \
      -e ZMS_PK_PASS=${ZMS_PK_PASS:-athenz} \
      -e ZTS_PK_PASS=${ZTS_PK_PASS:-athenz} \
      -e UI_PK_PASS=${UI_PK_PASS:-athenz} \
      -v `pwd`/docker:/usr/bin/docker \
      -v `pwd`/docker/setup-scripts/3.generate-self-signed-certificate.sh:/usr/bin/run.sh \
      openssl-alpine
    
    # run setup scripts (4)
    docker run --rm --entrypoint /usr/bin/run.sh \
      -e ZMS_PK_PASS=${ZMS_PK_PASS:-athenz} \
      -e ZTS_PK_PASS=${ZTS_PK_PASS:-athenz} \
      -e UI_PK_PASS=${UI_PK_PASS:-athenz} \
      -e ZMS_SSL_KEYSTORE_PASS=${ZMS_SSL_KEYSTORE_PASS:-athenz} \
      -e ZTS_SSL_KEYSTORE_PASS=${ZTS_SSL_KEYSTORE_PASS:-athenz} \
      -v `pwd`/docker:/usr/bin/docker \
      -v `pwd`/docker/setup-scripts/4.create-keystore.sh:/usr/bin/run.sh \
      openssl-alpine
    
    # run setup scripts (5)
    docker run --rm --entrypoint /usr/bin/run.sh \
      -e ZMS_SSL_TRUSTSTORE_PASS=${ZMS_SSL_TRUSTSTORE_PASS:-athenz} \
      -e ZTS_SSL_TRUSTSTORE_PASS=${ZTS_SSL_TRUSTSTORE_PASS:-athenz} \
      -v `pwd`/docker:/usr/bin/docker \
      -v `pwd`/docker/setup-scripts/5.create-truststore.sh:/usr/bin/run.sh \
      keytool-alpine
    ```
1. **[DEV env. only]** prepare key and certificate pairs for ZTS self cert signer
  
    ```bash
    # [DEV env. only] run setup scripts (6.1)
    docker run --rm --entrypoint /usr/bin/run.sh \
      -e ZTS_CERT_SIGNER_PK_PASS=${ZTS_CERT_SIGNER_PK_PASS:-athenz} \
      -v `pwd`/docker:/usr/bin/docker \
      -v `pwd`/docker/setup-scripts/6.1.create-zts-cert-signer-pair.sh:/usr/bin/run.sh \
      openssl-alpine
    
    # [DEV env. only] run setup scripts (6.2)
    docker run --rm --entrypoint /usr/bin/run.sh \
      -e ZTS_SSL_TRUSTSTORE_PASS=${ZTS_SSL_TRUSTSTORE_PASS:-athenz} \
      -v `pwd`/docker:/usr/bin/docker \
      -v `pwd`/docker/setup-scripts/6.2.trust-zts-cert-signer-CA.sh:/usr/bin/run.sh \
      keytool-alpine
    ```
1. run with docker stack
    ```bash
    # create folder for log files
    mkdir -p `pwd`/docker/logs/zms
    mkdir -p `pwd`/docker/logs/zts

    # run athenz
    # P.S. ZTS is not running normally at this state. We will update it in the following section.
    docker stack deploy -c ./docker/docker-stack.yaml athenz

    # (optional) restart ZMS service in docker stack if failed to DB during start up
    ZMS_SERVICE=`docker stack services -qf "name=athenz_zms-server" athenz`
    docker service update --force $ZMS_SERVICE
    ```
1. stop
    ```bash
    # stop athenz
    docker stack rm athenz
    rm -rf ./docker/logs
    ```

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

<a id="markdown-setup-zms-for-zts" name="setup-zms-for-zts"></a>
### setup ZMS for ZTS
- [register-ZTS-to-ZMS.sh](../register-ZTS-to-ZMS.sh)
```bash
cd ${PROJECT_ROOT}

# requirement: ZMS is running

# 1. add ZTS service public key to ZMS (if not specified, admin user password is set to `replace_me_with_a_strong_passowrd`)
export ZMS_ADMIN_PASS=${ZMS_ADMIN_PASS:-replace_me_with_a_strong_passowrd}
sh ./docker/register-ZTS-to-ZMS.sh

# 2. generate athenz.conf for ZTS (admin user password: `ZMS_ADMIN_PASS`)
docker run -it --rm --network=host \
  -v `pwd`/docker/zts/conf/athenz.conf:/tmp/athenz.conf \
  athenz-cli-util \
  ./utils/athenz-conf/target/linux/athenz-conf \
  -i user.admin -t https://localhost:8443 -z https://localhost:4443 \
  -k -o /tmp/athenz.conf

# 3. restart ZTS service in docker stack
rm -f ./docker/logs/zts/server.log
ZTS_SERVICE=`docker stack services -qf "name=athenz_zts-server" athenz`
docker service update --force $ZTS_SERVICE
```

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

<a id="markdown-setup-zms-for-ui" name="setup-zms-for-ui"></a>
### setup ZMS for UI
```bash
cd ${PROJECT_ROOT}

# requirement: ZMS is running (admin user password: `ZMS_ADMIN_PASS`)

# 1. add athenz.ui-server service to ZMS
docker run -it --rm --net=host \
  -v `pwd`/docker/zms/var/certs/zms_cert.pem:/etc/certs/zms_cert.pem \
  athenz-zms-cli \
  -i user.admin -z https://localhost:4443/zms/v1 -c /etc/certs/zms_cert.pem \
  add-domain athenz admin
docker run -it --rm --net=host \
  -v `pwd`/docker/zms/var/certs/zms_cert.pem:/etc/certs/zms_cert.pem \
  -v `pwd`/docker/ui/keys/athenz.ui-server_pub.pem:/etc/certs/athenz.ui-server_pub.pem \
  athenz-zms-cli \
  -i user.admin -z https://localhost:4443/zms/v1 -c /etc/certs/zms_cert.pem \
  -d athenz add-service ui-server 0 /etc/certs/athenz.ui-server_pub.pem

# 2. verify domain
docker run -it --rm --net=host \
  -v `pwd`/docker/zms/var/certs/zms_cert.pem:/etc/certs/zms_cert.pem \
  athenz-zms-cli \
  -i user.admin -z https://localhost:4443/zms/v1 -c /etc/certs/zms_cert.pem \
  show-domain athenz
```

<a id="markdown-deploy-ui" name="deploy-ui"></a>
### deploy UI
```bash
cd ${PROJECT_ROOT}

docker run -d -h localhost \
  --network=host -p 443 \
  -v `pwd`/docker/zts/conf/athenz.conf:/opt/athenz/ui/config/athenz.conf \
  -v `pwd`/docker/ui/keys:/opt/athenz/ui/keys \
  -e ZMS_SERVER=`hostname` \
  -e UI_SERVER=`hostname` \
  --name athenz-ui athenz-ui
```
