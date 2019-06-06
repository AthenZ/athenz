# setups

[setup-dev.md](./docs/setup-dev.md)

## useful commands

```bash

mkdir -p `pwd`/docker/logs/zms
mkdir -p `pwd`/docker/logs/zts
docker stack deploy -c ./docker/docker-stack.yaml athenz

docker stack rm athenz
rm -rf ./docker/logs

# ---

docker stack ps athenz
less ./docker/logs/zms/server.log
less ./docker/logs/zts/server.log

sudo systemctl restart docker

# remove single docker
docker stop athenz-zms-server; docker rm athenz-zms-server; sudo rm -f ./docker/logs/zms/server.log
docker stop athenz-zts-server; docker rm athenz-zts-server; sudo rm -f ./docker/logs/zts/server.log

# inspect
docker inspect athenz-zms-server | less
docker inspect athenz-zts-server | less

# check connectivity
apk add curl
curl localhost:4443/zms/v1 -o -
curl localhost:3306 -o -
telnet localhost 4443

# mysql
mysql -v -u root --password=${ZMS_JDBC_PASSWORD} --host=127.0.0.1 --port=3306
mysql -v -u root --password=${ZTS_CERT_JDBC_PASSWORD} --host=127.0.0.1 --port=3307

# keytool
keytool -list -keystore docker/zms/var/certs/zms_keystore.pkcs12
keytool -list -keystore docker/zts/var/certs/zts_truststore.jks
keytool -list -keystore docker/zts/var/certs/zts_keystore.pkcs12
```
## TO-DO

-   UI
    1.  convert `default-config.js` parameters to ENV
    1.  configurable listering port
-   ZMS
    1.  NO retry on DB connection error
    1.  `Loading class `com.mysql.jdbc.Driver'. This is deprecated. The new driver class is `com.mysql.cj.jdbc.Driver'. The driver is automatically registered via the SPI and manual loading of the driver class is generally unnecessary.`
-   ZTS
    1.  `docker/zts/var/zts_store/` create as root user by docker for storing policy
-   ZTS-DB
    1.  `DEFAULT CHARSET = latin1`
-   athenz-builder
    1.  use `maven:3-alpine` instead of `openjdk:8-jdk-alpine`
-   athenz-cli
    -   build with separated docker files
-   common
    -   split setup script for different component

## important files
- [docker-stack.yaml](./docker-stack.yaml)
- [zms Dockerfile](./zms/Dockerfile)
- [zts Dockerfile](./zts/Dockerfile)
