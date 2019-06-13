# setups

[setup-dev.md](./docs/setup-dev.md)

## useful commands

```bash
# start docker stack
mkdir -p `pwd`/docker/logs/zms
mkdir -p `pwd`/docker/logs/zts
docker stack deploy -c ./docker/docker-stack.yaml athenz

# reset docker stack
docker stack rm athenz
rm -rf ./docker/logs

# debug docker stack
docker stack ps athenz
less ./docker/logs/zms/server.log
less ./docker/logs/zts/server.log

# restart docker
sudo systemctl restart docker

# remove single docker
docker stop athenz-zms-server; docker rm athenz-zms-server; sudo rm -f ./docker/logs/zms/*
docker stop athenz-zts-server; docker rm athenz-zts-server; sudo rm -f ./docker/logs/zts/*

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
keytool -list -keystore docker/zts/var/keys/zts_cert_signer_keystore.pkcs12
```
## TO-DO

-   UI
    1.  convert `default-config.js` parameters to ENV
    1.  configurable listering port
-   ZMS
    1.  trustore password not exported; if empty, will cause error even if trustore not set
    1.  NO retry on DB connection error when deploy with docker stack
    1.  Warning message in docker log: `Loading class `com.mysql.jdbc.Driver'. This is deprecated. The new driver class is `com.mysql.cj.jdbc.Driver'. The driver is automatically registered via the SPI and manual loading of the driver class is generally unnecessary.`
-   ZTS
    1.  `docker/zts/var/zts_store/` create as root user by docker for storing policy, better to change the default location folder outside the Athenz project folder
    2.  should expose `ZTS_SELF_SIGNER_PRIVATE_KEY_PASSWORD` and `ZTS_SIGN_KEYSTORE_PASSWORD` in docker file?
-   ZTS-DB
    1.  `DEFAULT CHARSET = latin1`
-   ZPU
    1.  If volume not mount to `/home/athenz/tmp/zpe/`, will have error: `2019/06/12 06:34:09 Failed to get policies for domain: garm, Error:Unable to write Policies for domain:"garm" to file, Error:rename /home/athenz/tmp/zpe/garm.tmp /etc/acceptance-test/zpu/garm.pol: invalid cross-device link`
-   athenz-cli
    1.  build with separated docker files (add go.mod to support caching the dependency)
-   common
    1.  split setup script (gen-certs.sh) for different component

## important files
- [docker-stack.yaml](./docker-stack.yaml)
- [zms Dockerfile](./zms/Dockerfile)
- [zts Dockerfile](./zts/Dockerfile)
