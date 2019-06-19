# Athenz on Docker

## Build Athenz

```bash
cd ${PROJECT_ROOT}

make build-docker
```

## Deploy Athenz
### DEV env.

```bash
cd ${PROJECT_ROOT}

# 1. set passwords (P.S. values in *.properties files will overwrite these values)
source docker/setup-scripts/0.export-default-passwords.sh

# 2. generate key-pairs, certificates and keystore/truststore
make setup-dev

# 3. run Athenz
make run-docker-dev
```
```bash
# clean up
make remove-all
```

## Verify Athenz Deployment
[acceptance-test](./acceptance-test)

## Configuration Details
- [configuration.dev.md](./docs/configuration.dev.md)

## Useful Commands

```bash
# check logs
less ./docker/logs/zms/server.log
less ./docker/logs/zts/server.log

# remove single docker
docker stop athenz-zms-server; docker rm athenz-zms-server; sudo rm -f ./docker/logs/zms/*
docker stop athenz-zts-server; docker rm athenz-zts-server; sudo rm -f ./docker/logs/zts/*
docker stop athenz-ui; docker rm athenz-ui

# inspect
docker inspect athenz-zms-server | less
docker inspect athenz-zts-server | less

# check connectivity
telnet localhost 4443
curl localhost:4443/zms/v1 -o -
curl localhost:8443/zts/v1 -o -
curl localhost:3306 -o -
curl localhost:3307 -o -

# mysql
mysql -v -u root --host=127.0.0.1 --port=3306 --password=${ZMS_JDBC_PASSWORD} --database=zms_server -e 'show tables;'
mysql -v -u root --host=127.0.0.1 --port=3307 --password=${ZTS_CERT_JDBC_PASSWORD} --database=zts_store -e 'show tables;'

# keytool
openssl pkey -in docker/zms/var/certs/zms_key.pem
openssl pkey -in docker/zts/var/certs/zts_key.pem
openssl pkey -in docker/ui/var/certs/ui_key.pem
keytool -list -keystore docker/zms/var/certs/zms_keystore.pkcs12
keytool -list -keystore docker/zts/var/certs/zts_keystore.pkcs12
keytool -list -keystore docker/zms/var/certs/zms_truststore.jks
keytool -list -keystore docker/zts/var/certs/zts_truststore.jks
# openssl pkey -in docker/zts/var/keys/zts_cert_signer_key.pem
# keytool -list -keystore docker/zts/var/keys/zts_cert_signer_keystore.pkcs12
```

## [WIP] deploy with docker-stack
```bash
cd ${PROJECT_ROOT}

# 1. set passwords (P.S. values in *.properties files will overwrite these values)
source docker/setup-scripts/0.export-default-passwords.sh

# 2. generate key-pairs, certificates and keystore/truststore
make setup-dev

# 3. start docker stack (some components will fail, don't panic)
mkdir -p `pwd`/docker/logs/zms
mkdir -p `pwd`/docker/logs/zts
docker stack deploy -c ./docker/docker-stack.yaml athenz

# (optional) restart ZMS service if DB is not ready during start up
rm -f ./docker/logs/zms/server.log
ZMS_SERVICE=`docker stack services -qf "name=athenz_zms-server" athenz`
docker service update --force $ZMS_SERVICE

# 4.1. setup ZMS for ZTS
sh docker/deploy-scripts/1.2.config-zms-domain-admin.dev.sh
sh docker/deploy-scripts/2.1.register-ZTS-service.sh
sh docker/deploy-scripts/2.2.create-athenz-conf.sh
# 4.2. restart ZTS service to apply the new setting
rm -f ./docker/logs/zts/server.log
ZTS_SERVICE=`docker stack services -qf "name=athenz_zts-server" athenz`
docker service update --force $ZTS_SERVICE

# 5.1. setup ZMS for UI
sh docker/deploy-scripts/3.1.register-UI-service.sh
# 5.2. restart UI service to apply the new setting
UI_SERVICE=`docker stack services -qf "name=athenz_ui" athenz`
docker service update --force $UI_SERVICE
```
```bash
# debug docker stack
docker stack ps athenz
less ./docker/logs/zms/server.log
less ./docker/logs/zts/server.log

# reset docker stack
docker stack rm athenz
rm -rf ./docker/logs

# restart docker
sudo systemctl restart docker
```

## TO-DO

-   UI
    1.  convert `default-config.js` parameters to ENV
    1.  `server.js`, `login.js`, `serviceFQN`; `keys` folder is hard coded
    1.  configurable listering port
-   ZMS
    1.  NO retry on DB connection error when deploy with docker stack
    1.  Warning message in docker log: `Loading class `com.mysql.jdbc.Driver'. This is deprecated. The new driver class is `com.mysql.cj.jdbc.Driver'. The driver is automatically registered via the SPI and manual loading of the driver class is generally unnecessary.`
-   ZTS
    1.  `docker/zts/var/zts_store/` create as root user by docker for storing policy, better to change the default location folder outside the Athenz project folder
-   ZTS-DB
    1.  `DEFAULT CHARSET = latin1`
-   ZPU
    1.  If volume not mount to `/home/athenz/tmp/zpe/`, will have error: `2019/06/12 06:34:09 Failed to get policies for domain: garm, Error:Unable to write Policies for domain:"garm" to file, Error:rename /home/athenz/tmp/zpe/garm.tmp /etc/acceptance-test/zpu/garm.pol: invalid cross-device link`
-   athenz-cli
    1.  build with separated docker files (add go.mod to support caching the dependency)
-   common
    1.  file permission for keys (`chmod`)
    1.  bootstrap without user token for `zms-cli`
    1.  health check API entry point, no auth, `TODO: wait for Z`
    1.  fix IP/hostname problem in PROD deployment using docker, `athenz.conf`

## Important Files
- [zms Dockerfile](./zms/Dockerfile)
- [zts Dockerfile](./zts/Dockerfile)
- [Makefile](../Makefile)
- [setup-scripts](./setup-scripts)
- [deploy-scripts](../deploy-scripts)
- [docker-stack.yaml](./docker-stack.yaml)
