# Athenz on Docker

<a id="markdown-index" name="index"></a>
## Index
<!-- TOC depthFrom:2 updateOnSave:true -->

- [Athenz on Docker](#athenz-on-docker)
    - [Index](#index)
    - [Prerequisite](#prerequisite)
    - [Build Athenz](#build-athenz)
    - [Deploy Athenz](#deploy-athenz)
    - [Verify Athenz Deployment](#verify-athenz-deployment)
        - [JAVA Remote debugging](#java-remote-debugging)
    - [Cleanup](#cleanup)
    - [Appendix](#appendix)
        - [Important Files](#important-files)
        - [[WIP] Configuration Details](#wip-configuration-details)
        - [Useful Commands](#useful-commands)
        - [[WIP] Deploy with docker-stack](#wip-deploy-with-docker-stack)
        - [TODO](#todo)
        - [UI Section (backup)](#ui-section-backup)

<!-- /TOC -->

<a id="markdown-prerequisite" name="prerequisite"></a>
## Prerequisite
- `docker`
- `make`
- `openssl`
- `keytool`

<a id="markdown-build-athenz" name="build-athenz"></a>
## Build Athenz

```bash
cd `git rev-parse --show-toplevel`/docker

# it takes about 15-30 mins
make build
```

<a id="markdown-deploy-athenz" name="deploy-athenz"></a>
## Deploy Athenz

- production environment
    - [Athenz-bootstrap](./docs/Athenz-bootstrap.md)
- development environment
    ```bash
    make deploy-dev
    ```

<a id="markdown-verify-athenz-deployment" name="verify-athenz-deployment"></a>
## Verify Athenz Deployment

- [acceptance-test](./docs/acceptance-test.md)

<a id="markdown-java-remote-debugging" name="java-remote-debugging"></a>
### JAVA Remote debugging

```bash
### ZMS
ZMS_DEBUG_PORT=8001
export ZMS_JAVA_OPTS="-agentlib:jdwp=transport=dt_socket,server=y,suspend=n,address=${ZMS_DEBUG_PORT}"
# deploy ZMS
# expose debug port
docker run --rm \
    --network="${DOCKER_NETWORK}" \
    -p "${ZMS_DEBUG_PORT}:${ZMS_DEBUG_PORT}" \
    --link "${ZMS_HOST}:target" \
    alpine/socat \
    "tcp-listen:${ZMS_DEBUG_PORT},fork,reuseaddr" \
    "tcp-connect:target:${ZMS_DEBUG_PORT}"

### ZTS
ZTS_DEBUG_PORT=8002
export ZTS_JAVA_OPTS="-agentlib:jdwp=transport=dt_socket,server=y,suspend=n,address=${ZTS_DEBUG_PORT}"
# deploy ZTS
# expose debug port
docker run --rm \
    --network="${DOCKER_NETWORK}" \
    -p "${ZTS_DEBUG_PORT}:${ZTS_DEBUG_PORT}" \
    --link "${ZTS_HOST}:target" \
    alpine/socat \
    "tcp-listen:${ZTS_DEBUG_PORT},fork,reuseaddr" \
    "tcp-connect:target:${ZTS_DEBUG_PORT}"
```

<a id="markdown-cleanup" name="cleanup"></a>
## Cleanup

```bash
# remove deployment
make remove-all

# remove everything include docker images
make clean
```

<a id="markdown-appendix" name="appendix"></a>
## Appendix

<a id="markdown-important-files" name="important-files"></a>
### Important Files
- [zms Dockerfile](./zms/Dockerfile)
- [zts Dockerfile](./zts/Dockerfile)
- [Makefile](./Makefile)
- [setup-scripts](./setup-scripts)
- [deploy-scripts](./deploy-scripts)
- [docker-stack.yaml](./docker-stack.yaml)

<a id="markdown-wip-configuration-details" name="wip-configuration-details"></a>
### [WIP] Configuration Details
- development environment
    - [configuration.dev.md](./docs/configuration.dev.md)
    - server ports
        - `3306`: ZMS DB
            - [zms-db.cnf](./db/zms/zms-db.cnf#L2)
            - [zms.properties](./zms/conf/zms.properties#L154)
            - ENV: `ZMS_DB_PORT` ([deploy script](./deploy-scripts/1.1.deploy-ZMS.sh#L12))
        - `4443`: ZMS server
            - [athenz.properties](./zms/conf/athenz.properties#L6)
            - ENV: `ZMS_PORT` ([deploy script](./deploy-scripts/1.1.deploy-ZMS.sh#L14))
        - `3306`: ZTS DB
            - [zts-db.cnf](./db/zts/zts-db.cnf#L2)
            - [zts.properties](./zts/conf/zts.properties#L211)
            - ENV: `ZTS_DB_PORT` ([deploy script](./deploy-scripts/2.3.deploy-ZTS.sh#L12))
        - `8443`: ZTS server
            - [athenz.properties](./zts/conf/athenz.properties#L6)
            - ENV: `ZTS_PORT` ([deploy script](./deploy-scripts/2.2.create-athenz-conf.sh#L17))
        - `443`: UI
            - ENV: `UI_PORT` ([deploy script](./deploy-scripts/3.2.deploy-UI.sh#L16))

<a id="markdown-useful-commands" name="useful-commands"></a>
### Useful Commands

```bash
# check logs
less ./logs/zms/server.log
less ./logs/zts/server.log

# remove single docker
docker stop athenz-zms-server; docker rm athenz-zms-server; rm -f ./logs/zms/*
docker stop athenz-zts-server; docker rm athenz-zts-server; rm -f ./logs/zts/*
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

# server status
curl -k -o - https://localhost:4443/zms/v1/status
curl -k -o - https://localhost:8443/zts/v1/status

# mysql
mysql -v -u root --host=127.0.0.1 --port=3306 --password=${ZMS_DB_ROOT_PASS} --database=zms_server -e 'show tables;'
mysql -v -u root --host=127.0.0.1 --port=3307 --password=${ZTS_DB_ROOT_PASS} --database=zts_store -e 'show tables;'

# keytool
openssl pkey -in ./zms/var/certs/zms_key.pem
openssl pkey -in ./zts/var/certs/zts_key.pem
openssl pkey -in ./ui/var/certs/ui_key.pem
keytool -list -keystore ./zms/var/certs/zms_keystore.pkcs12
keytool -list -keystore ./zts/var/certs/zts_keystore.pkcs12
keytool -list -keystore ./zms/var/certs/zms_truststore.jks
keytool -list -keystore ./zts/var/certs/zts_truststore.jks
```

<a id="markdown-wip-deploy-with-docker-stack" name="wip-deploy-with-docker-stack"></a>
### [WIP] Deploy with docker-stack
```bash
cd `git rev-parse --show-toplevel`/docker

# 1. set passwords (P.S. values in *.properties files will overwrite these values)
source ./setup-scripts/0.export-default-passwords.sh

# 2. generate key-pairs, certificates and keystore/truststore
make setup-dev-config

# 3. docker network variables
export DOCKER_NETWORK=${DOCKER_NETWORK:-athenz}
export ZMS_DB_HOST=${ZMS_DB_HOST:-athenz-zms-db}
export ZMS_DB_PORT=${ZMS_DB_PORT:-3306}
export ZMS_HOST=${ZMS_HOST:-athenz-zms-server}
export ZMS_PORT=${ZMS_PORT:-4443}
export ZTS_DB_HOST=${ZTS_DB_HOST:-athenz-zts-db}
export ZTS_DB_PORT=${ZTS_DB_PORT:-3307}
export ZTS_HOST=${ZTS_HOST:-athenz-zts-server}
export ZTS_PORT=${ZTS_PORT:-8443}
export UI_HOST=${UI_HOST:-athenz-ui-server}
export UI_PORT=${UI_PORT:-443}

# 4. start docker stack (some components will fail, don't panic)
mkdir -p ./logs/zms
mkdir -p ./logs/zts
docker stack deploy -c ./docker-stack.yaml athenz

# (optional) restart ZMS service if DB is not ready during start up
rm -f ./logs/zms/server.log
ZMS_SERVICE=`docker stack services -qf "name=athenz_zms-server" athenz`
docker service update --force $ZMS_SERVICE
docker ps -qa -f "label=com.docker.swarm.service.name=athenz_zms-server" -f status=exited | xargs docker rm -f

# 5.1. setup ZMS for ZTS
sh ./deploy-scripts/1.2.config-zms-domain-admin.dev.sh
sh ./deploy-scripts/2.1.register-ZTS-service.sh
sh ./deploy-scripts/2.2.create-athenz-conf.sh
# 5.2. restart ZTS service to apply the new setting
rm -f ./logs/zts/server.log
ZTS_SERVICE=`docker stack services -qf "name=athenz_zts-server" athenz`
docker service update --force $ZTS_SERVICE
docker ps -qa -f "label=com.docker.swarm.service.name=athenz_zts-server" -f status=exited | xargs docker rm -f

# 6.1. setup ZMS for UI
sh ./deploy-scripts/3.1.register-UI-service.sh
# 6.2. restart UI service to apply the new setting
UI_SERVICE=`docker stack services -qf "name=athenz_ui" athenz`
docker service update --force $UI_SERVICE
docker ps -qa -f "label=com.docker.swarm.service.name=athenz_ui" -f status=exited | xargs docker rm -f
```
```bash
# debug docker stack
docker stack ps athenz
less ./logs/zms/server.log
less ./logs/zts/server.log

# reset docker stack
docker stack rm athenz
rm -rf ./logs

# restart docker
sudo systemctl restart docker
```

<a id="markdown-todo" name="todo"></a>
### TODO

- [Athenz-bootstrap#todo](./docs/Athenz-bootstrap.md#todo)
-   UI
    1.  convert `default-config.js` parameters to ENV
    1.  `server.js`, `login.js`, `serviceFQN`; `keys` folder is hard coded
    1.  configurable listening port
-   ZMS
    1.  need server health check, e.g. readiness probe
-   ZPU
    1.  If volume not mount to `/home/athenz/tmp/zpe/`, will have error: `2019/06/12 06:34:09 Failed to get policies for domain: garm, Error:Unable to write Policies for domain:"garm" to file, Error:rename /home/athenz/tmp/zpe/garm.tmp /etc/acceptance-test/zpu/garm.pol: invalid cross-device link`
-   athenz-cli
    1.  build with separated docker files (add go.mod to support caching the dependency)
-   common
    1.  file permission for keys (`chmod`)
    1.  no curl in JAVA container, docker health check on ZMS and ZTS are not working


<a id="markdown-ui-section-backup" name="ui-section-backup"></a>
### UI Section (backup)

```bash
# 4.1 (optional) if you are running web browser and docker containers in the same host
export HOSTNAME=localhost
# 4.2. run Athenz
make run-docker-dev
```
- Note for UI
    - To ignore certificate warning from the browser,
        1. for ZMS server certificate,
            1. get ZMS URL by `echo https://${HOSTNAME}:${ZMS_PORT:-4443}/zms/v1/status`
            1. access ZMS using above URL in the browser
            1. ignore the browser warning (certificate authority invalid)
        1. for UI server certificate,
            1. get UI URL by `echo https://${HOSTNAME}:${UI_PORT:-443}/`
            1. access UI using above URL in the browser
            1. ignore the browser warning (certificate authority invalid)
        - Why do I need to explicitly ignore certificate warning from the browser for both ZMS and UI?
            - You need to connect to ZMS to get a user token during the login process of UI.
            - Since the certificates generated in DEV. deployment are all self-signed certificates, they are not trusted by the browser.
            - Also, they may not have the correct `${HOSTNAME}` in the SAN field depending on your DEV. deployment.
            - Hence, explicitly ignoring the browsers warning message is needed for both ZMS and UI.
    - UI login username/password
        - username: `admin` ([zms.properties](./zms/conf/zms.properties#L37-L41))
        - password: `replace_me_with_a_strong_password` ([deploy script](./deploy-scripts/1.2.config-zms-domain-admin.dev.sh#L12))
