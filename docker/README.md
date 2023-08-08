# Athenz on Docker

<a id="markdown-index" name="index"></a>
## Index
<!-- TOC depthFrom:2 updateOnSave:true -->

- [Index](#index)
- [Prerequisites](#prerequisites)
- [Build Athenz](#build-athenz)
- [Deploy Athenz](#deploy-athenz)
- [Verify Athenz Deployment](#verify-athenz-deployment)
  - [JAVA Remote debugging](#java-remote-debugging)
- [Cleanup](#cleanup)
- [Appendix](#appendix)
  - [Important Files](#important-files)
  - [Default server ports](#default-server-ports)
  - [Useful Commands](#useful-commands)
  - [TODO](#todo)

<!-- /TOC -->

<a id="markdown-prerequisites" name="prerequisites"></a>
## Prerequisites

1. `git`
1. `docker`
1. `make`
1. `sh`

NOTE: Test are done on `CentOS-7` and `MacOS 10.14+` ONLY.

<a id="markdown-build-athenz" name="build-athenz"></a>
## Build Athenz

```bash
cd "$(git rev-parse --show-toplevel)/docker"

# it takes about 15-30 mins
make build

# P.S. the latest code may cause docker build to fail, please use older version by specifying the tag version (< v1.9.27) or post an issue
# make build TAG=v1.9.27
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

- production environment
  - [acceptance-test](./docs/acceptance-test.md)
- development environment
    ```bash
    make verify
    ```

<a id="markdown-java-remote-debugging" name="java-remote-debugging"></a>
### JAVA Remote debugging

```bash
### ZMS
ZMS_DEBUG_PORT=8001
export ZMS_JAVA_OPTS="-agentlib:jdwp=transport=dt_socket,server=y,suspend=n,address=${ZMS_DEBUG_PORT}"
# re-deploy ZMS, reference: ./deploy-scripts/zms-deploy.sh
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
# re-deploy ZTS, reference: ./deploy-scripts/zts-deploy.sh
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
# remove Athenz containers
make remove-containers

# remove server data
make remove-files

# remove bootstrap setup files
make reset-repo
```
```bash
# reset docker and repo
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

<a id="markdown-default-server-ports" name="default-server-ports"></a>
### Default server ports
- `3306->3306/tcp`: ZMS DB
  - [env.sh](./env.sh): `ZMS_DB_PORT`
  - related configuration:
    - [zms-db.cnf](./db/zms/zms-db.cnf): `mysqld.port`
    - [zms.properties](./zms/conf/zms.properties): `athenz.zms.jdbc_store`
- `4443->4443/tcp`: ZMS server
  - [env.sh](./env.sh): `ZMS_PORT`
  - related configuration:
    - [athenz.properties](./zms/conf/athenz.properties): `athenz.tls_port`
- `3307->3306/tcp`: ZTS DB
  - [env.sh](./env.sh): `ZTS_DB_PORT`
  - related configuration:
    - [zts-db.cnf](./db/zts/zts-db.cnf): `mysqld.port`
    - [zts.properties](./zts/conf/zts.properties): `athenz.zts.cert_jdbc_store`
- `8443->8443/tcp`: ZTS server
  - [env.sh](./env.sh): `ZTS_PORT`
  - related configuration:
    - [athenz.properties](./zts/conf/athenz.properties): `athenz.tls_port`

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
keytool -list -keystore ./zms/var/certs/zms_keystore.pkcs12
keytool -list -keystore ./zts/var/certs/zts_keystore.pkcs12
keytool -list -keystore ./zms/var/certs/zms_truststore.jks
keytool -list -keystore ./zts/var/certs/zts_truststore.jks
```

<a id="markdown-todo" name="todo"></a>
### TODO

- [Athenz-bootstrap#todo](./docs/Athenz-bootstrap.md#todo)
- UI
    1. convert `default-config.js` parameters to ENV
    1. add CA certificate settings for ZMS and ZTS server, so that `NODE_TLS_REJECT_UNAUTHORIZED=0` can be removed
    1. find a safe `serverCipherSuites` list for deploying locally
    1. show hint for using `user.github-7654321` to login when deploying locally
- ZMS
    1. need server health check, e.g. readiness probe
- ZPU
    1. If volume not mount to `/home/athenz/tmp/zpe/`, will have error: `2019/06/12 06:34:09 Failed to get policies for domain: garm, Error:Unable to write Policies for domain:"garm" to file, Error:rename /home/athenz/tmp/zpe/garm.tmp /etc/acceptance-test/zpu/garm.pol: invalid cross-device link`
- athenz-cli
    1. build with separated docker files (add go.mod to support caching the dependency)
- common
    1. file permission for keys (`chmod 600`?)
    1. support docker image version tag on `docker build` and `docker run` using ENV. `TAG`.
- `KeyStoreJwkKeyResolver`
    1. support setting CA certificate using system properties for `JwkProviderBuilder` to get JWK from Internet
