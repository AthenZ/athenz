#!/bin/sh

# to script directory
cd "$(dirname "$0")"

# to project root
cd ../..

# variables
DOCKER_NETWORK=${DOCKER_NETWORK:-host}

# check password
[[ -z "$ZTS_CERT_JDBC_PASSWORD" ]] && echo "ZTS_CERT_JDBC_PASSWORD not set" && exit 1

# start ZTS DB
printf "\nWill start ZTS DB...\n"
docker run -d -h localhost \
  --network="${DOCKER_NETWORK}" \
  -v "`pwd`/docker/db/zts/zts-db.cnf:/etc/mysql/conf.d/zts-db.cnf" \
  -e "MYSQL_ROOT_PASSWORD=${ZTS_CERT_JDBC_PASSWORD}" \
  --name athenz-zts-db athenz-zts-db

# wait for ZTS DB ready
ZTS_DB_CONTAINER=`docker ps -aqf "name=zts-db"`
ZTS_DB_IP=`docker inspect -f "{{ .NetworkSettings.Networks.${DOCKER_NETWORK}.IPAddress }}" ${ZTS_DB_CONTAINER}`
ZTS_DB_IP=${ZTS_DB_IP:-127.0.0.1}
docker run --rm -h localhost \
  --network="${DOCKER_NETWORK}" \
  -v "`pwd`/docker/db/zts/zts-db.cnf:/etc/my.cnf" \
  -e "MYSQL_PWD=${ZTS_CERT_JDBC_PASSWORD}" \
  --name wait-for-mysql wait-for-mysql "${ZTS_DB_IP}"

# start ZTS
printf "\nWill start ZTS server...\n"
docker run -d -h localhost \
  --network="${DOCKER_NETWORK}" \
  -v "`pwd`/docker/zts/var:/opt/athenz/zts/var" \
  -v "`pwd`/docker/zts/conf:/opt/athenz/zts/conf/zts_server" \
  -v "`pwd`/docker/logs/zts:/opt/athenz/zts/logs/zts_server" \
  -e "ZTS_CERT_JDBC_PASSWORD=${ZTS_CERT_JDBC_PASSWORD}" \
  -e "ZTS_SSL_KEYSTORE_PASS=${ZTS_SSL_KEYSTORE_PASS}" \
  -e "ZTS_SSL_TRUSTSTORE_PASS=${ZTS_SSL_TRUSTSTORE_PASS}" \
  -e "ZTS_ZTS_SSL_KEYSTORE_PASS=${ZTS_ZTS_SSL_KEYSTORE_PASS}" \
  -e "ZTS_ZTS_SSL_TRUSTSTORE_PASS=${ZTS_ZTS_SSL_TRUSTSTORE_PASS}" \
  --name athenz-zts-server athenz-zts-server

# TODO: wait for ZTS to be ready
printf "\nWill wait for ZTS to be ready...\n"
sleep 10
