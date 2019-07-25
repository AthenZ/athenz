#!/bin/sh

# to script directory
cd "$(dirname "$0")"

# to ${PROJECT_ROOT}/docker
cd ../

# variables
DOCKER_NETWORK=${DOCKER_NETWORK:-athenz}
ZTS_DB_HOST=${ZTS_DB_HOST:-athenz-zts-db}
ZTS_DB_PORT=${ZTS_DB_PORT:-3307}
ZTS_HOST=${ZTS_HOST:-athenz-zts-server}
ZTS_PORT=${ZTS_PORT:-8443}

# check password
[[ -z "$ZTS_CERT_JDBC_PASSWORD" ]] && echo "ZTS_CERT_JDBC_PASSWORD not set" && exit 1

# start ZTS DB
printf "\nWill start ZTS DB...\n"
docker run -d -h ${ZTS_DB_HOST} \
  -p "${ZTS_DB_PORT}:${ZTS_DB_PORT}" \
  --network="${DOCKER_NETWORK}" \
  -v "`pwd`/db/zts/zts-db.cnf:/etc/mysql/conf.d/zts-db.cnf" \
  -e "MYSQL_ROOT_PASSWORD=${ZTS_CERT_JDBC_PASSWORD}" \
  --name athenz-zts-db athenz-zts-db

# wait for ZTS DB ready
docker run --rm \
  --network="${DOCKER_NETWORK}" \
  -v "`pwd`/db/zts/zts-db.cnf:/etc/my.cnf" \
  -e "MYSQL_PWD=${ZTS_CERT_JDBC_PASSWORD}" \
  --name wait-for-mysql wait-for-mysql "${ZTS_DB_HOST}"

# start ZTS
printf "\nWill start ZTS server...\n"
docker run -d -h ${ZTS_HOST} \
  -p "${ZTS_PORT}:${ZTS_PORT}" \
  --network="${DOCKER_NETWORK}" \
  -v "`pwd`/zts/var:/opt/athenz/zts/var" \
  -v "`pwd`/zts/conf:/opt/athenz/zts/conf/zts_server" \
  -v "`pwd`/logs/zts:/opt/athenz/zts/logs/zts_server" \
  -e "ZTS_CERT_JDBC_PASSWORD=${ZTS_CERT_JDBC_PASSWORD}" \
  -e "ZTS_SSL_KEYSTORE_PASS=${ZTS_SSL_KEYSTORE_PASS}" \
  -e "ZTS_SSL_TRUSTSTORE_PASS=${ZTS_SSL_TRUSTSTORE_PASS}" \
  -e "ZTS_ZTS_SSL_KEYSTORE_PASS=${ZTS_ZTS_SSL_KEYSTORE_PASS}" \
  -e "ZTS_ZTS_SSL_TRUSTSTORE_PASS=${ZTS_ZTS_SSL_TRUSTSTORE_PASS}" \
  --name athenz-zts-server athenz-zts-server

# wait for ZTS to be ready
printf "\nWill wait for ZTS to be ready...\n"
until docker run --rm --entrypoint curl \
  --network="${DOCKER_NETWORK}" \
  --name athenz-curl appropriate/curl \
  -k --silent --output /dev/null "https://${ZTS_HOST}:${ZTS_PORT}/zts/v1/status" \
  ; do
  echo 'ZTS is unavailable - will sleep 3s...'
  sleep 3
done
echo 'ZTS is up!'
