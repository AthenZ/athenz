#!/bin/sh

# to script directory
cd "$(dirname "$0")"

# to ${PROJECT_ROOT}/docker
cd ../

# variables
DOCKER_NETWORK=${DOCKER_NETWORK:-athenz}
ZMS_DB_HOST=${ZMS_DB_HOST:-athenz-zms-db}
ZMS_DB_PORT=${ZMS_DB_PORT:-3306}
ZMS_HOST=${ZMS_HOST:-athenz-zms-server}
ZMS_PORT=${ZMS_PORT:-4443}

# check password
[[ -z "$ZMS_JDBC_PASSWORD" ]] && echo "ZMS_JDBC_PASSWORD not set" && exit 1

# start ZMS DB
printf "\nWill start ZMS DB...\n"
docker run -d -h ${ZMS_DB_HOST} \
  -p "${ZMS_DB_PORT}:${ZMS_DB_PORT}" \
  --network="${DOCKER_NETWORK}" \
  -v "`pwd`/db/zms/zms-db.cnf:/etc/mysql/conf.d/zms-db.cnf" \
  -e "MYSQL_ROOT_PASSWORD=${ZMS_JDBC_PASSWORD}" \
  --name athenz-zms-db athenz-zms-db

# wait for ZMS DB ready
docker run --rm \
  --network="${DOCKER_NETWORK}" \
  -v "`pwd`/db/zms/zms-db.cnf:/etc/my.cnf" \
  -e "MYSQL_PWD=${ZMS_JDBC_PASSWORD}" \
  --name wait-for-mysql wait-for-mysql "${ZMS_DB_HOST}"

# start ZMS
printf "\nWill start ZMS server...\n"
docker run -d -h ${ZMS_HOST} \
  -p "${ZMS_PORT}:${ZMS_PORT}" \
  --network="${DOCKER_NETWORK}" \
  -v "`pwd`/zms/var:/opt/athenz/zms/var" \
  -v "`pwd`/zms/conf:/opt/athenz/zms/conf/zms_server" \
  -v "`pwd`/logs/zms:/opt/athenz/zms/logs/zms_server" \
  -e "ZMS_JDBC_PASSWORD=${ZMS_JDBC_PASSWORD}" \
  -e "ZMS_SSL_KEYSTORE_PASS=${ZMS_SSL_KEYSTORE_PASS}" \
  -e "ZMS_SSL_TRUSTSTORE_PASS=${ZMS_SSL_TRUSTSTORE_PASS}" \
  --name athenz-zms-server athenz-zms-server

# wait for ZMS to be ready
printf "\nWill wait for ZMS to be ready...\n"
until docker run --rm --entrypoint curl \
  --network="${DOCKER_NETWORK}" \
  --name athenz-curl appropriate/curl \
  -k --silent --output /dev/null "https://${ZMS_HOST}:${ZMS_PORT}/zms/v1/status" \
  ; do
  echo 'ZMS is unavailable - will sleep 3s...'
  sleep 3
done
echo 'ZMS is up!'
