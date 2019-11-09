#!/bin/sh

set -eu
set -o pipefail

# to script directory
cd "$(dirname "$0")"

# to ${PROJECT_ROOT}/docker
cd ../

# variables
DOCKER_NETWORK=${DOCKER_NETWORK:-athenz}
DOCKER_NETWORK_SUBNET="${DOCKER_NETWORK_SUBNET:-172.21.0.0/16}"
ZTS_DB_HOST=${ZTS_DB_HOST:-athenz-zts-db}
ZTS_DB_PORT=${ZTS_DB_PORT:-3307}
ZTS_HOST=${ZTS_HOST:-athenz-zts-server}
ZTS_PORT=${ZTS_PORT:-8443}

# check password
[ -z "$ZTS_DB_ROOT_PASS" ] && echo "ZTS_DB_ROOT_PASS not set" && exit 1
[ -z "$ZTS_DB_ADMIN_PASS" ] && echo "ZTS_DB_ADMIN_PASS not set" && exit 1

# create docker network if not exist
if ! docker network inspect "${DOCKER_NETWORK}" > /dev/null 2>&1; then
  docker network create --subnet "${DOCKER_NETWORK_SUBNET}" "${DOCKER_NETWORK}";
fi

# start ZTS DB
printf "\nWill start ZTS DB...\n"
docker run -d -h "${ZTS_DB_HOST}" \
  -p "${ZTS_DB_PORT}:${ZTS_DB_PORT}" \
  --network="${DOCKER_NETWORK}" \
  --user mysql:mysql \
  -v "`pwd`/db/zts/zts-db.cnf:/etc/mysql/conf.d/zts-db.cnf" \
  -e "MYSQL_ROOT_PASSWORD=${ZTS_DB_ROOT_PASS}" \
  --name "${ZTS_DB_HOST}" athenz-zts-db \
  --port="${ZTS_DB_PORT}"

# wait for ZTS DB ready from outside
docker run --rm \
  --network="${DOCKER_NETWORK}" \
  --user mysql:mysql \
  -v "`pwd`/deploy-scripts/common/wait-for-mysql/wait-for-mysql.sh:/bin/wait-for-mysql.sh" \
  -v "`pwd`/db/zts/zts-db.cnf:/etc/my.cnf" \
  -e "MYSQL_PWD=${ZTS_DB_ROOT_PASS}" \
  --entrypoint '/bin/wait-for-mysql.sh' \
  --name wait-for-mysql athenz-zts-db \
  --user='root' \
  --host="${ZTS_DB_HOST}" \
  --port="${ZTS_DB_PORT}"

# add zts_admin
printf "\nWill add zts_admin user to DB and remove root user with wildcard host...\n"
docker exec --user mysql:mysql \
  "${ZTS_DB_HOST}" mysql \
  --database=zts_store \
  --user=root --password="${ZTS_DB_ROOT_PASS}" \
  --execute="CREATE USER 'zts_admin'@'${ZTS_HOST}.${DOCKER_NETWORK}' IDENTIFIED BY '${ZTS_DB_ADMIN_PASS}'; GRANT ALL PRIVILEGES ON zts_store.* TO 'zts_admin'@'${ZTS_HOST}.${DOCKER_NETWORK}'; FLUSH PRIVILEGES;"
docker exec --user mysql:mysql \
  "${ZTS_DB_HOST}" mysql \
  --database=mysql \
  --user=root --password="${ZTS_DB_ROOT_PASS}" \
  --execute="DELETE FROM user WHERE user = 'root' AND host = '%';"
docker exec --user mysql:mysql \
  "${ZTS_DB_HOST}" mysql \
  --database=mysql \
  --user=root --password="${ZTS_DB_ROOT_PASS}" \
  --execute="SELECT user, host FROM user;"

# start ZTS
printf "\nWill start ZTS server...\n"
docker run -d -h "${ZTS_HOST}" \
  -p "${ZTS_PORT}:${ZTS_PORT}" \
  --network="${DOCKER_NETWORK}" \
  --user "$(id -u):$(id -g)" \
  -v "`pwd`/zts/var:/opt/athenz/zts/var" \
  -v "`pwd`/zts/conf:/opt/athenz/zts/conf/zts_server" \
  -v "`pwd`/logs/zts:/opt/athenz/zts/logs/zts_server" \
  -v "`pwd`/jars:/usr/lib/jars" \
  -e "JAVA_OPTS=${ZTS_JAVA_OPTS}" \
  -e "ZTS_DB_ADMIN_PASS=${ZTS_DB_ADMIN_PASS}" \
  -e "ZTS_KEYSTORE_PASS=${ZTS_KEYSTORE_PASS}" \
  -e "ZTS_TRUSTSTORE_PASS=${ZTS_TRUSTSTORE_PASS}" \
  -e "ZTS_SIGNER_KEYSTORE_PASS=${ZTS_SIGNER_KEYSTORE_PASS}" \
  -e "ZTS_SIGNER_TRUSTSTORE_PASS=${ZTS_SIGNER_TRUSTSTORE_PASS}" \
  -e "ZMS_CLIENT_KEYSTORE_PASS=${ZMS_CLIENT_KEYSTORE_PASS}" \
  -e "ZMS_CLIENT_TRUSTSTORE_PASS=${ZMS_CLIENT_TRUSTSTORE_PASS}" \
  --name "${ZTS_HOST}" athenz-zts-server

# wait for ZTS to be ready
printf "\nWill wait for ZTS to be ready...\n"
until docker run --rm --entrypoint curl \
  --network="${DOCKER_NETWORK}" \
  --user "$(id -u):$(id -g)" \
  --name athenz-curl appropriate/curl \
  -k --silent --output /dev/null "https://${ZTS_HOST}:${ZTS_PORT}/zts/v1/status" \
  ; do
  echo 'ZTS is unavailable - will sleep 3s...'
  sleep 3
done
echo 'ZTS is up!'
