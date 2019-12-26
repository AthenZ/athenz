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
ZMS_DB_HOST=${ZMS_DB_HOST:-athenz-zms-db}
ZMS_DB_PORT=${ZMS_DB_PORT:-3306}
ZMS_HOST=${ZMS_HOST:-athenz-zms-server}
ZMS_PORT=${ZMS_PORT:-4443}

# check password
[ -z "$ZMS_DB_ROOT_PASS" ] && echo "ZMS_DB_ROOT_PASS not set" && exit 1
[ -z "$ZMS_DB_ADMIN_PASS" ] && echo "ZMS_DB_ADMIN_PASS not set" && exit 1

# create docker network if not exist
if ! docker network inspect "${DOCKER_NETWORK}" > /dev/null 2>&1; then
  docker network create --subnet "${DOCKER_NETWORK_SUBNET}" "${DOCKER_NETWORK}";
fi

# start ZMS DB
printf "\nWill start ZMS DB...\n"
docker run -d -h "${ZMS_DB_HOST}" \
  -p "${ZMS_DB_PORT}:3306" \
  --network="${DOCKER_NETWORK}" \
  --user mysql:mysql \
  -v "`pwd`/db/zms/zms-db.cnf:/etc/mysql/conf.d/zms-db.cnf" \
  -e "MYSQL_ROOT_PASSWORD=${ZMS_DB_ROOT_PASS}" \
  --name "${ZMS_DB_HOST}" athenz-zms-db

# wait for ZMS DB ready from outside
docker run --rm \
  --network="${DOCKER_NETWORK}" \
  --user mysql:mysql \
  -v "`pwd`/deploy-scripts/common/wait-for-mysql/wait-for-mysql.sh:/bin/wait-for-mysql.sh" \
  -v "`pwd`/db/zms/zms-db.cnf:/etc/my.cnf" \
  -e "MYSQL_PWD=${ZMS_DB_ROOT_PASS}" \
  --entrypoint '/bin/wait-for-mysql.sh' \
  --name wait-for-mysql athenz-zms-db \
  --user='root' \
  --host="${ZMS_DB_HOST}" \
  --port=3306

# add zms_admin
printf "\nWill add zms_admin user to DB and remove root user with wildcard host...\n"
docker exec --user mysql:mysql \
  "${ZMS_DB_HOST}" mysql \
  --database=zms_server \
  --user=root --password="${ZMS_DB_ROOT_PASS}" \
  --execute="CREATE USER 'zms_admin'@'${ZMS_HOST}.${DOCKER_NETWORK}' IDENTIFIED BY '${ZMS_DB_ADMIN_PASS}'; GRANT ALL PRIVILEGES ON zms_server.* TO 'zms_admin'@'${ZMS_HOST}.${DOCKER_NETWORK}'; FLUSH PRIVILEGES;"
docker exec --user mysql:mysql \
  "${ZMS_DB_HOST}" mysql \
  --database=mysql \
  --user=root --password="${ZMS_DB_ROOT_PASS}" \
  --execute="DELETE FROM user WHERE user = 'root' AND host = '%';"
docker exec --user mysql:mysql \
  "${ZMS_DB_HOST}" mysql \
  --database=mysql \
  --user=root --password="${ZMS_DB_ROOT_PASS}" \
  --execute="SELECT user, host FROM user;"

# start ZMS
printf "\nWill start ZMS server...\n"
docker run -d -h "${ZMS_HOST}" \
  -p "${ZMS_PORT}:${ZMS_PORT}" \
  --network="${DOCKER_NETWORK}" \
  --user "$(id -u):$(id -g)" \
  -v "`pwd`/zms/var:/opt/athenz/zms/var" \
  -v "`pwd`/zms/conf:/opt/athenz/zms/conf/zms_server" \
  -v "`pwd`/logs/zms:/opt/athenz/zms/logs/zms_server" \
  -v "`pwd`/jars:/usr/lib/jars" \
  -e "JAVA_OPTS=${ZMS_JAVA_OPTS}" \
  -e "ZMS_DB_ADMIN_PASS=${ZMS_DB_ADMIN_PASS}" \
  -e "ZMS_KEYSTORE_PASS=${ZMS_KEYSTORE_PASS}" \
  -e "ZMS_TRUSTSTORE_PASS=${ZMS_TRUSTSTORE_PASS}" \
  -e "ZMS_PORT=${ZMS_PORT}" \
  --name "${ZMS_HOST}" athenz-zms-server

# wait for ZMS to be ready
printf "\nWill wait for ZMS to be ready...\n"
until docker run --rm --entrypoint curl \
  --network="${DOCKER_NETWORK}" \
  --user "$(id -u):$(id -g)" \
  --name athenz-curl appropriate/curl \
  -k --silent --output /dev/null "https://${ZMS_HOST}:${ZMS_PORT}/zms/v1/status" \
  ; do
  echo 'ZMS is unavailable - will sleep 3s...'
  sleep 3
done
echo 'ZMS is up!'
