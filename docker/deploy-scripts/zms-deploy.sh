#!/usr/bin/env bash

set -eu
set -o pipefail

# to script directory
cd "$(dirname "$0")"

# import functions
. ../setup-scripts/common/color-print.sh

#################################################
### ZMS Deploy
#################################################

cat <<'EOF' | colored_cat c

#################################################
### ZMS Deploy
#################################################

EOF

# set up env.
BASE_DIR="$(git rev-parse --show-toplevel)"
. "${BASE_DIR}/docker/env.sh"
echo "Done loading ENV. from ${BASE_DIR}/docker/env.sh" | colored_cat p
if [ -f "${DOCKER_DIR}/setup-scripts/dev-env-exports.sh" ]; then
    . "${DOCKER_DIR}/setup-scripts/dev-env-exports.sh"
    echo 'NOTE: You are using the DEV settings in dev-env-exports.sh !!!' | colored_cat p
fi



### ----------------------------------------------------------------
# check password
[ -z "$ZMS_DB_ROOT_PASS" ] && echo '$ZMS_DB_ROOT_PASS not set' | colored_cat r && exit 1
[ -z "$ZMS_DB_ADMIN_PASS" ] && echo '$ZMS_DB_ADMIN_PASS not set' | colored_cat r && exit 1



### ----------------------------------------------------------------
echo ''
echo '# Deploy ZMS' | colored_cat r

echo '1. create docker network' | colored_cat g
if ! docker network inspect "${DOCKER_NETWORK}" > /dev/null 2>&1; then
    docker network create --subnet "${DOCKER_NETWORK_SUBNET}" "${DOCKER_NETWORK}";
fi

echo '2. start ZMS DB' | colored_cat g
docker run -d -h "${ZMS_DB_HOST}" \
    -p "${ZMS_DB_PORT}:3306" \
    --network="${DOCKER_NETWORK}" \
    --user mysql:mysql \
    -v "${DOCKER_DIR}/db/zms/zms-db.cnf:/etc/mysql/conf.d/zms-db.cnf" \
    -e "MYSQL_ROOT_PASSWORD=${ZMS_DB_ROOT_PASS}" \
    --name "${ZMS_DB_HOST}" athenz-zms-db
# wait for ZMS DB to be ready
docker run --rm \
    --network="${DOCKER_NETWORK}" \
    --user mysql:mysql \
    -v "${DOCKER_DIR}/deploy-scripts/common/wait-for-mysql/wait-for-mysql.sh:/bin/wait-for-mysql.sh" \
    -v "${DOCKER_DIR}/db/zms/zms-db.cnf:/etc/my.cnf" \
    -e "MYSQL_PWD=${ZMS_DB_ROOT_PASS}" \
    --entrypoint '/bin/wait-for-mysql.sh' \
    --name wait-for-mysql athenz-zms-db \
    --user='root' \
    --host="${ZMS_DB_HOST}" \
    --port=3306

echo '3. add zms_admin to ZMS DB' | colored_cat g
# also, remove root user with wildcard host
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

echo '4. start ZMS' | colored_cat g
docker run -d -h "${ZMS_HOST}" \
    -p "${ZMS_PORT}:${ZMS_PORT}" \
    --dns="${DOCKER_DNS}" \
    --network="${DOCKER_NETWORK}" \
    --user "$(id -u):$(id -g)" \
    -v "${DOCKER_DIR}/zms/var:/opt/athenz/zms/var" \
    -v "${DOCKER_DIR}/zms/conf:/opt/athenz/zms/conf/zms_server" \
    -v "${DOCKER_DIR}/logs/zms:/opt/athenz/zms/logs/zms_server" \
    -v "${DOCKER_DIR}/jars:/usr/lib/jars" \
    -e "JAVA_OPTS=${ZMS_JAVA_OPTS}" \
    -e "ZMS_DB_ADMIN_PASS=${ZMS_DB_ADMIN_PASS}" \
    -e "ZMS_RODB_ADMIN_PASS=${ZMS_RODB_ADMIN_PASS}" \
    -e "ZMS_KEYSTORE_PASS=${ZMS_KEYSTORE_PASS}" \
    -e "ZMS_TRUSTSTORE_PASS=${ZMS_TRUSTSTORE_PASS}" \
    -e "ZMS_PORT=${ZMS_PORT}" \
    --name "${ZMS_HOST}" athenz-zms-server
# wait for ZMS to be ready
until docker run --rm --entrypoint curl \
    --network="${DOCKER_NETWORK}" \
    --user "$(id -u):$(id -g)" \
    --name athenz-curl athenz-setup-env \
    -k --silent --fail --show-error --output /dev/null "https://${ZMS_HOST}:${ZMS_PORT}/zms/v1/status" \
    ; do
    echo 'ZMS is unavailable - will sleep 3s...'
    sleep 3
done

echo 'ZMS is up!' | colored_cat g
