#!/usr/bin/env bash

set -eu
set -o pipefail

# to script directory
cd "$(dirname "$0")"

# import functions
. ../setup-scripts/common/color-print.sh

#################################################
### ZTS Deploy
#################################################

cat <<'EOF' | colored_cat c

#################################################
### ZTS Deploy
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
[ -z "$ZTS_DB_ROOT_PASS" ] && echo '$ZTS_DB_ROOT_PASS not set' | colored_cat r && exit 1
[ -z "$ZTS_DB_ADMIN_PASS" ] && echo '$ZTS_DB_ADMIN_PASS not set' | colored_cat r && exit 1



### ----------------------------------------------------------------
echo ''
echo '# Deploy ZTS' | colored_cat r

echo '1. create docker network' | colored_cat g
if ! docker network inspect "${DOCKER_NETWORK}" > /dev/null 2>&1; then
    docker network create --subnet "${DOCKER_NETWORK_SUBNET}" "${DOCKER_NETWORK}";
fi

echo '2. start ZTS DB' | colored_cat g
docker run -d -h "${ZTS_DB_HOST}" \
    -p "${ZTS_DB_PORT}:3306" \
    --network="${DOCKER_NETWORK}" \
    --user mysql:mysql \
    -v "${DOCKER_DIR}/db/zts/zts-db.cnf:/etc/mysql/conf.d/zts-db.cnf" \
    -e "MYSQL_ROOT_PASSWORD=${ZTS_DB_ROOT_PASS}" \
    --name "${ZTS_DB_HOST}" athenz-zts-db
# wait for ZTS DB to be ready
docker run --rm \
    --network="${DOCKER_NETWORK}" \
    --user mysql:mysql \
    -v "${DOCKER_DIR}/deploy-scripts/common/wait-for-mysql/wait-for-mysql.sh:/bin/wait-for-mysql.sh" \
    -v "${DOCKER_DIR}/db/zts/zts-db.cnf:/etc/my.cnf" \
    -e "MYSQL_PWD=${ZTS_DB_ROOT_PASS}" \
    --entrypoint '/bin/wait-for-mysql.sh' \
    --name wait-for-mysql athenz-zts-db \
    --user='root' \
    --host="${ZTS_DB_HOST}" \
    --port=3306

echo '3. add zts_admin to ZTS DB' | colored_cat g
# also, remove root user with wildcard host
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

echo '4. start ZTS' | colored_cat g
docker run -d -h "${ZTS_HOST}" \
    -p "${ZTS_PORT}:${ZTS_PORT}" \
    --dns="${DOCKER_DNS}" \
    --network="${DOCKER_NETWORK}" \
    --user "$(id -u):$(id -g)" \
    -v "${DOCKER_DIR}/zts/var:/opt/athenz/zts/var" \
    -v "${DOCKER_DIR}/zts/conf:/opt/athenz/zts/conf/zts_server" \
    -v "${DOCKER_DIR}/logs/zts:/opt/athenz/zts/logs/zts_server" \
    -v "${DOCKER_DIR}/jars:/usr/lib/jars" \
    -e "JAVA_OPTS=${ZTS_JAVA_OPTS}" \
    -e "ZTS_DB_ADMIN_PASS=${ZTS_DB_ADMIN_PASS}" \
    -e "ZTS_KEYSTORE_PASS=${ZTS_KEYSTORE_PASS}" \
    -e "ZTS_TRUSTSTORE_PASS=${ZTS_TRUSTSTORE_PASS}" \
    -e "ZTS_SIGNER_KEYSTORE_PASS=${ZTS_SIGNER_KEYSTORE_PASS}" \
    -e "ZTS_SIGNER_TRUSTSTORE_PASS=${ZTS_SIGNER_TRUSTSTORE_PASS}" \
    -e "ZMS_CLIENT_KEYSTORE_PASS=${ZMS_CLIENT_KEYSTORE_PASS}" \
    -e "ZMS_CLIENT_TRUSTSTORE_PASS=${ZMS_CLIENT_TRUSTSTORE_PASS}" \
    -e "ZTS_PORT=${ZTS_PORT}" \
    --name "${ZTS_HOST}" athenz-zts-server
# wait for ZTS to be ready
until docker run --rm --entrypoint curl \
    --network="${DOCKER_NETWORK}" \
    --user "$(id -u):$(id -g)" \
    --name athenz-curl athenz-setup-env \
    -k --silent --fail --show-error --output /dev/null "https://${ZTS_HOST}:${ZTS_PORT}/zts/v1/status" \
    ; do
    echo 'ZTS is unavailable - will sleep 3s...'
    sleep 3
done

echo 'ZTS is up!' | colored_cat g
