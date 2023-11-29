#!/usr/bin/env bash

set -eu
set -o pipefail

# to script directory
cd "$(dirname "$0")"

# import functions
. ../setup-scripts/common/color-print.sh

#################################################
### UI Deploy
#################################################

cat <<'EOF' | colored_cat c

#################################################
### UI Deploy
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
echo ''
echo '# Deploy UI' | colored_cat r

echo '1. create docker network' | colored_cat g
if ! docker network inspect "${DOCKER_NETWORK}" > /dev/null 2>&1; then
    docker network create --subnet "${DOCKER_NETWORK_SUBNET}" "${DOCKER_NETWORK}";
fi

echo '2. start UI' | colored_cat g
if [ ${ENABLE_LOCAL_BUILD_UI:-} ]; then
    EXTRA_ARGS="-v ${UI_ASSY_DIR}/src:/opt/athenz/ui/src"
fi
docker run -d -h "${UI_HOST}" \
    -p "${UI_PORT}:${UI_CONTAINER_PORT}" \
    --dns="${DOCKER_DNS}" \
    --network="${DOCKER_NETWORK}" \
    --user "$(id -u):$(id -g)" \
    -v "/tmp/:/.npm/" \
    -v "${DOCKER_DIR}/ui/var/keys:/opt/athenz/ui/keys" \
    -v "${DOCKER_DIR}/ui/conf:/opt/athenz/ui/conf/ui_server" \
    -v "${DOCKER_DIR}/logs/ui:/opt/athenz/ui/logs/ui_server" \
    -v "${DOCKER_DIR}/ui/conf/extended-config.js:/opt/athenz/ui/src/config/extended-config.js" \
    -e 'NODE_TLS_REJECT_UNAUTHORIZED=0' \
    -e "ZTS_LOGIN_URL=https://localhost:${ZTS_PORT}/zts/v1/" \
    -e "DEBUG=AthenzUI:*" \
    -e "PORT=${UI_CONTAINER_PORT}" \
    -e "UI_CONF_PATH=/opt/athenz/ui/conf/ui_server" \
    -e "ZMS_SERVER_URL=https://${ZMS_HOST}:${ZMS_PORT}/zms/v1/" \
    ${EXTRA_ARGS:-} \
    --name "${UI_HOST}" athenz/athenz-ui:latest
# wait for UI to be ready
until docker run --rm --entrypoint curl \
    --network="${DOCKER_NETWORK}" \
    --user "$(id -u):$(id -g)" \
    --name athenz-curl athenz/athenz-setup-env:latest \
    -k --silent --fail --show-error --output /dev/null "https://${UI_HOST}:${UI_CONTAINER_PORT}/status" \
    ; do
    echo 'UI is unavailable - will sleep 3s...'
    sleep 3
done

echo 'UI is up!' | colored_cat g
