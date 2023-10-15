#!/usr/bin/env bash

set -eu
set -o pipefail
shopt -s expand_aliases

# to script directory
cd "$(dirname "$0")"

# import functions
. ../setup-scripts/common/color-print.sh

#################################################
### ZMS Debug
#################################################

cat <<'EOF' | colored_cat c

#################################################
### ZMS Debug
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
echo 'Debug ZMS' | colored_cat g
alias llm="less ${DOCKER_DIR}/logs/zms/server.log"
llm | tail | colored_cat w

# NOT necessary if inside docker network
# echo 'add ZMS host' | colored_cat y
# {
#     grep "${ZMS_HOST}" /etc/hosts && echo '/etc/hosts already set' || sudo sed -i "$ a\127.0.0.1 ${ZMS_HOST}" /etc/hosts
# } | colored_cat w

echo 'ZMS health check' | colored_cat y
{
    curl --silent --fail --show-error --cacert "${ATHENZ_CA_PATH}" "https://${ZMS_HOST}:${ZMS_PORT}/zms/v1/status"; echo '';
} | colored_cat w


echo 'get domains' | colored_cat y
{
    ZMS_URL="https://${ZMS_HOST}:${ZMS_PORT}"
    curl --silent --fail --show-error \
        --cacert "${ATHENZ_CA_PATH}" \
        --key "${DOMAIN_ADMIN_CERT_KEY_PATH}" \
        --cert "${DOMAIN_ADMIN_CERT_PATH}" \
        "${ZMS_URL}/zms/v1/domain"; echo '';
} | colored_cat w
