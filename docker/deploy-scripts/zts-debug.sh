#!/usr/bin/env bash

set -eu
set -o pipefail
shopt -s expand_aliases

# to script directory
cd "$(dirname "$0")"

# import functions
. ../setup-scripts/common/color-print.sh

#################################################
### ZTS Debug
#################################################

cat <<'EOF' | colored_cat c

#################################################
### ZTS Debug
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
echo 'Debug ZTS' | colored_cat g
alias llm="less ${DOCKER_DIR}/logs/zms/server.log"
alias llt="less ${DOCKER_DIR}/logs/zts/server.log"
alias llmf="less -f ${DOCKER_DIR}/logs/zms/server.log"
alias lltf="less -f ${DOCKER_DIR}/logs/zts/server.log"
llt | tail | colored_cat w

# NOT necessary if inside docker network
# echo 'add ZTS host' | colored_cat y
# {
#     grep "${ZTS_HOST}" /etc/hosts && echo '/etc/hosts already set' || sudo sed -i "$ a\127.0.0.1 ${ZTS_HOST}" /etc/hosts
# } | colored_cat w

echo 'ZTS health check' | colored_cat y
{
    curl --silent --fail --show-error --cacert "${ATHENZ_CA_PATH}" "https://${ZTS_HOST}:${ZTS_PORT}/zts/v1/status"; echo '';
} | colored_cat w
