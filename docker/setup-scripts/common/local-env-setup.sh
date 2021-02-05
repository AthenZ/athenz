#!/bin/sh

# set up env.
BASE_DIR="$(git rev-parse --show-toplevel)"
. "${BASE_DIR}/docker/env.sh"
echo "Done loading ENV. from ${BASE_DIR}/docker/env.sh" | colored_cat p
if [ -f "${DOCKER_DIR}/setup-scripts/dev-env-exports.sh" ]; then
    . "${DOCKER_DIR}/setup-scripts/dev-env-exports.sh"
    echo 'NOTE: You are using the DEV settings in dev-env-exports.sh !!!' | colored_cat p
fi

ZMS_URL="https://${ZMS_HOST}:${ZMS_PORT}"
ZTS_URL="https://${ZTS_HOST}:${ZTS_PORT}"
alias admin_curl="curl --cacert ${ATHENZ_CA_PATH} --key ${DOMAIN_ADMIN_CERT_KEY_PATH} --cert ${DOMAIN_ADMIN_CERT_PATH} --silent --show-error -D header.http -o response.json"