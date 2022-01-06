#!/usr/bin/env bash

set -eu
set -o pipefail

# to script directory
cd "$(dirname "$0")"

# import functions
. ../setup-scripts/common/color-print.sh

#################################################
### Acceptance Test Reset
#################################################

cat <<'EOF' | colored_cat c

#################################################
### Acceptance Test Reset
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
echo 'Reset test data' | colored_cat g
alias admin_curl="curl --cacert ${ATHENZ_CA_PATH} --key ${DOMAIN_ADMIN_CERT_KEY_PATH} --cert ${DOMAIN_ADMIN_CERT_PATH} --silent --show-error -D header.http -o response.json"

echo '1. delete policy' | colored_cat y
{
    admin_curl --request DELETE \
        --url "https://${ZMS_HOST}:${ZMS_PORT}/zms/v1/domain/testing/policy/test_policy" \
        --header 'content-type: application/json' \
        --data-binary '@body.json'
    cat header.http
    jq '.' response.json
} | colored_cat w
echo '2. delete role' | colored_cat y
{
    admin_curl --request DELETE \
        --url "https://${ZMS_HOST}:${ZMS_PORT}/zms/v1/domain/testing/role/test_role" \
        --header 'content-type: application/json' \
        --data-binary '@body.json'
    cat header.http
    jq '.' response.json
} | colored_cat w
echo '3. delete service' | colored_cat y
{
    admin_curl --request DELETE \
        --url "https://${ZMS_HOST}:${ZMS_PORT}/zms/v1/domain/testing/service/test_service" \
        --header 'content-type: application/json' \
        --data-binary '@body.json'
    cat header.http
    jq '.' response.json
} | colored_cat w
echo '4. delete domain' | colored_cat y
{
    admin_curl --request DELETE \
        --url "https://${ZMS_HOST}:${ZMS_PORT}/zms/v1/domain/testing" \
        --header 'content-type: application/json' \
        --data-binary '@body.json'
    cat header.http
    jq '.' response.json
} | colored_cat w
echo '5. confirm testing domain is deleted' | colored_cat y
{
    admin_curl --request GET \
        --url "https://${ZMS_HOST}:${ZMS_PORT}/zms/v1/domain"
    cat header.http
    jq '.' response.json
} | colored_cat w
