#!/usr/bin/env bash

set -eu
set -o pipefail

# to script directory
cd "$(dirname "$0")"

# import functions
. ../setup-scripts/common/color-print.sh

#################################################
### ZTS Verify
#################################################

cat <<'EOF' | colored_cat c

#################################################
### ZTS Verify
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
echo 'Verify ZTS' | colored_cat g
echo 'get ZTS service from ZTS' | colored_cat y
{
    curl --silent --fail --show-error \
        --cacert "${ATHENZ_CA_PATH}" \
        --key "${DOMAIN_ADMIN_CERT_KEY_PATH}" \
        --cert "${DOMAIN_ADMIN_CERT_PATH}" \
        "https://${ZTS_HOST}:${ZTS_PORT}/zts/v1/domain/sys.auth/service/zts"; echo '';
} | colored_cat w
