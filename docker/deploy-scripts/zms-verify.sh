#!/usr/bin/env bash

set -eu
set -o pipefail

# to script directory
cd "$(dirname "$0")"

# import functions
. ../setup-scripts/common/color-print.sh

#################################################
### ZMS Verify
#################################################

cat <<'EOF' | colored_cat c

#################################################
### ZMS Verify
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
echo 'Verify ZMS' | colored_cat git
echo 'get ZTS service from ZMS' | colored_cat y
{
    curl --silent --fail --show-error \
        --cacert "${ATHENZ_CA_PATH}" \
        --key "${DOMAIN_ADMIN_CERT_KEY_PATH}" \
        --cert "${DOMAIN_ADMIN_CERT_PATH}" \
        "https://${ZMS_HOST}:${ZMS_PORT}/zms/v1/domain/sys.auth/service/zts"; echo '';
} | colored_cat w
