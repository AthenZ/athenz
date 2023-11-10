#!/usr/bin/env bash

set -eu
set -o pipefail

# to setup-scripts directory
cd "$(dirname "$0")"

# import functions
. ./common/color-print.sh

#################################################
### ui-setup.md
#################################################
### WARNING: this file is just from copy-and-paste. Always update the document first.

cat <<'EOF' | colored_cat c

#################################################
### ui-setup.md
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
echo '# Steps' | colored_cat r

echo '1. update your passwords' | colored_cat g
echo 'We will just use the default ʅ(´◔౪◔)ʃ' | colored_cat y

echo '2. get a server certificate for UI' | colored_cat g
echo ${UI_CERT_KEY_PATH} | colored_cat y
echo ${UI_CERT_PATH} | colored_cat y

echo '3. create UI key pair to register as authorized service in ZMS' | colored_cat g
openssl genrsa -out "${UI_PRIVATE_KEY_PATH}" 4096 2> /dev/null
openssl rsa -pubout -in "${UI_PRIVATE_KEY_PATH}" -out "${UI_PUBLIC_KEY_PATH}"

echo '4. summary' | colored_cat g
tree "${CA_DIR}"
tree "${PROD_UI_DIR}"
tree "${UI_DIR}"

echo '5. register UI service to Athenz' | colored_cat g
# encode public key in ybase64, reference: https://github.com/AthenZ/athenz/blob/545d9487a866cad10ba864b435bdb7ece390d4bf/libs/java/auth_core/src/main/java/com/yahoo/athenz/auth/util/Crypto.java#L334-L343
ENCODED_UI_PUBLIC_KEY="$(base64 -w 0 "${UI_PUBLIC_KEY_PATH}" | tr '\+\=\/' '\.\-\_')"

DATA='{"name": "athenz.ui-server","publicKeys": [{"id": "0","key": "'"${ENCODED_UI_PUBLIC_KEY}"'"}]}'

sed -i "s/github-<REPLACE>/$(echo ${DOMAIN_ADMIN} | cut -d'.' -f2-)/g" "${UI_CONF_DIR}/users_data.json"

# add UI service using ZMS API
ZMS_URL="https://${ZMS_HOST}:${ZMS_PORT}"

curl --silent --fail --show-error --request PUT \
    --cacert "${ATHENZ_CA_PATH}" \
    --key "${TEAM_ADMIN_CERT_KEY_PATH}" \
    --cert "${TEAM_ADMIN_CERT_PATH}" \
    --url "${ZMS_URL}/zms/v1/domain/athenz/service/ui-server" \
    --header 'content-type: application/json' \
    --data "${DATA}"
# verify
curl --silent --fail --show-error --request GET \
    --cacert "${ATHENZ_CA_PATH}" \
    --key "${TEAM_ADMIN_CERT_KEY_PATH}" \
    --cert "${TEAM_ADMIN_CERT_PATH}" \
    --url "${ZMS_URL}/zms/v1/domain/athenz/service/ui-server"; echo '';

echo '6. create athenz.conf' | colored_cat g
athenz-conf \
    -svc-key-file "${TEAM_ADMIN_CERT_KEY_PATH}" \
    -svc-cert-file "${TEAM_ADMIN_CERT_PATH}" \
    -c "${ATHENZ_CA_PATH}" \
    -z "https://${ZMS_HOST}:${ZMS_PORT}" \
    -t "https://${UI_HOST}:${UI_PORT}" \
    -o "${UI_CONF_DIR}/athenz.conf"

echo '7. generate cookie session secret file and copy files'
touch ${UI_SESSION_SECRET_PATH}
cp ${CA_DIR}/athenz_ca.srl ${UI_SESSION_SECRET_PATH}

cp ${UI_CERT_KEY_PATH} ${UI_KEYS_DIR}
cp ${UI_CERT_PATH} ${UI_KEYS_DIR}

ls ${UI_KEYS_DIR}

echo '8. all done'
