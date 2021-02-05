#!/bin/sh

# to setup-scripts directory
cd "$(dirname "$0")"

# import functions
. ../common/color-print.sh
. ../common/local-env-setup.sh


cat <<'EOF' | colored_cat c

#################################################
### sample service setup
#################################################

EOF

echo ''
echo 'create key pair to register as a service in ZMS' | colored_cat g
mkdir -p "${BASE_DIR}"/docker/sample/example-service
openssl genrsa -out "${BASE_DIR}"/docker/sample/example-service/athenz.example-service.key.pem 4096 2> /dev/null
openssl rsa -pubout -in "${BASE_DIR}"/docker/sample/example-service/athenz.example-service.key.pem -out "${BASE_DIR}"/docker/sample/example-service/athenz.example-service.pub.key

echo 'register the example service to Athenz' | colored_cat g
# encode public key in ybase64, reference: https://github.com/AthenZ/athenz/blob/545d9487a866cad10ba864b435bdb7ece390d4bf/libs/java/auth_core/src/main/java/com/yahoo/athenz/auth/util/Crypto.java#L334-L343
ENCODED_EXAMPLE_PUBLIC_KEY="$(base64 -w 0 "${BASE_DIR}"/docker/sample/example-service/athenz.example-service.pub.key | tr '\+\=\/' '\.\-\_')"

DATA='{"name": "athenz.example-service","publicKeys": [{"id": "0","key": "'"${ENCODED_EXAMPLE_PUBLIC_KEY}"'"}]}'

curl --silent --fail --show-error --request PUT \
    --cacert "${ATHENZ_CA_PATH}" \
    --key "${TEAM_ADMIN_CERT_KEY_PATH}" \
    --cert "${TEAM_ADMIN_CERT_PATH}" \
    --url "${ZMS_URL}/zms/v1/domain/athenz/service/example-service" \
    --header 'content-type: application/json' \
    --data "${DATA}"

echo 'Confirm the service in ZMS' | colored_cat g
curl --silent --fail --show-error --request GET \
    --cacert "${ATHENZ_CA_PATH}" \
    --key "${TEAM_ADMIN_CERT_KEY_PATH}" \
    --cert "${TEAM_ADMIN_CERT_PATH}" \
    --url "${ZMS_URL}/zms/v1/domain/athenz/service/example-service"; echo '';

echo 'Confirm the service in ZTS' | colored_cat g
echo 'Wait for ZTS to sync...' | colored_cat p
PUB_KEY_IN_ZTS=''
until [ "${ENCODED_EXAMPLE_PUBLIC_KEY}" == "${PUB_KEY_IN_ZTS}" ]
do
    admin_curl -X GET "${ZTS_URL}/zts/v1/domain/athenz/service/example-service"
    jq '.' response.json | colored_cat w
    PUB_KEY_IN_ZTS="$(jq -r '.publicKeys[]? | select(.id == "0") | .key' response.json)"
    echo 'waiting 5s...'
    sleep 5s
done
echo 'ZMS and ZTS sync-ed.' | colored_cat p