#!/usr/bin/env bash

# to setup-scripts directory
cd "$(dirname "$0")"

# import functions
. ./common/color-print.sh

cat <<'EOF' | colored_cat c

#################################################
### sample identity setup
#################################################

EOF



### ----------------------------------------------------------------
echo ''
echo '# Steps' | colored_cat r

echo '1. create key pair to register as a service in ZMS' | colored_cat g
mkdir -p "${BASE_DIR}"/docker/sample/example-service
openssl genrsa -out "${BASE_DIR}"/docker/sample/example-service/athenz.example-service.key.pem 4096 2> /dev/null
openssl rsa -pubout -in "${BASE_DIR}"/docker/sample/example-service/athenz.example-service.key.pem -out "${BASE_DIR}"/docker/sample/example-service/athenz.example-service.pub.key

echo '2. register the example service to Athenz' | colored_cat g
# encode public key in ybase64, reference: https://github.com/yahoo/athenz/blob/545d9487a866cad10ba864b435bdb7ece390d4bf/libs/java/auth_core/src/main/java/com/yahoo/athenz/auth/util/Crypto.java#L334-L343
ENCODED_EXAMPLE_PUBLIC_KEY="$(base64 -w 0 "${BASE_DIR}"/docker/sample/example-service/athenz.example-service.pub.key | tr '\+\=\/' '\.\-\_')"

DATA='{"name": "athenz.example-service","publicKeys": [{"id": "0","key": "'"${ENCODED_EXAMPLE_PUBLIC_KEY}"'"}]}'
ZMS_URL="https://${ZMS_HOST}:${ZMS_PORT}"
ZTS_URL="https://${ZTS_HOST}:${ZTS_PORT}"
alias admin_curl="curl --cacert ${ATHENZ_CA_PATH} --key ${DOMAIN_ADMIN_CERT_KEY_PATH} --cert ${DOMAIN_ADMIN_CERT_PATH} --silent --show-error -D header.http -o response.json"

curl --silent --fail --show-error --request PUT \
    --cacert "${ATHENZ_CA_PATH}" \
    --key "${DOMAIN_ADMIN_CERT_KEY_PATH}" \
    --cert "${DOMAIN_ADMIN_CERT_PATH}" \
    --url "${ZMS_URL}/zms/v1/domain/athenz/service/example-service" \
    --header 'content-type: application/json' \
    --data "${DATA}"

echo '3. Confirm the service in ZMS' | colored_cat g
curl --silent --fail --show-error --request GET \
    --cacert "${ATHENZ_CA_PATH}" \
    --key "${DOMAIN_ADMIN_CERT_KEY_PATH}" \
    --cert "${DOMAIN_ADMIN_CERT_PATH}" \
    --url "${ZMS_URL}/zms/v1/domain/athenz/service/example-service"; echo '';

echo '4. Confirm the service in ZTS' | colored_cat g
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

echo '5. Setting up ZTS as provider'

zms-cli -z "${ZMS_URL}/zms/v1" --key "${DOMAIN_ADMIN_CERT_KEY_PATH}" --cert "${DOMAIN_ADMIN_CERT_PATH}" -c "${ATHENZ_CA_PATH}" \
    -d sys.auth add-regular-role providers sys.auth.zts

zms-cli -z "${ZMS_URL}/zms/v1" --key "${DOMAIN_ADMIN_CERT_KEY_PATH}" --cert "${DOMAIN_ADMIN_CERT_PATH}" -c "${ATHENZ_CA_PATH}" \
    -d sys.auth add-policy providers grant launch to providers on 'instance'

zms-cli -z "${ZMS_URL}/zms/v1" --key "${DOMAIN_ADMIN_CERT_KEY_PATH}" --cert "${DOMAIN_ADMIN_CERT_PATH}" -c "${ATHENZ_CA_PATH}" \
    -d sys.auth add-regular-role provider.sys.auth.zts sys.auth.zts

zms-cli -z "${ZMS_URL}/zms/v1" --key "${DOMAIN_ADMIN_CERT_KEY_PATH}" --cert "${DOMAIN_ADMIN_CERT_PATH}" -c "${ATHENZ_CA_PATH}" \
    -d sys.auth add-policy provider.sys.auth.zts grant launch to provider.sys.auth.zts on 'dns.zts.athenz.cloud'

zms-cli -z "${ZMS_URL}/zms/v1" --key "${DOMAIN_ADMIN_CERT_KEY_PATH}" --cert "${DOMAIN_ADMIN_CERT_PATH}" -c "${ATHENZ_CA_PATH}" \
    -d sys.auth set-service-endpoint zts class://com.yahoo.athenz.instance.provider.impl.InstanceZTSProvider

echo '5. Allowing ZTS provider to launch example-service'
zms-cli -z "${ZMS_URL}/zms/v1" --key "${DOMAIN_ADMIN_CERT_KEY_PATH}" --cert "${DOMAIN_ADMIN_CERT_PATH}" -c "${ATHENZ_CA_PATH}" \
    -d athenz set-domain-template zts_instance_launch_provider service=example-service

echo '6. Get identity certificate for example-service from ZTS using ZTS as a provider' | colored_cat g

until test -e "${BASE_DIR}/docker/sample/example-service/athenz.example-service.cert.pem" ;
do
  zts-svccert -domain athenz -service example-service \
      -private-key "${BASE_DIR}"/docker/sample/example-service/athenz.example-service.key.pem -key-version 0 -zts "${ZTS_URL}"/zts/v1 \
      -dns-domain zts.athenz.cloud -cert-file "${BASE_DIR}"/docker/sample/example-service/athenz.example-service.cert.pem \
      -cacert "${ATHENZ_CA_PATH}" -provider sys.auth.zts -instance instance123
  echo "waiting for 30s for ZTS to get provider authorization" | colored_cat y
  sleep 30
done

echo '7. verify cert CN'
openssl x509 -in "${BASE_DIR}"/docker/sample/example-service/athenz.example-service.cert.pem -noout -subject

echo ''