#!/usr/bin/env bash

set -eu
set -o pipefail

# to script directory
cd "$(dirname "$0")"

# import functions
. ./common/color-print.sh

#################################################
### zts-setup.md
#################################################
### WARNING: this file is just from copy-and-paste. Always update the document first.

cat <<'EOF' | colored_cat c

#################################################
### zts-setup.md
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

echo '2. get a server certificate for ZTS' | colored_cat g
echo ${ZTS_CERT_KEY_PATH} | colored_cat y
echo ${ZTS_CERT_PATH} | colored_cat y

echo '3. create ZTS key pairs for signing Athenz token' | colored_cat g
openssl genrsa -out "${ZTS_PRIVATE_KEY_PATH}" 4096 2> /dev/null
openssl rsa -pubout -in "${ZTS_PRIVATE_KEY_PATH}" -out "${ZTS_PUBLIC_KEY_PATH}"

echo '4. create trust store containing all the trusted CAs' | colored_cat g
rm -f "${ZTS_TRUSTSTORE_PATH}"

CERT_ALIAS='athenz_ca'
openssl x509 -outform pem -in "${ATHENZ_CA_PATH}" | keytool -importcert -noprompt \
    -keystore "${ZTS_TRUSTSTORE_PATH}" -storepass "${ZTS_TRUSTSTORE_PASS}" \
    -storetype JKS -alias "${CERT_ALIAS}"

CERT_ALIAS='user_ca'
openssl x509 -outform pem -in "${USER_CA_PATH}" | keytool -importcert -noprompt \
    -keystore "${ZTS_TRUSTSTORE_PATH}" -storepass "${ZTS_TRUSTSTORE_PASS}" \
    -storetype JKS -alias "${CERT_ALIAS}"

CERT_ALIAS='service_ca'
openssl x509 -outform pem -in "${SERVICE_CA_PATH}" | keytool -importcert -noprompt \
    -keystore "${ZTS_TRUSTSTORE_PATH}" -storepass "${ZTS_TRUSTSTORE_PASS}" \
    -storetype JKS -alias "${CERT_ALIAS}"

echo '5. create key store containing the ZTS server certificate' | colored_cat g
openssl pkcs12 -export -noiter -nomaciter \
    -out "${ZTS_KEYSTORE_PATH}" -passout "pass:${ZTS_KEYSTORE_PASS}" \
    -in "${ZTS_CERT_PATH}" -inkey "${ZTS_CERT_KEY_PATH}"

echo '6. set up for certificate signing' | colored_cat g
echo 'We will just use KeyStoreCertSigner !!!' | colored_cat y
# create key store
openssl pkcs12 -export -noiter -nomaciter \
    -out "${ZTS_SIGNER_KEYSTORE_PATH}" -passout "pass:${ZTS_SIGNER_KEYSTORE_PASS}" \
    -in "${ZTS_SIGNER_CERT_PATH}" -inkey "${ZTS_SIGNER_CERT_KEY_PATH}"

# create trust store (only used by HttpCertSigner)
rm -f "${ZTS_SIGNER_TRUSTSTORE_PATH}"
CERT_ALIAS='athenz_ca'
openssl x509 -outform pem -in "${ATHENZ_CA_PATH}" | keytool -importcert -noprompt \
    -keystore "${ZTS_SIGNER_TRUSTSTORE_PATH}" -storepass "${ZTS_SIGNER_TRUSTSTORE_PASS}" \
    -storetype JKS -alias "${CERT_ALIAS}"

if [ "$(ls -A ${BASE_DIR}/docker/zts/conf/awscas)" ]; then
  for FILE in ${BASE_DIR}/docker/zts/conf/awscas/*
  do
    echo "Processing $FILE file..."
    keytool -importcert -noprompt -file "${FILE}" \
      -keystore "${ZTS_SIGNER_TRUSTSTORE_PATH}" -storepass "${ZTS_SIGNER_TRUSTSTORE_PASS}" \
      -storetype JKS -alias "${FILE}"
  done
fi

echo '7. set up for ZMS connection' | colored_cat g
# create key store
openssl pkcs12 -export -noiter -nomaciter \
    -out "${ZMS_CLIENT_KEYSTORE_PATH}" -passout "pass:${ZMS_CLIENT_KEYSTORE_PASS}" \
    -in "${ZMS_CLIENT_CERT_PATH}" -inkey "${ZMS_CLIENT_CERT_KEY_PATH}"

# create trust store for verifying the ZMS server certificate
rm -f "${ZMS_CLIENT_TRUSTSTORE_PATH}"
CERT_ALIAS='athenz_ca'
openssl x509 -outform pem -in "${ATHENZ_CA_PATH}" | keytool -importcert -noprompt \
    -keystore "${ZMS_CLIENT_TRUSTSTORE_PATH}" -storepass "${ZMS_CLIENT_TRUSTSTORE_PASS}" \
    -storetype JKS -alias "${CERT_ALIAS}"

echo '8. summary' | colored_cat g
tree "${CA_DIR}"
tree "${PROD_ZTS_DIR}"
tree "${ZTS_DIR}"

echo '9. register ZTS service to Athenz' | colored_cat g
# encode public key in ybase64, reference: https://github.com/AthenZ/athenz/blob/545d9487a866cad10ba864b435bdb7ece390d4bf/libs/java/auth_core/src/main/java/com/yahoo/athenz/auth/util/Crypto.java#L334-L343
ENCODED_ZTS_PUBLIC_KEY="$(base64 -w 0 "${ZTS_PUBLIC_KEY_PATH}" | tr '\+\=\/' '\.\-\_')"

DATA='{"name": "sys.auth.zts","publicKeys": [{"id": "0","key": "'"${ENCODED_ZTS_PUBLIC_KEY}"'"}]}'

# add ZTS service using ZMS API
ZMS_URL="https://${ZMS_HOST}:${ZMS_PORT}"
curl --silent --fail --show-error --request PUT \
    --cacert "${ATHENZ_CA_PATH}" \
    --key "${DOMAIN_ADMIN_CERT_KEY_PATH}" \
    --cert "${DOMAIN_ADMIN_CERT_PATH}" \
    --url "${ZMS_URL}/zms/v1/domain/sys.auth/service/zts" \
    --header 'content-type: application/json' \
    --data "${DATA}"
# verify
curl --silent --fail --show-error --request GET \
    --cacert "${ATHENZ_CA_PATH}" \
    --key "${DOMAIN_ADMIN_CERT_KEY_PATH}" \
    --cert "${DOMAIN_ADMIN_CERT_PATH}" \
    --url "${ZMS_URL}/zms/v1/domain/sys.auth/service/zts"; echo '';

echo '10. create athenz.conf' | colored_cat g
athenz-conf \
    -svc-key-file "${DOMAIN_ADMIN_CERT_KEY_PATH}" \
    -svc-cert-file "${DOMAIN_ADMIN_CERT_PATH}" \
    -c "${ATHENZ_CA_PATH}" \
    -z "https://${ZMS_HOST}:${ZMS_PORT}" \
    -t "https://${ZTS_HOST}:${ZTS_PORT}" \
    -o "${ZTS_CONF_DIR}/athenz.conf"

echo '11. setup provider domains'  | colored_cat g

# top level domain

DOMAIN_DATA='{"name":"athenz","description":"test domain for local","org":"myorg","ypmId":4455,"adminUsers":["user.athenz-admin"]}'

curl --silent --fail --show-error --request POST \
    --cacert "${ATHENZ_CA_PATH}" \
    --key "${DOMAIN_ADMIN_CERT_KEY_PATH}" \
    --cert "${DOMAIN_ADMIN_CERT_PATH}" \
    --url "${ZMS_URL}/zms/v1/domain" \
    --header 'content-type: application/json' \
    --data "${DOMAIN_DATA}"

# EC2
DOMAIN_DATA='{"name":"aws","parent":"athenz","adminUsers":["user.athenz-admin"]}'

curl --silent --fail --show-error --request POST \
    --cacert "${ATHENZ_CA_PATH}" \
    --key "${TEAM_ADMIN_CERT_KEY_PATH}" \
    --cert "${TEAM_ADMIN_CERT_PATH}" \
    --url "${ZMS_URL}/zms/v1/subdomain/athenz" \
    --header 'content-type: application/json' \
    --data "${DOMAIN_DATA}"

zms-cli -z "${ZMS_URL}/zms/v1" --key "${TEAM_ADMIN_CERT_KEY_PATH}" --cert "${TEAM_ADMIN_CERT_PATH}" -c "${ATHENZ_CA_PATH}" \
    -d athenz.aws add-service us-west-2

zms-cli -z "${ZMS_URL}/zms/v1" --key "${DOMAIN_ADMIN_CERT_KEY_PATH}" --cert "${DOMAIN_ADMIN_CERT_PATH}" -c "${ATHENZ_CA_PATH}" \
    -d athenz.aws set-service-endpoint us-west-2 class://com.yahoo.athenz.instance.provider.impl.InstanceAWSProvider

# ECS

DOMAIN_DATA='{"name":"aws-ecs","parent":"athenz","adminUsers":["user.athenz-admin"]}'

curl --silent --fail --show-error --request POST \
    --cacert "${ATHENZ_CA_PATH}" \
    --key "${TEAM_ADMIN_CERT_KEY_PATH}" \
    --cert "${TEAM_ADMIN_CERT_PATH}" \
    --url "${ZMS_URL}/zms/v1/subdomain/athenz" \
    --header 'content-type: application/json' \
    --data "${DOMAIN_DATA}"

zms-cli -z "${ZMS_URL}/zms/v1" --key "${TEAM_ADMIN_CERT_KEY_PATH}" --cert "${TEAM_ADMIN_CERT_PATH}" -c "${ATHENZ_CA_PATH}" \
    -d athenz.aws-ecs add-service us-west-2

zms-cli -z "${ZMS_URL}/zms/v1" --key "${DOMAIN_ADMIN_CERT_KEY_PATH}" --cert "${DOMAIN_ADMIN_CERT_PATH}" -c "${ATHENZ_CA_PATH}" \
    -d athenz.aws-ecs set-service-endpoint us-west-2 class://com.yahoo.athenz.instance.provider.impl.InstanceAWSECSProvider

#Lambda
DOMAIN_DATA='{"name":"aws-lambda","parent":"athenz","adminUsers":["user.athenz-admin"]}'

curl --silent --fail --show-error --request POST \
    --cacert "${ATHENZ_CA_PATH}" \
    --key "${TEAM_ADMIN_CERT_KEY_PATH}" \
    --cert "${TEAM_ADMIN_CERT_PATH}" \
    --url "${ZMS_URL}/zms/v1/subdomain/athenz" \
    --header 'content-type: application/json' \
    --data "${DOMAIN_DATA}"

zms-cli -z "${ZMS_URL}/zms/v1" --key "${TEAM_ADMIN_CERT_KEY_PATH}" --cert "${TEAM_ADMIN_CERT_PATH}" -c "${ATHENZ_CA_PATH}" \
    -d athenz.aws-lambda add-service us-west-2

zms-cli -z "${ZMS_URL}/zms/v1" --key "${DOMAIN_ADMIN_CERT_KEY_PATH}" --cert "${DOMAIN_ADMIN_CERT_PATH}" -c "${ATHENZ_CA_PATH}" \
    -d athenz.aws-lambda set-service-endpoint us-west-2 class://com.yahoo.athenz.instance.provider.impl.InstanceAWSLambdaProvider

echo '12. setup general providers role for all providers' | colored_cat g

zms-cli -z "${ZMS_URL}/zms/v1" --key "${DOMAIN_ADMIN_CERT_KEY_PATH}" --cert "${DOMAIN_ADMIN_CERT_PATH}" -c "${ATHENZ_CA_PATH}" \
    -d sys.auth add-regular-role providers sys.auth.zts athenz.aws.us-west-2 athenz.aws-ecs.us-west-2 athenz.aws-lambda.us-west-2

zms-cli -z "${ZMS_URL}/zms/v1" --key "${DOMAIN_ADMIN_CERT_KEY_PATH}" --cert "${DOMAIN_ADMIN_CERT_PATH}" -c "${ATHENZ_CA_PATH}" \
    -d sys.auth add-policy providers grant launch to providers on 'instance'


echo '13. setup ZTS as identity provider' | colored_cat g

zms-cli -z "${ZMS_URL}/zms/v1" --key "${DOMAIN_ADMIN_CERT_KEY_PATH}" --cert "${DOMAIN_ADMIN_CERT_PATH}" -c "${ATHENZ_CA_PATH}" \
    -d sys.auth add-regular-role provider.sys.auth.zts sys.auth.zts

zms-cli -z "${ZMS_URL}/zms/v1" --key "${DOMAIN_ADMIN_CERT_KEY_PATH}" --cert "${DOMAIN_ADMIN_CERT_PATH}" -c "${ATHENZ_CA_PATH}" \
    -d sys.auth add-policy provider.sys.auth.zts grant launch to provider.sys.auth.zts on 'dns.zts.athenz.cloud'

zms-cli -z "${ZMS_URL}/zms/v1" --key "${DOMAIN_ADMIN_CERT_KEY_PATH}" --cert "${DOMAIN_ADMIN_CERT_PATH}" -c "${ATHENZ_CA_PATH}" \
    -d sys.auth set-service-endpoint zts class://com.yahoo.athenz.instance.provider.impl.InstanceZTSProvider

echo '14. setup AWS identity provider' | colored_cat g

zms-cli -z "${ZMS_URL}/zms/v1" --key "${DOMAIN_ADMIN_CERT_KEY_PATH}" --cert "${DOMAIN_ADMIN_CERT_PATH}" -c "${ATHENZ_CA_PATH}" \
    -d sys.auth add-regular-role provider.athenz.aws.us-west-2 athenz.aws.us-west-2

zms-cli -z "${ZMS_URL}/zms/v1" --key "${DOMAIN_ADMIN_CERT_KEY_PATH}" --cert "${DOMAIN_ADMIN_CERT_PATH}" -c "${ATHENZ_CA_PATH}" \
    -d sys.auth add-policy provider.athenz.aws.us-west-2 grant launch to provider.athenz.aws.us-west-2 on 'dns.aws.athenz.cloud'

zms-cli -z "${ZMS_URL}/zms/v1" --key "${DOMAIN_ADMIN_CERT_KEY_PATH}" --cert "${DOMAIN_ADMIN_CERT_PATH}" -c "${ATHENZ_CA_PATH}" \
    -d sys.auth add-regular-role provider.athenz.aws-ecs.us-west-2 athenz.aws-ecs.us-west-2

zms-cli -z "${ZMS_URL}/zms/v1" --key "${DOMAIN_ADMIN_CERT_KEY_PATH}" --cert "${DOMAIN_ADMIN_CERT_PATH}" -c "${ATHENZ_CA_PATH}" \
    -d sys.auth add-policy provider.athenz.aws-ecs.us-west-2 grant launch to provider.athenz.aws-ecs.us-west-2 on 'dns.aws.athenz.cloud'

zms-cli -z "${ZMS_URL}/zms/v1" --key "${DOMAIN_ADMIN_CERT_KEY_PATH}" --cert "${DOMAIN_ADMIN_CERT_PATH}" -c "${ATHENZ_CA_PATH}" \
    -d sys.auth add-regular-role provider.athenz.aws-lambda.us-west-2 athenz.aws-lambda.us-west-2

zms-cli -z "${ZMS_URL}/zms/v1" --key "${DOMAIN_ADMIN_CERT_KEY_PATH}" --cert "${DOMAIN_ADMIN_CERT_PATH}" -c "${ATHENZ_CA_PATH}" \
    -d sys.auth add-policy provider.athenz.aws-lambda.us-west-2 grant launch to provider.athenz.aws-lambda.us-west-2 on 'dns.aws.athenz.cloud'
