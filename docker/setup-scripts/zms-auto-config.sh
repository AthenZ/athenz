#!/usr/bin/env bash

set -eu
set -o pipefail

# to script directory
cd "$(dirname "$0")"

# import functions
. ./common/color-print.sh

#################################################
### zms-setup.md
#################################################
### WARNING: this file is just from copy-and-paste. Always update the document first.

cat <<'EOF' | colored_cat c

#################################################
### zms-setup.md
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

echo '2. get a server certificate for ZMS' | colored_cat g
echo "${ZMS_CERT_KEY_PATH}" | colored_cat y
echo "${ZMS_CERT_PATH}" | colored_cat y

echo '3. create ZMS key pairs for signing Athenz token' | colored_cat g
openssl genrsa -out "${ZMS_PRIVATE_KEY_PATH}" 4096 2> /dev/null
openssl rsa -pubout -in "${ZMS_PRIVATE_KEY_PATH}" -out "${ZMS_PUBLIC_KEY_PATH}"

echo '4. create ZMS trust store for HTTPS connections' | colored_cat g
rm -f "${ZMS_TRUSTSTORE_PATH}"

CERT_ALIAS='athenz_ca'
openssl x509 -outform pem -in "${ATHENZ_CA_PATH}" | keytool -importcert -noprompt \
    -keystore "${ZMS_TRUSTSTORE_PATH}" -storepass "${ZMS_TRUSTSTORE_PASS}" \
    -storetype JKS -alias "${CERT_ALIAS}"

CERT_ALIAS='user_ca'
openssl x509 -outform pem -in "${USER_CA_PATH}" | keytool -importcert -noprompt \
    -keystore "${ZMS_TRUSTSTORE_PATH}" -storepass "${ZMS_TRUSTSTORE_PASS}" \
    -storetype JKS -alias "${CERT_ALIAS}"

CERT_ALIAS='service_ca'
openssl x509 -outform pem -in "${SERVICE_CA_PATH}" | keytool -importcert -noprompt \
    -keystore "${ZMS_TRUSTSTORE_PATH}" -storepass "${ZMS_TRUSTSTORE_PASS}" \
    -storetype JKS -alias "${CERT_ALIAS}"

echo '5. create ZMS key store with ZMS server certificate' | colored_cat g
openssl pkcs12 -export -noiter -nomaciter \
    -out "${ZMS_KEYSTORE_PATH}" -passout "pass:${ZMS_KEYSTORE_PASS}" \
    -in "${ZMS_CERT_PATH}" -inkey "${ZMS_CERT_KEY_PATH}"

echo '6. config the Athenz domain admin' | colored_cat g
echo "your setting: DOMAIN_ADMIN=${DOMAIN_ADMIN}" | colored_cat y
sed -i "s/user\.github-.*$/${DOMAIN_ADMIN}/g" "${ZMS_CONF_DIR}/zms.properties"

echo '7. configure the necessary user authorities to work in local / test environment.' | colored_cat g
sed -i "s/athenz\.zms\.authority_classes=/athenz\.zms\.authority_classes=com\.yahoo\.athenz\.auth\.impl\.PrincipalAuthority,com\.yahoo\.athenz\.auth\.impl\.TestUserAuthority,/g" "${ZMS_CONF_DIR}/zms.properties"
sed -i "s/athenz\.zms\.user_authority_class=/athenz\.zms\.user_authority_class=com\.yahoo\.athenz\.auth\.impl\.TestUserAuthority/g" "${ZMS_CONF_DIR}/zms.properties"

echo '8. summary' | colored_cat g
tree "${CA_DIR}"
tree "${PROD_ZMS_DIR}"
tree "${ZMS_DIR}"


### ----------------------------------------------------------------
echo ''
echo '# Get Athenz domain admin user certificate for accessing ZMS' | colored_cat r
echo "${DOMAIN_ADMIN_CERT_KEY_PATH}" | colored_cat y
echo "${DOMAIN_ADMIN_CERT_PATH}" | colored_cat y
