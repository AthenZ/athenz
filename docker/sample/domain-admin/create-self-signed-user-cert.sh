#!/usr/bin/env bash

set -eu
set -o pipefail

# to script directory
cd "$(dirname "$0")"
echo 'running...'

# create CSR
CN="${DEV_DOMAIN_ADMIN}" openssl req -nodes \
  -config "${SELF_SIGN_CNF_PATH}" \
  -newkey rsa:4096 \
  -keyout "${DEV_DOMAIN_ADMIN_CERT_KEY_PATH}" \
  -out "${DEV_DOMAIN_ADMIN_CSR_PATH}" 2> /dev/null
# sign request
openssl x509 -req -days 30 \
  -in "${DEV_DOMAIN_ADMIN_CSR_PATH}" \
  -CA "${DEV_USER_CA_PATH}" \
  -CAkey "${DEV_USER_CA_KEY_PATH}" \
  -CAcreateserial \
  -extfile "${SELF_SIGN_CNF_PATH}" -extensions usr_cert \
  -out "${DEV_DOMAIN_ADMIN_CERT_PATH}"

cat <<EOF

self-signed Athenz domain admin user certificate created.
  ca: ${DEV_USER_CA_PATH}
  key: ${DEV_DOMAIN_ADMIN_CERT_KEY_PATH}
  cert: ${DEV_DOMAIN_ADMIN_CERT_PATH}

EOF

# create team-admin CSR
CN="${DEV_TEAM_ADMIN}" openssl req -nodes \
  -config "${SELF_SIGN_CNF_PATH}" \
  -newkey rsa:4096 \
  -keyout "${DEV_TEAM_ADMIN_CERT_KEY_PATH}" \
  -out "${DEV_TEAM_ADMIN_CSR_PATH}" 2> /dev/null
# sign request
openssl x509 -req -days 30 \
  -in "${DEV_TEAM_ADMIN_CSR_PATH}" \
  -CA "${DEV_USER_CA_PATH}" \
  -CAkey "${DEV_USER_CA_KEY_PATH}" \
  -CAcreateserial \
  -extfile "${SELF_SIGN_CNF_PATH}" -extensions usr_cert \
  -out "${DEV_TEAM_ADMIN_CERT_PATH}"

cat <<EOF

self-signed team admin user certificate created.
  ca: ${DEV_USER_CA_PATH}
  key: ${DEV_TEAM_ADMIN_CERT_KEY_PATH}
  cert: ${DEV_TEAM_ADMIN_CERT_PATH}

EOF
