#!/usr/bin/env bash

set -eu
set -o pipefail

# to script directory
cd "$(dirname "$0")"
echo 'running...'

# create CSR
CN='Sample Self Signed ZMS' SAN="${ZMS_HOST}" IPSAN="${HOST_EXTERNAL_IP}" openssl req -nodes \
  -config "${SELF_SIGN_CNF_PATH}" \
  -reqexts v3_req -extensions usr_cert \
  -newkey rsa:4096 \
  -keyout "${DEV_ZMS_CERT_KEY_PATH}" \
  -out "${DEV_ZMS_CSR_PATH}" 2> /dev/null
# sign request
SAN="${ZMS_HOST}" IPSAN="${HOST_EXTERNAL_IP}" openssl x509 -req -days 364 \
  -in "${DEV_ZMS_CSR_PATH}" \
  -CA "${DEV_ATHENZ_CA_PATH}" \
  -CAkey "${DEV_ATHENZ_CA_KEY_PATH}" \
  -CAcreateserial \
  -extfile "${SELF_SIGN_CNF_PATH}" -extensions usr_cert \
  -out "${DEV_ZMS_CERT_PATH}"

cat <<EOF

self-signed ZMS server certificate created.
  ca: ${DEV_ATHENZ_CA_PATH}
  key: ${DEV_ZMS_CERT_KEY_PATH}
  cert: ${DEV_ZMS_CERT_PATH}

EOF
