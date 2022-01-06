#!/usr/bin/env bash

set -eu
set -o pipefail

# to script directory
cd "$(dirname "$0")"
echo 'running...'

### ----------------------------------------------------------------
# UI server certificate
# create CSR
CN='Sample Self Signed UI' SAN="${UI_HOST}" openssl req -nodes \
  -config "${SELF_SIGN_CNF_PATH}" \
  -reqexts v3_req -extensions usr_cert \
  -newkey rsa:4096 \
  -keyout "${DEV_UI_CERT_KEY_PATH}" \
  -out "${DEV_UI_CSR_PATH}" 2> /dev/null
# sign request
SAN="${UI_HOST}" openssl x509 -req -days 364 \
  -in "${DEV_UI_CSR_PATH}" \
  -CA "${DEV_ATHENZ_CA_PATH}" \
  -CAkey "${DEV_ATHENZ_CA_KEY_PATH}" \
  -CAcreateserial \
  -extfile "${SELF_SIGN_CNF_PATH}" -extensions usr_cert \
  -out "${DEV_UI_CERT_PATH}"

cat <<EOF

self-signed UI server certificate created.
  ca: ${DEV_ATHENZ_CA_PATH}
  key: ${DEV_UI_CERT_KEY_PATH}
  cert: ${DEV_UI_CERT_PATH}

EOF
