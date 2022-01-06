#!/usr/bin/env bash

set -eu
set -o pipefail

# to script directory
cd "$(dirname "$0")"
echo 'running...'

### ----------------------------------------------------------------
# ZTS server certificate
# create CSR
CN='Sample Self Signed ZTS' SAN="${ZTS_HOST}" IPSAN="${HOST_EXTERNAL_IP}" openssl req -nodes \
  -config "${SELF_SIGN_CNF_PATH}" \
  -reqexts v3_req -extensions usr_cert \
  -newkey rsa:4096 \
  -keyout "${DEV_ZTS_CERT_KEY_PATH}" \
  -out "${DEV_ZTS_CSR_PATH}" 2> /dev/null
# sign request
SAN="${ZTS_HOST}" IPSAN="${HOST_EXTERNAL_IP}" openssl x509 -req -days 364 \
  -in "${DEV_ZTS_CSR_PATH}" \
  -CA "${DEV_ATHENZ_CA_PATH}" \
  -CAkey "${DEV_ATHENZ_CA_KEY_PATH}" \
  -CAcreateserial \
  -extfile "${SELF_SIGN_CNF_PATH}" -extensions usr_cert \
  -out "${DEV_ZTS_CERT_PATH}"

### ----------------------------------------------------------------
# intermediate certificate for certificate signing
# create CSR
CN='Sample Self Signed Intermediate CA' openssl req -nodes \
  -config "${SELF_SIGN_CNF_PATH}" \
  -newkey rsa:4096 \
  -keyout "${DEV_ZTS_SIGNER_CERT_KEY_PATH}" \
  -out "${DEV_ZTS_SIGNER_CSR_PATH}" 2> /dev/null
# sign request using Athenz CA
openssl x509 -req -days 3650 \
  -in "${DEV_ZTS_SIGNER_CSR_PATH}" \
  -CA "${DEV_SERVICE_CA_PATH}" \
  -CAkey "${DEV_SERVICE_CA_KEY_PATH}" \
  -CAcreateserial \
  -extfile "${SELF_SIGN_CNF_PATH}" -extensions v3_ca \
  -out "${DEV_ZTS_SIGNER_CERT_PATH}"

### ----------------------------------------------------------------
# ZTS client certificate
# create CSR (make sure the CN == 'sys.auth.zts')
CN='sys.auth.zts' openssl req -nodes \
  -config "${SELF_SIGN_CNF_PATH}" \
  -newkey rsa:4096 \
  -keyout "${DEV_ZMS_CLIENT_CERT_KEY_PATH}" \
  -out "${DEV_ZMS_CLIENT_CSR_PATH}" 2> /dev/null
# sign request using the intermediate CA of certificate signer
openssl x509 -req -days 3650 \
  -in "${DEV_ZMS_CLIENT_CSR_PATH}" \
  -CA "${DEV_ZTS_SIGNER_CERT_PATH}" \
  -CAkey "${DEV_ZTS_SIGNER_CERT_KEY_PATH}" \
  -CAcreateserial \
  -extfile "${SELF_SIGN_CNF_PATH}" -extensions usr_cert \
  -out "${DEV_ZMS_CLIENT_CERT_PATH}"
# create certificate bundle with client certificate and intermediate certificate
cat "${DEV_ZMS_CLIENT_CERT_PATH}" "${DEV_ZTS_SIGNER_CERT_PATH}" > "${DEV_ZMS_CLIENT_CERT_BUNDLE_PATH}"

cat <<EOF

self-signed ZTS server certificate created.
  ca: ${DEV_ATHENZ_CA_PATH}
  key: ${DEV_ZTS_CERT_KEY_PATH}
  cert: ${DEV_ZTS_CERT_PATH}

self-signed Intermediate CA certificate created.
  ca: ${DEV_SERVICE_CA_PATH}
  key: ${DEV_ZTS_SIGNER_CERT_KEY_PATH}
  cert: ${DEV_ZTS_SIGNER_CERT_PATH}

self-signed ZTS client certificate created.
  ca: ${DEV_ZTS_SIGNER_CERT_PATH}
  key: ${DEV_ZMS_CLIENT_CERT_KEY_PATH}
  cert: ${DEV_ZMS_CLIENT_CERT_PATH}
  cert_bundle: ${DEV_ZMS_CLIENT_CERT_BUNDLE_PATH}

EOF
