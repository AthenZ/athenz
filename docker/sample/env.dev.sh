#!/usr/bin/env bash

set -u
set -o pipefail

# Base dirs
export SAMPLE_DIR="${DOCKER_DIR}/sample"

export SELF_SIGN_CNF_PATH="${SAMPLE_DIR}/self-sign.cnf"

### ----------------------------------------------------------------
### CAs
export DEV_CA_DIR="${SAMPLE_DIR}/CAs"
export DEV_ATHENZ_CA_KEY_PATH="${DEV_CA_DIR}/athenz_ca.pem"
export DEV_ATHENZ_CA_PATH="${DEV_CA_DIR}/athenz_ca.pem"
export DEV_USER_CA_KEY_PATH="${DEV_CA_DIR}/user_ca.pem"
export DEV_USER_CA_PATH="${DEV_CA_DIR}/user_ca.pem"
export DEV_SERVICE_CA_KEY_PATH="${DEV_CA_DIR}/service_ca.pem"
export DEV_SERVICE_CA_PATH="${DEV_CA_DIR}/service_ca.pem"
export DEV_ATHENZ_CA_DER_PATH="${DEV_CA_DIR}/athenz_ca.der"

### ----------------------------------------------------------------
### domain admin
export DEV_DOMAIN_ADMIN="${DEV_DOMAIN_ADMIN:-user.github-7654321}"
export DEV_DOMAIN_ADMIN_DIR="${SAMPLE_DIR}/domain-admin"
export DEV_DOMAIN_ADMIN_CERT_KEY_PATH="${DEV_DOMAIN_ADMIN_DIR}/domain_admin_key.pem"
export DEV_DOMAIN_ADMIN_CSR_PATH="${DEV_DOMAIN_ADMIN_DIR}/domain_admin_csr.pem"
export DEV_DOMAIN_ADMIN_CERT_PATH="${DEV_DOMAIN_ADMIN_DIR}/domain_admin_cert.pem"

### ----------------------------------------------------------------
### team admin
export DEV_TEAM_ADMIN="${DEV_TEAM_ADMIN:-user.athenz-admin}"
export DEV_TEAM_ADMIN_DIR="${SAMPLE_DIR}/domain-admin"
export DEV_TEAM_ADMIN_CERT_KEY_PATH="${DEV_TEAM_ADMIN_DIR}/team_admin_key.pem"
export DEV_TEAM_ADMIN_CSR_PATH="${DEV_TEAM_ADMIN_DIR}/team_admin_csr.pem"
export DEV_TEAM_ADMIN_CERT_PATH="${DEV_TEAM_ADMIN_DIR}/team_admin_cert.pem"

### ----------------------------------------------------------------
### ZMS
export DEV_ZMS_DIR="${SAMPLE_DIR}/zms"
export DEV_ZMS_CERT_KEY_PATH="${DEV_ZMS_DIR}/zms_key.pem"
export DEV_ZMS_CSR_PATH="${DEV_ZMS_DIR}/zms_csr.pem"
export DEV_ZMS_CERT_PATH="${DEV_ZMS_DIR}/zms_cert.pem"

### ----------------------------------------------------------------
### ZTS
export DEV_ZTS_DIR="${SAMPLE_DIR}/zts"
export DEV_ZTS_CERT_KEY_PATH="${DEV_ZTS_DIR}/zts_key.pem"
export DEV_ZTS_CSR_PATH="${DEV_ZTS_DIR}/zts_csr.pem"
export DEV_ZTS_CERT_PATH="${DEV_ZTS_DIR}/zts_cert.pem"
export DEV_ZTS_SIGNER_CERT_KEY_PATH="${DEV_ZTS_DIR}/zts_signer_key.pem"
export DEV_ZTS_SIGNER_CSR_PATH="${DEV_ZTS_DIR}/zts_signer_csr.pem"
export DEV_ZTS_SIGNER_CERT_PATH="${DEV_ZTS_DIR}/zts_signer_cert.pem"
export DEV_ZMS_CLIENT_CERT_KEY_PATH="${DEV_ZTS_DIR}/zms_client_key.pem"
export DEV_ZMS_CLIENT_CSR_PATH="${DEV_ZTS_DIR}/zms_client_csr.pem"
export DEV_ZMS_CLIENT_CERT_PATH="${DEV_ZTS_DIR}/zms_client_cert.pem"
export DEV_ZMS_CLIENT_CERT_BUNDLE_PATH="${DEV_ZTS_DIR}/zms_client_cert_bundle.pem"

### ----------------------------------------------------------------
### UI
export DEV_UI_DIR="${SAMPLE_DIR}/ui"
export DEV_UI_CERT_KEY_PATH="${DEV_UI_DIR}/ui_key.pem"
export DEV_UI_CSR_PATH="${DEV_UI_DIR}/ui_csr.pem"
export DEV_UI_CERT_PATH="${DEV_UI_DIR}/ui_cert.pem"