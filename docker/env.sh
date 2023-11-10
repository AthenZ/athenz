#!/usr/bin/env bash

set -u
set -o pipefail

export ATHENZ_TAG=$(sed -n -e 's|<version>\(.*SNAPSHOT\)</version>|\1|p' ${BASE_DIR}/pom.xml | tr -d ' ')

# Base dirs
export BASE_DIR="$(git rev-parse --show-toplevel)"
export DOCKER_DIR="${BASE_DIR}/docker"
export JARS_DIR="${DOCKER_DIR}/jars"
mkdir -p "${JARS_DIR}"

### ----------------------------------------------------------------
# ZMS JAVA OPTS
export ZMS_JAVA_OPTS="${ZMS_JAVA_OPTS:-}"
# ZMS dirs
export ZMS_DIR="${DOCKER_DIR}/zms"
export ZMS_LOGS_DIR="${DOCKER_DIR}/logs/zms"
export ZMS_CONF_DIR="${ZMS_DIR}/conf"
export ZMS_CERTS_DIR="${ZMS_DIR}/var/certs"
export ZMS_KEYS_DIR="${ZMS_DIR}/var/keys"
export ZMS_ASSY_DIR="${BASE_DIR}/assembly/zms/target/athenz-zms-${ATHENZ_TAG}"
mkdir -p "${ZMS_LOGS_DIR}"
mkdir -p "${ZMS_CONF_DIR}"
mkdir -p "${ZMS_CERTS_DIR}"
mkdir -p "${ZMS_KEYS_DIR}"
## ZMS filepaths
export ZMS_KEYSTORE_PATH="${ZMS_CERTS_DIR}/zms_keystore.pkcs12"
export ZMS_TRUSTSTORE_PATH="${ZMS_CERTS_DIR}/zms_truststore.jks"
export ZMS_PRIVATE_KEY_PATH="${ZMS_KEYS_DIR}/zms_private.pem"
export ZMS_PUBLIC_KEY_PATH="${ZMS_KEYS_DIR}/zms_public.pem"
### PROD env. ZMS PATH
export PROD_ZMS_DIR="${DOCKER_DIR}/prod/zms"
mkdir -p "${PROD_ZMS_DIR}"
export ZMS_CERT_KEY_PATH="${PROD_ZMS_DIR}/zms_key.pem"
# export ZMS_CSR_PATH="${PROD_ZMS_DIR}/zms_csr.pem"
export ZMS_CERT_PATH="${PROD_ZMS_DIR}/zms_cert.pem"

### ----------------------------------------------------------------
# ZTS JAVA OPTS
export ZTS_JAVA_OPTS="${ZTS_JAVA_OPTS:-}"
# ZTS dirs
export ZTS_DIR="${DOCKER_DIR}/zts"
export ZTS_LOGS_DIR="${DOCKER_DIR}/logs/zts"
export ZTS_CONF_DIR="${ZTS_DIR}/conf"
export ZTS_CERTS_DIR="${ZTS_DIR}/var/certs"
export ZTS_KEYS_DIR="${ZTS_DIR}/var/keys"
export ZTS_ASSY_DIR="${BASE_DIR}/assembly/zts/target/athenz-zts-${ATHENZ_TAG}"
mkdir -p "${ZTS_LOGS_DIR}"
mkdir -p "${ZTS_CONF_DIR}"
mkdir -p "${ZTS_CERTS_DIR}"
mkdir -p "${ZTS_KEYS_DIR}"
## ZTS filepaths
export ZTS_ATHENZ_CONF="${ZTS_CONF_DIR}/athenz.conf"
export ZTS_KEYSTORE_PATH="${ZTS_CERTS_DIR}/zts_keystore.pkcs12"
export ZTS_TRUSTSTORE_PATH="${ZTS_CERTS_DIR}/zts_truststore.jks"
export ZTS_PRIVATE_KEY_PATH="${ZTS_KEYS_DIR}/zts_private.pem"
export ZTS_PUBLIC_KEY_PATH="${ZTS_KEYS_DIR}/zts_public.pem"
## ZTS signer filepaths
export ZTS_SIGNER_KEYSTORE_PATH="${ZTS_CERTS_DIR}/zts_signer_keystore.pkcs12"
export ZTS_SIGNER_TRUSTSTORE_PATH="${ZTS_CERTS_DIR}/zts_signer_truststore.jks"
## ZMS client filepaths
export ZMS_CLIENT_KEYSTORE_PATH="${ZTS_CERTS_DIR}/zms_client_keystore.pkcs12"
export ZMS_CLIENT_TRUSTSTORE_PATH="${ZTS_CERTS_DIR}/zms_client_truststore.jks"
### PROD env. ZTS PATH
export PROD_ZTS_DIR="${DOCKER_DIR}/prod/zts"
mkdir -p "${PROD_ZTS_DIR}"
export ZTS_CERT_KEY_PATH="${PROD_ZTS_DIR}/zts_key.pem"
export ZTS_CSR_PATH="${PROD_ZTS_DIR}/zts_csr.pem"
export ZTS_CERT_PATH="${PROD_ZTS_DIR}/zts_cert.pem"
export ZTS_SIGNER_CERT_KEY_PATH="${PROD_ZTS_DIR}/zts_signer_key.pem"
# export ZTS_SIGNER_CSR_PATH="${PROD_ZTS_DIR}/zts_signer_csr.pem"
export ZTS_SIGNER_CERT_PATH="${PROD_ZTS_DIR}/zts_signer_cert.pem"
export ZMS_CLIENT_CERT_KEY_PATH="${PROD_ZTS_DIR}/zms_client_key.pem"
# export ZMS_CLIENT_CSR_PATH="${PROD_ZTS_DIR}/zms_client_csr.pem"
export ZMS_CLIENT_CERT_PATH="${PROD_ZTS_DIR}/zms_client_cert.pem"

### ----------------------------------------------------------------
# UI dirs
export UI_DIR="${DOCKER_DIR}/ui"
export UI_LOGS_DIR="${DOCKER_DIR}/logs/ui"
export UI_CONF_DIR="${UI_DIR}/conf"
export UI_CERTS_DIR="${UI_DIR}/var/certs"
export UI_KEYS_DIR="${UI_DIR}/var/keys"
export UI_ASSY_DIR="${BASE_DIR}/assembly/ui/target/athenz-ui-${ATHENZ_TAG}"
mkdir -p "${UI_LOGS_DIR}"
mkdir -p "${UI_CONF_DIR}"
mkdir -p "${UI_CERTS_DIR}"
mkdir -p "${UI_KEYS_DIR}"
## UI filepaths
export UI_ATHENZ_CONF="${UI_CONF_DIR}/athenz.conf"
export UI_PRIVATE_KEY_PATH="${UI_KEYS_DIR}/athenz.ui-server.pem"
export UI_PUBLIC_KEY_PATH="${UI_KEYS_DIR}/athenz.ui-server_pub.pem"
export UI_SESSION_SECRET_PATH="${UI_KEYS_DIR}/cookie-session"

### PROD env. UI PATH
export PROD_UI_DIR="${DOCKER_DIR}/prod/ui"
mkdir -p "${PROD_UI_DIR}"
export UI_CERT_KEY_PATH="${PROD_UI_DIR}/ui_key.pem"
export UI_CSR_PATH="${PROD_UI_DIR}/ui_csr.pem"
export UI_CERT_PATH="${PROD_UI_DIR}/ui_cert.pem"

### ----------------------------------------------------------------
### 3rd-party paths
export CA_DIR="${DOCKER_DIR}/prod/CAs"
mkdir -p "${CA_DIR}"
export ATHENZ_CA_PATH="${CA_DIR}/athenz_ca.pem"
# export ATHENZ_CA_KEY_PATH="${CA_DIR}/athenz_ca.pem"
export USER_CA_PATH="${CA_DIR}/user_ca.pem"
# export USER_CA_KEY_PATH="${CA_DIR}/user_ca.pem"
export SERVICE_CA_PATH="${CA_DIR}/service_ca.pem"
# export SERVICE_CA_KEY_PATH="${CA_DIR}/service_ca.pem"

export DOMAIN_ADMIN_DIR="${DOCKER_DIR}/prod/domain-admin"
export DOMAIN_ADMIN_CERT_KEY_PATH="${DOMAIN_ADMIN_DIR}/domain_admin_key.pem"
export DOMAIN_ADMIN_CERT_PATH="${DOMAIN_ADMIN_DIR}/domain_admin_cert.pem"



### ----------------------------------------------------------------
### docker variables
export DOCKER_GID="${DOCKER_GID:-1001}"
export DOCKER_UID="${DOCKER_UID:-10001}"
export DOCKER_DNS="${DOCKER_DNS:-8.8.8.8}"
export DOCKER_NETWORK="${DOCKER_NETWORK:-athenz}"
export DOCKER_NETWORK_SUBNET="${DOCKER_NETWORK_SUBNET:-172.21.0.0/16}"
export ZMS_DB_HOST="${ZMS_DB_HOST:-athenz-zms-db}"
export ZMS_DB_PORT="${ZMS_DB_PORT:-3306}"
export ZMS_HOST="${ZMS_HOST:-athenz-zms-server}"
export ZMS_PORT="${ZMS_PORT:-4443}"
export ZTS_DB_HOST="${ZTS_DB_HOST:-athenz-zts-db}"
export ZTS_DB_PORT="${ZTS_DB_PORT:-3307}"
export ZTS_HOST="${ZTS_HOST:-athenz-zts-server}"
export ZTS_PORT="${ZTS_PORT:-8443}"
export HOST_EXTERNAL_IP="${HOST_EXTERNAL_IP:-127.0.0.1}"
export UI_HOST="${UI_HOST:-athenz-ui-server}"
export UI_PORT="${UI_PORT:-443}"
export UI_CONTAINER_PORT="${UI_CONTAINER_PORT:-5443}"

### ----------------------------------------------------------------
# domain admin
export DOMAIN_ADMIN="${DOMAIN_ADMIN:-user.github-7654321}"
### ZMS passwords
export ZMS_DB_ROOT_PASS="${ZMS_DB_ROOT_PASS:-mariadb}"
export ZMS_DB_ADMIN_PASS="${ZMS_DB_ADMIN_PASS:-mariadbmariadb}"
export ZMS_RODB_ADMIN_PASS="${ZMS_RODB_ADMIN_PASS:-mariadbmariadb}"
export ZMS_KEYSTORE_PASS="${ZMS_KEYSTORE_PASS:-athenz}"
export ZMS_TRUSTSTORE_PASS="${ZMS_TRUSTSTORE_PASS:-athenz}"
### ZTS passwords
export ZTS_DB_ROOT_PASS="${ZTS_DB_ROOT_PASS:-mariadb}"
export ZTS_DB_ADMIN_PASS="${ZTS_DB_ADMIN_PASS:-mariadbmariadb}"
export ZTS_KEYSTORE_PASS="${ZTS_KEYSTORE_PASS:-athenz}"
export ZTS_TRUSTSTORE_PASS="${ZTS_TRUSTSTORE_PASS:-athenz}"
export ZTS_SIGNER_KEYSTORE_PASS="${ZTS_SIGNER_KEYSTORE_PASS:-athenz}"
export ZTS_SIGNER_TRUSTSTORE_PASS="${ZTS_SIGNER_TRUSTSTORE_PASS:-athenz}"
export ZMS_CLIENT_KEYSTORE_PASS="${ZMS_CLIENT_KEYSTORE_PASS:-athenz}"
export ZMS_CLIENT_TRUSTSTORE_PASS="${ZMS_CLIENT_TRUSTSTORE_PASS:-athenz}"
# export ZTS_JAVAX_TRUSTSTORE_PASS="${ZTS_JAVAX_TRUSTSTORE_PASS:-athenz}"
