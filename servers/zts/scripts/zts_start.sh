#!/bin/bash

if [ -z "${ROOT}" ]; then
    ROOT="/home/athenz"
fi

CONTAINER_NAME=zts_server

## pick up our service settings which should override
# some of the default values set by the code
if [ ! -f ${ROOT}/conf/${CONTAINER_NAME}/container_settings ]; then
    echo "Unable to find container settings: ${ROOT}/conf/${CONTAINER_NAME}/container_settings aborting"
    exit -1
fi

. "${ROOT}/conf/${CONTAINER_NAME}/container_settings"

CONTAINER_RUN_PATH=${ROOT}/var/run/zts_server
CONTAINER_CLASSPATH=${ROOT}/lib/jar/zts_server*.jar:${ROOT}/lib/jars/*
CONTAINER_BOOTSTRAP_CLASS=com.yahoo.athenz.zts.ZTS

export JAVA_OPTS="${JAVA_OPTS} -Dathenz.zts.port=${CONTAINER_PORT}"
export JAVA_OPTS="${JAVA_OPTS} -Dathenz.zts.tls_port=${CONTAINER_TLS_PORT}"
export JAVA_OPTS="${JAVA_OPTS} -Dathenz.zts.logs=${ROOT}/logs/${CONTAINER_NAME}"

if [ "x${CONTAINER_LOG_CONFIG}" != "x" ]; then
    export JAVA_OPTS="${JAVA_OPTS} -Dlogback.configurationFile=${CONTAINER_LOG_CONFIG}"
fi

if [ "x${CONTAINER_PRIVKEY}" != "x" ]; then
    export JAVA_OPTS="${JAVA_OPTS} -Dathenz.auth.private_key_store.private_key=${CONTAINER_PRIVKEY}"
fi

if [ "x${CONTAINER_PRIVKEY_ID}" != "x" ]; then
    export JAVA_OPTS="${JAVA_OPTS} -Dathenz.auth.private_key_store.private_key_id=${CONTAINER_PRIVKEY_ID}"
fi

if [ "x${CONTAINER_HOSTNAME}" != "x" ]; then
    export JAVA_OPTS="${JAVA_OPTS} -Dathenz.zts.hostname=${CONTAINER_HOSTNAME}"
fi

if [ "x${CONTAINER_ROLE_TOKEN_MAX_TIMEOUT}" != "x" ]; then
    export JAVA_OPTS="${JAVA_OPTS} -Dathenz.zts.role_token_max_timeout=${CONTAINER_ROLE_TOKEN_MAX_TIMEOUT}"
fi

if [ "x${CONTAINER_ROLE_TOKEN_DEFAULT_TIMEOUT}" != "x" ]; then
    export JAVA_OPTS="${JAVA_OPTS} -Dathenz.zts.role_token_default_timeout=${CONTAINER_ROLE_TOKEN_DEFAULT_TIMEOUT}"
fi

if [ "x${CONTAINER_SIGNED_POLICY_TIMEOUT}" != "x" ]; then
    export JAVA_OPTS="${JAVA_OPTS} -Dathenz.zts.signed_policy_timeout=${CONTAINER_SIGNED_POLICY_TIMEOUT}"
fi

if [ "x${CONTAINER_ZMS_DOMAIN_UPDATE_TIMEOUT}" != "x" ]; then
    export JAVA_OPTS="${JAVA_OPTS} -Dathenz.zts.zms_domain_update_timeout=${CONTAINER_ZMS_DOMAIN_UPDATE_TIMEOUT}"
fi

if [ "x${CONTAINER_ZMS_DOMAIN_DELETE_TIMEOUT}" != "x" ]; then
    export JAVA_OPTS="${JAVA_OPTS} -Dathenz.zts.zms_domain_delete_timeout=${CONTAINER_ZMS_DOMAIN_DELETE_TIMEOUT}"
fi

if [ "x${CONTAINER_ZMS_CLIENT_READ_TIMEOUT}" != "x" ]; then
    export JAVA_OPTS="${JAVA_OPTS} -Dyahoo.zms_java_client.read_timeout=${CONTAINER_ZMS_CLIENT_READ_TIMEOUT}"
fi

if [ "x${CONTAINER_SSL_KEYSTORE}" != "x" ]; then
    export JAVA_OPTS="${JAVA_OPTS} -Dathenz.zts.ssl_key_store=${CONTAINER_SSL_KEYSTORE}"
fi

if [ "x${CONTAINER_SSL_KEYSTORE_TYPE}" != "x" ]; then
    export JAVA_OPTS="${JAVA_OPTS} -Dathenz.zts.ssl_key_store_type=${CONTAINER_SSL_KEYSTORE_TYPE}"
fi

if [ "x${CONTAINER_SSL_KEYSTORE_PASSWORD}" != "x" ]; then
    export JAVA_OPTS="${JAVA_OPTS} -Dathenz.zts.ssl_key_store_password=${CONTAINER_SSL_KEYSTORE_PASSWORD}"
fi

if [ "x${CONTAINER_SSL_TRUSTSTORE}" != "x" ]; then
    export JAVA_OPTS="${JAVA_OPTS} -Dathenz.zts.ssl_trust_store=${CONTAINER_SSL_TRUSTSTORE}"
    export JAVA_OPTS="${JAVA_OPTS} -Djavax.net.ssl.trustStore=${CONTAINER_SSL_TRUSTSTORE}"
fi

if [ "x${CONTAINER_SSL_TRUSTSTORE_TYPE}" != "x" ]; then
    export JAVA_OPTS="${JAVA_OPTS} -Dathenz.zts.ssl_trust_store_type=${CONTAINER_SSL_TRUSTSTORE_TYPE}"
fi

if [ "x${CONTAINER_SSL_TRUSTSTORE_PASSWORD}" != "x" ]; then
    export JAVA_OPTS="${JAVA_OPTS} -Dathenz.zts.ssl_trust_store_password=${CONTAINER_SSL_TRUSTSTORE_PASSWORD}"
fi

if [ "x${CONTAINER_SSL_KEYMANAGER_PASSWORD}" != "x" ]; then
    export JAVA_OPTS="${JAVA_OPTS} -Dathenz.zts.ssl_key_manager_password=${CONTAINER_SSL_KEYMANAGER_PASSWORD}"
fi

if [ "x${CONTAINER_SSL_EXCLUDED_CIPHER_SUITES}" != "x" ]; then
    export JAVA_OPTS="${JAVA_OPTS} -Dathenz.zts.ssl_excluded_cipher_suites=${CONTAINER_SSL_EXCLUDED_CIPHER_SUITES}"
fi

if [ "x${CONTAINER_SSL_EXCLUDED_PROTOCOLS}" != "x" ]; then
    export JAVA_OPTS="${JAVA_OPTS} -Dathenz.zts.ssl_excluded_protocols=${CONTAINER_SSL_EXCLUDED_PROTOCOLS}"
fi

if [ "x${CONTAINER_ACCESS_LOG_DIR}" != "x" ]; then
    export JAVA_OPTS="${JAVA_OPTS} -Dathenz.zts.access_log_dir=${CONTAINER_ACCESS_LOG_DIR}"
fi

if [ "x${CONTAINER_ACCESS_LOG_NAME}" != "x" ]; then
    export JAVA_OPTS="${JAVA_OPTS} -Dathenz.zts.access_log_name=${CONTAINER_ACCESS_LOG_NAME}"
fi

if [ "x${CONTAINER_ACCESS_LOG_OPTIONS}" != "x" ]; then
    export JAVA_OPTS="${JAVA_OPTS} -Dathenz.zts.access_log_options=${CONTAINER_ACCESS_LOG_OPTIONS}"
fi

if [ "x${CONTAINER_ACCESS_LOG_RETAIN_DAYS}" != "x" ]; then
    export JAVA_OPTS="${JAVA_OPTS} -Dathenz.zts.access_log_retain_days=${CONTAINER_ACCESS_LOG_RETAIN_DAYS}"
fi

if [ "x${CONTAINER_ACCESS_LOG_ROTATION_PERIOD}" != "x" ]; then
    export JAVA_OPTS="${JAVA_OPTS} -Dathenz.zts.access_log_rotation_period=${CONTAINER_ACCESS_LOG_ROTATION_PERIOD}"
fi

if [ "x${CONTAINER_ACCESS_LOG_ROTATION_UNIT}" != "x" ]; then
    export JAVA_OPTS="${JAVA_OPTS} -Dathenz.zts.access_log_rotation_unit=${CONTAINER_ACCESS_LOG_ROTATION_UNIT}"
fi

if [ "x${CONTAINER_LISTEN_HOST}" != "x" ]; then
    export JAVA_OPTS="${JAVA_OPTS} -Dathenz.zts.listen_host=${CONTAINER_LISTEN_HOST}"
fi

if [ "x${CONTAINER_DATA_CHANGE_LOG_STORE_FACTORY_CLASS}" != "x" ]; then
    export JAVA_OPTS="${JAVA_OPTS} -Dathenz.zts.data_change_log_store_factory_class=${CONTAINER_DATA_CHANGE_LOG_STORE_CLASS}"
fi

if [ "x${CONTAINER_PRIVATE_KEY_STORE_FACTORY_CLASS}" != "x" ]; then
    export JAVA_OPTS="${JAVA_OPTS} -Dathenz.zts.private_key_store_factory_class=${CONTAINER_PRIVATE_KEY_STORE_FACTORY_CLASS}"
fi

if [ "x${CONTAINER_CERT_SIGNER_FACTORY_CLASS}" != "x" ]; then
    export JAVA_OPTS="${JAVA_OPTS} -Dathenz.zts.cert_signer_factory_class=${CONTAINER_CERT_SIGNER_FACTORY_CLASS}"
fi

if [ "x${CONTAINER_SELF_SIGNER_PRIVATE_KEY_FNAME}" != "x" ]; then
    export JAVA_OPTS="${JAVA_OPTS} -Dathenz.zts.self_signer_private_key_fname=${CONTAINER_SELF_SIGNER_PRIVATE_KEY_FNAME}"
fi

if [ "x${CONTAINER_CERTSIGN_BASE_URI}" != "x" ]; then
    export JAVA_OPTS="${JAVA_OPTS} -Dathenz.zts.certsign_base_uri=${CONTAINER_CERTSIGN_BASE_URI}"
fi

if [ "x${CONTAINER_HOST_SIGNER_SERVICE}" != "x" ]; then
    export JAVA_OPTS="${JAVA_OPTS} -Dathenz.zts.host_signer_service=${CONTAINER_HOST_SIGNER_SERVICE}"
fi

if [ "x${CONTAINER_KRB_KEYTAB}" != "x" ]; then
    export JAVA_OPTS="${JAVA_OPTS} -Dyahoo.auth_core.keytab_location=${CONTAINER_KRB_KEYTAB}"
fi

if [ "x${CONTAINER_KRB_PRINCIPAL}" != "x" ]; then
    export JAVA_OPTS="${JAVA_OPTS} -Dyahoo.auth_core.service_principal=${CONTAINER_KRB_PRINCIPAL}"
fi

if [ "x${CONTAINER_KRB_TKT_CACHE}" != "x" ]; then
    export JAVA_OPTS="${JAVA_OPTS} -Dyahoo.auth_core.use_ticket_cache=${CONTAINER_KRB_TKT_CACHE}"
fi

if [ "x${CONTAINER_KRB_TKT_CACHE_PATH}" != "x" ]; then
    export JAVA_OPTS="${JAVA_OPTS} -Dyahoo.auth_core.ticket_cache_name=${CONTAINER_KRB_TKT_CACHE_PATH}"
fi

if [ "x${CONTAINER_KRB_TGT_RENEW}" != "x" ]; then
    export JAVA_OPTS="${JAVA_OPTS} -Dyahoo.auth_core.renewTGT=${CONTAINER_KRB_TGT_RENEW}"
fi

if [ "x${CONTAINER_KRB_DEBUG}" != "x" ]; then
    export JAVA_OPTS="${JAVA_OPTS} -Dsun.security.krb5.debug=${CONTAINER_KRB_DEBUG}"
fi

if [ "x${CONTAINER_KRB_JAAS_CONF}" != "x" ]; then
    export JAVA_OPTS="${JAVA_OPTS} -Djava.security.auth.login.config=${CONTAINER_KRB_JAAS_CONF}"
fi

if [ "x${CONTAINER_AUTHZ_PROXY_USERS}" != "x" ]; then
    export JAVA_OPTS="${JAVA_OPTS} -Dathenz.zts.authorized_proxy_users=${CONTAINER_AUTHZ_PROXY_USERS}"
fi

if [ "x${CONTAINER_ATHENZ_CONF}" != "x" ]; then
    export JAVA_OPTS="${JAVA_OPTS} -Dathenz.athenz_conf=${CONTAINER_ATHENZ_CONF}"
fi

echo "Executing: java -classpath ${CONTAINER_CLASSPATH} ${JAVA_OPTS} ${CONTAINER_BOOTSTRAP_CLASS}"

java -classpath ${CONTAINER_CLASSPATH} ${JAVA_OPTS} ${CONTAINER_BOOTSTRAP_CLASS} 2>&1 < /dev/null
