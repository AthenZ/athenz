#!/bin/bash

if [ -z "${ROOT}" ]; then
    ROOT="/home/athenz"
fi

CONTAINER_NAME=zms_server

# pick up our service settings which should override
# some of the default values set by the code
if [ ! -f ${ROOT}/conf/${CONTAINER_NAME}/container_settings ]; then
    echo "Unable to find container settings: ${ROOT}/conf/${CONTAINER_NAME}/container_settings aborting"
    exit -1
fi

. "${ROOT}/conf/${CONTAINER_NAME}/container_settings"

CONTAINER_RUN_PATH=${ROOT}/var/run/zms_server
CONTAINER_CLASSPATH=${ROOT}/lib/jar/zms_server*.jar:${ROOT}/lib/jars/*
CONTAINER_BOOTSTRAP_CLASS=com.yahoo.athenz.zms.ZMS

if [ "${CONTAINER_READ_ONLY_MODE}" == "true" ]; then
    export JAVA_OPTS="${JAVA_OPTS} -Dathenz.zms.read_only_mode=true"
fi

if [ "${CONTAINER_VIRTUAL_DOMAIN_SUPPORT}" == "true" ]; then
    export JAVA_OPTS="${JAVA_OPTS} -Dathenz.zms.virtual_domain_support=true"
fi

if [ "x${CONTAINER_VIRTUAL_DOMAIN_LIMIT}" != "x" ]; then
    export JAVA_OPTS="${JAVA_OPTS} -Dathenz.zms.virtual_domain_limit=${CONTAINER_VIRTUAL_DOMAIN_LIMIT}"
fi

export JAVA_OPTS="${JAVA_OPTS} -Dathenz.zms.port=${CONTAINER_PORT}"
export JAVA_OPTS="${JAVA_OPTS} -Dathenz.zms.tls_port=${CONTAINER_TLS_PORT}"
export JAVA_OPTS="${JAVA_OPTS} -Dathenz.zms.logs=${ROOT}/logs/${CONTAINER_NAME}"

if [ "x${CONTAINER_LOG_CONFIG}" != "x" ]; then
    export JAVA_OPTS="${JAVA_OPTS} -Dlogback.configurationFile=${CONTAINER_LOG_CONFIG}"
fi

if [ "x{$CONTAINER_PRIVKEY}" != "x" ]; then
    export JAVA_OPTS="${JAVA_OPTS} -Dathenz.auth.private_key_store.private_key=${CONTAINER_PRIVKEY}"
fi

if [ "x${CONTAINER_PRIVKEY_ID}" != "x" ]; then
    export JAVA_OPTS="${JAVA_OPTS} -Dathenz.auth.private_key_store.private_key_id=${CONTAINER_PRIVKEY_ID}"
fi

if [ "x${CONTAINER_PRIVATE_KEY_STORE_FACTORY_CLASS}" != "x" ]; then
    export JAVA_OPTS="${JAVA_OPTS} -Dathenz.zms.private_key_store_factory_class=${CONTAINER_PRIVATE_KEY_STORE_FACTORY_CLASS}"
fi

if [ "x${CONTAINER_HOSTNAME}" != "x" ]; then
    export JAVA_OPTS="${JAVA_OPTS} -Dathenz.zms.hostname=${CONTAINER_HOSTNAME}"
fi

if [ "x${CONTAINER_CONFLICT_RETRY_TIMEOUT}" != "x" ]; then
    export JAVA_OPTS="${JAVA_OPTS} -Dathenz.zms.conflict_retry_timeout=${CONTAINER_CONFLICT_RETRY_TIMEOUT}"
fi

if [ "x${CONTAINER_RETRY_DELAY_TIMEOUT}" != "x" ]; then
    export JAVA_OPTS="${JAVA_OPTS} -Dathenz.zms.retry_delay_timeout=${CONTAINER_RETRY_DELAY_TIMEOUT}"
fi

if [ "x${CONTAINER_USER_TOKEN_TIMEOUT}" != "x" ]; then
    export JAVA_OPTS="${JAVA_OPTS} -Dathenz.zms.user_token_timeout=${CONTAINER_USER_TOKEN_TIMEOUT}"
fi

if [ "x${CONTAINER_SIGNED_POLICY_TIMEOUT}" != "x" ]; then
    export JAVA_OPTS="${JAVA_OPTS} -Dathenz.zms.signed_policy_timeout=${CONTAINER_SIGNED_POLICY_TIMEOUT}"
fi

if [ "x${CONTAINER_ADMINUSER}" != "x" ]; then
    export JAVA_OPTS="${JAVA_OPTS} -Dathenz.zms.domain_admin=${CONTAINER_ADMINUSER}"
fi

if [ "x${CONTAINER_JDBC_STORE}" != "x" ]; then
    export JAVA_OPTS="${JAVA_OPTS} -Dathenz.zms.jdbc_store=${CONTAINER_JDBC_STORE}"
fi

if [ "x${CONTAINER_JDBC_USER}" != "x" ]; then
    export JAVA_OPTS="${JAVA_OPTS} -Dathenz.zms.jdbc_user=${CONTAINER_JDBC_USER}"
fi

if [ "x${CONTAINER_JDBC_PASSWORD}" != "x" ]; then
    export JAVA_OPTS="${JAVA_OPTS} -Dathenz.zms.jdbc_password=${CONTAINER_JDBC_PASSWORD}"
fi

if [ "x${CONTAINER_FILE_STORE}" != "x" ]; then
    export JAVA_OPTS="${JAVA_OPTS} -Dathenz.zms.file_store=${CONTAINER_FILE_STORE}"
fi

if [ "x${CONTAINER_DBPOOL_MAX_TOTAL}" != "x" ]; then
    export JAVA_OPTS="${JAVA_OPTS} -Dathenz.db.pool_max_total=${CONTAINER_DBPOOL_MAX_TOTAL}"
fi

if [ "x${CONTAINER_DBPOOL_MAX_IDLE}" != "x" ]; then
    export JAVA_OPTS="${JAVA_OPTS} -Dathenz.db.pool_max_idle=${CONTAINER_DBPOOL_MAX_IDLE}"
fi

if [ "x${CONTAINER_DBPOOL_MIN_IDLE}" != "x" ]; then
    export JAVA_OPTS="${JAVA_OPTS} -Dathenz.db.pool_min_idle=${CONTAINER_DBPOOL_MIN_IDLE}"
fi

if [ "x${CONTAINER_DBPOOL_MAX_WAIT}" != "x" ]; then
    export JAVA_OPTS="${JAVA_OPTS} -Dathenz.db.pool_max_wait=${CONTAINER_DBPOOL_MAX_WAIT}"
fi

if [ "x${CONTAINER_DBPOOL_EVICT_IDLE_TIMEOUT}" != "x" ]; then
    export JAVA_OPTS="${JAVA_OPTS} -Dathenz.db.pool_evict_idle_timeout=${CONTAINER_DBPOOL_EVICT_IDLE_TIMEOUT}"
fi

if [ "x${CONTAINER_DBPOOL_EVICT_IDLE_INTERVAL}" != "x" ]; then
    export JAVA_OPTS="${JAVA_OPTS} -Dathenz.db.pool_evict_idle_interval=${CONTAINER_DBPOOL_EVICT_IDLE_INTERVAL}"
fi

if [ "x${CONTAINER_DBPOOL_MAX_TTL}" != "x" ]; then
    export JAVA_OPTS="${JAVA_OPTS} -Dathenz.db.pool_max_ttl=${CONTAINER_DBPOOL_MAX_TTL}"
fi

if [ "x${CONTAINER_SSL_KEYSTORE}" != "x" ]; then
    export JAVA_OPTS="${JAVA_OPTS} -Dathenz.zms.ssl_key_store=${CONTAINER_SSL_KEYSTORE}"
fi

if [ "x${CONTAINER_SSL_KEYSTORE_TYPE}" != "x" ]; then
    export JAVA_OPTS="${JAVA_OPTS} -Dathenz.zms.ssl_key_store_type=${CONTAINER_SSL_KEYSTORE_TYPE}"
fi

if [ "x${CONTAINER_SSL_KEYSTORE_PASSWORD}" != "x" ]; then
    export JAVA_OPTS="${JAVA_OPTS} -Dathenz.zms.ssl_key_store_password=${CONTAINER_SSL_KEYSTORE_PASSWORD}"
fi

if [ "x${CONTAINER_SSL_TRUSTSTORE}" != "x" ]; then
    export JAVA_OPTS="${JAVA_OPTS} -Dathenz.zms.ssl_trust_store=${CONTAINER_SSL_TRUSTSTORE}"
fi

if [ "x${CONTAINER_SSL_TRUSTSTORE_TYPE}" != "x" ]; then
    export JAVA_OPTS="${JAVA_OPTS} -Dathenz.zms.ssl_trust_store_type=${CONTAINER_SSL_TRUSTSTORE_TYPE}"
fi

if [ "x${CONTAINER_SSL_TRUSTSTORE_PASSWORD}" != "x" ]; then
    export JAVA_OPTS="${JAVA_OPTS} -Dathenz.zms.ssl_trust_store_password=${CONTAINER_SSL_TRUSTSTORE_PASSWORD}"
fi

if [ "x${CONTAINER_SSL_KEYMANAGER_PASSWORD}" != "x" ]; then
    export JAVA_OPTS="${JAVA_OPTS} -Dathenz.zms.ssl_key_manager_password=${CONTAINER_SSL_KEYMANAGER_PASSWORD}"
fi

if [ "x${CONTAINER_SSL_EXCLUDED_CIPHER_SUITES}" != "x" ]; then
    export JAVA_OPTS="${JAVA_OPTS} -Dathenz.zms.ssl_excluded_cipher_suites=${CONTAINER_SSL_EXCLUDED_CIPHER_SUITES}"
fi

if [ "x${CONTAINER_SSL_EXCLUDED_PROTOCOLS}" != "x" ]; then
    export JAVA_OPTS="${JAVA_OPTS} -Dathenz.zms.ssl_excluded_protocols=${CONTAINER_SSL_EXCLUDED_PROTOCOLS}"
fi

if [ "x${CONTAINER_ACCESS_LOG_DIR}" != "x" ]; then
    export JAVA_OPTS="${JAVA_OPTS} -Dathenz.zms.access_log_dir=${CONTAINER_ACCESS_LOG_DIR}"
fi

if [ "x${CONTAINER_ACCESS_LOG_NAME}" != "x" ]; then
    export JAVA_OPTS="${JAVA_OPTS} -Dathenz.zms.access_log_name=${CONTAINER_ACCESS_LOG_NAME}"
fi

if [ "x${CONTAINER_ACCESS_LOG_RETAIN_DAYS}" != "x" ]; then
    export JAVA_OPTS="${JAVA_OPTS} -Dathenz.zms.access_log_retain_days=${CONTAINER_ACCESS_LOG_RETAIN_DAYS}"
fi

if [ "x${CONTAINER_LISTEN_HOST}" != "x" ]; then
    export JAVA_OPTS="${JAVA_OPTS} -Dathenz.zms.listen_host=${CONTAINER_LISTEN_HOST}"
fi

if [ "x${CONTAINER_AUTHZ_SERVICE_FNAME}" != "x" ]; then
    export JAVA_OPTS="${JAVA_OPTS} -Dathenz.zms.authz_service_fname=${CONTAINER_AUTHZ_SERVICE_FNAME}"
fi

if [ "x${CONTAINER_SOLUTION_TEMPLATES_FNAME}" != "x" ]; then
    export JAVA_OPTS="${JAVA_OPTS} -Dathenz.zms.solution_templates_fname=${CONTAINER_SOLUTION_TEMPLATES_FNAME}"
fi

if [ "x${CONTAINER_DOMAIN_NAME_MAX_LEN}" != "x" ]; then
    export JAVA_OPTS="${JAVA_OPTS} -Dathenz.zms.domain_name_max_len=${CONTAINER_DOMAIN_NAME_MAX_LEN}"
fi

if [ "x${CONTAINER_AUTHORITY_CLASSES}" != "x" ]; then
    export JAVA_OPTS="${JAVA_OPTS} -Dathenz.zms.authority_classes=${CONTAINER_AUTHORITY_CLASSES}"
fi

if [ "x${CONTAINER_AUTH_PAM_SERVICE}" != "x" ]; then
    export JAVA_OPTS="${JAVA_OPTS} -Dathenz.auth.user.pam_service_name=${CONTAINER_AUTH_PAM_SERVICE}"
fi

echo "Executing: java -classpath ${CONTAINER_CLASSPATH} ${JAVA_OPTS} ${CONTAINER_BOOTSTRAP_CLASS}"

java -classpath ${CONTAINER_CLASSPATH} ${JAVA_OPTS} ${CONTAINER_BOOTSTRAP_CLASS} 2>&1 < /dev/null
