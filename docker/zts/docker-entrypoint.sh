#!/usr/bin/env bash

ZTS_STOP_TIMEOUT=${ZTS_STOP_TIMEOUT:-30}
ZTS_CLASSPATH="${CLASSPATH}:${USER_CLASSPATH}"
ZTS_BOOTSTRAP_CLASS="com.yahoo.athenz.container.AthenzJettyContainer"

JAVA_OPTS="${JAVA_OPTS} -Dathenz.root_dir=."
JAVA_OPTS="${JAVA_OPTS} -Dathenz.zts.root_dir=."
JAVA_OPTS="${JAVA_OPTS} -Dathenz.prop_file=${CONF_PATH}/athenz.properties"
JAVA_OPTS="${JAVA_OPTS} -Dathenz.zts.prop_file=${CONF_PATH}/zts.properties"
JAVA_OPTS="${JAVA_OPTS} -Dlogback.configurationFile=${CONF_PATH}/logback.xml"
# system properties for passwords
JAVA_OPTS="${JAVA_OPTS} -Dathenz.zts.cert_jdbc_password=${ZTS_DB_ADMIN_PASS}"
JAVA_OPTS="${JAVA_OPTS} -Dathenz.ssl_key_store_password=${ZTS_KEYSTORE_PASS}"
JAVA_OPTS="${JAVA_OPTS} -Dathenz.ssl_trust_store_password=${ZTS_TRUSTSTORE_PASS}"
JAVA_OPTS="${JAVA_OPTS} -Dathenz.zts.keystore_signer.keystore_password=${ZTS_SIGNER_KEYSTORE_PASS}"
JAVA_OPTS="${JAVA_OPTS} -Dathenz.zts.ssl_key_store_password=${ZTS_SIGNER_KEYSTORE_PASS}"
JAVA_OPTS="${JAVA_OPTS} -Dathenz.zts.ssl_trust_store_password=${ZTS_SIGNER_TRUSTSTORE_PASS}"
JAVA_OPTS="${JAVA_OPTS} -Djavax.net.ssl.trustStorePassword=${ZTS_SIGNER_TRUSTSTORE_PASS}"
JAVA_OPTS="${JAVA_OPTS} -Dathenz.zms.client.keystore_password=${ZMS_CLIENT_KEYSTORE_PASS}"
JAVA_OPTS="${JAVA_OPTS} -Dathenz.zms.client.truststore_password=${ZMS_CLIENT_TRUSTSTORE_PASS}"

### !!! P.S. cannot quote JAVA_OPTS !!!
### reference: https://github.com/koalaman/shellcheck/wiki/SC2086
java -classpath "${ZTS_CLASSPATH}" ${JAVA_OPTS} ${ZTS_BOOTSTRAP_CLASS} < /dev/null &
PID=$!

sleep 2;
if ! kill -0 "${PID}" > /dev/null 2>&1; then
    exit 1
fi

force_shutdown() {
    echo 'Will forcefully stopping ZTS...'
    kill -9 ${PID} >/dev/null 2>&1
    echo 'Forcefully stopped ZTS success'
    exit 1
}
shutdown() {
    if [ -z ${PID} ]; then
        echo 'ZTS is not running'
        exit 1
    else
        if ! kill -0 ${PID} > /dev/null 2>&1; then
            echo 'ZTS is not running'
            exit 1
        else
            # start shutdown
            echo 'Will stopping ZTS...'
            kill ${PID}

            # wait for shutdown
            count=0
            while [ -d "/proc/${PID}" ]; do
                echo 'Shutdown is in progress... Please wait...'
                sleep 1
                count="$((count + 1))"
    
                if [ "${count}" = "${ZTS_STOP_TIMEOUT}" ]; then
                    break
                fi
            done
            if [ "${count}" != "${ZTS_STOP_TIMEOUT}" ]; then
                echo 'Shutdown completed.'
            fi

            # if not success, force shutdown
            if kill -0 ${PID} > /dev/null 2>&1; then
                force_shutdown
            fi
        fi
    fi

    # confirm ZTS stopped
    if ! kill -0 ${PID} > /dev/null 2>&1; then
        exit 0
    fi
}

# SIGINT
trap shutdown 2

# SIGTERM
trap shutdown 15

# wait
wait ${PID}
