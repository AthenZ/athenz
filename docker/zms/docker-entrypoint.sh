#!/usr/bin/env bash

ZMS_STOP_TIMEOUT=${ZMS_STOP_TIMEOUT:-30}
ZMS_CLASSPATH="${CLASSPATH}:${USER_CLASSPATH}"
ZMS_BOOTSTRAP_CLASS="com.yahoo.athenz.container.AthenzJettyContainer"

JAVA_OPTS="${JAVA_OPTS} -Dathenz.prop_file=${CONF_PATH}/athenz.properties"
JAVA_OPTS="${JAVA_OPTS} -Dathenz.zms.prop_file=${CONF_PATH}/zms.properties"
JAVA_OPTS="${JAVA_OPTS} -Dlogback.configurationFile=${CONF_PATH}/logback.xml"
# system properties for passwords
JAVA_OPTS="${JAVA_OPTS} -Dathenz.zms.jdbc_password=${ZMS_DB_ADMIN_PASS}"
JAVA_OPTS="${JAVA_OPTS} -Dathenz.zms.jdbc_ro_password=${ZMS_RODB_ADMIN_PASS}"
JAVA_OPTS="${JAVA_OPTS} -Dathenz.ssl_key_store_password=${ZMS_KEYSTORE_PASS}"
JAVA_OPTS="${JAVA_OPTS} -Dathenz.ssl_trust_store_password=${ZMS_TRUSTSTORE_PASS}"

### !!! P.S. cannot quote JAVA_OPTS !!!
### reference: https://github.com/koalaman/shellcheck/wiki/SC2086
java -classpath "${ZMS_CLASSPATH}" ${JAVA_OPTS} ${ZMS_BOOTSTRAP_CLASS} < /dev/null &
PID=$!

sleep 2;
if ! kill -0 "${PID}" > /dev/null 2>&1; then
    exit 1
fi

force_shutdown() {
    echo 'Will forcefully stopping ZMS...'
    kill -9 ${PID} >/dev/null 2>&1
    echo 'Forcefully stopped ZMS success'
    exit 1
}
shutdown() {
    if [ -z ${PID} ]; then
        echo 'ZMS is not running'
        exit 1
    else
        if ! kill -0 ${PID} > /dev/null 2>&1; then
            echo 'ZMS is not running'
            exit 1
        else
            # start shutdown
            echo 'Will stopping ZMS...'
            kill ${PID}

            # wait for shutdown
            count=0
            while [ -d "/proc/${PID}" ]; do
                echo 'Shutdown is in progress... Please wait...'
                sleep 1
                count="$((count + 1))"
    
                if [ "${count}" = "${ZMS_STOP_TIMEOUT}" ]; then
                    break
                fi
            done
            if [ "${count}" != "${ZMS_STOP_TIMEOUT}" ]; then
                echo 'Shutdown completed.'
            fi

            # if not success, force shutdown
            if kill -0 ${PID} > /dev/null 2>&1; then
                force_shutdown
            fi
        fi
    fi

    # confirm ZMS stopped
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
