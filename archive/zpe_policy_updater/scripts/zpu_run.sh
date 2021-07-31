#!/bin/bash

if [ -z "${ROOT}" ]; then
    ROOT="/home/athenz"
fi

UTILITY_NAME=zpe_policy_updater
UTILITY_CLASSPATH=${ROOT}/lib/jars/athenz-zpe-policy-updater-*.jar:${ROOT}/lib/jars/*
UTILITY_BOOTSTRAP_CLASS=com.yahoo.athenz.zpe_policy_updater.PolicyUpdater

## pick up our service settings which should override
# some of the default values set by the code
if [ ! -f ${ROOT}/conf/${UTILITY_NAME}/utility_settings ]; then
    echo "Unable to find utility settings: ${ROOT}/conf/${UTILITY_NAME}/utility_settings aborting"
    exit -1
fi

. "${ROOT}/conf/${UTILITY_NAME}/utility_settings"

export JAVA_OPTS="${JAVA_OPTS} -Dathenz.zpe_policy_updater.dir=${UTILITY_POLICY_FILE_DIR}"
export JAVA_OPTS="${JAVA_OPTS} -Dlogback.configurationFile=${UTILITY_LOG_CONFIG}"
export JAVA_OPTS="${JAVA_OPTS} -Dathenz.athenz_conf=${UTILITY_ATHENZ_CONF}"
export JAVA_OPTS="${JAVA_OPTS} -Djavax.net.ssl.trustStore=${UTILITY_SSL_TRUSTSTORE}"

if [ ! -d "${UTILITY_POLICY_FILE_DIR}" ]; then
    mkdir -p ${UTILITY_POLICY_FILE_DIR}
fi

date

echo "Executing: java -classpath ${UTILITY_CLASSPATH} ${JAVA_OPTS} ${UTILITY_BOOTSTRAP_CLASS}"

java -classpath ${UTILITY_CLASSPATH} ${JAVA_OPTS} ${UTILITY_BOOTSTRAP_CLASS} 2>&1 < /dev/null
