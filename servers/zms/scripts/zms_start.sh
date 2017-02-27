#!/bin/bash

if [ -z "${ROOT}" ]; then
    ROOT="/home/athenz"
fi

CONTAINER_NAME=zms_server

export JAVA_OPTS="${JAVA_OPTS} -Dathenz.prop_file=${ROOT}/conf/${CONTAINER_NAME}/athenz.properties"
export JAVA_OPTS="${JAVA_OPTS} -Dathenz.zms.prop_file=${ROOT}/conf/${CONTAINER_NAME}/zms.properties"

CONTAINER_CLASSPATH=${ROOT}/lib/jars/*
CONTAINER_BOOTSTRAP_CLASS=com.yahoo.athenz.container.AthenzJettyContainer

echo "Executing: java -classpath ${CONTAINER_CLASSPATH} ${JAVA_OPTS} ${CONTAINER_BOOTSTRAP_CLASS}"

java -classpath "${CONTAINER_CLASSPATH}" ${JAVA_OPTS} ${CONTAINER_BOOTSTRAP_CLASS} 2>&1 < /dev/null
