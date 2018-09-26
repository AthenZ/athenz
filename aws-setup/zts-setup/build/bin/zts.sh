#!/bin/bash

set -e

source /opt/zts/bin/aws_init.sh

/opt/zts/bin/initialize_zts.sh
cd /opt/zts

# setup our database cluster endpoint and other environment
# specific settings. us-west-2 is our primary region while
# us-east-1 is our backup read-only region



JAVA_OPTS="-XX:+UseG1GC -XX:+ParallelRefProcEnabled -XX:+PrintGCDetails -Xloggc:/opt/zts/logs/gc.log"
JAVA_OPTS="${JAVA_OPTS} -XX:+PrintGCDateStamps -XX:+UseGCLogFileRotation"
JAVA_OPTS="${JAVA_OPTS} -XX:NumberOfGCLogFiles=10 -XX:GCLogFileSize=4M"
JAVA_OPTS="${JAVA_OPTS} -XX:+HeapDumpOnOutOfMemoryError -XX:HeapDumpPath=/opt/zts/logs"

java -server $JAVA_OPTS                                                                   \
     -Dathenz.root_dir=/opt/zts                                                           \
     -Dathenz.zts.root_dir=/opt/zts                                                       \
     -Dlogback.configurationFile=/opt/zts/conf/logback.xml                                \
     -Dathenz.prop_file=/opt/zts/conf/athenz.properties                                   \
     -Dathenz.zts.prop_file=/opt/zts/conf/zts.properties                                  \                                 \
     -Dathenz.zts.cert_jdbc_store=jdbc:mysql://${RDS_MASTER}:3306/${DATASTORE_NAME}               \
     -Dathenz.aws.zts.bucket_name=$ZTS_DATA_BUCKET_NAME                                   \
     -Dathenz.zts.cert_jdbc_app_name=$ZTS_DATA_BUCKET_NAME                                \
     -Dathenz.zts.ssl_key_store_password_appname=$ZTS_DATA_BUCKET_NAME                    \
     -Dathenz.zts.ssl_trust_store_password_appname=$ZTS_DATA_BUCKET_NAME                  \
     -Dathenz.ssl_key_store_password_appname=$ZTS_DATA_BUCKET_NAME                        \
     -Dathenz.ssl_trust_store_password_appname=$ZTS_DATA_BUCKET_NAME                      \
     -Dathenz.zts.aws_region_name=$REGION                                                 \
     -Dathenz.zts.read_only_mode=false                                                    \
     -classpath ":/opt/zts/jars/*:"                                                       \
     com.yahoo.athenz.container.AthenzJettyContainer
