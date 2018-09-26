#!/bin/bash

set -e

source /opt/zms/bin/aws_init.sh

/opt/zms/bin/initialize_zms.sh
cd /opt/zms

# setup our database cluster endpoint and other environment
# specific settings. us-west-2 is our primary region while

# us-east-1 is our backup read-only region

JAVA_OPTS="-XX:+UseG1GC -XX:+ParallelRefProcEnabled -XX:+PrintGCDetails -Xloggc:/opt/zms/logs/gc.log"
JAVA_OPTS="${JAVA_OPTS} -XX:+PrintGCDateStamps -XX:+UseGCLogFileRotation"
JAVA_OPTS="${JAVA_OPTS} -XX:NumberOfGCLogFiles=10 -XX:GCLogFileSize=4M"
JAVA_OPTS="${JAVA_OPTS} -XX:+HeapDumpOnOutOfMemoryError -XX:HeapDumpPath=/opt/zms/logs"

java -server $JAVA_OPTS                                                             \
     -Dathenz.root_dir=/opt/zms                                                     \
     -Dathenz.zms.root_dir=/opt/zms                                                 \
     -Dlogback.configurationFile=/opt/zms/conf/logback.xml                          \
     -Dathenz.prop_file=/opt/zms/conf/athenz.properties                             \
     -Dathenz.zms.prop_file=/opt/zms/conf/zms.properties                            \
     -Dathenz.aws.zms.bucket_name=$ZMS_DATA_BUCKET_NAME                             \
     -Dathenz.ssl_key_store_password_appname=$ZMS_DATA_BUCKET_NAME                  \
     -Dathenz.ssl_trust_store_password_appname=$ZMS_DATA_BUCKET_NAME                \
     -Dathenz.zms.jdbc_store=jdbc:mysql://${RDS_MASTER}:3306/${DATASTORE_NAME}      \
     -Dathenz.zms.jdbc_app_name=$ZMS_DATA_BUCKET_NAME                               \
     -Dathenz.zms.aws_rds_master_instance=$RDS_MASTER                               \
     -Dathenz.aws.s3.region=$REGION                                                 \
     -Dathenz.zms.read_only_mode=false                                              \
     -classpath ":/opt/zms/jars/*:"                                                 \
     com.yahoo.athenz.container.AthenzJettyContainer
