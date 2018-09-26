#!/bin/bash

# Exposes bucket names based on account and region
#   ENV
#   ZTS_DATA_BUCKET_NAME
#   ZTS_DOMAIN_BUCKET_NAME
#   ZTS_AUDIT_LOG_BUCKET_NAME
#   CERTSIGN_BUCKET_NAME
#   REGION

set -e

export REGION=`curl http://169.254.169.254/latest/dynamic/instance-identity/document|grep region|awk -F\" '{print $4}'`
export ENV="dev"


export ZTS_DATA_BUCKET_NAME="athenz-zts-data-bucket-name"
export ZTS_AUDIT_LOG_BUCKET_NAME="athenz-audit-log-bucket-name"
export ZTS_URL="https://zts.url:4443"
export ZMS_URL="https://zms.url:4443"
export RDS_MASTER="zts-rds-databasecluster-endpoint"
export ZTS_TRUST_STORE_PATH="/opt/zts/conf/zts_truststore.jks"
export TRUST_STORE_PATH="/opt/zts/conf/zts_java_truststore.jks"
export KEY_STORE_PATH="/opt/zts/conf/zts_keystore.pkcs12"
export JDK_CA_CERTS_PATH="/etc/alternatives/jre_1.8.0_openjdk/lib/security/cacerts"
export JDK_CA_CERTS_PWD="changeit"
export ATHENZ_CONF_PATH="/opt/zts/conf/athenz.conf"
export DATASTORE_NAME="zts_store"