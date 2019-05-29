#!/bin/bash

Usage: initialize_zms.sh

# Runs aws_zms_truststore_gen.sh to get trust store
# Runs ws_java_truststore_gen.sh to get java trust store
# Runs aws_zms_keystore_gen.sh to generate key store.

set -e

echo "creating aws config"
/opt/zms/bin/aws_config.sh

echo "initializing aws cloudwatch log setup"
sudo python /opt/zms/logs/awslogs-agent-setup.py -n -r $REGION -c /opt/zms/conf/awslogs.conf

cd /opt/zms/temp

echo "generating zms trust store /opt/zms/bin/aws_zms_truststore_gen.sh $ZMS_DATA_BUCKET_NAME $ZMS_TRUST_STORE_PATH"
rm -f $ZMS_TRUST_STORE_PATH
/opt/zms/bin/aws_zms_truststore_gen.sh $ZMS_DATA_BUCKET_NAME $ZMS_TRUST_STORE_PATH

echo "generating java trust store $JDK_CA_CERTS_PATH $JDK_CA_CERTS_PWD $ZMS_DATA_BUCKET_NAME $TRUST_STORE_PATH"
rm -f $TRUST_STORE_PATH
/opt/zms/bin/aws_java_truststore_gen.sh $JDK_CA_CERTS_PATH $JDK_CA_CERTS_PWD $ZMS_DATA_BUCKET_NAME $TRUST_STORE_PATH

echo "generating zms key store /opt/zms/bin/aws_zms_keystore_gen.sh $ZMS_DATA_BUCKET_NAME $KEY_STORE_PATH"
rm -f $KEY_STORE_PATH
/opt/zms/bin/aws_zms_keystore_gen.sh $ZMS_DATA_BUCKET_NAME $KEY_STORE_PATH

echo "Adding domain admin /opt/zms/bin/add_user.sh $DOMAIN_ADMIN $ZMS_DATA_BUCKET_NAME"
/opt/zms/bin/add_user.sh $DOMAIN_ADMIN $ZMS_DATA_BUCKET_NAME


