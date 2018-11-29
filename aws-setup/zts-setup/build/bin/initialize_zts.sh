#!/bin/bash

# Usage: initialize_zts.sh

#Runs athenz.conf.sh to get athenz.conf file
# Runs aws_zts_truststore_gen.sh to get trust store
# Runs aws_java_truststore_gen.sh to get java trust store
# Runs aws_zts_keystore_gen.sh to generate key store.


set -e

echo "creating aws config"
/opt/zts/bin/aws_config.sh

echo "initializing aws cloudwatch log setup"
sudo python /opt/zts/logs/awslogs-agent-setup.py -n -r $REGION -c /opt/zts/conf/awslogs.conf

cd /opt/zts/temp

echo "generating athenz conf"
/opt/zts/bin/athenz_conf.sh $ATHENZ_CONF_PATH $ZTS_DATA_BUCKET_NAME $ZTS_URL $ZMS_URL

echo "generating zts trust store /opt/zts/bin/aws_zts_truststore_gen.sh $ZTS_DATA_BUCKET_NAME $ZTS_TRUST_STORE_PATH"
rm -f $ZTS_TRUST_STORE_PATH
/opt/zts/bin/aws_zts_truststore_gen.sh $ZTS_DATA_BUCKET_NAME $ZTS_TRUST_STORE_PATH

echo "generating java trust store /opt/zts/bin/aws_java_truststore_gen.sh $JDK_CA_CERTS_PATH $JDK_CA_CERTS_PWD $ZTS_DATA_BUCKET_NAME $TRUST_STORE_PATH"
rm -f $TRUST_STORE_PATH
/opt/zts/bin/aws_java_truststore_gen.sh $JDK_CA_CERTS_PATH $JDK_CA_CERTS_PWD $ZTS_DATA_BUCKET_NAME $TRUST_STORE_PATH

echo "generating zts key store /opt/zts/bin/aws_zts_keystore_gen.sh $ZTS_DATA_BUCKET_NAME $KEY_STORE_PATH"
rm -f $KEY_STORE_PATH
/opt/zts/bin/aws_zts_keystore_gen.sh $ZTS_DATA_BUCKET_NAME $KEY_STORE_PATH

# echo "Downloading self cert signer key"
# aws s3 cp s3://$bucket_name/self_cert_signer_key /opt/zts/conf/self_cert_signer_key


