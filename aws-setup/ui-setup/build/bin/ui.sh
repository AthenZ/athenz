#!/usr/bin/env bash
set -e

echo "========= Getting region and env from AWS ========="

REGION=$(curl http://169.254.169.254/latest/meta-data/placement/availability-zone | sed 's/.$//')
ENV="dev"
BUCKET_NAME=test-athenz-ui-data-bucket
ATHENZ_CONF_PATH=/opt/athenz-ui/conf/athenz.conf

export ENVIRONMENT="${ENV}"
export REGION="${REGION}"
export UI_SERVER="test.ui.athens.aws.oath.cloud"
export ZMS_SERVER="test.athens.aws.oath.cloud"
export ZMS_SERVER_URL="https://${ZMS_SERVER}:4443/zms/v1/"
export ROOT=/opt
export NODE_ENV="production"
# APP_ENV value will be used to load the appropriate config from src/config/default-config.js of ui code
# export APP_ENV="athenz.ui"

echo "initializing aws cloudwatch log setup"
sudo python /opt/athenz-ui/logs/awslogs-agent-setup.py -n -r $REGION -c /opt/athenz-ui/conf/awslogs.conf

echo "generating athenz conf"
/opt/athenz-ui/bin/athenz_conf.sh $ATHENZ_CONF_PATH $BUCKET_NAME $ZMS_SERVER

echo "Downloading certs and keys from s3 bucket"
/opt/athenz-ui/bin/get_certs.sh $BUCKET_NAME

echo "Starting UI Server"
DEBUG=AthenzUI:server:* /bin/node /opt/athenz-ui/app.js
echo "UI server running at 443"