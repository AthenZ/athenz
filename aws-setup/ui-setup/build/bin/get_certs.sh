#!/usr/bin/env bash

# download server cert and key from private s3 bucket
# aws s3 client will automatically decrypt the data

BUCKET_NAME=$1
KEY_FILE=service_x509_key
CERT_FILE=service_x509_cert
SERVICE_PRIVATE_KEY_FILE=service_private_key
ZMS_CA_CERT_FILE=zms_service_x509_ca_certs

sudo mkdir -p /opt/athenz-ui/keys
aws s3 cp s3://$BUCKET_NAME/$KEY_FILE /opt/athenz-ui/keys/ui_key.pem
aws s3 cp s3://$BUCKET_NAME/$CERT_FILE /opt/athenz-ui/keys/ui_cert.pem
aws s3 cp s3://$BUCKET_NAME/$SERVICE_PRIVATE_KEY_FILE /opt/athenz-ui/keys/athenz.ui-server.pem
openssl rsa -in /opt/athenz-ui/keys/athenz.ui-server.pem -pubout > /opt/athenz-ui/keys/athenz.ui-server_pub.pem
aws s3 cp s3://$BUCKET_NAME/$ZMS_CA_CERT_FILE /opt/athenz-ui/keys/zms_cert.pem
