#!/bin/bash

#############
# Usage: athenz_conf.sh [outputFile] [zts key bucket path] [zts url] [zms key bucket path] [zms url]
# Generates Athenz conf file
###############

displayUsage() {
  echo "athenz_conf.sh [outputFile] [uiDataBucketName][zmsUrl]";
  echo 'athenz_conf.sh ./output.json athenz-zts-data-us-west-2  https://zms.athenz.com:4443/';
}

if [ $# -ne 3 ]
then
  displayUsage
  exit 1
fi

zms_public_key_file=zms_service_x509_key_public.pem


outputFile=$1
dataBucketName=$2
zmsUrl=$3

# download CA certs from S3 bucket and store locally in temp directory
aws s3 cp s3://$dataBucketName/$zms_public_key_file /tmp/zms_pub_key

sudo /opt/athenz-ui/bin/linux/athenz-conf-aws -z $zmsUrl -k /tmp/zms_pub_key  -o $outputFile
