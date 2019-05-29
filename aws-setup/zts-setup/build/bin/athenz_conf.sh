#!/bin/bash

#############
# Usage: athenz_conf.sh [outputFile] [zts key bucket path] [zts url] [zms key bucket path] [zms url]
# Generates Athenz conf file
###############

displayUsage() {
  echo "athenz_conf.sh [outputFile] [ztsDataBucketName] [ztsUrl] [zmsUrl]";
  echo 'athenz_conf.sh ./output.json athenz-zts-data-us-west-2 https://zts.athenz.com:4443/  https://zms.athenz.com:4443/';
}

if [ $# -ne 4 ]
then
  displayUsage
  exit 1
fi

zms_public_key_file=zms_service_x509_key_public.pem
zts_public_key_file=zts_service_x509_key_public.pem

outputFile=$1
ztsDataBucketName=$2
ztsUrl=$3
zmsUrl=$4

# download CA certs from S3 bucket and store locally in temp directory
aws s3 cp s3://$ztsDataBucketName/$zts_public_key_file /tmp/zts_pub_key
aws s3 cp s3://$ztsDataBucketName/$zms_public_key_file /tmp/zms_pub_key

sudo /opt/zts/bin/athenz-conf-aws -z $zmsUrl -t $ztsUrl -k /tmp/zms_pub_key -e /tmp/zts_pub_key -o $outputFile
