#!/bin/bash
#############
# Usage: aws_zts_truststore_gen.sh [bucket name] [trust store path]
# Downloads CA certs from S3 bucket. Creates pkcs12 truststore for jetty.
# Check for generated truststore: openssl pkcs12 -info -in /opt/zts/conf/ca.pkcs12
###############

display_usage() {
    echo "aws_zts_truststore_gen.sh [bucket name] [trust store path]";
    echo "example: aws_zts_truststore_gen.sh oath-aws-athenz-sys-auth-certsign-us-west-2 /opt/zts/conf/ca.pkcs12"
}

cleanup() {
    rm -f /tmp/service_x509_ca_certs
    rm -f split_cacert-*
}

if [  $# -ne 2 ]
then
    display_usage
    exit 1
fi

cleanup

# define our S3 bucket filenames. we'll be using the same names
# when we store files locally

ca_certs_file=service_x509_ca_certs
pwd_file=service_x509_store_pwd

bucket_name=$1
trust_store_path=$2

# download CA certs from s3 bucket
# aws s3 client will automatically decrypt the data

aws s3 cp s3://$bucket_name/$ca_certs_file /tmp/$ca_certs_file

# extract the password the truststore

aws s3 cp s3://$bucket_name/$pwd_file /tmp/$pwd_file
trust_store_pass=`cat /tmp/$pwd_file`

# split the CA certs and add them to the truststore

csplit -f split_cacert- -s -z /tmp/$ca_certs_file '/^-----BEGIN CERTIFICATE-----/' {*}
CERT_FILES=split_cacert-*
for file in $CERT_FILES
do
  echo "Processing $file file..."
  keytool -import -noprompt -alias $file -keystore $trust_store_path -file $file -storepass $trust_store_pass
  rc=$?; if [[ $rc != 0 ]]; then cleanup; exit $rc; fi
done

cleanup

echo "successfully generated trust store"
