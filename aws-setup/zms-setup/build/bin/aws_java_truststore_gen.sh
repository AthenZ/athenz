#!/bin/bash
#############
# Usage: aws_java_truststore_gen.sh [jdk-ca-certs-path] [jdk-ca-certs-pwd] [bucket name] [trust store path]
# Downloads CA certs from S3 bucket. Creates pkcs12 truststore for jetty.
# Check for generated truststore: openssl pkcs12 -info -in /opt/zms/conf/ca.pkcs12
###############

display_usage() {
    echo "aws_java_truststore_gen.sh [jdk-ca-certs-path] [jdk-ca-certs-pwd] [bucket name] [trust store path]";
    echo "example: aws_java_truststore_gen.sh /opt/jvm/cacerts changeit oath-aws-athenz-sys-auth-certsign-us-west-2 /opt/zms/conf/ca.pkcs12"
}

cleanup() {
    rm -f /tmp/service_rds_ca_certs
    rm -f split_cacert-*
}

if [  $# -ne 4 ]
then
    display_usage
    exit 1
fi

cleanup

# define our S3 bucket filenames. we'll be using the same names
# when we store files locally

rds_ca_certs=service_rds_ca_certs

jdk_ca_certs_path=$1
jdk_ca_certs_pwd=$2
bucket_name=$3
trust_store_path=$4

# download RDS CA certs from s3 bucket
# aws s3 client will automatically decrypt the data

aws s3 cp s3://$bucket_name/$rds_ca_certs /tmp/$rds_ca_certs

# first copy the jdk ca certs into our given filename

cp $jdk_ca_certs_path $trust_store_path
rc=$?; if [[ $rc != 0 ]]; then cleanup; exit $rc; fi
chmod u+w $trust_store_path

# split the CA certs and add them to the truststore

csplit -f split_cacert- -s -z /tmp/$rds_ca_certs '/^-----BEGIN CERTIFICATE-----/' {*}
CERT_FILES=split_cacert-*
for file in $CERT_FILES
do
  echo "Processing $file file..."
  keytool -import -noprompt -alias $file -keystore $trust_store_path -file $file -storepass $jdk_ca_certs_pwd
  rc=$?; if [[ $rc != 0 ]]; then cleanup; exit $rc; fi
done

cleanup

echo "successfully generated trust store"
