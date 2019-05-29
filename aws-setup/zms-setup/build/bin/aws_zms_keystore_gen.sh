#!/bin/bash
#############
# Usage: aws_zms_keystore_gen.sh [bucket name] [key store path]
# Downloads encrypted server.key and server.cert from private S3 bucket.
# Decrypts and creates pkcs12 keystore for jetty.
# Assumes that this script runs on an instance with a role that has policy
# set to allow kms decrypt and read access to private S3 bucket.
# Check for generated keystore: openssl pkcs12 -info -in jetty.pkcs12
###############

display_usage() {
    echo "aws_zms_keystore_gen.sh [bucket name] [key store path]";
    echo "example: aws_zms_keystore_gen.sh oath-aws-athenz-sys-auth-zms-prod-data-us-west-2 jetty.pkcs12"
}

cleanup() {
    rm -f /tmp/service_x509_*
}

if [  $# -ne 2 ]
then
    display_usage
    exit 1
fi

cleanup

# define our S3 bucket filenames. we'll be using the same names
# when we store files locally

key_file=service_x509_key
cert_file=service_x509_cert
pwd_file=service_x509_store_pwd

bucket_name=$1
key_store_path=$2

# download server cert and key from private s3 bucket
# aws s3 client will automatically decrypt the data

aws s3 cp s3://$bucket_name/$key_file /tmp/$key_file
aws s3 cp s3://$bucket_name/$cert_file /tmp/$cert_file

# extract the password the keystore

aws s3 cp s3://$bucket_name/$pwd_file /tmp/$pwd_file
key_store_pass=`cat /tmp/$pwd_file`

# generate pkcs12 keystore using openssl

openssl pkcs12 -export -inkey /tmp/$key_file -in /tmp/$cert_file -out $key_store_path -password pass:$key_store_pass -noiter -nomaciter
openssl_status=$?

cleanup

if [ ! $openssl_status -eq 0 ]; then
    echo "failed to generate key store"
    exit 1
fi

echo "successfully generated key store"

