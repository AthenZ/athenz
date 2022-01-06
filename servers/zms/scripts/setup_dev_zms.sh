#!/usr/bin/env bash

# Determine our run-time directory

BINDIR=$(dirname "$0")
ROOT=$(cd $BINDIR/..;pwd)

# Generate ZMS Server Private Key

echo "Generating private key for ZMS Server..."
cd $ROOT/var/zms_server/keys
openssl genrsa -out zms_private.pem 2048

# Generate a self-signed x509 certificate

echo "Generating a self signed certificate for ZMS Server..."
cd ../certs
HOSTNAME=$(hostname -f)
sed s/__athenz_hostname__/$HOSTNAME/g $ROOT/conf/zms_server/dev_x509_cert.cnf > ./dev_x509_cert.cnf
openssl req -x509 -nodes -newkey rsa:2048 -keyout zms_key.pem -out zms_cert.pem -days 365 -config ./dev_x509_cert.cnf

# Generate a keystore in PKCS#12 format

echo "Generating PKCS12 keystore for ZMS Server..."
openssl pkcs12 -export -out zms_keystore.pkcs12 -in zms_cert.pem -inkey zms_key.pem -noiter -password pass:athenz

echo "ZMS Dev Environment setup complete"
