#!/bin/sh

# Determine our run-time directory

BINDIR=$(dirname "$0")
ROOT=$(cd $BINDIR/..;pwd)

if [ $# != 2 ] ; then
  echo "usage: setup_dev_ui.sh <zms-hostname> <zms-public-cert-path>"
  exit 1
fi

ZMS_HOSTNAME=$1
ZMS_CERT=$2

if [ ! -f $ZMS_CERT ] ; then
  echo "unable to access zms public certificate: $ZMS_CERT"
  exit 1
fi

# Generate Athenz UI Server Private Key

echo "Generating private key for Athenz UI Server..."
cd $ROOT/keys
openssl genrsa -out athenz.ui.pem 2048
openssl rsa -in athenz.ui.pem -pubout > athenz.ui_pub.pem

# Generate a self-signed x509 certificate

echo "Generating a self signed certificate for Athenz UI Server..."

UI_HOSTNAME=$(hostname)
sed s/__athenz_hostname__/$UI_HOSTNAME/g ./dev_x509_cert.cnf > ./dev_ui_x509_cert.cnf
openssl req -x509 -nodes -newkey rsa:2048 -keyout ui_key.pem -out ui_cert.pem -days 365 -config ./dev_ui_x509_cert.cnf

# Register Athenz UI Server in ZMS Server

echo "Registering UI Service in Athenz..."
cd $ROOT
HOST_PLATFORM=$(uname | tr '[:upper:]' '[:lower:]')
cp $ZMS_CERT $ROOT/keys/zms_cert.pem
$ROOT/bin/$HOST_PLATFORM/zms-cli -c $ROOT/keys/zms_cert.pem -z https://$ZMS_HOSTNAME:4443/zms/v1 add-domain athenz
$ROOT/bin/$HOST_PLATFORM/zms-cli -c $ROOT/keys/zms_cert.pem -z https://$ZMS_HOSTNAME:4443/zms/v1 -d athenz add-service ui 0 $ROOT/keys/athenz.ui_pub.pem

echo "Athenz UI Dev Enviornment setup complete"
