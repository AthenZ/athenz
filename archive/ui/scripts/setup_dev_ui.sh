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
openssl genrsa -out athenz.ui-server.pem 2048
openssl rsa -in athenz.ui-server.pem -pubout > athenz.ui-server_pub.pem

# Generate a self-signed x509 certificate

echo "Generating a self signed certificate for Athenz UI Server..."

UI_HOSTNAME=$(hostname -f)
sed s/__athenz_hostname__/$UI_HOSTNAME/g ./dev_x509_cert.cnf > ./dev_ui_x509_cert.cnf
openssl req -x509 -nodes -newkey rsa:2048 -keyout ui_key.pem -out ui_cert.pem -days 365 -config ./dev_ui_x509_cert.cnf

# Register Athenz UI Server in ZMS Server

echo "Registering UI Service in Athenz..."
cd $ROOT
HOST_PLATFORM=$(uname | tr '[:upper:]' '[:lower:]')
cp $ZMS_CERT $ROOT/keys/zms_cert.pem
$ROOT/bin/$HOST_PLATFORM/zms-cli -c $ROOT/keys/zms_cert.pem -z https://$ZMS_HOSTNAME:4443/zms/v1 add-domain athenz
$ROOT/bin/$HOST_PLATFORM/zms-cli -c $ROOT/keys/zms_cert.pem -z https://$ZMS_HOSTNAME:4443/zms/v1 -d athenz add-service ui-server 0 $ROOT/keys/athenz.ui-server_pub.pem

# Generate athenz configuration file

echo "Generating Athenz configuration file..."
$ROOT/bin/$HOST_PLATFORM/athenz-conf -o $ROOT/config/athenz.conf -c $ROOT/keys/zms_cert.pem -z https://$ZMS_HOSTNAME:4443/

echo "Athenz UI Dev Environment setup complete"
