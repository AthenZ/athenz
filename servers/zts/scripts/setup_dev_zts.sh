#!/bin/sh

# Determine our run-time directory

BINDIR=$(dirname "$0")
ROOT=$(cd $BINDIR/..;pwd)

if [ $# != 2 ] ; then
  echo "usage: setup_dev_zts.sh <zms-hostname> <zms-public-cert-path>"
  exit 1
fi

ZMS_HOSTNAME=$1
ZMS_CERT=$2

if [ ! -f $ZMS_CERT ] ; then
  echo "unable to access zms public certificate: $ZMS_CERT"
  exit 1
fi

# Generate ZTS Server Private Key

echo "Generating private key for ZTS Server..."
cd $ROOT/var/zts_server/keys
openssl genrsa -out zts_private.pem 2048
openssl rsa -in zts_private.pem -pubout > zts_public.pem

# Generate a self-signed x509 certificate

echo "Generating a self signed certificate for ZTS Server..."
cd ../certs
ZTS_HOSTNAME=$(hostname -f)
sed s/__athenz_hostname__/$ZTS_HOSTNAME/g $ROOT/conf/zts_server/dev_x509_cert.cnf > ./dev_x509_cert.cnf
openssl req -x509 -nodes -newkey rsa:2048 -keyout zts_key.pem -out zts_cert.pem -days 365 -config ./dev_x509_cert.cnf

# Generate a keystore in PKCS#12 format

echo "Generating PKCS12 keystore for ZTS Server..."
rm -rf zts_keystore.pkcs12
openssl pkcs12 -export -out zts_keystore.pkcs12 -in zts_cert.pem -inkey zts_key.pem -noiter -password pass:athenz

# Generate a truststore in JKS format

echo "Generating JKS truststore for ZTS Server..."
rm -rf zts_truststore.jks
cp $ZMS_CERT $ROOT/var/zts_server/certs/zms_cert.pem
keytool -importcert -noprompt -alias zms -keystore zts_truststore.jks -file zms_cert.pem -storepass athenz

# Register ZTS Server in ZMS Server

echo "Registering ZTS Service in Athenz..."
cd $ROOT
HOST_PLATFORM=$(uname | tr '[:upper:]' '[:lower:]')
$ROOT/bin/$HOST_PLATFORM/zms-cli -c $ROOT/var/zts_server/certs/zms_cert.pem -z https://$ZMS_HOSTNAME:4443/zms/v1 -d sys.auth add-service zts 0 $ROOT/var/zts_server/keys/zts_public.pem

# Generate athenz configuration file

echo "Generating Athenz configuration file..."
$ROOT/bin/$HOST_PLATFORM/athenz-conf -o $ROOT/conf/zts_server/athenz.conf -c $ROOT/var/zts_server/certs/zms_cert.pem -z https://$ZMS_HOSTNAME:4443/ -t https://$ZTS_HOSTNAME:8443/

echo "ZTS Dev Environment setup complete"
