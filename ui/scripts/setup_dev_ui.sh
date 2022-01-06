#!/usr/bin/env bash

# Determine our run-time directory

BINDIR=$(dirname "$0")
ROOT=$(cd "$BINDIR"/.. || true;pwd)

if [ $# != 4 ] ; then
  echo "usage: setup_dev_ui.sh <zms-hostname> <zms-public-cert-path> <admin-username> <admin-fullname>"
  exit 1
fi

ZMS_HOSTNAME=$1
ZMS_CERT=$2
ADMIN_USERNAME=$3
ADMIN_FULLNAME=$4

if [ ! -f "$ZMS_CERT" ] ; then
  echo "unable to access zms public certificate: $ZMS_CERT"
  exit 1
fi

# Generate Athenz UI Server Private Key

echo "Generating private key for Athenz UI Server..."
cd "$ROOT"/keys || true
openssl genrsa -out athenz.ui-server.pem 2048
openssl rsa -in athenz.ui-server.pem -pubout > athenz.ui-server_pub.pem

# Generate a self-signed x509 certificate

echo "Generating a self signed certificate for Athenz UI Server..."

UI_HOSTNAME=$(hostname -f)
sed s/__athenz_hostname__/"$UI_HOSTNAME"/g ./dev_x509_cert.cnf > ./dev_ui_x509_cert.cnf
openssl req -x509 -nodes -newkey rsa:2048 -keyout ui_key.pem -out ui_cert.pem -days 365 -config ./dev_ui_x509_cert.cnf

# Register Athenz UI Server in ZMS Server

echo "Registering UI Service in Athenz..."
cd $ROOT || true
HOST_PLATFORM=$(uname | tr '[:upper:]' '[:lower:]')
cp "$ZMS_CERT" "$ROOT"/keys/zms_cert.pem
"$ROOT"/bin/"$HOST_PLATFORM"/zms-cli -c "$ROOT"/keys/zms_cert.pem -z https://"$ZMS_HOSTNAME":4443/zms/v1 add-domain athenz
"$ROOT"/bin/"$HOST_PLATFORM"/zms-cli -c "$ROOT"/keys/zms_cert.pem -z https://"$ZMS_HOSTNAME":4443/zms/v1 -d athenz add-service ui-server 0 "$ROOT"/keys/athenz.ui-server_pub.pem

# Generate athenz configuration file

echo "Generating Athenz configuration file..."
"$ROOT"/bin/"$HOST_PLATFORM"/athenz-conf -o "$ROOT"/src/config/athenz.conf -c "$ROOT"/keys/zms_cert.pem -z https://"$ZMS_HOSTNAME":4443/

echo "Generating User Data file..."
sed "s/__admin__/$ADMIN_USERNAME/g; s/__fullname__/$ADMIN_FULLNAME/g" "$ROOT"/src/config/users_data_template.json > "$ROOT"/src/config/users_data.json

echo "Generating Cookie Session Secret file..."
if [ "$HOST_PLATFORM" != 'darwin' ] ; then
  cat /dev/urandom | tr -dc 'a-zA-Z0-9' | fold -w 32 | head -n 1 > "$ROOT"/keys/cookie-session
elif [ "$HOST_PLATFORM" == 'darwin' ] ; then
  cat /dev/urandom | env LC_CTYPE=C tr -dc a-zA-Z0-9 | head -c 16 > "$ROOT"/keys/cookie-session
fi

echo "Creating a dummy token file"
sudo mkdir -p /var/lib/sia/tokens/msd-api-access/ && sudo chown -R "$(id -u)":"$(id -g)" /var/lib/sia/tokens/msd-api-access
touch /var/lib/sia/tokens/msd-api-access/msd-api-access-token

echo "Athenz UI Dev Environment setup complete"
