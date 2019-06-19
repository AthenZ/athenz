#!/bin/sh

# to script directory
cd "$(dirname "$0")"

# to project root
cd ../..

# variables
DOCKER_NETWORK=${DOCKER_NETWORK:-host}
UI_PK_PATH=${UI_PK_PATH:-./docker/ui/var/certs/ui_key.pem}
UI_X509_OUT_PATH=${UI_X509_OUT_PATH:-./docker/ui/var/certs/ui_cert.pem}
UI_SERVICE_PK_PATH=${UI_SERVICE_PK_PATH:-./docker/ui/var/keys/athenz.ui-server.pem}
UI_SERVICE_PUB_PATH=${UI_SERVICE_PUB_PATH:-./docker/ui/var/keys/athenz.ui-server_pub.pem}

# start UI
printf "\nWill start Athenz UI...\n"
docker run -d -h localhost \
  --network="${DOCKER_NETWORK}" \
  -v "`pwd`/docker/zts/conf/athenz.conf:/opt/athenz/ui/config/athenz.conf" \
  -v "`pwd`/${UI_PK_PATH}:/opt/athenz/ui/keys/ui_key.pem" \
  -v "`pwd`/${UI_X509_OUT_PATH}:/opt/athenz/ui/keys/ui_cert.pem" \
  -v "`pwd`/${UI_SERVICE_PK_PATH}:/opt/athenz/ui/keys/$(basename $UI_SERVICE_PK_PATH)" \
  -v "`pwd`/${UI_SERVICE_PUB_PATH}:/opt/athenz/ui/keys/$(basename $UI_SERVICE_PUB_PATH)" \
  -e "ZMS_SERVER=`hostname`" \
  -e "UI_SERVER=`hostname`" \
  --name athenz-ui athenz-ui
