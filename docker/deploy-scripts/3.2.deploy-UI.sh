#!/bin/sh

# to script directory
cd "$(dirname "$0")"

# to ${PROJECT_ROOT}/docker
cd ../

# variables
DOCKER_NETWORK=${DOCKER_NETWORK:-athenz}
UI_PK_PATH=${UI_PK_PATH:-./ui/var/certs/ui_key.pem}
UI_X509_OUT_PATH=${UI_X509_OUT_PATH:-./ui/var/certs/ui_cert.pem}
UI_SERVICE_PK_PATH=${UI_SERVICE_PK_PATH:-./ui/var/keys/athenz.ui-server.pem}
UI_SERVICE_PUB_PATH=${UI_SERVICE_PUB_PATH:-./ui/var/keys/athenz.ui-server_pub.pem}
UI_HOST=${UI_HOST:-athenz-ui-server}
UI_PORT=${UI_PORT:-443}
ZMS_HOST=${ZMS_HOST:-athenz-zms-server}
ZMS_PORT=${ZMS_PORT:-4443}

# start UI
printf "\nWill start Athenz UI...\n"
docker run -d -h ${UI_HOST} \
  -p "${UI_PORT}:${UI_PORT}" \
  --network="${DOCKER_NETWORK}" \
  --user athenz:athenz \
  -v "`pwd`/zts/conf/athenz.conf:/opt/athenz/ui/config/athenz.conf" \
  -v "`pwd`/${UI_PK_PATH}:/opt/athenz/ui/keys/ui_key.pem" \
  -v "`pwd`/${UI_X509_OUT_PATH}:/opt/athenz/ui/keys/ui_cert.pem" \
  -v "`pwd`/${UI_SERVICE_PK_PATH}:/opt/athenz/ui/keys/$(basename $UI_SERVICE_PK_PATH)" \
  -v "`pwd`/${UI_SERVICE_PUB_PATH}:/opt/athenz/ui/keys/$(basename $UI_SERVICE_PUB_PATH)" \
  -e "ZMS_SERVER_URL=https://${ZMS_HOST}:${ZMS_PORT}/zms/v1/" \
  -e "ZMS_AJAX_URL=https://${HOSTNAME}:${ZMS_PORT}/zms/v1/" \
  -e "UI_SERVER=${HOSTNAME}" \
  --name athenz-ui athenz-ui
