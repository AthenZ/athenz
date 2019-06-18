#!/bin/sh

# to script directory
cd "$(dirname "$0")"

# to project root
cd ../..

# variables
USER_TOKEN_PATH=${USER_TOKEN_PATH:-"`pwd`/docker/deploy-scripts/user-token.txt"}
[[ -r "${USER_TOKEN_PATH}" ]] && N_TOKEN_PATH="${USER_TOKEN_PATH}"
N_TOKEN_PATH=${N_TOKEN_PATH:-"`pwd`/docker/deploy-scripts/n-token.txt"}
DOCKER_NETWORK=${DOCKER_NETWORK:-host}

# get ZMS container info.
ZMS_CONTAINER=`docker ps -aqf "name=zms-server"`
ZMS_IP=`docker inspect -f "{{ .NetworkSettings.Networks.${DOCKER_NETWORK}.IPAddress }}" ${ZMS_CONTAINER}`
ZMS_IP=${ZMS_IP:-127.0.0.1}

# confirm zms version
printf "\n"
docker run --rm --name athenz-zms-cli athenz-zms-cli version

# add athenz.ui-server service to ZMS
printf "\nWill add domain \"athenz\"...\n"
docker run --rm --network="${DOCKER_NETWORK}" \
  -v "${N_TOKEN_PATH}:/etc/token/ntoken" \
  -v "`pwd`/docker/zms/var/certs/zms_cert.pem:/etc/certs/zms_cert.pem" \
  --name athenz-zms-cli athenz-zms-cli \
  -f /etc/token/ntoken -i user.admin \
  -z "https://${ZMS_IP}:4443/zms/v1" -c /etc/certs/zms_cert.pem \
  add-domain athenz admin
printf "\nWill add service \"athenz.ui-server\"...\n"
docker run --rm --network="${DOCKER_NETWORK}" \
  -v "${N_TOKEN_PATH}:/etc/token/ntoken" \
  -v "`pwd`/docker/zms/var/certs/zms_cert.pem:/etc/certs/zms_cert.pem" \
  -v "`pwd`/docker/ui/var/keys/athenz.ui-server_pub.pem:/etc/certs/athenz.ui-server_pub.pem" \
  --name athenz-zms-cli athenz-zms-cli \
  -f /etc/token/ntoken \
  -z "https://${ZMS_IP}:4443/zms/v1" -c /etc/certs/zms_cert.pem \
  -d athenz add-service ui-server 0 /etc/certs/athenz.ui-server_pub.pem

# verify domain
printf "\nWill show domain \"athenz\"...\n"
docker run --rm --network="${DOCKER_NETWORK}" \
  -v "${N_TOKEN_PATH}:/etc/token/ntoken" \
  -v "`pwd`/docker/zms/var/certs/zms_cert.pem:/etc/certs/zms_cert.pem" \
  --name athenz-zms-cli athenz-zms-cli \
  -f /etc/token/ntoken \
  -z "https://${ZMS_IP}:4443/zms/v1" -c /etc/certs/zms_cert.pem \
  show-domain athenz
