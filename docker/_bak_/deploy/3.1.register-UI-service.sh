#!/bin/sh

# to script directory
cd "$(dirname "$0")"

# to ${PROJECT_ROOT}/docker
cd ../

# variables
USER_TOKEN_PATH=${USER_TOKEN_PATH:-"`pwd`/deploy-scripts/user-token.txt"}
[[ -r "${USER_TOKEN_PATH}" ]] && N_TOKEN_PATH="${USER_TOKEN_PATH}"
N_TOKEN_PATH=${N_TOKEN_PATH:-"`pwd`/deploy-scripts/n-token.txt"}
DOCKER_NETWORK=${DOCKER_NETWORK:-athenz}
ZMS_HOST=${ZMS_HOST:-athenz-zms-server}
ZMS_PORT=${ZMS_PORT:-4443}
CLI_STATIC_IP=${CLI_STATIC_IP:-172.21.255.254}

# confirm zms version
printf "\n"
docker run --rm --name athenz-zms-cli athenz-zms-cli version

# add athenz.ui-server service to ZMS
printf "\nWill add domain \"athenz\"...\n"
docker run --rm --network="${DOCKER_NETWORK}" \
  --ip "${CLI_STATIC_IP}" \
  -v "${N_TOKEN_PATH}:/etc/token/ntoken" \
  -v "`pwd`/zms/var/certs/zms_cert.pem:/etc/certs/zms_cert.pem" \
  --name athenz-zms-cli athenz-zms-cli \
  -f /etc/token/ntoken -i user.admin \
  -z "https://${ZMS_HOST}:${ZMS_PORT}/zms/v1" -c /etc/certs/zms_cert.pem \
  add-domain athenz admin
printf "\nWill add service \"athenz.ui-server\"...\n"
docker run --rm --network="${DOCKER_NETWORK}" \
  --ip "${CLI_STATIC_IP}" \
  -v "${N_TOKEN_PATH}:/etc/token/ntoken" \
  -v "`pwd`/zms/var/certs/zms_cert.pem:/etc/certs/zms_cert.pem" \
  -v "`pwd`/ui/var/keys/athenz.ui-server_pub.pem:/etc/certs/athenz.ui-server_pub.pem" \
  --name athenz-zms-cli athenz-zms-cli \
  -f /etc/token/ntoken \
  -z "https://${ZMS_HOST}:${ZMS_PORT}/zms/v1" -c /etc/certs/zms_cert.pem \
  -d athenz add-service ui-server 0 /etc/certs/athenz.ui-server_pub.pem

# verify domain
printf "\nWill show domain \"athenz\"...\n"
docker run --rm --network="${DOCKER_NETWORK}" \
  --ip "${CLI_STATIC_IP}" \
  -v "${N_TOKEN_PATH}:/etc/token/ntoken" \
  -v "`pwd`/zms/var/certs/zms_cert.pem:/etc/certs/zms_cert.pem" \
  --name athenz-zms-cli athenz-zms-cli \
  -f /etc/token/ntoken \
  -z "https://${ZMS_HOST}:${ZMS_PORT}/zms/v1" -c /etc/certs/zms_cert.pem \
  show-domain athenz
