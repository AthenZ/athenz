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

# confirm the user token is valid
printf "\nWill show Athenz admin domain...\n"
docker run --rm --network="${DOCKER_NETWORK}" \
  --ip "${CLI_STATIC_IP}" \
  -v "${N_TOKEN_PATH}:/etc/token/ntoken" \
  -v "`pwd`/zms/var/certs/zms_cert.pem:/etc/certs/zms_cert.pem" \
  --name athenz-zms-cli athenz-zms-cli \
  -f /etc/token/ntoken \
  -z "https://${ZMS_HOST}:${ZMS_PORT}/zms/v1" -c /etc/certs/zms_cert.pem \
  -d sys.auth show-role admin

# add ZTS service to ZMS
printf "\nWill register ZTS service public key to ZMS...\n"
docker run --rm --network="${DOCKER_NETWORK}" \
  --ip "${CLI_STATIC_IP}" \
  -v "${N_TOKEN_PATH}:/etc/token/ntoken" \
  -v "`pwd`/zms/var/certs/zms_cert.pem:/etc/certs/zms_cert.pem" \
  -v "`pwd`/zts/var/keys/zts_public.pem:/etc/certs/zts_public.pem" \
  --name athenz-zms-cli athenz-zms-cli \
  -f /etc/token/ntoken \
  -z "https://${ZMS_HOST}:${ZMS_PORT}/zms/v1" -c /etc/certs/zms_cert.pem \
  -d sys.auth add-service zts 0 /etc/certs/zts_public.pem
