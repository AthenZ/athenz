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
ZTS_HOST=${ZTS_HOST:-athenz-zts-server}
ZTS_PORT=${ZTS_PORT:-8443}
CLI_STATIC_IP=${CLI_STATIC_IP:-172.21.255.254}

# confirm zms version
printf "\n"
docker run --rm --name athenz-zms-cli athenz-zms-cli version

# confirm the user token is valid
printf "\nWill create athenz.conf...\n"
docker run --rm --network="${DOCKER_NETWORK}" \
  --ip "${CLI_STATIC_IP}" \
  -v "${N_TOKEN_PATH}:/etc/token/ntoken" \
  -v "`pwd`/zms/var/certs/zms_cert.pem:/etc/certs/zms_cert.pem" \
  -v "`pwd`/zts/conf:/tmp" \
  --name athenz-cli-util athenz-cli-util \
  ./utils/athenz-conf/target/linux/athenz-conf \
  -f /etc/token/ntoken \
  -z "https://${ZMS_HOST}:${ZMS_PORT}" -c /etc/certs/zms_cert.pem \
  -t "https://${ZTS_HOST}:${ZTS_PORT}" \
  -o /tmp/athenz.conf
