#!/bin/sh

# to script directory
cd "$(dirname "$0")"

# to ${PROJECT_ROOT}/docker
cd ../

# variables
DOCKER_NETWORK=${DOCKER_NETWORK:-athenz}
USER_TOKEN_PATH=${USER_TOKEN_PATH:-"`pwd`/deploy-scripts/user-token.txt"}
ZMS_ADMIN_PASS=${ZMS_ADMIN_PASS:-replace_me_with_a_strong_password}
ZMS_HOST=${ZMS_HOST:-athenz-zms-server}
ZMS_PORT=${ZMS_PORT:-4443}
CLI_STATIC_IP=${CLI_STATIC_IP:-172.21.255.254}

# get ZMS container info.
ZMS_CONTAINER=`docker ps -aqf "name=zms-server"`

# add linux-pam and Athenz domain admin user
printf "\nWill install linux-pam to ZMS container for using UserAuthority...\n"
docker exec "$ZMS_CONTAINER" apk add --no-cache --update openssl linux-pam

printf "\nWill add Athenz domain admin user to ZMS container...\n"
docker exec "$ZMS_CONTAINER" addgroup -S athenz-admin
docker exec "$ZMS_CONTAINER" adduser -s /sbin/nologin -G athenz-admin -S -D -H admin
docker exec -e "ZMS_ADMIN_PASS=${ZMS_ADMIN_PASS}" "$ZMS_CONTAINER" \
  sh -c 'echo "admin:${ZMS_ADMIN_PASS}" | chpasswd'

# get user token for admin user
set -o pipefail
docker run --rm --entrypoint curl \
  --ip "${CLI_STATIC_IP}" \
  --network="${DOCKER_NETWORK}" \
  --name athenz-curl appropriate/curl \
  -k --silent -u "admin:${ZMS_ADMIN_PASS}" \
  "https://${ZMS_HOST}:${ZMS_PORT}/zms/v1/user/_self_/token" \
  | sed 's/^{"token":"//' | sed 's/"}$//' \
  > ${USER_TOKEN_PATH}
rc=$?; if [[ $rc != 0 ]]; then exit $rc; else printf "\nUser token of admin saved in ${USER_TOKEN_PATH}\n"; fi
