#!/bin/sh

# to script directory
cd "$(dirname "$0")"

# to project root
cd ../..

# variables
DOCKER_NETWORK=${DOCKER_NETWORK:-host}
USER_TOKEN_PATH=${USER_TOKEN_PATH:-"`pwd`/docker/deploy-scripts/user-token.txt"}
ZMS_ADMIN_PASS=${ZMS_ADMIN_PASS:-replace_me_with_a_strong_passowrd}

# get ZMS container info.
ZMS_CONTAINER=`docker ps -aqf "name=zms-server"`
ZMS_IP=`docker inspect -f "{{ .NetworkSettings.Networks.${DOCKER_NETWORK}.IPAddress }}" ${ZMS_CONTAINER}`
ZMS_IP=${ZMS_IP:-127.0.0.1}

# add linux-pam and Athenz domain admin user
printf "\nWill install linux-pam to ZMS container for using UserAuthority...\n"
docker exec "$ZMS_CONTAINER" apk add --no-cache --update openssl linux-pam

printf "\nWill add Athenz domain admin user to ZMS container...\n"
docker exec "$ZMS_CONTAINER" addgroup -S athenz-admin
docker exec "$ZMS_CONTAINER" adduser -s /sbin/nologin -G athenz-admin -S -D -H admin
docker exec -e "ZMS_ADMIN_PASS=${ZMS_ADMIN_PASS}" "$ZMS_CONTAINER" \
  sh -c 'echo "admin:${ZMS_ADMIN_PASS}" | chpasswd'

# get user token for admin user
curl --silent -k -u "admin:${ZMS_ADMIN_PASS}" "https://${ZMS_IP}:4443/zms/v1/user/_self_/token" \
  | sed 's/^{"token":"//' | sed 's/"}$//' \
  > ${USER_TOKEN_PATH}
rc=$?; if [[ $rc != 0 ]]; then exit $rc; else printf "\nUser token of admin saved in ${USER_TOKEN_PATH}\n"; fi
