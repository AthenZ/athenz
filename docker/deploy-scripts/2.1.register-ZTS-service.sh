#!/bin/sh

# to script directory
cd "$(dirname "$0")"

# to project root
cd ../..

# variables
USER_TOKEN_PATH=${USER_TOKEN_PATH:-"`pwd`/user-token.txt"}
[[ -r "${USER_TOKEN_PATH}" ]] && N_TOKEN_PATH="${USER_TOKEN_PATH}"
N_TOKEN_PATH=${N_TOKEN_PATH:-"`pwd`/n-token.txt"}
DOCKER_NETWORK=${DOCKER_NETWORK:-host}
ZMS_ADMIN_PASS=${ZMS_ADMIN_PASS:-replace_me_with_a_strong_passowrd}

# get ZMS container info.
ZMS_CONTAINER=`docker ps -aqf "name=zms-server"`
ZMS_IP=`docker inspect -f "{{ .NetworkSettings.Networks.${DOCKER_NETWORK}.IPAddress }}" ${ZMS_CONTAINER}`
ZMS_IP=${ZMS_IP:-127.0.0.1}

# confirm zms version
printf "\n"
docker run --rm --name athenz-zms-cli athenz-zms-cli version

# confirm the user token is valid
printf "\nWill show Athenz admin domain...\n"
docker run --rm -it --net=host \
  -v "${N_TOKEN_PATH}:/etc/token/ntoken" \
  -v "`pwd`/docker/zms/var/certs/zms_cert.pem:/etc/certs/zms_cert.pem" \
  --name athenz-zms-cli athenz-zms-cli \
  -f /etc/token/ntoken \
  -z "https://${ZMS_IP}:4443/zms/v1" -c /etc/certs/zms_cert.pem \
  -d sys.auth show-role admin

# add ZTS service to ZMS
printf "\nWill register ZTS service public key to ZMS...\n"
docker run --rm -it --net=host \
  -v "${N_TOKEN_PATH}:/etc/token/ntoken" \
  -v "`pwd`/docker/zms/var/certs/zms_cert.pem:/etc/certs/zms_cert.pem" \
  -v "`pwd`/docker/zts/var/keys/zts_public.pem:/etc/certs/zts_public.pem" \
  --name athenz-zms-cli athenz-zms-cli \
  -f /etc/token/ntoken \
  -z "https://${ZMS_IP}:4443/zms/v1" -c /etc/certs/zms_cert.pem \
  -d sys.auth add-service zts 0 /etc/certs/zts_public.pem
