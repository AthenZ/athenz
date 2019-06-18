#!/bin/sh

# to script directory
cd "$(dirname "$0")"

# to project root
cd ../..

# variables
DOCKER_NETWORK='host'
ZMS_ADMIN_PASS=${ZMS_ADMIN_PASS:-replace_me_with_a_strong_passowrd}

# add linux-pam and admin user for Athenz
printf "\nWill add Athenz admin user to ZMS container...\n"
ZMS_CONTAINER=`docker ps -aqf "name=zms-server"`
docker exec $ZMS_CONTAINER apk add --no-cache --update openssl linux-pam
docker exec $ZMS_CONTAINER addgroup -S athenz-admin
docker exec $ZMS_CONTAINER adduser -s /sbin/nologin -G athenz-admin -S -D -H admin
docker exec -e ZMS_ADMIN_PASS=${ZMS_ADMIN_PASS} $ZMS_CONTAINER sh -c 'echo "admin:${ZMS_ADMIN_PASS}" | chpasswd'

# confirm zms version
printf "\n"
docker run --rm --name athenz-zms-cli athenz-zms-cli version

# confirm the target user belongs to the admin role
printf "\nMembers of Athenz admin\n"
ZMS_IP=`docker inspect -f "{{ .NetworkSettings.Networks.${DOCKER_NETWORK}.IPAddress }}" ${ZMS_CONTAINER}`
ZMS_IP=${ZMS_IP:-127.0.0.1}
USER_TOKEN_PATH="/tmp/user-token.`date +%s`.txt"
curl --silent -k -u "admin:${ZMS_ADMIN_PASS}" https://localhost:4443/zms/v1/user/_self_/token | sed 's/^{"token":"//' | sed 's/"}$//' > ${USER_TOKEN_PATH}
docker run --rm -it --net=host \
  -v ${USER_TOKEN_PATH}:/etc/token/user-token \
  -v `pwd`/docker/zms/var/certs/zms_cert.pem:/etc/certs/zms_cert.pem \
  --name athenz-zms-cli athenz-zms-cli \
  -f /etc/token/user-token \
  -z https://${ZMS_IP}:4443/zms/v1 -c /etc/certs/zms_cert.pem \
  -d sys.auth show-role admin

# add ZTS public key to ZMS
printf "\nRegister ZTS public key to ZMS\n"
docker run --rm -it --net=host \
  -v `pwd`/docker/zms/var/certs/zms_cert.pem:/etc/certs/zms_cert.pem \
  -v `pwd`/docker/zts/var/keys/zts_public.pem:/etc/certs/zts_public.pem \
  --name athenz-zms-cli athenz-zms-cli \
  -f /etc/token/user-token \
  -z https://localhost:4443/zms/v1 -c /etc/certs/zms_cert.pem \
  -d sys.auth add-service zts 0 /etc/certs/zts_public.pem
