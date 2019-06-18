#!/bin/sh

# to script directory
cd "$(dirname "$0")"

# to project root
cd ../..

ZMS_CONTAINER=`docker ps -aqf "name=zms-server"`
ZMS_ADMIN_PASS=${ZMS_ADMIN_PASS:-replace_me_with_a_strong_passowrd}

# add linux-pam and admin user for Athenz
echo "Will add Athenz admin user to ZMS container..."
docker exec $ZMS_CONTAINER apk add --no-cache --update openssl linux-pam
docker exec $ZMS_CONTAINER addgroup -S athenz-admin
docker exec $ZMS_CONTAINER adduser -s /sbin/nologin -G athenz-admin -S -D -H admin
docker exec -e ZMS_ADMIN_PASS=${ZMS_ADMIN_PASS} $ZMS_CONTAINER sh -c 'echo "admin:${ZMS_ADMIN_PASS}" | chpasswd'

# confirm zms version
docker run --rm --name athenz-zms-cli athenz-zms-cli version

# confirm the target user belongs to the admin role
docker run --rm -it --net=host \
  -e ZMS_ADMIN_PASS=${ZMS_ADMIN_PASS} \
  -v `pwd`/docker/zms/var/certs/zms_cert.pem:/etc/certs/zms_cert.pem \
  --name athenz-zms-cli athenz-zms-cli \
  -i user.admin -z https://localhost:4443/zms/v1 -c /etc/certs/zms_cert.pem \
  -d sys.auth show-role admin

# add public key to ZMS
docker run --rm -it --net=host \
  -v `pwd`/docker/zms/var/certs/zms_cert.pem:/etc/certs/zms_cert.pem \
  -v `pwd`/docker/zts/var/keys/zts_public.pem:/etc/certs/zts_public.pem \
  --name athenz-zms-cli athenz-zms-cli \
  -i user.admin -z https://localhost:4443/zms/v1 -c /etc/certs/zms_cert.pem \
  -d sys.auth add-service zts 0 /etc/certs/zts_public.pem
