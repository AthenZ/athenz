#!/bin/sh

ZMS_CONTAINER=`docker ps -aqf "name=zms-server"`

docker exec $ZMS_CONTAINER addgroup -S athenz-admin
docker exec $ZMS_CONTAINER adduser -s /sbin/nologin -G athenz-admin -S -D -H admin
docker exec $ZMS_CONTAINER sh -c 'echo "admin:12345678" | chpasswd'

# confirm zms version
docker run --name athenz-zms-cli athenz-zms-cli version; docker rm athenz-zms-cli

# confirm the target user belongs to the admin role
docker rm athenz-zms-cli; docker run -it --net=host \
  --name athenz-zms-cli athenz-zms-cli \
  -i admin -k -z https://localhost:4443/zms/v1 -d sys.auth show-role admin; docker rm athenz-zms-cli

# add public key to ZMS
docker run -it --net=host \
  -v `pwd`/zms/var/certs/zms_cert.pem:/etc/certs/zms_cert.pem \
  -v `pwd`/zts/var/keys/zts_public.pem:/etc/certs/zts_public.pem \
  --name athenz-zms-cli athenz-zms-cli \
  -i admin -z https://localhost:4443/zms/v1 -c /etc/certs/zms_cert.pem \
  -d sys.auth add-service zts 0 /etc/certs/zts_public.pem; docker rm athenz-zms-cli
