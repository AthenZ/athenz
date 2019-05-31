## pending issues
1. athenz ui not config-ed

# setups
```bash
# 0. back to project root
cd ..

# 1. generate server certificates
sh ./docker/gen-certs.sh

# 2. build docker images
make build-docker

# 3. run dockers
# alternative: using make file
mkdir -p `pwd`/docker/logs/zms
mkdir -p `pwd`/docker/logs/zts
make run-docker
# alternative: using docker stack
mkdir -p `pwd`/docker/logs/zms
mkdir -p `pwd`/docker/logs/zts
docker stack deploy -c ./docker/docker-stack.yaml athenz

# 4. add ZTS public key to ZMS
sh ./docker/register-ZTS-to-ZMS.sh

# 5. generate athenz.conf for ZTS
docker run -it --network=host \
  -v `pwd`/docker/zts/conf/athenz.conf:/tmp/athenz.conf \
  --name athenz-cli-util athenz-cli-util \
  ./utils/athenz-conf/target/linux/athenz-conf \
  -i user.admin -t https://localhost:8443 -z https://localhost:4443 \
  -k -o /tmp/athenz.conf \
  ; docker rm athenz-cli-util;

# 6. restart ZTS
# alternative: using make file
docker ps -a | grep athenz-zts-server | awk '{print $1}' | xargs docker restart
# alternative: using docker stack
ZTS_SERVICE=`docker stack services -qf "name=athenz_zts-server" athenz`
docker service update --force $ZTS_SERVICE

# 7. stop
# alternative: using make file
make clean-docker
rm -rf ./docker/logs
# alternative: using docker stack
docker stack rm athenz
rm -rf ./docker/logs
```

## about UI set up
```bash
# add athenz.ui service to ZMS
docker run -it --net=host \
    -v `pwd`/docker/zms/var/certs/zms_cert.pem:/etc/certs/zms_cert.pem \
    --name athenz-zms-cli athenz-zms-cli \
    -i user.admin -z https://localhost:4443/zms/v1 -c /etc/certs/zms_cert.pem \
    add-domain athenz admin \
    ; docker rm athenz-zms-cli
docker run -it --net=host \
    -v `pwd`/docker/zms/var/certs/zms_cert.pem:/etc/certs/zms_cert.pem \
    -v `pwd`/docker/ui/keys/athenz.ui_pub.pem:/etc/certs/athenz.ui_pub.pem \
    --name athenz-zms-cli athenz-zms-cli \
    -i user.admin -z https://localhost:4443/zms/v1 -c /etc/certs/zms_cert.pem \
    -d athenz add-service ui-server 0 /etc/certs/athenz.ui_pub.pem \
    ; docker rm athenz-zms-cli
docker run -it --net=host \
    -v `pwd`/docker/zms/var/certs/zms_cert.pem:/etc/certs/zms_cert.pem \
    --name athenz-zms-cli athenz-zms-cli \
    -i user.admin -z https://localhost:4443/zms/v1 -c /etc/certs/zms_cert.pem \
    show-domain athenz \
    ; docker rm athenz-zms-cli

# run the UI docker
docker run -d -h localhost \
    --network=host -p 9443 \
    -v `pwd`/docker/zts/conf/athenz.conf:/opt/athenz/ui/config/athenz.conf \
    -v `pwd`/docker/ui/keys:/opt/athenz/ui/keys \
    -e ZMS_SERVER=`hostname` \
    -e UI_SERVER=`hostname` \
    --name athenz-ui athenz-ui
```

## useful commands
```bash
docker stack ps athenz
less ./docker/logs/zms/server.log
less ./docker/logs/zts/server.log

sudo systemctl restart docker

# check connectivity
apk add curl
curl localhost:4443/zms/v1 -o -
curl localhost:3306 -o -
telnet localhost 4443

# mysql
mysql -v -u root --password=mariadb --host=127.0.0.1 --port=3306
mysql -v -u root --password=mariadb --host=127.0.0.1 --port=3307
```
### note for production
- remove `RUN apk add linux-pam` in the docker file
