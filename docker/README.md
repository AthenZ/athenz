# setups
```bash
# 1. generate server certificates
sh ./gen-certs.sh

# 2. build docker images
cd ..; make build-docker; cd -;

# 3. run dockers
# alternative: using make file
mkdir -p `pwd`/logs/zms
mkdir -p `pwd`/logs/zts
make run-docker
# alternative: using docker stack
mkdir -p ./logs/zms
mkdir -p ./logs/zts
docker stack deploy -c docker-stack.yaml athenz

# 4. add ZTS public key to ZMS
sh register-ZTS-to-ZMS.sh

# 5. generate athenz.conf for ZTS
# athenz-conf -i user.admin -t https://localhost:8443 -z https://localhost:4443

# 6. restart ZTS
# alternative: using make file
docker ps -a | grep athenz_zts-server | awk '{print $1}' | xargs docker restart
# alternative: using docker stack
ZTS_SERVICE=`docker stack services -qf "name=athenz_zts-server" athenz`
docker service update --force $ZTS_SERVICE

# 7. stop
# alternative: using make file
make clean-docker
rm -rf ./logs
# alternative: using docker stack
docker stack rm athenz
rm -rf ./logs
```

## pending issues
1. docker network setup for DB

## useful commands
```bash
docker stack ps athenz
less ./logs/zms/server.log
less ./logs/zts/server.log

sudo systemctl restart docker

# check connectivity
apk add curl
curl localhost:4443/zms/v1 -o -
curl localhost:3306 -o -
telnet localhost 4443
```
### note for production
- remove `RUN apk add linux-pam` in the docker file
