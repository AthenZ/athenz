### [WIP] Deploy with docker-stack
```bash
cd `git rev-parse --show-toplevel`/docker

# 1. set passwords (P.S. values in *.properties files will overwrite these values)
source ./setup-scripts/0.export-default-passwords.sh

# 2. generate key-pairs, certificates and keystore/truststore
make setup-dev-config

# 3. docker network variables
export DOCKER_DNS=${DOCKER_DNS:-8.8.8.8}
export DOCKER_NETWORK=${DOCKER_NETWORK:-athenz}
export ZMS_DB_HOST=${ZMS_DB_HOST:-athenz-zms-db}
export ZMS_DB_PORT=${ZMS_DB_PORT:-3306}
export ZMS_HOST=${ZMS_HOST:-athenz-zms-server}
export ZMS_PORT=${ZMS_PORT:-4443}
export ZTS_DB_HOST=${ZTS_DB_HOST:-athenz-zts-db}
export ZTS_DB_PORT=${ZTS_DB_PORT:-3307}
export ZTS_HOST=${ZTS_HOST:-athenz-zts-server}
export ZTS_PORT=${ZTS_PORT:-8443}
export UI_HOST=${UI_HOST:-athenz-ui-server}
export UI_PORT=${UI_PORT:-443}

# 4. start docker stack (some components will fail, don't panic)
mkdir -p ./logs/zms
mkdir -p ./logs/zts
docker stack deploy -c ./docker-stack.yaml athenz

# (optional) restart ZMS service if DB is not ready during start up
rm -f ./logs/zms/server.log
ZMS_SERVICE=`docker stack services -qf "name=athenz_zms-server" athenz`
docker service update --force $ZMS_SERVICE
docker ps -qa -f "label=com.docker.swarm.service.name=athenz_zms-server" -f status=exited | xargs docker rm -f

# 5.1. setup ZMS for ZTS
sh ./deploy-scripts/1.2.config-zms-domain-admin.dev.sh
sh ./deploy-scripts/2.1.register-ZTS-service.sh
sh ./deploy-scripts/2.2.create-athenz-conf.sh
# 5.2. restart ZTS service to apply the new setting
rm -f ./logs/zts/server.log
ZTS_SERVICE=`docker stack services -qf "name=athenz_zts-server" athenz`
docker service update --force $ZTS_SERVICE
docker ps -qa -f "label=com.docker.swarm.service.name=athenz_zts-server" -f status=exited | xargs docker rm -f

# 6.1. setup ZMS for UI
sh ./deploy-scripts/3.1.register-UI-service.sh
# 6.2. restart UI service to apply the new setting
UI_SERVICE=`docker stack services -qf "name=athenz_ui" athenz`
docker service update --force $UI_SERVICE
docker ps -qa -f "label=com.docker.swarm.service.name=athenz_ui" -f status=exited | xargs docker rm -f
```
```bash
# debug docker stack
docker stack ps athenz
less ./logs/zms/server.log
less ./logs/zts/server.log

# reset docker stack
docker stack rm athenz
rm -rf ./logs

# restart docker
sudo systemctl restart docker
```
