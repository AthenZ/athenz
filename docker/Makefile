build:
	docker build -t wait-for-mysql -f ./deploy-scripts/common/wait-for-mysql/Dockerfile ./deploy-scripts/common/wait-for-mysql
	docker build -t rdl-athenz-server -f ./util/rdl-athenz-server/Dockerfile ../rdl/rdl-gen-athenz-server
	docker build -t athenz-mvn-base -f ./util/athenz-mvn-base/Dockerfile ../
	docker build -t athenz-builder -f ./util/athenz-builder/Dockerfile ../
	docker build -t athenz-zms-server -f ./zms/Dockerfile ../
	docker build -t athenz-zts-server -f ./zts/Dockerfile ../
	docker build -t athenz-ui -f ./ui/Dockerfile ../ui
	docker build -t athenz-zms-db -f ./db/zms/Dockerfile ../servers/zms/schema
	docker build -t athenz-zts-db -f ./db/zts/Dockerfile ../servers/zts/schema
	docker build -t athenz-zms-cli -f ./util/zms-cli/Dockerfile ../
	docker build -t athenz-cli-util -f ./util/Dockerfile ../

setup-dev-config:
	sh ./setup-scripts/all-in-one.dev.sh
setup-docker-network:
	docker network create --subnet 172.21.0.0/16 $${DOCKER_NETWORK:-athenz}

run-docker-dev: run-zms-dev run-zts run-ui
run-zms-dev:
	sh ./deploy-scripts/1.1.deploy-ZMS.sh
	sh ./deploy-scripts/1.2.config-zms-domain-admin.dev.sh
	echo '"run-zms-dev" step DONE!'
run-zts:
	sh ./deploy-scripts/2.1.register-ZTS-service.sh
	sh ./deploy-scripts/2.2.create-athenz-conf.sh
	sh ./deploy-scripts/2.3.deploy-ZTS.sh
	echo '"run-zms" step DONE!'
run-ui:
	sh ./deploy-scripts/3.1.register-UI-service.sh
	sh ./deploy-scripts/3.2.deploy-UI.sh
	echo '"run-ui" step DONE!'

remove-all: remove-containers remove-networks remove-files
remove-containers:
	docker ps -a | grep athenz- | awk '{print $$1}' | xargs docker stop
	docker ps -a | grep athenz- | awk '{print $$1}' | xargs docker rm
remove-networks:
	docker network rm $${DOCKER_NETWORK:-athenz}
remove-files:
	sudo rm -rf ./logs
	sudo rm -rf ./zts/var/zts_store

clean: remove-all
	docker image rm wait-for-mysql
	docker image rm rdl-athenz-server
	docker image rm athenz-mvn-base
	docker image rm athenz-builder
	docker image rm athenz-zms-server
	docker image rm athenz-zts-server
	docker image rm athenz-ui
	docker image rm athenz-zms-db
	docker image rm athenz-zts-db
	docker image rm athenz-zms-cli
	docker image rm athenz-cli-util
