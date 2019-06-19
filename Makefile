build-docker:
	docker build -t wait-for-mysql -f docker/deploy-scripts/common/wait-for-mysql/Dockerfile docker/deploy-scripts/common/wait-for-mysql
	docker build -t rdl-athenz-server -f docker/util/rdl-athenz-server/Dockerfile rdl/rdl-gen-athenz-server
	docker build -t athenz-mvn-base -f docker/util/athenz-mvn-base/Dockerfile .
	docker build -t athenz-builder -f docker/util/athenz-builder/Dockerfile .
	docker build -t athenz-zms-server -f docker/zms/Dockerfile .
	docker build -t athenz-zts-server -f docker/zts/Dockerfile .
	docker build -t athenz-ui -f docker/ui/Dockerfile ui
	docker build -t athenz-zms-db -f docker/db/zms/Dockerfile servers/zms/schema
	docker build -t athenz-zts-db -f docker/db/zts/Dockerfile servers/zts/schema
	docker build -t athenz-zms-cli -f docker/util/zms-cli/Dockerfile .
	docker build -t athenz-cli-util -f docker/util/Dockerfile .

setup-dev:
	sh docker/setup-scripts/AIO.dev.sh

run-zms-dev:
	sh docker/deploy-scripts/1.1.deploy-ZMS.sh
	sh docker/deploy-scripts/1.2.config-zms-domain-admin.dev.sh
run-zts:
	sh docker/deploy-scripts/2.1.register-ZTS-service.sh
	sh docker/deploy-scripts/2.2.create-athenz-conf.sh
	sh docker/deploy-scripts/2.3.deploy-ZTS.sh
run-ui:
	sh docker/deploy-scripts/3.1.register-UI-service.sh
	sh docker/deploy-scripts/3.2.deploy-UI.sh

run-docker-dev: run-zms-dev run-zts run-ui

remove-docker:
	docker ps -a | grep athenz- | awk '{print $$1}' | xargs docker stop
	docker ps -a | grep athenz- | awk '{print $$1}' | xargs docker rm

remove-files:
	sudo rm -rf ./docker/logs
	sudo rm -rf ./docker/zts/var/zts_store

remove-all: remove-docker remove-files
