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

run-docker:
	sh docker/deploy-scripts/1.deploy-ZMS.sh
	sh docker/deploy-scripts/2.register-ZTS-to-ZMS.dev.sh
	sh docker/deploy-scripts/3.deploy-ZTS.sh
	sh docker/deploy-scripts/4.register-UI-to-ZMS.dev.sh
	sh docker/deploy-scripts/5.deploy-UI.sh

remove-docker:
	docker ps -a | grep athenz- | awk '{print $$1}' | xargs docker stop
	docker ps -a | grep athenz- | awk '{print $$1}' | xargs docker rm

remove-log:
	rm -rf ./docker/logs

remove-all: remove-docker remove-log
