# GID and UID of the default athenz:athenz user inside the container
GID=$(DOCKER_GID)
UID=$(DOCKER_UID)
GID_ARG := $(if $(GID),--build-arg GID=$(GID),--build-arg GID)
UID_ARG := $(if $(UID),--build-arg UID=$(UID),--build-arg UID)

DOCKER_DNS := $(if $(DOCKER_DNS),$(DOCKER_DNS),8.8.8.8)
DOCKER_NETWORK := $(if $(DOCKER_NETWORK),$(DOCKER_NETWORK),athenz)
BASE_DIR=$(shell git rev-parse --show-toplevel)

BUILD_DATE=$(shell date -u +'%Y-%m-%dT%H:%M:%SZ')
VCS_REF=$(shell git rev-parse --short HEAD)
BUILD_ARG := --build-arg 'BUILD_DATE=$(BUILD_DATE)' --build-arg 'VCS_REF=$(VCS_REF)'

# specify build version by git tag
ifdef TAG
TAG_COMMIT := $(shell git rev-list -n 1 $(TAG))
ifeq ($(TAG_COMMIT),)
	$(error TAG=$(TAG) is not found)
	exit 1
endif
endif

build:
ifneq ($(TAG_COMMIT),)
	$(info Build using TAG=$(TAG), TAG_COMMIT=$(TAG_COMMIT))
	git checkout $(TAG_COMMIT)
else
	$(info Build using current source code)
endif
	DOCKER_BUILDKIT=1 docker build $(BUILD_ARG) -t rdl-athenz-server -f ./util/rdl-athenz-server/Dockerfile ../rdl/rdl-gen-athenz-server
	DOCKER_BUILDKIT=1 docker build $(BUILD_ARG) -t rdl-athenz-java-model -f ./util/rdl-athenz-java-model/Dockerfile ../rdl/rdl-gen-athenz-java-model
	DOCKER_BUILDKIT=1 docker build $(BUILD_ARG) -t athenz-mvn-base -f ./util/athenz-mvn-base/Dockerfile ../
	DOCKER_BUILDKIT=1 docker build $(BUILD_ARG) -t athenz-builder -f ./util/athenz-builder/Dockerfile ../
	DOCKER_BUILDKIT=1 docker build $(BUILD_ARG) $(GID_ARG) $(UID_ARG) -t athenz-zms-server -f ./zms/Dockerfile ../
	DOCKER_BUILDKIT=1 docker build $(BUILD_ARG) $(GID_ARG) $(UID_ARG) -t athenz-zts-server -f ./zts/Dockerfile ../
	DOCKER_BUILDKIT=1 docker build $(BUILD_ARG) $(GID_ARG) $(UID_ARG) -t athenz-ui -f ./ui/Dockerfile ../ui
	DOCKER_BUILDKIT=1 docker build $(BUILD_ARG) -t athenz-zms-db -f ./db/zms/Dockerfile ../servers/zms/schema
	DOCKER_BUILDKIT=1 docker build $(BUILD_ARG) -t athenz-zts-db -f ./db/zts/Dockerfile ../servers/zts/schema
	DOCKER_BUILDKIT=1 docker build $(BUILD_ARG) -t athenz-conf -f ./util/athenz-conf/Dockerfile ../
	DOCKER_BUILDKIT=1 docker build $(BUILD_ARG) -t athenz-setup-env -f ./setup-scripts/Dockerfile ../
	# DOCKER_BUILDKIT=1 docker build -t athenz-cli-util -f ./util/Dockerfile ../
ifneq ($(TAG_COMMIT),)
	git checkout -
endif

deploy-dev:
	# generate self-signed certificates
	docker run --rm -t -v "$(BASE_DIR):/athenz" --user "$(shell id -u):$(shell id -g)" athenz-setup-env sh /athenz/docker/setup-scripts/self-signed-certificates.sh
	# ZMS
	docker run --rm -t -v "$(BASE_DIR):/athenz" --user "$(shell id -u):$(shell id -g)" athenz-setup-env sh /athenz/docker/setup-scripts/zms-auto-config.sh
	sh "./deploy-scripts/zms-deploy.sh"
	docker run --rm -t --network="$(DOCKER_NETWORK)" -v "$(BASE_DIR):/athenz" --user "$(shell id -u):$(shell id -g)" athenz-setup-env sh /athenz/docker/deploy-scripts/zms-debug.sh
	# ZTS
	docker run --rm -t --network="$(DOCKER_NETWORK)" -v "$(BASE_DIR):/athenz" --user "$(shell id -u):$(shell id -g)" athenz-setup-env sh /athenz/docker/setup-scripts/zts-auto-config.sh
	sh "./deploy-scripts/zts-deploy.sh"
	docker run --rm -t --network="$(DOCKER_NETWORK)" -v "$(BASE_DIR):/athenz" --user "$(shell id -u):$(shell id -g)" athenz-setup-env sh /athenz/docker/deploy-scripts/zts-debug.sh

deploy-local:
	# generate self-signed certificates
	docker run --rm -t -v "$(BASE_DIR):/athenz" --user "$(shell id -u):$(shell id -g)" athenz/athenz-setup-env:1.9.22 sh /athenz/docker/setup-scripts/self-signed-certificates.sh
	# ZMS
	docker run --rm -t -v "$(BASE_DIR):/athenz" --user "$(shell id -u):$(shell id -g)" athenz/athenz-setup-env:1.9.22 sh /athenz/docker/setup-scripts/zms-auto-config.sh
	sh "./deploy-scripts/zms-deploy-local.sh"
	docker run --rm -t --network="$(DOCKER_NETWORK)" -v "$(BASE_DIR):/athenz" --user "$(shell id -u):$(shell id -g)" athenz/athenz-setup-env:1.9.22 sh /athenz/docker/deploy-scripts/zms-debug.sh
	# ZTS
	docker run --rm -t --network="$(DOCKER_NETWORK)" -v "$(BASE_DIR):/athenz" --user "$(shell id -u):$(shell id -g)" athenz/athenz-setup-env:1.9.22 sh /athenz/docker/setup-scripts/zts-auto-config.sh
	sh "./deploy-scripts/zts-deploy-local.sh"
	docker run --rm -t --network="$(DOCKER_NETWORK)" -v "$(BASE_DIR):/athenz" --user "$(shell id -u):$(shell id -g)" athenz/athenz-setup-env:1.9.22 sh /athenz/docker/deploy-scripts/zts-debug.sh
	# UI
	docker run --rm -t --network="$(DOCKER_NETWORK)" -v "$(BASE_DIR):/athenz" --user "$(shell id -u):$(shell id -g)" athenz/athenz-setup-env:1.9.22 sh /athenz/docker/setup-scripts/ui-auto-config.sh
	sh "./deploy-scripts/ui-deploy-local.sh"


verify:
	docker run --rm -t --network="$(DOCKER_NETWORK)" -v "$(BASE_DIR):/athenz" --user "$(shell id -u):$(shell id -g)" athenz-setup-env sh /athenz/docker/deploy-scripts/zms-verify.sh
	docker run --rm -t --network="$(DOCKER_NETWORK)" -v "$(BASE_DIR):/athenz" --user "$(shell id -u):$(shell id -g)" athenz-setup-env sh /athenz/docker/deploy-scripts/zts-verify.sh

verify-local:
	docker run --rm -t --network="$(DOCKER_NETWORK)" -v "$(BASE_DIR):/athenz" --user "$(shell id -u):$(shell id -g)" athenz/athenz-setup-env:1.9.22 sh /athenz/docker/deploy-scripts/zms-verify.sh
	docker run --rm -t --network="$(DOCKER_NETWORK)" -v "$(BASE_DIR):/athenz" --user "$(shell id -u):$(shell id -g)" athenz/athenz-setup-env:1.9.22 sh /athenz/docker/deploy-scripts/zts-verify.sh

CONTAINERS := $(shell docker ps -aq --filter 'label=org.label-schema.url=https://www.athenz.io/')
remove-all: remove-containers remove-networks remove-files reset-repo
remove-containers:
ifneq ($(CONTAINERS),)
	docker stop $(shell docker ps -aq --filter 'label=org.label-schema.url=https://www.athenz.io/')
	docker rm $(shell docker ps -aq --filter 'label=org.label-schema.url=https://www.athenz.io/')
else
	$(info No containers to be removed.)
endif
remove-networks:
	docker network rm $(DOCKER_NETWORK) || true
remove-files:
	rm -rf ./logs
	rm -rf ./zts/var/zts_store
reset-repo:
	git reset --hard HEAD
	git clean -fdx

clean: remove-all
	docker image rm rdl-athenz-server || true
	docker image rm athenz-mvn-base || true
	docker image rm athenz-builder || true
	docker image rm athenz-zms-server || true
	docker image rm athenz-zts-server || true
	docker image rm athenz-ui || true
	docker image rm athenz-zms-db || true
	docker image rm athenz-zts-db || true
	docker image rm athenz-conf || true
	docker image rm athenz-setup-env || true
	docker image rm rdl-athenz-java-model || true

remove-local-images:
	docker image rm athenz/athenz-setup-env:1.9.22 || true
	docker image rm athenz/athenz-zms-db:1.9.22 || true
	docker image rm athenz/athenz-zms-server:1.9.22 || true
	docker image rm athenz/athenz-zts-db:1.9.22 || true
	docker image rm athenz/athenz-zts-server:1.9.22 || true
	docker image rm athenz/athenz-ui:1.9.22 || true