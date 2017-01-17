#
# Makefile to build ZMS Go client utility
# Prerequisite: Go development environment
#
# Copyright 2016 Yahoo Inc.
# Licensed under the Apache License, Version 2.0 - http://www.apache.org/licenses/LICENSE-2.0
#

PKG_DATE=$(shell date '+%Y-%m-%dT%H:%M:%S')
BINARY=zms-cli
SRC=zms-cli.go

.PHONY: linux darwin
all: linux darwin

darwin:
	@echo "Building darwin client"
	GOOS=darwin go build -ldflags "-X main.VERSION=$(PKG_VERSION) -X main.BUILD_DATE=$(PKG_DATE)" -o target/darwin/$(BINARY) $(SRC)

linux:
	@echo "Building linux client"
	GOOS=linux go build -ldflags "-X main.VERSION=$(PKG_VERSION) -X main.BUILD_DATE=$(PKG_DATE)" -o target/linux/$(BINARY) $(SRC)

clean::
	rm -rf target
