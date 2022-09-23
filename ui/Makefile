#
# Makefile to build Athenz UI
# Prerequisite: Node.JS development environment
#
# Copyright The Athenz Authors
# Licensed under the Apache License, Version 2.0 - http://www.apache.org/licenses/LICENSE-2.0
#

# check to see if npm is installed
NPM := $(shell command -v npm 2> /dev/null)

ifdef NPM

.PHONY: build lint test
all: build lint test
else

all:
	@echo "npm is not available please install npm"

endif

build:
	@echo "Athenz UI -- Build"
	npm install
	npm run build

lint:
	@echo "Athenz UI -- lint"
	npm run ci-lint

test:
	@echo "Athenz UI -- unit tests"
	npm run test

clean:
	rm -rf node_modules artifacts
