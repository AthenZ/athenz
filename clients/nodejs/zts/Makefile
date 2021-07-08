#
# Makefile to build ZTS Node.js client code
# based on the ZTS json file. 
# Prerequisite: Node.JS development environment
#
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
	@echo "Make: Build"
	npm install

lint:
	@echo "Make: lint"
	npm run ci-lint

test:
	@echo "Make: unit tests"
	npm run test

clean:
	rm -rf node_modules artifacts
