#
# Makefile to build ZPE Node.js client code
# Prerequisite: Node.JS development environment
#
# Licensed under the Apache License, Version 2.0 - http://www.apache.org/licenses/LICENSE-2.0
#

# check to see if npm is installed
NPM := $(shell command -v npm 2> /dev/null)

ifdef NPM

all:
	npm install
	$(PWD)/node_modules/grunt-cli/bin/grunt

else

all:
	@echo "npm is not available please install npm"

endif

clean:
	rm -rf build node_modules artifacts
