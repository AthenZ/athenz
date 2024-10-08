#
# Makefile to generate ZTS Go client and model code
# based on the ZTS RDL files. 
# Prerequisite: Go development environment
#
# Copyright The Athenz Authors
# Licensed under the Apache License, Version 2.0: http://www.apache.org/licenses/LICENSE-2.0
#

RDL_FILE=../../../core/zts/src/main/rdl/ZTS.rdl

# check to see if go utility is installed
GO := $(shell command -v go 2> /dev/null)
export GOPATH ?= /tmp/go

# we're not going to generate our code during our automated builds since
# builds must be done based on files already checked-in into git

CICD := $(or ${GITHUB_ACTIONS},${SCREWDRIVER},${TRAVIS_PULL_REQUEST},${TRAVIS_TAG})

ifdef CICD

all:
	@echo "ci/cd pipeline - code generation skipped"

clean:

else

ifdef GO

all: build model.go client.go

clean:
	rm -rf model.go client.go zts_schema.go *~ ./src

else

all:
	@echo "go is not available please install golang"

clean:

endif

endif

build:
	go install github.com/ardielle/ardielle-tools/rdl@latest

model.go: $(RDL_FILE)
	$(GOPATH)/bin/rdl -ps generate -t -o $@ go-model $(RDL_FILE)

client.go: $(RDL_FILE)
	$(GOPATH)/bin/rdl -ps generate -t -o $@ athenz-go-client $(RDL_FILE)

