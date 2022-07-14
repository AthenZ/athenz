#
# Makefile to build ZTS Role Token client utility
# Prerequisite: Go development environment
#
# Copyright 2017 Yahoo Holdings, Inc.
# Licensed under the Apache License, Version 2.0 - http://www.apache.org/licenses/LICENSE-2.0
#

GOPKGNAME = github.com/AthenZ/athenz/libs/go/ztsroletoken

# check to see if go utility is installed
GO := $(shell command -v go 2> /dev/null)
GOPATH := $(shell pwd)
export $(GOPATH)

ifdef GO

# we need to make sure we have go 1.18+
# the output for the go version command is:
# go version go1.18.4 darwin/amd64

GO_VER_GTEQ := $(shell expr `go version | cut -f 3 -d' ' | cut -f2 -d.` \>= 18)
ifneq "$(GO_VER_GTEQ)" "1"
all:
	@echo "Please install 1.18.x or newer version of golang"
else

.PHONY: vet fmt build test
all: vet fmt build test

endif

else

all:
	@echo "go is not available please install golang"

endif

vet:
	go vet .

fmt:
	gofmt -l .

build:
	@echo "Building ztsroletoken library..."
	go install -v $(GOPKGNAME)

test:
	go test -v $(GOPKGNAME)

clean:
	rm -rf target
