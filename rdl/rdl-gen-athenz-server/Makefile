#
# Makefile to build Athenz Server RDL Code Generator
# Prerequisite: Go development environment
#
# Copyright 2018 Oath Inc.
# Licensed under the Apache License, Version 2.0 - http://www.apache.org/licenses/LICENSE-2.0
#

# check to see if go utility is installed

GO := $(shell command -v go 2> /dev/null)
ifndef GO
	@echo "go is not available. please install golang"
	exit 1
endif

# we need to make sure we have go 1.7+
# the output for the go version command is:
# go version go1.7.3 darwin/amd64

GO_VER_GTEQ7 := $(shell expr `go version | cut -f 3 -d' ' | cut -f2 -d.` \>= 7)
ifneq "$(GO_VER_GTEQ7)" "1"
	@echo "Please install 1.7.x or newer version of golang"
	exit 2
endif

ifndef GOPATH
	@echo "GOPATH is not set. please configure this environment variable"
	exit 3
endif

all:
	@echo "Building client..."
	go get -u github.com/ardielle/ardielle-go/...
	go build
	cp rdl-gen-athenz-server $(GOPATH)/bin/rdl-gen-athenz-server

clean:
	rm -rf rdl-gen-athenz-server
