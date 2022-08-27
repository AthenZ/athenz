# Copyright The Athenz Authors
# Licensed under the terms of the Apache version 2.0 license. See LICENSE file for terms.

# Makefile to build msd-agent Go utility

# check to see if go utility is installed
GO := $(shell command -v go 2> /dev/null)
GOPATH := $(shell pwd)
export $(GOPATH)

ifdef GO

# we need to make sure we have go 1.19+
# the output for the go version command is:
# go version go1.19 darwin/amd64

GO_VER_GTEQ := $(shell expr `go version | cut -f 3 -d' ' | cut -f2 -d.` \>= 19)
ifneq "$(GO_VER_GTEQ)" "1"
all:
	@echo "Please install 1.19.x or newer version of golang"
else

.PHONY: vet fmt linux darwin
all: unit

endif

else

all:
	@echo "go is not available please install golang"

endif

vet:
	go vet .

fmt:
	gofmt -l .

unit: vet fmt
	go test -v ./...

clean:
	rm -rf target
