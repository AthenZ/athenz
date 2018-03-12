#
# Makefile to build ZPE Updater Go utility
# Prerequisite: Go development environment
# Company name: Yahoo Holdings,Inc.
# Copyright 2017 Yahoo Holdings, Inc.
# Licensed under the Apache License, Version 2.0 - http://www.apache.org/licenses/LICENSE-2.0
#

GOPKGNAME = github.com/yahoo/athenz/utils/zpe-updater
PKG_DATE=$(shell date '+%Y-%m-%dT%H:%M:%S')
BINARY=zpu
SRC=cmd/tools/main.go
FMT_LOG=/tmp/zpu-fmt.log
IMPORTS_LOG=/tmp/zpu-imports.log

# check to see if go utility is installed
GO := $(shell command -v go 2> /dev/null)
export GOPATH=$(PWD)

ifdef GO

# we need to make sure we have go 1.7+
# the output for the go version command is:
# go version go1.7.3 darwin/amd64

GO_VER_GTEQ7 := $(shell expr `go version | cut -f 3 -d' ' | cut -f2 -d.` \>= 7)
ifneq "$(GO_VER_GTEQ7)" "1"
all:
	@echo "Please install 1.7.x or newer version of golang"
else

.PHONY: source vet fmt imports linux darwin unit
all: source vet fmt imports linux darwin unit

endif

else

all:
	@echo "go is not available please install golang"

endif

init: source

test: unit

build : linux

source:
	@echo "Cleanup up local GOPATH src directory..."
	rm -rf src
	@echo "Setting up the source code..."
	mkdir -p /tmp/zpu-go-build/src/$(GOPKGNAME)
	cp -r * /tmp/zpu-go-build/src/$(GOPKGNAME)/.
	mv /tmp/zpu-go-build/src .
	@echo "Copying local source files..."
	mkdir -p $(GOPATH)/src/github.com/yahoo/athenz/clients/go
	cp -r ../../clients/go/zts $(GOPATH)/src/github.com/yahoo/athenz/clients/go
	cp -r ../../clients/go/zms $(GOPATH)/src/github.com/yahoo/athenz/clients/go
	mkdir -p $(GOPATH)/src/github.com/yahoo/athenz/libs/go
	cp -r ../../libs/go/zmssvctoken $(GOPATH)/src/github.com/yahoo/athenz/libs/go
	cp -r ../../libs/go/ztsclientutil $(GOPATH)/src/github.com/yahoo/athenz/libs/go
	@echo "Getting dependency packages..."
	go get -t -d -tags testing $(GOPKGNAME)/...

vet:
	go vet $(GOPKGNAME)/...

fmt:
	go list $(GOPKGNAME)/... | sed "s:^:$(GOPATH)/src/:" | xargs gofmt -d >$(FMT_LOG)
	@if [ -s $(FMT_LOG) ]; then echo gofmt FAIL; cat $(FMT_LOG); false; fi

imports:
	go get golang.org/x/tools/cmd/goimports
	go list $(GOPKGNAME)/... | sed "s:^:$(GOPATH)/src/:" | xargs $(GOPATH)/bin/goimports -d >$(IMPORTS_LOG)
	@if [ -s $(IMPORTS_LOG) ]; then echo goimports FAIL; cat $(IMPORTS_LOG); false; fi

unit: vet fmt
	go test -v $(GOPKGNAME)/...

darwin:
	@echo "Building darwin client..."
	GOOS=darwin go build -ldflags "-X main.VERSION=$(PKG_VERSION) -X main.BUILD_DATE=$(PKG_DATE)" $(GOPKGNAME)/...
	GOOS=darwin go build -ldflags "-X main.VERSION=$(PKG_VERSION) -X main.BUILD_DATE=$(PKG_DATE)" -o target/darwin/$(BINARY) $(SRC)

linux:
	@echo "Building linux client..."
	GOOS=linux go build -ldflags "-X main.VERSION=$(PKG_VERSION) -X main.BUILD_DATE=$(PKG_DATE)" $(GOPKGNAME)/...
	GOOS=linux go build -ldflags "-X main.VERSION=$(PKG_VERSION) -X main.BUILD_DATE=$(PKG_DATE)" -o target/linux/$(BINARY) $(SRC)

clean:
	rm -rf target src bin pkg /tmp/zpu-go-build $(FMT_LOG) $(IMPORTS_LOG)
