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

.PHONY: source linux darwin
all: source linux darwin

endif

else

all:
	@echo "go is not available please install golang"

endif

source:
	@echo "Getting dependency packages..."
	go get github.com/ardielle/ardielle-go/rdl
	go get github.com/boynton/repl
	go get golang.org/x/crypto/ssh/terminal
	go get golang.org/x/net/proxy
	go get gopkg.in/yaml.v2

darwin:
	@echo "Building darwin client..."
	GOOS=darwin go build -ldflags "-X main.VERSION=$(PKG_VERSION) -X main.BUILD_DATE=$(PKG_DATE)" -o target/darwin/$(BINARY) $(SRC)

linux:
	@echo "Building linux client..."
	GOOS=linux go build -ldflags "-X main.VERSION=$(PKG_VERSION) -X main.BUILD_DATE=$(PKG_DATE)" -o target/linux/$(BINARY) $(SRC)

clean:
	rm -rf target
