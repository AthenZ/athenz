#
# Makefile to build SIA Go Client library
# Prerequisite: Go development environment
#
# Copyright The Athenz Authors
# Licensed under the Apache License, Version 2.0 - http://www.apache.org/licenses/LICENSE-2.0
#

SIA_DIR = /libs/go/sia
ATHENZ_DIR = $(PWD)
ifneq ($(patsubst %$(SIA_DIR),,$(lastword $(ATHENZ_DIR))),)
	ATHENZ_DIR = $(PWD)/$(SIA_DIR)
endif

SUBDIRS = access/config access/tokens agent aws/agent aws/attestation aws/doc aws/lambda aws/meta \
	aws/options aws/sds aws/stssession file futil gcp/attestation gcp/meta gcp/functions \
	host/hostdoc host/ip host/provider host/signature host/utils logutil options pki/cert \
	sds ssh/hostcert ssh/hostkey util verify
OS = darwin linux windows

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

.PHONY: vet fmt build test
all: vet fmt build test

endif

else

all:
	@echo "go is not available please install golang"

endif

vet:
	for subdir in $(SUBDIRS); do set -e && cd $(ATHENZ_DIR) && cd $$subdir && go vet .; done

fmt:
	for subdir in $(SUBDIRS); do set -e && cd $(ATHENZ_DIR) && cd $$subdir && gofmt -l .; done

build:
	@echo "Building sia library..."
	for subdir in $(SUBDIRS); do \
		set -e && cd $(ATHENZ_DIR) && cd $$subdir; \
		for os in $(OS); do GOOS=$$os go build .; done \
	done

test:
	for subdir in $(SUBDIRS); do set -e && cd $(ATHENZ_DIR) && cd $$subdir && go test .; done

clean:
	rm -rf target
