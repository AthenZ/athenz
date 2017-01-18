#
# Makefile to generate ZMS Go client and model code
# based on the ZMS RDL files. 
# Prerequisite: Go development environment
#
# Copyright 2016 Yahoo Inc.
# Licensed under the Apache License, Version 2.0: http://www.apache.org/licenses/LICENSE-2.0
#

RDL_FILE=../../../core/zms/src/main/rdl/ZMS.rdl
RDL_LIB=github.com/ardielle/ardielle-go/rdl

# check to see if go utility is installed
GO := $(shell command -v go 2> /dev/null)
export GOPATH=$(PWD)

ifdef GO

all: build model.go client.go

clean:
	rm -rf model.go client.go zms_schema.go *~ ./src

else

all:
	@echo "go is not available please install golang"

clean:

endif

build: src/$(RDL_LIB)

src/$(RDL_LIB):
	go get $(RDL_LIB)
	go get github.com/ardielle/ardielle-tools/...

model.go: $(RDL_FILE)
	$(GOPATH)/bin/rdl -ps generate -t -o $@ go-model $(RDL_FILE)

client.go: $(RDL_FILE)
	$(GOPATH)/bin/rdl -ps generate -t -o $@ go-client $(RDL_FILE)

