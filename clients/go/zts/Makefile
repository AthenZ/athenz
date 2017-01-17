#
# Makefile to generate ZTS Go client and model code
# based on the ZTS RDL files. 
# Prerequisite: Go development environment
#
# Copyright 2016 Yahoo Inc.
# Licensed under the Apache License, Version 2.0: http://www.apache.org/licenses/LICENSE-2.0
#

RDL_FILE=../../../core/zts/src/main/rdl/ZTS.rdl
RDL_LIB=github.com/ardielle/ardielle-go/rdl

export GOPATH=$(PWD)

all: build model.go client.go

build: src/$(RDL_LIB)

src/$(RDL_LIB):
	go get $(RDL_LIB)
	go get github.com/ardielle/ardielle-tools/...

model.go: $(RDL_FILE)
	rdl -ps generate -t -o $@ go-model $(RDL_FILE)

client.go: $(RDL_FILE)
	rdl -ps generate -t -o $@ go-client $(RDL_FILE)

clean::
	rm -rf model.go client.go zts_schema.go *~ ./src
