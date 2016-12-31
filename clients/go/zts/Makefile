RDL_FILE=../../../core/zts/src/main/rdl/ZTS.rdl
RDL_LIB=github.com/ardielle/ardielle-go/rdl

export GOPATH=$(PWD)

all: model.go client.go build

build: src/$(RDL_LIB)

src/$(RDL_LIB):
	go get $(RDL_LIB)

model.go: $(RDL_FILE)
	rdl -ps generate -t -o $@ go-model $(RDL_FILE)

client.go: $(RDL_FILE)
	rdl -ps generate -t -o $@ go-client $(RDL_FILE)

clean::
	rm -rf model.go client.go zts_schema.go *~ ./src
