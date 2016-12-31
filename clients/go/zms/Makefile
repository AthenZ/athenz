RDL_FILE=../../../core/zms/src/main/rdl/ZMS.rdl
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
	rm -rf model.go client.go zms_schema.go *~ ./src
