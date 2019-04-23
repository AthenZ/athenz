FROM golang:1.12-alpine AS builder

ENV APP_NAME athenz-cli

RUN set -eux \
    && apk --no-cache add --virtual build-dependencies cmake g++ make unzip curl upx git

WORKDIR ${GOPATH}/src/github.com/yahoo/athenz/

COPY . .

RUN go get ./...
RUN go build ./...
RUN go install ./...
