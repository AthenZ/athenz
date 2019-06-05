FROM maven:3-alpine AS mvn

RUN mvn -v
COPY . .
RUN mvn help:evaluate -Dexpression=project.version -q -DforceStdout > PKG_VERSION
# RUN cat pom.xml | grep "<version>.*</version>" | head -1 | awk -F'[><]' '{print $3}'

FROM golang:1.12-alpine AS builder

# install build dependency
RUN set -eux \
    && apk --no-cache add --virtual build-dependencies cmake g++ make unzip curl upx git

# project variables
ENV APP_NAME=zts-rolecert
ENV GOPKGNAME=github.com/yahoo/athenz/utils/zts-rolecert
ENV BINARY=zts-rolecert
ENV SRC=zts-rolecert.go

WORKDIR ${GOPATH}/src/github.com/yahoo/athenz
COPY . .

WORKDIR ${GOPATH}/src/github.com/yahoo/athenz/utils/zts-rolecert
COPY --from=mvn PKG_VERSION .

RUN GO111MODULE=on \
    CGO_ENABLED=1 \
    CGO_CXXFLAGS="-g -Ofast -march=native" \
    CGO_FFLAGS="-g -Ofast -march=native" \
    CGO_LDFLAGS="-g -Ofast -march=native" \
    GOOS=$(go env GOOS) \
    GOARCH=$(go env GOARCH) \
    PKG_DATE=$(shell date '+%Y-%m-%dT%H:%M:%S') \
    PKG_VERSION=$(cat PKG_VERSION) \
    go build --ldflags '-s -w -linkmode "external" -extldflags "-static -fPIC -m64 -pthread -std=c++11 -lstdc++"'"-X main.VERSION=${PKG_VERSION} -X main.BUILD_DATE=${PKG_DATE}" -a -tags "cgo netgo" -installsuffix "cgo netgo" -o "${APP_NAME}" ${SRC} \
    && upx -9 -o "/usr/bin/${APP_NAME}" "${APP_NAME}"

RUN apk del build-dependencies --purge \
    && rm -rf "${GOPATH}"

# Start From Scratch For Running Environment
FROM scratch

ENV APP_NAME=zts-rolecert
COPY --from=builder /usr/bin/${APP_NAME} /usr/bin/${APP_NAME}

# docker build -t athenz-cli-zts-rolecert -f docker/util/zts-rolecert/Dockerfile .
# docker run --name athenz-cli-zts-rolecert athenz-cli-zts-rolecert /usr/bin/zts-rolecert -help; docker rm athenz-cli-zts-rolecert
