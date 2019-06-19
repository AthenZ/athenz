FROM golang:1.10-alpine AS builder

ENV APP_NAME rdl-gen-athenz-server

RUN set -eux \
    && apk --no-cache add --virtual build-dependencies cmake g++ make unzip curl upx git

WORKDIR ${GOPATH}/src/github.com/yahoo/athenz/rdl/rdl-gen-athenz-server

RUN go get -u github.com/ardielle/ardielle-go/... \
    && go get -u github.com/ardielle/ardielle-tools/... \
    && mv ${GOPATH}/bin/rdl /usr/bin/rdl

COPY . .

RUN CGO_ENABLED=1 \
    CGO_CXXFLAGS="-g -Ofast -march=native" \
    CGO_FFLAGS="-g -Ofast -march=native" \
    CGO_LDFLAGS="-g -Ofast -march=native" \
    GOOS=$(go env GOOS) \
    GOARCH=$(go env GOARCH) \
    go build --ldflags '-s -w -linkmode "external" -extldflags "-static -fPIC -m64 -pthread -std=c++11 -lstdc++"' -a -tags "cgo netgo" -installsuffix "cgo netgo" -o "${APP_NAME}" \
    && upx -9 -o "/usr/bin/${APP_NAME}" "${APP_NAME}"

RUN apk del build-dependencies --purge \
    && rm -rf "${GOPATH}"

# Start From Scratch For Running Environment
FROM scratch
LABEL maintainer "yusukato <yusukato@yahoo-corp.jp>"

ENV APP_NAME rdl-gen-athenz-server

COPY --from=builder /usr/bin/${APP_NAME} /usr/bin/${APP_NAME}
COPY --from=builder /usr/bin/rdl /usr/bin/rdl
