FROM golang:1.14-alpine AS builder

ENV APP_NAME rdl-gen-athenz-server

RUN set -eux \
    && apk --no-cache add --virtual build-dependencies libgcc libstdc++ cmake g++ make unzip curl upx git

WORKDIR ${GOPATH}/src/github.com/AthenZ/athenz/rdl/rdl-gen-athenz-server

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
# date -u +'%Y-%m-%dT%H:%M:%SZ'
ARG BUILD_DATE
# git rev-parse --short HEAD
ARG VCS_REF

LABEL org.label-schema.schema-version="1.0"
LABEL org.label-schema.build-date=$BUILD_DATE
LABEL org.label-schema.name="rdl-athenz-server"
LABEL org.label-schema.description="base image of RDL"
LABEL org.label-schema.url="https://www.athenz.io/"
LABEL org.label-schema.vcs-url="https://github.com/AthenZ/athenz"
LABEL org.label-schema.vcs-ref=$VCS_REF

ENV APP_NAME rdl-gen-athenz-server

COPY --from=builder /usr/bin/${APP_NAME} /usr/bin/${APP_NAME}
COPY --from=builder /usr/bin/rdl /usr/bin/rdl
