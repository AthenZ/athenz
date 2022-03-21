FROM golang:1.14-alpine AS builder

ENV APP_NAME athenz-conf

RUN set -eux \
    && apk --no-cache add --virtual build-dependencies cmake g++ make unzip curl upx git

WORKDIR ${GOPATH}/src/github.com/AthenZ/athenz

COPY . .

WORKDIR ${GOPATH}/src/github.com/AthenZ/athenz/utils/athenz-conf

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
LABEL org.label-schema.name="athenz-conf"
LABEL org.label-schema.description="athenz-conf CLI"
LABEL org.label-schema.url="https://www.athenz.io/"
LABEL org.label-schema.vcs-url="https://github.com/AthenZ/athenz"
LABEL org.label-schema.vcs-ref=$VCS_REF

ENV APP_NAME athenz-conf

COPY --from=builder /usr/bin/${APP_NAME} /usr/bin/${APP_NAME}

USER ${APP_NAME}:${APP_NAME}

ENTRYPOINT ["/usr/bin/athenz-conf"]
